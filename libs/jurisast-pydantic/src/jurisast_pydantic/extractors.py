"""
Tool Call → AST IR Extractor.

Converts Pydantic AI tool call metadata and arguments into ExecutionGraph
fragments for Z3 verification. This is the bridge between the agent runtime
and the formal verification engine.

The ToolCallExtractor reads JurisAST decorator metadata (attached by
@tainted_source, @tainted_sink, etc.) and the current TaintRegistry state
to build an ExecutionGraph that represents the proposed data flow for a
single tool call.

Design Decision:
    We build a focused graph fragment per tool call rather than a
    full-session graph because:
    - Each tool call is verified independently before execution
    - This avoids quadratic growth in Z3 constraint size
    - The TaintRegistry provides the "memory" between calls
    - Fragments can be composed later for end-to-end analysis
"""

from __future__ import annotations

import uuid
from typing import Any, Callable, Dict, List, Optional

from jurisast_core.ast_ir import (
    DataSourceNode,
    DeclassifyNode,
    ExecutionGraph,
    ExecutionGraphBuilder,
    SinkNode,
    TransformNode,
)
from jurisast_core.labels import (
    LABEL_PUBLIC,
    Classification,
    Jurisdiction,
    SecurityLabel,
)
from jurisast_core.taint import TaintRegistry

from jurisast_pydantic.decorators import JURISAST_METADATA_KEY, get_jurisast_metadata


class ToolCallExtractor:
    """
    Extracts ExecutionGraph fragments from tool call metadata and arguments.

    For each tool call, the extractor:
    1. Reads JurisAST metadata from the tool function's __jurisast_metadata__
    2. Resolves taint labels from the TaintRegistry for all arguments
    3. Builds an ExecutionGraph fragment with the appropriate node types
    4. Returns the graph ready for Z3 encoding

    The extractor handles four tool types:
        - source: Creates a DataSourceNode (data enters the pipeline)
        - sink: Creates DataSourceNode(s) for inputs + SinkNode (data exits)
        - declassifier: Creates DataSourceNode + DeclassifyNode (label downgrade)
        - transform: Creates DataSourceNode(s) + TransformNode (data processing)

    For tools without JurisAST metadata, a default "transform" graph is built
    using the joined label from all tainted arguments.
    """

    def extract(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        tool_callable: Callable[..., Any],
        registry: TaintRegistry,
        agent_id: str = "default_agent",
    ) -> ExecutionGraph:
        """
        Build an ExecutionGraph fragment from a tool call.

        Args:
            tool_name: Name of the tool being called.
            tool_args: Validated tool call arguments.
            tool_callable: The actual tool function (inspected for metadata).
            registry: The current TaintRegistry for resolving input labels.
            agent_id: ID of the agent making the call.

        Returns:
            An ExecutionGraph fragment for Z3 verification.
        """
        metadata = get_jurisast_metadata(tool_callable)

        if metadata is None:
            # No JurisAST metadata → treat as a generic transform
            return self._build_transform_graph(
                tool_name, tool_args, registry, agent_id
            )

        tool_type = metadata.get("type", "transform")

        if tool_type == "source":
            return self._build_source_graph(
                tool_name, tool_args, metadata, agent_id
            )
        elif tool_type == "sink":
            return self._build_sink_graph(
                tool_name, tool_args, metadata, registry, agent_id
            )
        elif tool_type == "declassifier":
            return self._build_declassifier_graph(
                tool_name, tool_args, metadata, registry, agent_id
            )
        elif tool_type == "handoff":
            return self._build_handoff_graph(
                tool_name, tool_args, metadata, registry, agent_id
            )
        else:
            # Unknown type → treat as transform
            return self._build_transform_graph(
                tool_name, tool_args, registry, agent_id
            )

    def _build_source_graph(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        metadata: Dict[str, Any],
        agent_id: str,
    ) -> ExecutionGraph:
        """
        Build graph for a data source tool.

        Source tools introduce new tainted data. The graph is a single
        DataSourceNode with the label from the decorator metadata.
        """
        label: SecurityLabel = metadata["label"]
        builder = ExecutionGraphBuilder(agent_id=agent_id)

        builder.add_source(
            tool_name=tool_name,
            label=label,
            arguments=tool_args,
            node_id=f"src_{tool_name}",
            description=metadata.get("description", f"Data source: {tool_name}"),
        )

        return builder.build()

    def _build_sink_graph(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        metadata: Dict[str, Any],
        registry: TaintRegistry,
        agent_id: str,
    ) -> ExecutionGraph:
        """
        Build graph for a sink tool.

        Sink tools send data externally. The graph has:
        - One or more DataSourceNodes representing the tainted inputs
        - A SinkNode with the target jurisdiction/classification constraints

        The Z3 solver checks that all input labels are ≤ the sink's constraints.
        """
        target_jurisdiction: Jurisdiction = metadata["target_jurisdiction"]
        max_classification: Classification = metadata["max_classification"]

        builder = ExecutionGraphBuilder(agent_id=agent_id)

        # Build source nodes for each tainted argument
        input_node_ids = self._build_input_sources(
            tool_args, registry, builder, tool_name
        )

        # If no tainted inputs were found, create a public source
        if not input_node_ids:
            src = builder.add_source(
                tool_name=f"{tool_name}_input",
                label=LABEL_PUBLIC,
                arguments=tool_args,
                node_id=f"src_{tool_name}_public",
                description=f"Untainted input to sink {tool_name}",
            )
            input_node_ids = [src.node_id]

        # Add the sink node
        builder.add_sink(
            tool_name=tool_name,
            target_jurisdiction=target_jurisdiction,
            max_classification=max_classification,
            input_node_ids=input_node_ids,
            node_id=f"snk_{tool_name}",
            description=metadata.get("description", f"Sink: {tool_name}"),
        )

        return builder.build()

    def _build_declassifier_graph(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        metadata: Dict[str, Any],
        registry: TaintRegistry,
        agent_id: str,
    ) -> ExecutionGraph:
        """
        Build graph for a declassifier tool.

        Declassifier tools reduce information. The graph has:
        - A DataSourceNode for the tainted input
        - A DeclassifyNode that downgrades the label

        The Z3 solver recognizes the downgrade as valid, allowing
        downstream sinks to accept the declassified data.
        """
        output_label: SecurityLabel = metadata["output_label"]
        max_bits: float = metadata["max_bits"]
        output_type: str = metadata.get("output_type", "bool")
        output_schema: Dict[str, Any] = metadata.get("output_schema", {})

        builder = ExecutionGraphBuilder(agent_id=agent_id)

        # Find the primary tainted input
        input_label = registry.get_label_for_args(tool_args)
        src = builder.add_source(
            tool_name=f"{tool_name}_input",
            label=input_label,
            arguments=tool_args,
            node_id=f"src_{tool_name}_input",
            description=f"Input to declassifier {tool_name}",
        )

        # Add the declassification node
        builder.add_declassifier(
            input_node_id=src.node_id,
            output_type=output_type,
            output_label=output_label,
            max_bits=max_bits,
            output_schema=output_schema,
            node_id=f"dcl_{tool_name}",
            description=metadata.get(
                "description",
                f"Declassify via {tool_name} ({max_bits} bits)",
            ),
        )

        return builder.build()

    def _build_handoff_graph(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        metadata: Dict[str, Any],
        registry: TaintRegistry,
        agent_id: str,
    ) -> ExecutionGraph:
        """
        Build graph for an agent handoff tool.

        Handoff tools transfer data between agents. The graph has:
        - DataSourceNode(s) for tainted inputs
        - An AgentHandoffNode that propagates the joined label
        """
        target_agent_id: str = metadata["target_agent_id"]

        builder = ExecutionGraphBuilder(agent_id=agent_id)

        # Build source nodes for tainted args
        input_node_ids = self._build_input_sources(
            tool_args, registry, builder, tool_name
        )

        if not input_node_ids:
            src = builder.add_source(
                tool_name=f"{tool_name}_input",
                label=LABEL_PUBLIC,
                arguments=tool_args,
                node_id=f"src_{tool_name}_public",
            )
            input_node_ids = [src.node_id]

        # Compute joined label
        input_label = registry.get_label_for_args(tool_args)

        builder.add_handoff(
            source_agent_id=agent_id,
            target_agent_id=target_agent_id,
            input_node_ids=input_node_ids,
            propagated_label=input_label,
            node_id=f"hnd_{tool_name}",
            description=metadata.get(
                "description",
                f"Handoff to {target_agent_id} via {tool_name}",
            ),
        )

        return builder.build()

    def _build_transform_graph(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        registry: TaintRegistry,
        agent_id: str,
    ) -> ExecutionGraph:
        """
        Build graph for a generic transform tool (no JurisAST metadata).

        Transform tools process data without changing its label. The graph has:
        - DataSourceNode(s) for tainted inputs
        - A TransformNode with the joined label of all inputs
        """
        builder = ExecutionGraphBuilder(agent_id=agent_id)

        input_node_ids = self._build_input_sources(
            tool_args, registry, builder, tool_name
        )

        if not input_node_ids:
            # No tainted inputs — create a trivial public source + transform
            src = builder.add_source(
                tool_name=f"{tool_name}_input",
                label=LABEL_PUBLIC,
                arguments=tool_args,
                node_id=f"src_{tool_name}_public",
            )
            input_node_ids = [src.node_id]

        input_label = registry.get_label_for_args(tool_args)

        builder.add_transform(
            operation=tool_name,
            input_node_ids=input_node_ids,
            output_label=input_label,
            node_id=f"xfm_{tool_name}",
            description=f"Transform: {tool_name}",
        )

        return builder.build()

    def _build_input_sources(
        self,
        tool_args: Dict[str, Any],
        registry: TaintRegistry,
        builder: ExecutionGraphBuilder,
        tool_name: str,
    ) -> List[str]:
        """
        Build DataSourceNodes for all tainted values referenced in tool arguments.

        For each argument value that is a key in the TaintRegistry, creates
        a DataSourceNode with the corresponding label.

        Args:
            tool_args: The tool call arguments.
            registry: The TaintRegistry to look up tainted values.
            builder: The graph builder to add nodes to.
            tool_name: Name of the tool (for node naming).

        Returns:
            List of created node IDs.
        """
        input_node_ids: List[str] = []
        seen_keys: set[str] = set()

        for arg_name, arg_value in tool_args.items():
            if not isinstance(arg_value, str):
                continue

            # Check if arg value is a field projection (e.g. parent.field)
            if "." in arg_value:
                parent_key, field_name = arg_value.split(".", 1)
                parent_tv = registry.lookup(parent_key)
                if parent_tv is not None and field_name in parent_tv.field_labels:
                    parent_node_id = f"src_{tool_name}_{parent_key.replace('.', '_')}"
                    if parent_node_id not in builder._node_ids:
                        builder.add_source(
                            tool_name=parent_key,
                            label=parent_tv.label,
                            arguments={arg_name: parent_key},
                            node_id=parent_node_id,
                            description=f"Parent composite source for '{parent_key}'",
                        )
                    prj_node_id = f"prj_{tool_name}_{arg_name}"
                    field_label = parent_tv.field_labels[field_name]
                    builder.add_projection(
                        input_node_id=parent_node_id,
                        field_names=[field_name],
                        projected_label=field_label,
                        node_id=prj_node_id,
                        description=f"Field projection of '{field_name}' from '{parent_key}'",
                    )
                    input_node_ids.append(prj_node_id)
                    continue

            # Check if arg value is a registry key
            tv = registry.lookup(arg_value)
            if tv is not None and arg_value not in seen_keys:
                seen_keys.add(arg_value)
                node_id = f"src_{tool_name}_{arg_name}"
                builder.add_source(
                    tool_name=f"{tool_name}_{arg_name}",
                    label=tv.label,
                    arguments={arg_name: arg_value},
                    node_id=node_id,
                    description=f"Tainted input '{arg_name}' from registry key '{arg_value}'",
                )
                input_node_ids.append(node_id)
                continue

            # Check if arg value matches a taint_id
            for reg_key, reg_tv in registry.get_all_tainted().items():
                if arg_value == reg_tv.taint_id and reg_key not in seen_keys:
                    seen_keys.add(reg_key)
                    node_id = f"src_{tool_name}_{arg_name}"
                    builder.add_source(
                        tool_name=f"{tool_name}_{arg_name}",
                        label=reg_tv.label,
                        arguments={arg_name: arg_value},
                        node_id=node_id,
                        description=f"Tainted input '{arg_name}' from taint_id '{arg_value}'",
                    )
                    input_node_ids.append(node_id)
                    break

        return input_node_ids

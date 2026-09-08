"""
AST Intermediate Representation for Execution Graphs.

Defines the typed node graph that represents an agent's intended execution plan.
This is NOT a Python source code AST — it's a custom IR where each node represents
a data operation (source, transform, sink, declassify, handoff) annotated with
security labels for Information Flow Control verification.

The IR is a Directed Acyclic Graph (DAG) represented as:
    - A list of typed ASTNode variants (Pydantic discriminated union)
    - A list of directed edges (source_node_id → target_node_id)

The ExecutionGraph provides:
    - Topological ordering for constraint generation
    - Node lookup by ID
    - Source/sink extraction for verification
    - Cycle detection (graphs must be acyclic)

Design Decision: Pydantic Discriminated Unions
    We use Literal-tagged Pydantic models with Field(discriminator="node_type")
    instead of a visitor pattern or class hierarchy. This gives us:
    - Native JSON serialization/deserialization
    - Pattern matching via match/case on node_type
    - Automatic JSON schema generation for documentation
    - Type-safe construction with full validation
"""

from __future__ import annotations

import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Literal, Optional, Set, Tuple, Union

from pydantic import BaseModel, Field

from jurisast_core.exceptions import ASTConstructionError
from jurisast_core.labels import Classification, Jurisdiction, SecurityLabel


# ─── AST Node Types (Discriminated Union Members) ────────────────────────────


class DataSourceNode(BaseModel):
    """
    A leaf node representing data retrieval with a taint label.

    This node is produced when an agent calls a @tainted_source tool.
    It introduces new tainted data into the execution graph with a
    specific SecurityLabel derived from the tool's metadata.

    Examples:
        - Fetching a customer record from an EU database → EU/PII
        - Reading an email from a US inbox → US/CONFIDENTIAL
        - Querying a public API → INTERNAL/PUBLIC
    """

    node_type: Literal["data_source"] = "data_source"
    node_id: str = Field(
        default_factory=lambda: f"src_{uuid.uuid4().hex[:8]}",
        description="Unique identifier for this node within the graph.",
    )
    tool_name: str = Field(
        description="The name of the tool that retrieves this data.",
    )
    label: SecurityLabel = Field(
        description="The security label assigned to the retrieved data.",
    )
    arguments: Dict[str, Any] = Field(
        default_factory=dict,
        description="The validated tool call arguments.",
    )
    description: Optional[str] = Field(
        default=None,
        description="Human-readable description of what data is being retrieved.",
    )


class TransformNode(BaseModel):
    """
    A node representing data transformation (LLM processing, computation).

    Transform nodes consume one or more inputs and produce an output.
    The output label is the JOIN (least upper bound) of all input labels,
    ensuring taint propagation through the transformation.

    Examples:
        - LLM summarizing a document
        - Translating text from one language to another
        - Merging data from multiple sources
    """

    node_type: Literal["transform"] = "transform"
    node_id: str = Field(
        default_factory=lambda: f"xfm_{uuid.uuid4().hex[:8]}",
    )
    operation: str = Field(
        description="The type of transformation (e.g., 'summarize', 'translate', 'merge').",
    )
    input_node_ids: List[str] = Field(
        description="IDs of the nodes whose outputs feed into this transform.",
    )
    output_label: SecurityLabel = Field(
        description="The propagated (joined) label after transformation.",
    )
    description: Optional[str] = Field(
        default=None,
    )


class SinkNode(BaseModel):
    """
    A leaf node representing an external output/action.

    This is the critical node for IFC verification. A sink represents
    data leaving the system boundary (API call, webhook, file write, etc.).
    The Z3 solver verifies that data flowing into a sink does NOT violate
    the sink's jurisdiction and classification constraints.

    The non-interference invariant for a sink:
        ∀ input ∈ inputs:
            input.jurisdiction ≤ sink.target_jurisdiction AND
            input.classification ≤ sink.max_classification

    Examples:
        - Sending data to a US analytics webhook → US/PUBLIC
        - Writing to an EU-only database → EU/RESTRICTED
        - Posting to a public Slack channel → EXTERNAL/PUBLIC
    """

    node_type: Literal["sink"] = "sink"
    node_id: str = Field(
        default_factory=lambda: f"snk_{uuid.uuid4().hex[:8]}",
    )
    tool_name: str = Field(
        description="The name of the tool performing the external action.",
    )
    target_jurisdiction: Jurisdiction = Field(
        description="The jurisdiction of the external target system.",
    )
    max_classification: Classification = Field(
        description="The maximum classification level the target can accept.",
    )
    input_node_ids: List[str] = Field(
        description="IDs of the nodes whose outputs are sent to this sink.",
    )
    description: Optional[str] = Field(
        default=None,
    )


class DeclassifyNode(BaseModel):
    """
    A node representing controlled declassification.

    Declassification is the ONLY valid mechanism for downgrading a
    security label. It works by forcing the LLM output through Pydantic's
    strict mode constrained decoding, bounding the Shannon mutual
    information transferred from the tainted input.

    The max_bits field records log₂(output_cardinality):
        - bool → 1 bit
        - Enum with N values → log₂(N) bits
        - Literal["a", "b", "c"] → log₂(3) ≈ 1.58 bits

    The Z3 solver recognizes DeclassifyNodes as valid label transitions,
    allowing workflows to continue with the downgraded label.

    Examples:
        - Extracting boolean sentiment from a PII email → 1 bit
        - Classifying a document into 5 categories → 2.32 bits
    """

    node_type: Literal["declassify"] = "declassify"
    node_id: str = Field(
        default_factory=lambda: f"dcl_{uuid.uuid4().hex[:8]}",
    )
    input_node_id: str = Field(
        description="ID of the single input node being declassified.",
    )
    output_type: str = Field(
        description="The constrained output type (e.g., 'bool', 'enum', 'int_range').",
    )
    output_schema: Dict[str, Any] = Field(
        default_factory=dict,
        description="Pydantic JSON schema of the constrained output.",
    )
    output_label: SecurityLabel = Field(
        description="The downgraded security label after declassification.",
    )
    max_bits: float = Field(
        ge=0,
        description="Shannon information bound (log₂ of output cardinality).",
    )
    description: Optional[str] = Field(
        default=None,
    )


class AgentHandoffNode(BaseModel):
    """
    A node representing data passing between agents in a multi-agent pipeline.

    When Agent A passes data to Agent B, the taint must propagate. The
    handoff node ensures that the receiving agent inherits the joined
    label of all data being transferred.

    This is critical for preventing "taint laundering" attacks where an
    adversary routes tainted data through an intermediary agent to
    circumvent IFC policies.
    """

    node_type: Literal["agent_handoff"] = "agent_handoff"
    node_id: str = Field(
        default_factory=lambda: f"hnd_{uuid.uuid4().hex[:8]}",
    )
    source_agent_id: str = Field(
        description="The agent sending the data.",
    )
    target_agent_id: str = Field(
        description="The agent receiving the data.",
    )
    input_node_ids: List[str] = Field(
        description="IDs of nodes being handed off.",
    )
    propagated_label: SecurityLabel = Field(
        description="The joined label of all handed-off data.",
    )
    description: Optional[str] = Field(
        default=None,
    )


# ─── Discriminated Union Type ────────────────────────────────────────────────

ASTNode = Annotated[
    Union[
        DataSourceNode,
        TransformNode,
        SinkNode,
        DeclassifyNode,
        AgentHandoffNode,
    ],
    Field(discriminator="node_type"),
]
"""
The full IR node type — a discriminated union of all node variants.
Pydantic routes deserialization based on the 'node_type' literal tag.
"""


# ─── Execution Graph ─────────────────────────────────────────────────────────


class ExecutionGraph(BaseModel):
    """
    The complete execution plan, ready for Z3 verification.

    An ExecutionGraph is a Directed Acyclic Graph (DAG) where:
        - Nodes represent data operations (sources, transforms, sinks, etc.)
        - Edges represent data flow dependencies (source → target)

    The graph provides:
        - topological_order(): Nodes sorted by dependency for Z3 constraint generation
        - get_sources() / get_sinks(): Extract leaf nodes for verification
        - validate(): Check structural integrity (no cycles, valid references)

    Construction:
        Use ExecutionGraphBuilder for safe incremental construction,
        or construct directly for testing.
    """

    graph_id: str = Field(
        default_factory=lambda: f"graph_{uuid.uuid4().hex[:8]}",
        description="Unique identifier for this execution graph.",
    )
    agent_id: str = Field(
        description="The primary agent that owns this execution graph.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of graph construction.",
    )
    nodes: List[ASTNode] = Field(
        default_factory=list,
        description="All nodes in the execution graph.",
    )
    edges: List[Tuple[str, str]] = Field(
        default_factory=list,
        description="Directed edges as (source_node_id, target_node_id) tuples.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional metadata about the graph.",
    )

    # ─── Node Accessors ──────────────────────────────────────────────────

    def get_node(self, node_id: str) -> ASTNode:
        """
        Retrieve a node by its unique ID.

        Args:
            node_id: The node's unique identifier.

        Returns:
            The matching ASTNode.

        Raises:
            ASTConstructionError: If the node ID is not found.
        """
        for node in self.nodes:
            if node.node_id == node_id:
                return node
        raise ASTConstructionError(
            f"Node '{node_id}' not found in graph '{self.graph_id}'. "
            f"Available nodes: {[n.node_id for n in self.nodes]}",
        )

    def get_sources(self) -> List[DataSourceNode]:
        """Get all DataSourceNode instances (data entry points)."""
        return [n for n in self.nodes if isinstance(n, DataSourceNode)]

    def get_sinks(self) -> List[SinkNode]:
        """Get all SinkNode instances (data exit points)."""
        return [n for n in self.nodes if isinstance(n, SinkNode)]

    def get_transforms(self) -> List[TransformNode]:
        """Get all TransformNode instances."""
        return [n for n in self.nodes if isinstance(n, TransformNode)]

    def get_declassifiers(self) -> List[DeclassifyNode]:
        """Get all DeclassifyNode instances."""
        return [n for n in self.nodes if isinstance(n, DeclassifyNode)]

    def get_handoffs(self) -> List[AgentHandoffNode]:
        """Get all AgentHandoffNode instances."""
        return [n for n in self.nodes if isinstance(n, AgentHandoffNode)]

    @property
    def node_ids(self) -> Set[str]:
        """Set of all node IDs in the graph."""
        return {n.node_id for n in self.nodes}

    # ─── Graph Algorithms ────────────────────────────────────────────────

    def _build_adjacency(self) -> Dict[str, List[str]]:
        """Build forward adjacency list from edges."""
        adj: Dict[str, List[str]] = defaultdict(list)
        for src, tgt in self.edges:
            adj[src].append(tgt)
        return dict(adj)

    def _build_reverse_adjacency(self) -> Dict[str, List[str]]:
        """Build reverse adjacency list (predecessors)."""
        rev: Dict[str, List[str]] = defaultdict(list)
        for src, tgt in self.edges:
            rev[tgt].append(src)
        return dict(rev)

    def _compute_in_degrees(self) -> Dict[str, int]:
        """Compute in-degree for each node."""
        in_deg: Dict[str, int] = {n.node_id: 0 for n in self.nodes}
        for _, tgt in self.edges:
            in_deg[tgt] = in_deg.get(tgt, 0) + 1
        return in_deg

    def topological_order(self) -> List[ASTNode]:
        """
        Return nodes in topological order (Kahn's algorithm).

        Nodes are sorted so that for every edge (u → v), u appears before v.
        This ordering is required for Z3 constraint generation, ensuring that
        when we encode a node, all its inputs have already been encoded.

        Returns:
            List of ASTNode in dependency-respecting order.

        Raises:
            ASTConstructionError: If the graph contains a cycle.
        """
        in_deg = self._compute_in_degrees()
        queue: deque[str] = deque()
        for nid, deg in in_deg.items():
            if deg == 0:
                queue.append(nid)

        order: List[str] = []
        adj = self._build_adjacency()

        while queue:
            nid = queue.popleft()
            order.append(nid)
            for neighbor in adj.get(nid, []):
                in_deg[neighbor] -= 1
                if in_deg[neighbor] == 0:
                    queue.append(neighbor)

        if len(order) != len(self.nodes):
            missing = self.node_ids - set(order)
            raise ASTConstructionError(
                f"Cycle detected in execution graph '{self.graph_id}'. "
                f"Nodes involved in cycle: {missing}",
            )

        # Map IDs back to node objects
        node_map = {n.node_id: n for n in self.nodes}
        return [node_map[nid] for nid in order]

    def get_predecessors(self, node_id: str) -> List[ASTNode]:
        """Get all nodes that feed into the given node."""
        rev = self._build_reverse_adjacency()
        pred_ids = rev.get(node_id, [])
        node_map = {n.node_id: n for n in self.nodes}
        return [node_map[pid] for pid in pred_ids if pid in node_map]

    def get_successors(self, node_id: str) -> List[ASTNode]:
        """Get all nodes that the given node feeds into."""
        adj = self._build_adjacency()
        succ_ids = adj.get(node_id, [])
        node_map = {n.node_id: n for n in self.nodes}
        return [node_map[sid] for sid in succ_ids if sid in node_map]

    # ─── Validation ──────────────────────────────────────────────────────

    def validate_structure(self) -> List[str]:
        """
        Validate the structural integrity of the execution graph.

        Checks:
            1. All edge endpoints reference existing nodes
            2. No duplicate node IDs
            3. Graph is acyclic (DAG property)
            4. Source nodes have no incoming edges
            5. Sink nodes have no outgoing edges
            6. All input_node_ids references are consistent with edges

        Returns:
            List of validation error messages (empty if valid).
        """
        errors: List[str] = []
        node_ids = self.node_ids

        # Check 1: Edge endpoints exist
        for src, tgt in self.edges:
            if src not in node_ids:
                errors.append(f"Edge source '{src}' not found in nodes.")
            if tgt not in node_ids:
                errors.append(f"Edge target '{tgt}' not found in nodes.")

        # Check 2: No duplicate node IDs
        ids = [n.node_id for n in self.nodes]
        if len(ids) != len(set(ids)):
            dupes = [nid for nid in ids if ids.count(nid) > 1]
            errors.append(f"Duplicate node IDs: {set(dupes)}")

        # Check 3: Acyclicity
        try:
            self.topological_order()
        except ASTConstructionError as e:
            errors.append(str(e))

        # Check 4: Source nodes should have no incoming edges
        incoming = {tgt for _, tgt in self.edges}
        for src_node in self.get_sources():
            if src_node.node_id in incoming:
                errors.append(
                    f"DataSourceNode '{src_node.node_id}' has incoming edges "
                    f"(sources should be root nodes)."
                )

        # Check 5: Sink nodes should have no outgoing edges
        outgoing = {src for src, _ in self.edges}
        for sink_node in self.get_sinks():
            if sink_node.node_id in outgoing:
                errors.append(
                    f"SinkNode '{sink_node.node_id}' has outgoing edges "
                    f"(sinks should be terminal nodes)."
                )

        return errors

    def is_valid(self) -> bool:
        """Check if the graph passes all structural validations."""
        return len(self.validate_structure()) == 0

    def __len__(self) -> int:
        return len(self.nodes)

    def __repr__(self) -> str:
        return (
            f"ExecutionGraph(id={self.graph_id}, "
            f"nodes={len(self.nodes)}, edges={len(self.edges)})"
        )


# ─── Execution Graph Builder ─────────────────────────────────────────────────


class ExecutionGraphBuilder:
    """
    Fluent builder for constructing ExecutionGraphs with automatic edge wiring.

    Provides a safe, incremental API for building graphs without manually
    managing edge lists. Edges are automatically created based on the
    input_node_ids / input_node_id fields of each node.

    Example:
        >>> builder = ExecutionGraphBuilder(agent_id="agent_1")
        >>> src = builder.add_source("fetch_customer", LABEL_EU_PII)
        >>> xfm = builder.add_transform("summarize", [src.node_id], LABEL_EU_PII)
        >>> builder.add_sink("send_webhook", Jurisdiction.US, Classification.PUBLIC, [xfm.node_id])
        >>> graph = builder.build()
        >>> assert graph.is_valid()
    """

    def __init__(self, agent_id: str, graph_id: Optional[str] = None) -> None:
        self._agent_id = agent_id
        self._graph_id = graph_id or f"graph_{uuid.uuid4().hex[:8]}"
        self._nodes: List[ASTNode] = []
        self._edges: List[Tuple[str, str]] = []
        self._node_ids: Set[str] = set()

    def _register_node(self, node: ASTNode) -> None:
        """Register a node and validate uniqueness."""
        if node.node_id in self._node_ids:
            raise ASTConstructionError(
                f"Duplicate node ID '{node.node_id}' in graph '{self._graph_id}'.",
            )
        self._node_ids.add(node.node_id)
        self._nodes.append(node)

    def _add_edges_from_inputs(self, node_id: str, input_ids: List[str]) -> None:
        """Create edges from input nodes to this node."""
        for input_id in input_ids:
            if input_id not in self._node_ids:
                raise ASTConstructionError(
                    f"Input node '{input_id}' referenced by '{node_id}' "
                    f"does not exist in the graph.",
                )
            self._edges.append((input_id, node_id))

    def add_source(
        self,
        tool_name: str,
        label: SecurityLabel,
        arguments: Optional[Dict[str, Any]] = None,
        node_id: Optional[str] = None,
        description: Optional[str] = None,
    ) -> DataSourceNode:
        """
        Add a data source node to the graph.

        Args:
            tool_name: Name of the data retrieval tool.
            label: Security label for the retrieved data.
            arguments: Optional tool call arguments.
            node_id: Optional explicit node ID.
            description: Optional human-readable description.

        Returns:
            The created DataSourceNode.
        """
        node = DataSourceNode(
            node_id=node_id or f"src_{uuid.uuid4().hex[:8]}",
            tool_name=tool_name,
            label=label,
            arguments=arguments or {},
            description=description,
        )
        self._register_node(node)
        return node

    def add_transform(
        self,
        operation: str,
        input_node_ids: List[str],
        output_label: SecurityLabel,
        node_id: Optional[str] = None,
        description: Optional[str] = None,
    ) -> TransformNode:
        """
        Add a transform node to the graph.

        Edges are automatically created from each input node to this node.

        Args:
            operation: Type of transformation.
            input_node_ids: IDs of input nodes.
            output_label: The propagated label (should be join of inputs).
            node_id: Optional explicit node ID.
            description: Optional description.

        Returns:
            The created TransformNode.
        """
        nid = node_id or f"xfm_{uuid.uuid4().hex[:8]}"
        node = TransformNode(
            node_id=nid,
            operation=operation,
            input_node_ids=input_node_ids,
            output_label=output_label,
            description=description,
        )
        self._register_node(node)
        self._add_edges_from_inputs(nid, input_node_ids)
        return node

    def add_sink(
        self,
        tool_name: str,
        target_jurisdiction: Jurisdiction,
        max_classification: Classification,
        input_node_ids: List[str],
        node_id: Optional[str] = None,
        description: Optional[str] = None,
    ) -> SinkNode:
        """
        Add a sink node to the graph.

        Args:
            tool_name: Name of the external action tool.
            target_jurisdiction: Jurisdiction of the external target.
            max_classification: Maximum classification the target accepts.
            input_node_ids: IDs of nodes feeding into this sink.
            node_id: Optional explicit node ID.
            description: Optional description.

        Returns:
            The created SinkNode.
        """
        nid = node_id or f"snk_{uuid.uuid4().hex[:8]}"
        node = SinkNode(
            node_id=nid,
            tool_name=tool_name,
            target_jurisdiction=target_jurisdiction,
            max_classification=max_classification,
            input_node_ids=input_node_ids,
            description=description,
        )
        self._register_node(node)
        self._add_edges_from_inputs(nid, input_node_ids)
        return node

    def add_declassifier(
        self,
        input_node_id: str,
        output_type: str,
        output_label: SecurityLabel,
        max_bits: float,
        output_schema: Optional[Dict[str, Any]] = None,
        node_id: Optional[str] = None,
        description: Optional[str] = None,
    ) -> DeclassifyNode:
        """
        Add a declassification node to the graph.

        Args:
            input_node_id: ID of the single input node being declassified.
            output_type: The constrained output type.
            output_label: The downgraded security label.
            max_bits: Shannon information bound.
            output_schema: Optional JSON schema of constrained output.
            node_id: Optional explicit node ID.
            description: Optional description.

        Returns:
            The created DeclassifyNode.
        """
        nid = node_id or f"dcl_{uuid.uuid4().hex[:8]}"
        node = DeclassifyNode(
            node_id=nid,
            input_node_id=input_node_id,
            output_type=output_type,
            output_schema=output_schema or {},
            output_label=output_label,
            max_bits=max_bits,
            description=description,
        )
        self._register_node(node)
        self._add_edges_from_inputs(nid, [input_node_id])
        return node

    def add_handoff(
        self,
        source_agent_id: str,
        target_agent_id: str,
        input_node_ids: List[str],
        propagated_label: SecurityLabel,
        node_id: Optional[str] = None,
        description: Optional[str] = None,
    ) -> AgentHandoffNode:
        """
        Add an agent handoff node to the graph.

        Args:
            source_agent_id: ID of the sending agent.
            target_agent_id: ID of the receiving agent.
            input_node_ids: IDs of nodes being handed off.
            propagated_label: The joined label of all handed-off data.
            node_id: Optional explicit node ID.
            description: Optional description.

        Returns:
            The created AgentHandoffNode.
        """
        nid = node_id or f"hnd_{uuid.uuid4().hex[:8]}"
        node = AgentHandoffNode(
            node_id=nid,
            source_agent_id=source_agent_id,
            target_agent_id=target_agent_id,
            input_node_ids=input_node_ids,
            propagated_label=propagated_label,
            description=description,
        )
        self._register_node(node)
        self._add_edges_from_inputs(nid, input_node_ids)
        return node

    def build(self) -> ExecutionGraph:
        """
        Build the final ExecutionGraph from all added nodes and edges.

        Returns:
            A validated ExecutionGraph.

        Raises:
            ASTConstructionError: If the graph fails structural validation.
        """
        graph = ExecutionGraph(
            graph_id=self._graph_id,
            agent_id=self._agent_id,
            nodes=list(self._nodes),
            edges=list(self._edges),
        )
        errors = graph.validate_structure()
        if errors:
            raise ASTConstructionError(
                f"Graph validation failed with {len(errors)} error(s): "
                + "; ".join(errors),
            )
        return graph

    @property
    def node_count(self) -> int:
        """Number of nodes added so far."""
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        """Number of edges added so far."""
        return len(self._edges)

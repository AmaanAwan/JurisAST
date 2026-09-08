"""
Declarative Decorators for JurisAST Tool Metadata Annotation.

Provides decorators that annotate Pydantic AI tool functions with IFC metadata.
These decorators are the primary user-facing API for declaring data flow properties:

    @tainted_source — marks a tool as a data retrieval point with a SecurityLabel
    @tainted_sink — marks a tool as an external output with jurisdiction constraints
    @declassifier — marks a tool as a controlled information reduction
    @agent_handoff — marks a tool as an inter-agent data transfer

The decorators attach a `__jurisast_metadata__` dict to the function object.
This metadata is later read by the ToolCallExtractor (extractors.py) to build
AST IR fragments for Z3 verification.

Design Decision:
    We use function attribute annotation (func.__jurisast_metadata__) rather than
    a decorator registry because:
    - It works with any function regardless of where it's defined
    - It survives Pydantic AI's internal wrapping of tool functions
    - It's inspectable via getattr() without global state
    - It composes cleanly with other decorators (@agent.tool, etc.)
"""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, FrozenSet, Optional, TypeVar

from jurisast_core.labels import Classification, Jurisdiction, SecurityLabel

F = TypeVar("F", bound=Callable[..., Any])

# Metadata key attached to annotated functions
JURISAST_METADATA_KEY = "__jurisast_metadata__"


def tainted_source(
    jurisdiction: Jurisdiction,
    classification: Classification,
    compartments: FrozenSet[str] | None = None,
    description: str = "",
) -> Callable[[F], F]:
    """
    Mark a tool as a data source that produces tainted data.

    When the agent calls this tool, the returned data will be wrapped
    in a TaintedValue with the specified SecurityLabel, and the flow
    will be tracked through the execution graph.

    Args:
        jurisdiction: Geographic jurisdiction of the data's origin.
        classification: Sensitivity classification of the retrieved data.
        compartments: Optional set-based compartments for need-to-know isolation.
        description: Human-readable description of the data source.

    Returns:
        Decorator that annotates the function with JurisAST source metadata.

    Example:
        >>> @tainted_source(
        ...     jurisdiction=Jurisdiction.EU,
        ...     classification=Classification.SENSITIVE_PII,
        ...     compartments=frozenset({"finance"}),
        ... )
        ... async def fetch_customer_record(customer_id: str) -> str:
        ...     return await db.get_customer(customer_id)
    """

    def decorator(func: F) -> F:
        label = SecurityLabel(
            jurisdiction=jurisdiction,
            classification=classification,
            compartments=compartments or frozenset(),
        )
        metadata: Dict[str, Any] = {
            "type": "source",
            "label": label,
            "jurisdiction": jurisdiction,
            "classification": classification,
            "compartments": compartments or frozenset(),
            "description": description,
        }
        setattr(func, JURISAST_METADATA_KEY, metadata)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        # Preserve metadata through wrapping
        setattr(wrapper, JURISAST_METADATA_KEY, metadata)
        return wrapper  # type: ignore[return-value]

    return decorator


def tainted_sink(
    target_jurisdiction: Jurisdiction,
    max_classification: Classification,
    description: str = "",
) -> Callable[[F], F]:
    """
    Mark a tool as an external sink with jurisdiction constraints.

    When the agent calls this tool, JurisAST's firewall will verify that
    all data flowing into the tool satisfies:
        data.jurisdiction ≤ target_jurisdiction AND
        data.classification ≤ max_classification

    If the check fails, the tool call is blocked (in enforce mode).

    Args:
        target_jurisdiction: Jurisdiction of the external target system.
        max_classification: Maximum classification the target can accept.
        description: Human-readable description of the sink.

    Returns:
        Decorator that annotates the function with JurisAST sink metadata.

    Example:
        >>> @tainted_sink(
        ...     target_jurisdiction=Jurisdiction.US,
        ...     max_classification=Classification.PUBLIC,
        ... )
        ... async def send_to_analytics(payload: str) -> str:
        ...     return await http.post("https://analytics.us.example.com", json=payload)
    """

    def decorator(func: F) -> F:
        metadata: Dict[str, Any] = {
            "type": "sink",
            "target_jurisdiction": target_jurisdiction,
            "max_classification": max_classification,
            "description": description,
        }
        setattr(func, JURISAST_METADATA_KEY, metadata)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        setattr(wrapper, JURISAST_METADATA_KEY, metadata)
        return wrapper  # type: ignore[return-value]

    return decorator


def declassifier(
    output_label: SecurityLabel,
    max_bits: float,
    output_type: str = "bool",
    output_schema: Dict[str, Any] | None = None,
    description: str = "",
) -> Callable[[F], F]:
    """
    Mark a tool as a controlled declassifier with bounded output.

    Declassification is the ONLY valid mechanism for downgrading a security
    label. The output must be structurally bounded (via Pydantic strict mode
    constrained decoding) to limit Shannon mutual information leakage.

    Args:
        output_label: The downgraded security label after declassification.
        max_bits: Shannon information bound (log₂ of output cardinality).
                  - bool → 1.0 bit
                  - Enum with N values → log₂(N) bits
                  - Literal["a", "b", "c"] → log₂(3) ≈ 1.58 bits
        output_type: The constrained output type name (e.g., "bool", "enum").
        output_schema: Optional Pydantic JSON schema of the constrained output.
        description: Human-readable description.

    Returns:
        Decorator that annotates the function with JurisAST declassifier metadata.

    Example:
        >>> @declassifier(
        ...     output_label=SecurityLabel(
        ...         jurisdiction=Jurisdiction.INTERNAL,
        ...         classification=Classification.PUBLIC,
        ...     ),
        ...     max_bits=1.0,
        ...     output_type="bool",
        ... )
        ... async def extract_sentiment(text: str) -> bool:
        ...     return await llm.generate(text, result_type=bool)
    """

    def decorator(func: F) -> F:
        metadata: Dict[str, Any] = {
            "type": "declassifier",
            "output_label": output_label,
            "max_bits": max_bits,
            "output_type": output_type,
            "output_schema": output_schema or {},
            "description": description,
        }
        setattr(func, JURISAST_METADATA_KEY, metadata)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        setattr(wrapper, JURISAST_METADATA_KEY, metadata)
        return wrapper  # type: ignore[return-value]

    return decorator


def agent_handoff(
    target_agent_id: str,
    description: str = "",
) -> Callable[[F], F]:
    """
    Mark a tool as an inter-agent data transfer.

    When data passes between agents, the taint must propagate. This decorator
    ensures that the receiving agent inherits the joined label of all data
    being transferred, preventing taint laundering attacks.

    Args:
        target_agent_id: The identifier of the receiving agent.
        description: Human-readable description.

    Returns:
        Decorator that annotates the function with JurisAST handoff metadata.

    Example:
        >>> @agent_handoff(target_agent_id="summarizer_agent")
        ... async def send_to_summarizer(data: str) -> str:
        ...     return await summarizer.process(data)
    """

    def decorator(func: F) -> F:
        metadata: Dict[str, Any] = {
            "type": "handoff",
            "target_agent_id": target_agent_id,
            "description": description,
        }
        setattr(func, JURISAST_METADATA_KEY, metadata)

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        setattr(wrapper, JURISAST_METADATA_KEY, metadata)
        return wrapper  # type: ignore[return-value]

    return decorator


# ─── Metadata Inspection Utilities ────────────────────────────────────────────


def get_jurisast_metadata(func: Callable[..., Any]) -> Dict[str, Any] | None:
    """
    Extract JurisAST metadata from a decorated function.

    Returns the metadata dict if the function was decorated with a JurisAST
    decorator, or None if the function has no JurisAST metadata.

    Args:
        func: The function to inspect.

    Returns:
        The metadata dict, or None.
    """
    return getattr(func, JURISAST_METADATA_KEY, None)


def get_tool_type(func: Callable[..., Any]) -> str | None:
    """
    Get the JurisAST tool type of a decorated function.

    Returns one of: "source", "sink", "declassifier", "handoff", or None.

    Args:
        func: The function to inspect.

    Returns:
        The tool type string, or None if not decorated.
    """
    metadata = get_jurisast_metadata(func)
    if metadata is None:
        return None
    return metadata.get("type")


def is_tainted_tool(func: Callable[..., Any]) -> bool:
    """
    Check if a function is decorated with any JurisAST metadata.

    Args:
        func: The function to inspect.

    Returns:
        True if the function has JurisAST metadata.
    """
    return get_jurisast_metadata(func) is not None

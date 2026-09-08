"""
JurisAST Pydantic AI Integration Layer.

Provides the execution firewall, decorators, and context extensions that
integrate JurisAST's formal verification engine with Pydantic AI agents.

Key Components:
    - JurisASTFirewall: Core firewall intercepting tool calls for Z3 verification
    - JurisASTDeps: RunContext dependency payload for agent pipelines
    - Decorators: @tainted_source, @tainted_sink, @declassifier, @agent_handoff
    - ToolCallExtractor: Converts tool calls to AST IR execution graphs
    - Agent utilities: Model resolution, dependency factory
"""

from jurisast_pydantic.decorators import (
    JURISAST_METADATA_KEY,
    agent_handoff,
    declassifier,
    get_jurisast_metadata,
    get_tool_type,
    is_tainted_tool,
    tainted_sink,
    tainted_source,
)
from jurisast_pydantic.tainted_context import (
    JurisASTDeps,
)
from jurisast_pydantic.extractors import (
    ToolCallExtractor,
)
from jurisast_pydantic.capability import (
    JurisASTFirewall,
)
from jurisast_pydantic.agent import (
    DEFAULT_MODEL,
    GEMINI_FLASH,
    GEMINI_PRO,
    MODEL_ALIASES,
    create_jurisast_deps,
    resolve_model,
)

__all__ = [
    # Firewall
    "JurisASTFirewall",
    # Context
    "JurisASTDeps",
    # Decorators
    "tainted_source",
    "tainted_sink",
    "declassifier",
    "agent_handoff",
    "get_jurisast_metadata",
    "get_tool_type",
    "is_tainted_tool",
    "JURISAST_METADATA_KEY",
    # Extractor
    "ToolCallExtractor",
    # Agent utilities
    "create_jurisast_deps",
    "resolve_model",
    "GEMINI_FLASH",
    "GEMINI_PRO",
    "DEFAULT_MODEL",
    "MODEL_ALIASES",
]

__version__ = "0.1.0"

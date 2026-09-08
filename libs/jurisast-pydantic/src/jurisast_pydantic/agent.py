"""
JurisAST Agent Factory for Pydantic AI.

Provides factory functions for creating Pydantic AI agents pre-configured
with JurisAST firewall enforcement, Gemini model support, and proper
dependency injection.

Supported models:
    - google-gla:gemini-2.5-flash (fast, cost-effective, default)
    - google-gla:gemini-2.5-pro (highest capability)
    - test (Pydantic AI TestModel for offline testing)

The factory handles:
    - Agent construction with JurisASTDeps dependency type
    - JurisASTFirewall capability configuration
    - Model selection with Gemini API support
    - Taint registry threading for multi-agent pipelines
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from jurisast_core.config import JurisASTConfig
from jurisast_core.taint import TaintRegistry

from jurisast_pydantic.capability import JurisASTFirewall
from jurisast_pydantic.tainted_context import JurisASTDeps


# ─── Model Constants ─────────────────────────────────────────────────────────

# Gemini model identifiers for Pydantic AI
GEMINI_FLASH = "google-gla:gemini-2.5-flash"
GEMINI_PRO = "google-gla:gemini-2.5-pro"

# Mapping from friendly names to Pydantic AI model strings
MODEL_ALIASES: Dict[str, str] = {
    "gemini-flash": GEMINI_FLASH,
    "gemini-pro": GEMINI_PRO,
    "flash": GEMINI_FLASH,
    "pro": GEMINI_PRO,
    "gemini-2.5-flash": GEMINI_FLASH,
    "gemini-2.5-pro": GEMINI_PRO,
}

DEFAULT_MODEL = GEMINI_FLASH


def resolve_model(model: str) -> str:
    """
    Resolve a model name or alias to a Pydantic AI model string.

    Supports both fully-qualified Pydantic AI model strings and
    friendly aliases.

    Args:
        model: Model name, alias, or fully-qualified string.

    Returns:
        The resolved Pydantic AI model string.

    Example:
        >>> resolve_model("gemini-flash")
        'google-gla:gemini-2.5-flash'
        >>> resolve_model("google-gla:gemini-2.5-pro")
        'google-gla:gemini-2.5-pro'
    """
    return MODEL_ALIASES.get(model, model)


def create_jurisast_deps(
    agent_id: str = "jurisast_agent",
    session_id: str | None = None,
    config: JurisASTConfig | None = None,
    taint_registry: TaintRegistry | None = None,
) -> JurisASTDeps:
    """
    Create a JurisASTDeps instance with optional shared state.

    This is the primary factory for creating dependency payloads that
    are injected into Pydantic AI agents via RunContext.

    For multi-agent pipelines, pass the same taint_registry to all
    agents to ensure shared taint tracking.

    Args:
        agent_id: Unique identifier for the agent.
        session_id: Optional session identifier (auto-generated if None).
        config: JurisAST configuration (defaults to enforce mode).
        taint_registry: Shared taint registry (creates new if None).

    Returns:
        Configured JurisASTDeps instance.
    """
    registry = taint_registry if taint_registry is not None else TaintRegistry()
    cfg = config or JurisASTConfig()

    firewall = JurisASTFirewall(
        config=cfg,
        taint_registry=registry,
        agent_id=agent_id,
    )

    deps = JurisASTDeps(
        taint_registry=registry,
        agent_id=agent_id,
        config=cfg,
        firewall=firewall,
    )

    if session_id:
        deps.session_id = session_id

    return deps

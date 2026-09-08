"""
Custom Policy Builder for JurisAST.

Provides a fluent, ergonomic API for enterprise developers to define
domain-specific information flow policies and custom regulatory constraints.
"""

from __future__ import annotations

from typing import FrozenSet, List, Optional, Set

from jurisast_core.labels import Classification, Jurisdiction
from jurisast_core.policies import ConstraintAction, FlowConstraint, PolicySet


class PolicyBuilder:
    """
    Fluent builder for constructing custom PolicySet instances.

    Example:
        >>> policy = (
        ...     PolicyBuilder("HEALTHCARE_HIPAA")
        ...     .with_description("HIPAA Privacy Rule PHI protections")
        ...     .block_cross_border(
        ...         name="phi_no_export",
        ...         source=Jurisdiction.US,
        ...         forbidden_sinks={Jurisdiction.EXTERNAL},
        ...         min_classification=Classification.SENSITIVE_PII,
        ...         regulation="HIPAA Security Rule § 164.312",
        ...     )
        ...     .isolate_compartment(
        ...         name="ehr_isolation",
        ...         compartment="electronic_health_record",
        ...         forbidden_sinks={Jurisdiction.EXTERNAL, Jurisdiction.APAC},
        ...     )
        ...     .build()
        ... )
    """

    def __init__(
        self,
        policy_name: str,
        version: str = "1.0.0",
        description: str = "",
    ) -> None:
        self.policy_name = policy_name
        self.version = version
        self.description = description
        self.constraints: List[FlowConstraint] = []

    def with_description(self, description: str) -> PolicyBuilder:
        """Set the policy set description."""
        self.description = description
        return self

    def with_version(self, version: str) -> PolicyBuilder:
        """Set the semantic version string."""
        self.version = version
        return self

    def add_constraint(self, constraint: FlowConstraint) -> PolicyBuilder:
        """Add a pre-constructed FlowConstraint."""
        self.constraints.append(constraint)
        return self

    def block_cross_border(
        self,
        name: str,
        source: Jurisdiction | Set[Jurisdiction],
        forbidden_sinks: Set[Jurisdiction],
        min_classification: Classification = Classification.PII,
        regulation: str = "",
        description: str = "",
    ) -> PolicyBuilder:
        """
        Add a constraint blocking cross-border data transfer.

        Args:
            name: Identifier for the constraint.
            source: Jurisdiction or set of jurisdictions generating the data.
            forbidden_sinks: Jurisdictions forbidden from receiving this data.
            min_classification: Minimum classification triggering the block.
            regulation: Optional legal citation.
            description: Optional human explanation.
        """
        src_set = {source} if isinstance(source, Jurisdiction) else source
        desc = description or f"Prevent data from {src_set} reaching {forbidden_sinks}"
        self.constraints.append(
            FlowConstraint(
                name=name,
                description=desc,
                regulation=regulation,
                source_jurisdictions=src_set,
                source_classification_min=min_classification,
                forbidden_sink_jurisdictions=forbidden_sinks,
                action=ConstraintAction.BLOCK,
            )
        )
        return self

    def require_declassification(
        self,
        name: str,
        source: Jurisdiction | Set[Jurisdiction],
        forbidden_sinks: Set[Jurisdiction],
        min_classification: Classification = Classification.PII,
        regulation: str = "",
        description: str = "",
    ) -> PolicyBuilder:
        """
        Add a constraint requiring declassification before transfer to external sinks.

        Args:
            name: Identifier for the constraint.
            source: Source jurisdiction(s).
            forbidden_sinks: Destination sinks that require declassification.
            min_classification: Minimum classification triggering the requirement.
            regulation: Optional legal citation.
            description: Optional human explanation.
        """
        src_set = {source} if isinstance(source, Jurisdiction) else source
        desc = description or f"Require declassification for {src_set} data exiting to {forbidden_sinks}"
        self.constraints.append(
            FlowConstraint(
                name=name,
                description=desc,
                regulation=regulation,
                source_jurisdictions=src_set,
                source_classification_min=min_classification,
                forbidden_sink_jurisdictions=forbidden_sinks,
                allow_declassified=True,
                action=ConstraintAction.DECLASSIFY_REQUIRED,
            )
        )
        return self

    def isolate_compartment(
        self,
        name: str,
        compartment: str | FrozenSet[str],
        forbidden_sinks: Set[Jurisdiction],
        regulation: str = "",
        description: str = "",
    ) -> PolicyBuilder:
        """
        Isolate a categorical compartment from flowing to specific sinks.

        Args:
            name: Identifier for the constraint.
            compartment: Single compartment string or frozen set of compartments.
            forbidden_sinks: Destination jurisdictions forbidden to receive this compartment.
            regulation: Optional legal citation.
            description: Optional human explanation.
        """
        comp_set = frozenset([compartment]) if isinstance(compartment, str) else compartment
        desc = description or f"Isolate compartment {comp_set} from {forbidden_sinks}"
        self.constraints.append(
            FlowConstraint(
                name=name,
                description=desc,
                regulation=regulation,
                forbidden_compartments=comp_set,
                forbidden_sink_jurisdictions=forbidden_sinks,
                action=ConstraintAction.BLOCK,
            )
        )
        return self

    def build(self) -> PolicySet:
        """Construct and return the finalized PolicySet."""
        return PolicySet(
            policy_name=self.policy_name,
            version=self.version,
            description=self.description,
            constraints=list(self.constraints),
        )

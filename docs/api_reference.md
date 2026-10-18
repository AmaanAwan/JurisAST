# JurisAST — Core API Reference

> Complete reference documentation for `jurisast-core`.

---

## Table of Contents

1. [`jurisast_core.labels`](#1-jurisast_corelabels)
2. [`jurisast_core.taint`](#2-jurisast_coretaint)
3. [`jurisast_core.ast_ir`](#3-jurisast_coreast_ir)
4. [`jurisast_core.solver`](#4-jurisast_coresolver)
5. [`jurisast_core.exceptions`](#5-jurisast_coreexceptions)
6. [`jurisast_core.config`](#6-jurisast_coreconfig)
7. [`jurisast_core.policies`](#7-jurisast_corepolicies)
8. [`jurisast_core.declassifier`](#8-jurisast_coredeclassifier)
9. [`jurisast_policies`](#9-jurisast_policies)
10. [`jurisast_pydantic`](#10-jurisast_pydantic)

---

## 1. `jurisast_core.labels`

Defines the mathematical security lattice combining geographic jurisdiction, sensitivity classification, and compartments.

### `Jurisdiction` (IntEnum)

Geographic data sovereignty jurisdictions.

| Member | Value | Description |
|:---|:---|:---|
| `INTERNAL` | `0` | Originating local system boundary only |
| `EU` | `10` | European Union / EEA (GDPR jurisdiction) |
| `UK` | `20` | United Kingdom (UK GDPR adequacy) |
| `US` | `30` | United States |
| `APAC` | `40` | Asia-Pacific region |
| `EXTERNAL` | `100` | Unrestricted external systems / webhooks |

### `Classification` (IntEnum)

Data sensitivity classification levels.

| Member | Value | Description |
|:---|:---|:---|
| `PUBLIC` | `0` | Public domain information |
| `INTERNAL_ONLY` | `10` | Non-sensitive internal business records |
| `CONFIDENTIAL` | `20` | Proprietary business information |
| `PII` | `30` | Personally Identifiable Information (GDPR Art. 4) |
| `SENSITIVE_PII` | `40` | Financial, biometric, health records (GDPR Art. 9) |
| `RESTRICTED` | `50` | Board-level secrets, master encryption keys |

### `SecurityLabel` (BaseModel)

Immutable security label representing an element in the lattice.

```python
class SecurityLabel(BaseModel):
    jurisdiction: Jurisdiction
    classification: Classification
    compartments: FrozenSet[str] = frozenset()
```

#### Methods

- **`dominates(other: SecurityLabel) -> bool`**  
  Checks if `self >= other` in the lattice. Returns `True` iff `self.jurisdiction >= other.jurisdiction`, `self.classification >= other.classification`, and `other.compartments.issubset(self.compartments)`.
- **`join(other: SecurityLabel) -> SecurityLabel`**  
  Computes the Least Upper Bound (LUB). Takes `max` of jurisdiction and classification, and `union` of compartments.
- **`meet(other: SecurityLabel) -> SecurityLabel`**  
  Computes the Greatest Lower Bound (GLB). Takes `min` of jurisdiction and classification, and `intersection` of compartments.
- **`can_flow_to(target: SecurityLabel) -> bool`**  
  Checks if data can flow to `target` (equivalent to `target.dominates(self)`).
- **`is_pii() -> bool`**  
  Returns `True` if `classification >= Classification.PII`.
- **`is_eu_sovereign() -> bool`**  
  Returns `True` if `jurisdiction == Jurisdiction.EU`.
- **`is_cross_border_risk(target_jurisdiction: Jurisdiction) -> bool`**  
  Returns `True` if data is EU PII and target jurisdiction is not in `EU_ADEQUATE_JURISDICTIONS`.
- **`without_compartments(to_remove: Set[str] | FrozenSet[str]) -> SecurityLabel`**  
  Returns a new `SecurityLabel` with the specified compartment tags removed.
- **`to_tuple() -> tuple[int, int, frozenset[str]]`**  
  Returns a hashable tuple representation `(jurisdiction.value, classification.value, compartments)`.

### Helper Functions & Constants

- **`label_from_metadata(metadata: dict[str, Any]) -> SecurityLabel`**  
  Parses raw string dictionary into a typed `SecurityLabel`.
- Pre-built constants: `LABEL_PUBLIC`, `LABEL_EU_PII`, `LABEL_EU_SENSITIVE_PII`, `LABEL_EU_RESTRICTED`, `LABEL_US_INTERNAL`, `LABEL_EXTERNAL_PUBLIC`.

---

## 2. `jurisast_core.taint`

Provides dynamic taint tracking, field-level projections, and immutable audit trails.

### `ProvenanceRecord` (BaseModel)

Immutable audit log entry for a single taint operation.

```python
class ProvenanceRecord(BaseModel):
    record_id: str
    timestamp: datetime
    source_tool: str
    agent_id: str
    operation: str  # "create", "propagate", "merge", "declassify", "handoff", "project"
    label_before: SecurityLabel
    label_after: SecurityLabel
    details: Optional[str] = None
```

#### Methods
- `label_changed() -> bool`: Returns `True` if `label_before != label_after`.
- `was_escalation() -> bool`: Returns `True` if label became more restrictive.
- `was_declassification() -> bool`: Returns `True` if label was downgraded.

### `TaintedValue[T]` (BaseModel, Generic[T])

Generic immutable container wrapping a value with its security label, field-level labels, and provenance chain.

```python
class TaintedValue(BaseModel, Generic[T]):
    value: Any
    label: SecurityLabel
    field_labels: Dict[str, SecurityLabel] = Field(default_factory=dict)
    provenance: List[ProvenanceRecord] = []
    taint_id: str
```

#### Methods
- **`project(field_path: str) -> TaintedValue`**  
  Extracts a subfield and its isolated security label. Bypasses monotonic join over-tainting.
- **`propagate(new_label, tool, agent_id, operation="propagate", details=None) -> TaintedValue[T]`**  
  Returns a **new** `TaintedValue` with updated label and appended provenance record.
- **`declassify(target_label, declassified_value, tool, agent_id, max_bits, details=None) -> TaintedValue`**  
  Returns a **new** `TaintedValue` wrapping the declassified output.
- **`static merge_labels(values: Sequence[TaintedValue]) -> SecurityLabel`**  
  Computes the LUB join of all input labels.
- **`static create(value, label, source_tool, agent_id, details=None) -> TaintedValue`**  
  Factory method creating a `TaintedValue` with an initial creation record.

### `TaintedRecord`

Factory for constructing field-sensitive composite records.

#### Methods
- **`static create(data: dict[str, Any] | BaseModel, field_labels: dict[str, SecurityLabel], source_tool: str, agent_id: str = "agent", default_label: SecurityLabel = LABEL_PUBLIC) -> TaintedValue`**  
  Constructs a `TaintedValue` where the record-level label is the join $\bigsqcup \text{field\_labels}$, and individual field labels are recorded in `field_labels`.

### `TaintRegistry`

Session-scoped registry mapping string keys to `TaintedValue` instances. Supports field-level dot-notation accessors (`"tool_result.field_name"`).

#### Methods
- `register(key: str, tainted: TaintedValue) -> None`
- `lookup(key: str) -> Optional[TaintedValue]`: Automatically resolves dot-notation field paths (e.g. `report.public_metrics` calls `record.project("public_metrics")`).
- `lookup_or_raise(key: str) -> TaintedValue`
- `get_label_for_args(args: dict[str, Any]) -> SecurityLabel`: Resolves string arguments containing dot-notation keys to their exact projected labels.
- `get_provenance_chain(key: str) -> List[ProvenanceRecord]`
- `get_all_tainted() -> Dict[str, TaintedValue]`
- `clear() -> None`

---

## 3. `jurisast_core.ast_ir`

Intermediate representation for agent execution plans.

### Node Types (`ASTNode` Discriminated Union)

#### `DataSourceNode`
```python
class DataSourceNode(BaseModel):
    node_type: Literal["data_source"] = "data_source"
    node_id: str
    tool_name: str
    label: SecurityLabel
    arguments: Dict[str, Any] = {}
    description: Optional[str] = None
```

#### `TransformNode`
```python
class TransformNode(BaseModel):
    node_type: Literal["transform"] = "transform"
    node_id: str
    operation: str
    input_node_ids: List[str]
    output_label: SecurityLabel
    description: Optional[str] = None
```

#### `SinkNode`
```python
class SinkNode(BaseModel):
    node_type: Literal["sink"] = "sink"
    node_id: str
    tool_name: str
    target_jurisdiction: Jurisdiction
    max_classification: Classification
    input_node_ids: List[str]
    description: Optional[str] = None
```

#### `DeclassifyNode`
```python
class DeclassifyNode(BaseModel):
    node_type: Literal["declassify"] = "declassify"
    node_id: str
    input_node_id: str
    output_type: str
    output_schema: Dict[str, Any] = {}
    output_label: SecurityLabel
    max_bits: float
    description: Optional[str] = None
```

#### `AgentHandoffNode`
```python
class AgentHandoffNode(BaseModel):
    node_type: Literal["agent_handoff"] = "agent_handoff"
    node_id: str
    source_agent_id: str
    target_agent_id: str
    input_node_ids: List[str]
    propagated_label: SecurityLabel
    description: Optional[str] = None
```

#### `ProjectionNode`
```python
class ProjectionNode(BaseModel):
    node_type: Literal["projection"] = "projection"
    node_id: str
    source_node_id: str
    field_path: str
    projected_label: SecurityLabel
    description: Optional[str] = None
```

#### `ChatOutputSinkNode`
```python
class ChatOutputSinkNode(BaseModel):
    node_type: Literal["chat_sink"] = "chat_sink"
    node_id: str
    target_user_id: str
    user_clearance: SecurityLabel
    input_node_ids: List[str]
    description: Optional[str] = None
```

#### `HumanAttestedDeclassifyNode`
```python
class HumanAttestedDeclassifyNode(BaseModel):
    node_type: Literal["human_attested_declassify"] = "human_attested_declassify"
    node_id: str
    input_node_id: str
    approver_id: str
    token_id: str
    content_hash: str
    output_label: SecurityLabel
    description: Optional[str] = None
```

### `ExecutionGraph` (BaseModel)

A Directed Acyclic Graph (DAG) of AST nodes.

#### Methods
- `topological_order() -> List[ASTNode]`: Returns dependency-ordered nodes using Kahn's algorithm. Raises `ASTConstructionError` if a cycle exists.
- `get_node(node_id: str) -> ASTNode`
- `get_sources() -> List[DataSourceNode]`
- `get_sinks() -> List[SinkNode]`
- `get_transforms() -> List[TransformNode]`
- `get_declassifiers() -> List[DeclassifyNode]`
- `get_handoffs() -> List[AgentHandoffNode]`
- `get_projections() -> List[ProjectionNode]`
- `get_chat_sinks() -> List[ChatOutputSinkNode]`
- `get_human_declassifiers() -> List[HumanAttestedDeclassifyNode]`
- `validate_structure() -> List[str]`: Validates acyclicity, edge reference consistency, and root/leaf integrity.
- `is_valid() -> bool`

### `ExecutionGraphBuilder`

Fluent builder with automated edge wiring.

```python
builder = ExecutionGraphBuilder(agent_id="agent_1")
src = builder.add_source("fetch_data", LABEL_EU_PII)
prj = builder.add_projection(src.node_id, "public_metrics", LABEL_PUBLIC)
snk = builder.add_sink("send_webhook", Jurisdiction.EU, Classification.PUBLIC, [prj.node_id])
chat = builder.add_chat_sink("visitor_1", LABEL_PUBLIC, [src.node_id])
graph = builder.build()
```

#### Methods
- `add_source(tool_name, label, arguments=None, description=None) -> DataSourceNode`
- `add_transform(operation, input_node_ids, output_label, description=None) -> TransformNode`
- `add_sink(tool_name, target_jurisdiction, max_classification, input_node_ids, description=None) -> SinkNode`
- `add_projection(source_node_id, field_path, projected_label, description=None) -> ProjectionNode`
- `add_chat_sink(target_user_id, user_clearance, input_node_ids, description=None) -> ChatOutputSinkNode`
- `add_human_attested_declassify(input_node_id, approver_id, token_id, content_hash, output_label, description=None) -> HumanAttestedDeclassifyNode`
- `add_declassify(input_node_id, output_type, output_schema, output_label, max_bits, description=None) -> DeclassifyNode`
- `add_handoff(source_agent_id, target_agent_id, input_node_ids, propagated_label, description=None) -> AgentHandoffNode`
- `build() -> ExecutionGraph`

---

## 4. `jurisast_core.solver`

Microsoft Z3 SMT solver interface for non-interference verification.

### `Z3SolverEngine`

```python
class Z3SolverEngine:
    def __init__(self, timeout_ms: int = 50)
```

#### Methods
- **`encode_graph(graph: ExecutionGraph) -> None`**  
  Translates graph nodes and propagation constraints into first-order logic formulas.
- **`add_custom_constraint(name: str, constraint: Any, description: str = "") -> None`**  
  Injects custom Z3 constraints with an assumption literal for regulatory policy sets.
- **`add_policy_constraints(policies: PolicySet | Sequence[PolicySet], graph: ExecutionGraph) -> List[str]`**  
  Compiles declarative regulatory policies against the graph into assumption-gated Z3 formulas.
- **`verify() -> VerificationResult`**  
  Evaluates constraints using assumption literals. Returns `VerificationResult`.
- **`verify_or_raise() -> VerificationResult`**  
  Evaluates constraints and raises `TaintViolationError` or `SolverTimeoutError` on failure (fail-closed).
- **`reset() -> None`**  
  Clears all assertions, assumptions, and variable maps for solver reuse.

### `VerificationResult` (BaseModel)

```python
class VerificationResult(BaseModel):
    status: Literal["SAFE", "VIOLATION", "TIMEOUT"]
    latency_ms: float
    violated_constraints: List[str] = []
    violation_details: List[str] = []
    graph_id: str = ""
    node_count: int = 0
    constraint_count: int = 0
```

---

## 5. `jurisast_core.exceptions`

Structured exception hierarchy:

```
JurisASTError (Base)
├── TaintViolationError (Policy violation with unsat core & Z3 metadata)
├── DeclassificationDeniedError (Information budget exceeded)
├── PolicyCompilationError (Malformed regulatory policy)
├── SolverTimeoutError (Fail-closed timeout trigger)
├── TaintRegistryError (Registry lookup failure)
└── ASTConstructionError (Invalid DAG, cycles, bad node IDs)
```

---

## 6. `jurisast_core.config`

Central configuration models:

```python
config = JurisASTConfig(
    mode="enforce",  # "enforce", "audit", "permissive"
    solver=SolverConfig(timeout_ms=50, use_incremental=True),
    audit=AuditConfig(enabled=True, log_safe_executions=False),
    fail_closed=True,
)
```

---

## 7. `jurisast_core.policies`

Declarative regulatory policy specification and Z3 compilation engine.

### `ConstraintAction` (str, Enum)
- `BLOCK`: Hard enforcement; verification fails on match.
- `DECLASSIFY_REQUIRED`: Flow blocked unless passed through an approved declassification node.
- `AUDIT`: Logged in audit trail without blocking.

### `FlowConstraint` (BaseModel)
```python
class FlowConstraint(BaseModel):
    name: str
    description: str
    regulation: str = ""
    source_jurisdictions: Optional[Set[Jurisdiction]] = None
    source_classification_min: Optional[Classification] = None
    forbidden_sink_jurisdictions: Optional[Set[Jurisdiction]] = None
    sink_classification_max: Optional[Classification] = None
    forbidden_compartments: Optional[FrozenSet[str]] = None
    required_compartments: Optional[FrozenSet[str]] = None
    allow_declassified: bool = True
    action: ConstraintAction = ConstraintAction.BLOCK
```

### `PolicySet` (BaseModel)
```python
class PolicySet(BaseModel):
    policy_name: str
    version: str = "1.0.0"
    description: str = ""
    constraints: List[FlowConstraint] = []
```

#### Methods
- **`add_constraint(constraint: FlowConstraint) -> None`**
- **`get_constraint(name: str) -> Optional[FlowConstraint]`**
- **`compile_to_z3(graph: ExecutionGraph, solver: Z3SolverEngine) -> List[str]`**: Translates each constraint into assumption-gated Z3 implications with human-readable unsat core attribution.

---

## 8. `jurisast_core.declassifier`

Mathematical Shannon entropy limits, slotted templates, pattern scrubbers, and cryptographic human attestations.

### `DeclassificationBoundary`
- **`compute_max_bits(output_type: Any) -> float`**  
  Computes exact Shannon mutual information capacity:
  - `bool` $\to 1.0\text{ bit}$
  - `Enum` $\to \log_2(N)\text{ bits}$
  - `Literal` $\to \log_2(K)\text{ bits}$
  - `Annotated[int, Field(ge=A, le=B)]` $\to \log_2(B - A + 1)\text{ bits}$
  - `BaseModel` $\to$ recursive sum of field bounds
  - Unbounded types (`str`, `float`, `dict`, `list`, open `int`) raise `ValueError`.
- **`validate_declassification(output_type: Any, max_allowed_bits: float) -> bool`**
- **`validate_runtime_value(value: Any, output_type: Any) -> None`**  
  Enforces Pydantic strict mode validation (`TypeAdapter.validate_python(strict=True)`).
- **`declassify_value(tainted_value, output_value, output_type, output_label, max_allowed_bits, agent_id, tool_name) -> TaintedValue`**  
  Validates entropy and runtime conformity, then issues a downgraded `TaintedValue` with full audit provenance.

### `AttestationToken` (BaseModel)
Cryptographically signed attestation issued by an authorized human compliance officer:
```python
class AttestationToken(BaseModel):
    token_id: str
    approver_id: str
    target_label: SecurityLabel
    content_hash: str          # SHA-256 of declassified content
    issued_at: datetime
    expires_at: Optional[datetime]
    signature: str             # HMAC-SHA256 signature
```

### `HumanDeclassificationAuthority`
Issues and cryptographically verifies human-in-the-loop (HITL) declassification tokens:
- **`create_attestation(content, approver_id, secret_key, target_label, ttl_seconds=3600) -> AttestationToken`**: Generates a tamper-proof signed token.
- **`verify_attestation(token, content, secret_key) -> bool`**: Verifies HMAC-SHA256 signature, expiry, and content hash.

### `SlottedTemplate`
Constrains natural language generation to predefined templates with typed, finite slots:
- **`compute_max_bits() -> float`**: Computes the subadditive Shannon bound $\sum_{i=1}^m \log_2(|S_i|)$.
- **`render(slots: dict[str, Any] | BaseModel) -> str`**: Validates slots against Pydantic schema and formats the template string.

### `CompartmentScrubber`
Pattern-based regex scrubber for removing categorical compartments:
- **`scrub(text: str, scrub_compartments: Optional[Set[str]] = None) -> tuple[str, Set[str]]`**: Redacts credit cards, SSNs, phone numbers, and returns scrubbed text and identified compartments.
- **`scrub_label(label: SecurityLabel, text: str) -> tuple[str, SecurityLabel]`**: Scrubs patterns and returns the sanitized text with stripped compartment labels.

---

## 9. `jurisast_policies`

Pre-built enterprise regulatory frameworks and policy builders.

- **`GDPR_DATA_SOVEREIGNTY`**: Enforces GDPR Chapter V cross-border restrictions, blocking EU PII/Sensitive PII from non-adequate destinations (e.g. US, EXTERNAL).
- **`EU_AI_ACT_COMPLIANCE`**: Enforces Articles 5 & 10, isolating biometric data and prohibiting unconstrained high-risk automated profiling.
- **`PCI_DSS_COMPLIANCE`**: Enforces PCI-DSS Requirements 1.3 & 3.4, isolating the cardholder data environment (CDE) and PAN/CVV records.
- **`PolicyBuilder`**: Fluent API for custom regulatory sets:
  ```python
  policy = (
      PolicyBuilder("MY_POLICY")
      .block_cross_border("rule_1", source=Jurisdiction.EU, forbidden_sinks={Jurisdiction.US})
      .isolate_compartment("rule_2", compartment="secret", forbidden_sinks={Jurisdiction.EXTERNAL})
      .build()
  )
  ```

---

## 10. `jurisast_pydantic`

Pydantic AI agent integration layer and neuro-symbolic firewall.

### `JurisASTFirewall`
Execution firewall intercepting tools via lifecycle hooks and guarding conversational responses:
```python
firewall = JurisASTFirewall(
    config=JurisASTConfig(mode="enforce"),
    taint_registry=TaintRegistry(),
    policies=GDPR_DATA_SOVEREIGNTY,
    agent_id="fintech_agent",
)
```
#### Methods
- **`verify_tool_call(tool_name, tool_args, tool_callable) -> VerificationResult`**: Intercepts tool call, extracts AST (including field projections), compiles active policies into Z3, proves safety, and blocks violations before API trigger.
- **`record_tool_result(tool_name, tool_args, tool_result, tool_callable) -> Optional[TaintedValue]`**: Wraps outputs of `@tainted_source` and `@declassifier` tools into `TaintedValue` instances and tracks session taint.
- **`verify_chat_response(response_text: str, user_clearance: SecurityLabel, user_id: str = "default_user") -> None`**: Intercepts raw chat prose from the agent model. Verifies against all data sources read during the session. Raises `TaintViolationError` if response exceeds user clearance.
- **`sanitize_chat_response(response_text: str, user_clearance: SecurityLabel, user_id: str = "default_user") -> str`**: Verifies chat response and safely replaces leaking content with `[REDACTED: SENSITIVE DATA EXCEEDS USER CLEARANCE]`.
- **`register_field_projections(base_key: str, tainted: TaintedValue) -> None`**: Automatically flattens and registers subfield keys in `TaintRegistry` for dot-notation resolution.

### Tool Decorators
- **`@tainted_source(jurisdiction, classification, compartments=None)`**: Annotates tools retrieving sensitive/sovereign data.
- **`@tainted_sink(target_jurisdiction, max_classification)`**: Annotates tools emitting data to external destinations.
- **`@declassifier(output_label, max_bits, output_type=None)`**: Annotates tools performing certified information downgrades.


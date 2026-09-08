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

### Helper Functions & Constants

- **`label_from_metadata(metadata: dict[str, Any]) -> SecurityLabel`**  
  Parses raw string dictionary into a typed `SecurityLabel`.
- Pre-built constants: `LABEL_PUBLIC`, `LABEL_EU_PII`, `LABEL_EU_SENSITIVE_PII`, `LABEL_EU_RESTRICTED`, `LABEL_US_INTERNAL`, `LABEL_EXTERNAL_PUBLIC`.

---

## 2. `jurisast_core.taint`

Provides dynamic taint tracking and immutable audit trails.

### `ProvenanceRecord` (BaseModel)

Immutable audit log entry for a single taint operation.

```python
class ProvenanceRecord(BaseModel):
    record_id: str
    timestamp: datetime
    source_tool: str
    agent_id: str
    operation: str  # "create", "propagate", "merge", "declassify", "handoff"
    label_before: SecurityLabel
    label_after: SecurityLabel
    details: Optional[str] = None
```

#### Methods
- `label_changed() -> bool`: Returns `True` if `label_before != label_after`.
- `was_escalation() -> bool`: Returns `True` if label became more restrictive.
- `was_declassification() -> bool`: Returns `True` if label was downgraded.

### `TaintedValue[T]` (BaseModel, Generic[T])

Generic immutable container wrapping a value with its security label and provenance chain.

```python
class TaintedValue(BaseModel, Generic[T]):
    value: Any
    label: SecurityLabel
    provenance: List[ProvenanceRecord] = []
    taint_id: str
```

#### Methods
- **`propagate(new_label, tool, agent_id, operation="propagate", details=None) -> TaintedValue[T]`**  
  Returns a **new** `TaintedValue` with updated label and appended provenance record.
- **`declassify(target_label, declassified_value, tool, agent_id, max_bits, details=None) -> TaintedValue`**  
  Returns a **new** `TaintedValue` wrapping the declassified output.
- **`static merge_labels(values: Sequence[TaintedValue]) -> SecurityLabel`**  
  Computes the LUB join of all input labels.
- **`static create(value, label, source_tool, agent_id, details=None) -> TaintedValue`**  
  Factory method creating a `TaintedValue` with an initial creation record.

### `TaintRegistry`

Session-scoped registry mapping string keys to `TaintedValue` instances.

#### Methods
- `register(key: str, tainted: TaintedValue) -> None`
- `lookup(key: str) -> Optional[TaintedValue]`
- `lookup_or_raise(key: str) -> TaintedValue`
- `get_label_for_args(args: dict[str, Any]) -> SecurityLabel`
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
- `validate_structure() -> List[str]`: Validates acyclicity, edge reference consistency, and root/leaf integrity.
- `is_valid() -> bool`

### `ExecutionGraphBuilder`

Fluent builder with automated edge wiring.

```python
builder = ExecutionGraphBuilder(agent_id="agent_1")
src = builder.add_source("fetch_data", LABEL_EU_PII)
xfm = builder.add_transform("summarize", [src.node_id], LABEL_EU_PII)
snk = builder.add_sink("send_webhook", Jurisdiction.EU, Classification.SENSITIVE_PII, [xfm.node_id])
graph = builder.build()
```

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

Mathematical Shannon entropy limits and strict schema validation for controlled declassification.

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
Execution firewall intercepting tools via lifecycle hooks:
```python
firewall = JurisASTFirewall(
    config=JurisASTConfig(mode="enforce"),
    taint_registry=TaintRegistry(),
    policies=GDPR_DATA_SOVEREIGNTY,
    agent_id="fintech_agent",
)
```
#### Methods
- **`verify_tool_call(tool_name, tool_args, tool_callable) -> VerificationResult`**: Intercepts tool call, extracts AST, compiles active policies into Z3, proves safety, and blocks violations before API trigger.
- **`record_tool_result(tool_name, tool_args, tool_result, tool_callable) -> Optional[TaintedValue]`**: Wraps outputs of `@tainted_source` and `@declassifier` tools into `TaintedValue` instances.

### Tool Decorators
- **`@tainted_source(jurisdiction, classification, compartments=None)`**: Annotates tools retrieving sensitive/sovereign data.
- **`@tainted_sink(target_jurisdiction, max_classification)`**: Annotates tools emitting data to external destinations.
- **`@declassifier(output_label, max_bits, output_type=None)`**: Annotates tools performing certified information downgrades.

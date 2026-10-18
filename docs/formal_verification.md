# JurisAST — Formal Verification & Mathematical Specification

> **Theoretical foundations, non-interference theorems, SMT constraint encodings, and Shannon information bounding mechanics.**

---

## 1. Security Lattice Formalization

Let $\mathcal{L} = \langle L, \sqsubseteq, \sqcup, \sqcap, \bot, \top \rangle$ be a bounded product lattice defined as:

$$\mathcal{L} = \mathcal{J} \times \mathcal{C} \times \mathcal{P}(\mathcal{K})$$

Where:
- $\mathcal{J} = \{0, 10, 20, 30, 40, 100\}$ is the totally ordered set of Jurisdictions ($\text{INTERNAL} < \text{EU} < \text{UK} < \text{US} < \text{APAC} < \text{EXTERNAL}$).
- $\mathcal{C} = \{0, 10, 20, 30, 40, 50\}$ is the totally ordered set of Classifications ($\text{PUBLIC} < \dots < \text{RESTRICTED}$).
- $\mathcal{P}(\mathcal{K})$ is the powerset lattice of categorical compartments $\mathcal{K}$ ordered by set inclusion $\subseteq$.

### Algebraic Properties (Formally Verified via Hypothesis)

For all elements $a, b, c \in \mathcal{L}$:

1. **Partial Order (Dominance):**
   - **Reflexivity:** $a \sqsubseteq a$
   - **Antisymmetry:** $(a \sqsubseteq b \land b \sqsubseteq a) \implies a = b$
   - **Transitivity:** $(a \sqsubseteq b \land b \sqsubseteq c) \implies a \sqsubseteq c$
2. **Least Upper Bound (Join / $\sqcup$):**
   - **Commutativity:** $a \sqcup b = b \sqcup a$
   - **Associativity:** $(a \sqcup b) \sqcup c = a \sqcup (b \sqcup c)$
   - **Idempotency:** $a \sqcup a = a$
   - **Upper Bound Property:** $a \sqsubseteq (a \sqcup b) \land b \sqsubseteq (a \sqcup b)$
3. **Greatest Lower Bound (Meet / $\sqcap$):**
   - **Commutativity:** $a \sqcap b = b \sqcap a$
   - **Associativity:** $(a \sqcap b) \sqcap c = a \sqcap (b \sqcap c)$
   - **Idempotency:** $a \sqcap a = a$
   - **Lower Bound Property:** $(a \sqcap b) \sqsubseteq a \land (a \sqcap b) \sqsubseteq b$
4. **Absorption Laws:**
   - $a \sqcup (a \sqcap b) = a$
   - $a \sqcap (a \sqcup b) = a$

---

## 2. Non-Interference Property

### Definition (Classical Non-Interference)
Let $S$ be a system state with high-security inputs $H$ and low-security outputs $L$. A system satisfies **Non-Interference** if for any two initial states $s_1, s_2$ differing only in high-security inputs:

$$\text{Project}_L(Execute(s_1)) = \text{Project}_L(Execute(s_2))$$

In JurisAST, this guarantees that an adversary observing an external sink (e.g., US public webhook) cannot learn any information about EU sovereign PII processed within the agent network.

---

## 3. Z3 SMT Constraint Encodings

The execution graph $G = (V, E)$ is translated into first-order logic formulas over the theory of Linear Integer Arithmetic ($\text{QF}\_\text{LIA}$) and Booleans.

### 3.1 Data Source Nodes ($v \in V_{\text{source}}$)
For each source node with security label $\ell = (j_\ell, c_\ell)$:
$$\text{jurisdiction}(v) = j_\ell \quad \land \quad \text{classification}(v) = c_\ell$$

### 3.2 Transform Nodes ($v \in V_{\text{transform}}$)
Let $\text{Pred}(v)$ be the set of direct predecessor nodes. For an operation producing output label $\ell_{out}$:
$$\text{jurisdiction}(v) = j_{out} \quad \land \quad \text{classification}(v) = c_{out}$$
$$\forall u \in \text{Pred}(v): \quad \text{jurisdiction}(v) \ge \text{jurisdiction}(u) \quad \land \quad \text{classification}(v) \ge \text{classification}(u)$$

### 3.3 Sink Nodes ($v \in V_{\text{sink}}$)
Let $j_{\text{target}}$ and $c_{\text{max}}$ be the sink's clearance constraints. For each input $u \in \text{Pred}(v)$, we define a named assumption literal $\alpha_{u,v}$:
$$\alpha_{u,v} \implies \left( \text{jurisdiction}(u) \le j_{\text{target}} \quad \land \quad \text{classification}(u) \le c_{\text{max}} \right)$$

### 3.4 Verification & Unsat Core Extraction
The solver evaluates:
$$\text{Check}(\alpha_1, \alpha_2, \dots, \alpha_n)$$
- If **SAT**: All assumptions are mutually consistent; no non-interference invariants are violated. $\implies \text{SAFE}$.
- If **UNSAT**: At least one assumption contradicts the asserted graph facts. Z3 computes the minimal unsatisfiable subset $\mathcal{U} \subseteq \{\alpha_1, \dots, \alpha_n\}$, precisely attributing the violating flow without false positives.

### 3.5 Field Projection Nodes ($v \in V_{\text{proj}}$)
Let $u \in \text{Pred}(v)$ be the composite parent record, and let $\ell_f = (j_f, c_f, K_f)$ be the specific label of projected field $f$. The projection asserts:
$$\text{jurisdiction}(v) = j_f \quad \land \quad \text{classification}(v) = c_f$$
$$\forall k \in K_f: \text{has\_compartment}(v, k) = \text{True}$$
$$\forall k \notin K_f: \text{has\_compartment}(v, k) = \text{False}$$
By lattice construction, $\ell_f \sqsubseteq \ell(u)$. Isolating $\ell_f$ prevents conservative over-tainting and eliminates label creep on downstream sinks.

### 3.6 Conversational Response Sink Nodes ($v \in V_{\text{chat}}$)
Let $\ell_{\text{user}} = (j_{\text{user}}, c_{\text{user}}, K_{\text{user}})$ be the recipient's clearance label, and let $\text{SessionInputs}(v)$ be all sources consumed during the interactive run session. For each $u \in \text{SessionInputs}(v)$, an assumption literal $\alpha_{u, v}$ asserts:
$$\alpha_{u, v} \implies \left( \text{jurisdiction}(u) \le j_{\text{user}} \quad \land \quad \text{classification}(u) \le c_{\text{user}} \quad \land \quad \text{compartments}(u) \subseteq K_{\text{user}} \right)$$
If the session ingested confidential data exceeding $\ell_{\text{user}}$, Z3 proves UNSAT and the response is safely intercepted and redacted before delivery.

### 3.7 Human-Attested Declassification Nodes ($v \in V_{\text{hitl}}$)
Let $u \in \text{Pred}(v)$ be the tainted input node, and let $\ell_{\text{target}}$ be the approved downgraded label:
$$\text{jurisdiction}(v) = j_{\text{target}} \quad \land \quad \text{classification}(v) = c_{\text{target}}$$
$$\forall k \in K_{\text{target}}: \text{has\_compartment}(v, k) = \text{True}$$
$$\forall k \notin K_{\text{target}}: \text{has\_compartment}(v, k) = \text{False}$$
This node is certified in the AST if and only if accompanied by a valid `AttestationToken` whose HMAC-SHA256 signature is verified against the human authority's secret key.

---

## 4. Symbolic Declassification & Information Bounding

A strict non-interference policy forbids all flows from high to low clearances. However, realistic workflows require extracting low-entropy facts from high-security context.

JurisAST introduces **Bounded Structural Declassification**.

### 4.1 Shannon Entropy Bound
Let $X \in \mathcal{X}$ be the tainted high-security input, and let $Y \in \mathcal{Y}$ be the output generated by the LLM under constrained decoding (Pydantic schema).

The mutual information $I(X; Y)$ is bounded by the Shannon entropy $H(Y)$:
$$I(X; Y) = H(Y) - H(Y \mid X) \le H(Y) \le \log_2(|\mathcal{Y}|)$$

| Output Schema Type | Cardinality $|\mathcal{Y}|$ | Max Leaked Information $I(X; Y)$ |
|:---|:---|:---|
| `bool` | $2$ | $\mathbf{1.000\text{ bit}}$ |
| `Literal["low", "medium", "high"]` | $3$ | $\mathbf{1.585\text{ bits}}$ |
| `Enum` (8 members) | $8$ | $\mathbf{3.000\text{ bits}}$ |
| `int` (range $[0, 255]$) | $256$ | $\mathbf{8.000\text{ bits}}$ |
| Slotted Template (3 finite slots) | $\prod |S_i| = 3 \times 3 \times 5 = 45$ | $\mathbf{5.492\text{ bits}}$ |
| Arbitrary unstructured `str` (100 tokens) | $V^{100} \approx (10^5)^{100}$ | $\approx \mathbf{1661\text{ bits}}$ (Unbounded Exfiltration Risk) |

### 4.2 Enforcement Invariant
A `DeclassifyNode` is certified valid if and only if:
1. The output type is a compiled structural primitive (not open-ended text).
2. The computed information bound satisfies $\log_2(|\mathcal{Y}|) \le \text{max}\_\text{bits}$.
3. The LLM output was validated under strict schema parsing.

### 4.3 Subadditivity for Structured Models & Slotted Templates
For composite Pydantic `BaseModel` schemas and `SlottedTemplate` instances $Y = (S_1, S_2, \dots, S_m)$, Shannon joint entropy satisfies subadditivity:
$$H(S_1, S_2, \dots, S_m) \le \sum_{i=1}^m H(S_i) \le \sum_{i=1}^m \log_2(|\mathcal{S}_i|)$$

For bounded integer intervals $Z \in [A, B]$:
$$H(Z) \le \log_2(B - A + 1)$$

If any constituent field has unbounded entropy (e.g. open `str`, unconstrained `float`), the total bound diverges to $\infty$ and algorithmic declassification is rejected.

### 4.4 Cryptographic Human-in-the-Loop Attestation
For unstructured natural language summaries that cannot be algorithmically bounded:
Let $\tau = \langle \text{token\_id}, \text{approver\_id}, \text{content\_hash}, \ell_{\text{target}}, t_{\text{issued}}, t_{\text{expires}}, \sigma \rangle$ be an attestation token, where:
$$\sigma = \text{HMAC-SHA256}_{K_{\text{secret}}}(\text{token\_id} \parallel \text{approver\_id} \parallel \text{content\_hash} \parallel \ell_{\text{target}} \parallel t_{\text{issued}} \parallel t_{\text{expires}})$$
Under the standard Existential Unforgeability under Chosen-Message Attack (EUF-CMA) assumption, an untrusted generative LLM cannot forge a valid signature $\sigma$ for any modified text $c' \neq c$, mathematically preventing unauthorized free-text declassifications.

---

## 5. Formal Regulatory Policy Encodings in Z3

Let $\mathcal{P} = \{c_1, c_2, \dots, c_k\}$ be a `PolicySet`. For each constraint $c \in \mathcal{P}$ matching a destination sink $v \in V_{\text{sink}}$:

Let $u \in \text{Pred}(v)$ be an input node feeding into the sink, and let $\alpha_{c, u, v}$ be a named Z3 assumption literal.

The constraint is encoded as:
$$\alpha_{c, u, v} \implies \neg \left( \text{Violation}_c(u, v) \right)$$

Where:
$$\text{Violation}_c(u, v) = \left( \bigvee_{j \in \mathcal{J}_{\text{src}}} \text{jurisdiction}(u) = j \right) \land \left( \text{classification}(u) \ge C_{\text{min}} \right) \land \left( \text{target}\_\text{jurisdiction}(v) \in \mathcal{J}_{\text{forbidden}} \right)$$

If $u$ represents a valid declassification path, its security variables are reset to the downgraded output label $\ell_{\text{out}}$, ensuring $\text{Violation}_c(u, v)$ evaluates to $\text{False}$, allowing legitimate anonymized data to flow freely.

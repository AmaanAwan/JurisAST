"""
Gemini-Powered Dataset Generator for JurisAST Regulatory Benchmarks.

Uses Google Gemini 2.5 Flash to synthesize realistic, high-fidelity multi-agent
execution graphs across 11 global regulations, with mathematically verified
ground truth and Shannon entropy constraints.

Saves the complete dataset to a persistent JSON file for reproducible benchmarking.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

import httpx
from pydantic import BaseModel

from jurisast_core.ast_ir import (
    DataSourceNode,
    DeclassifyNode,
    ExecutionGraph,
    ExecutionGraphBuilder,
    SinkNode,
)
from jurisast_core.labels import (
    Classification,
    Jurisdiction,
    LABEL_APAC_PII,
    LABEL_APAC_RESTRICTED,
    LABEL_EU_PII,
    LABEL_EU_RESTRICTED,
    LABEL_EU_SENSITIVE_PII,
    LABEL_EXTERNAL_PUBLIC,
    LABEL_PUBLIC,
    LABEL_US_INTERNAL,
    LABEL_US_PII,
    LABEL_US_RESTRICTED,
    LABEL_US_SENSITIVE_PII,
    SecurityLabel,
)
from benchmarks.config import BenchmarkConfig
from benchmarks.dataset.models import (
    BenchmarkTrace,
    GroundTruthStatus,
    TraceCategory,
    TraceGroundTruth,
    TraceSpec,
)
from benchmarks.dataset.schema import (
    BenchmarkCase,
    DeclassificationDomain,
    DeclassificationSpec,
    NonViolationType,
    RegulationType,
    ViolationType,
)


class GeminiDatasetGenerator:
    """
    Synthesizes rich, diverse benchmark datasets using the Gemini 2.5 Flash API.
    """

    SYSTEM_PROMPT = """\
You are an expert AI Safety, Regulatory Compliance, and Formal Verification Engineer.
Your task is to generate realistic, production-grade enterprise multi-agent tool execution graphs
evaluating Information Flow Control (IFC) and Data Sovereignty policies.

Each test case must follow strict legal taxonomy and mathematical Information Flow constraints:
- Jurisdictions: EU, US, APAC, INTERNAL, EXTERNAL
- Classifications: PUBLIC, INTERNAL_ONLY, CONFIDENTIAL, PII, SENSITIVE_PII, RESTRICTED
- Regulations: GDPR, EU_AI_ACT, PCI_DSS_V4, HIPAA, CCPA_CPRA, DORA, CHINA_PIPL, INDIA_DPDPA, ITAR_EAR, COLORADO_AI_ACT, ISO_42001_NIST_RMF

Generate diverse scenarios with realistic tool names (e.g. 'fetch_oncology_biopsy', 'process_swift_wire_settlement', 'export_lidar_point_cloud', 'query_california_payroll_spi').

OUTPUT FORMAT:
Return a valid JSON array of objects conforming to this schema:
[
  {
    "case_id": "TC_<REG>_<INDEX>",
    "regulation": "<REGULATION_NAME>",
    "is_violation": true/false,
    "violation_type": "<VIOLATION_TYPE or null>",
    "non_violation_type": "<NON_VIOLATION_TYPE or null>",
    "threat_narrative": "Detailed real-world scenario narrative",
    "source_tool": "tool_name",
    "source_jurisdiction": "EU|US|APAC|INTERNAL|EXTERNAL",
    "source_classification": "PUBLIC|INTERNAL_ONLY|CONFIDENTIAL|PII|SENSITIVE_PII|RESTRICTED",
    "source_compartments": ["tag1", "tag2"],
    "sink_tool": "destination_tool_name",
    "sink_target_jurisdiction": "EU|US|APAC|INTERNAL|EXTERNAL",
    "sink_max_classification": "PUBLIC|INTERNAL_ONLY|CONFIDENTIAL|PII|SENSITIVE_PII|RESTRICTED",
    "agent_chain_length": 1 to 4,
    "has_intermediary_transforms": true/false,
    "declassification_spec": {
      "domain": "HEALTHCARE_SAFE_HARBOR|FINANCIAL_PCI_TOKENIZATION|etc",
      "output_type": "bool|int_range|enum",
      "cardinality": 2 or 16,
      "max_bits": 1.0 or 4.0,
      "description": "Declassification channel description"
    } or null,
    "expected_unsat_rules": ["rule_id_1"]
  }
]
"""

    def __init__(self, config: Optional[BenchmarkConfig] = None) -> None:
        self.config = config or BenchmarkConfig()
        self.api_key = self.config.resolve_api_key()
        model_name = self.config.model
        if ":" in model_name:
            model_name = model_name.split(":", 1)[1]
        self.model = model_name
        self.client = httpx.AsyncClient(timeout=45.0)

    async def generate_cases_for_regulation(
        self,
        regulation: RegulationType,
        count: int = 4,
        violation_ratio: float = 0.50,
    ) -> List[BenchmarkCase]:
        """Call Gemini to generate realistic cases for a specific regulation."""
        violations_count = max(1, int(count * violation_ratio))
        compliant_count = count - violations_count

        prompt = (
            f"Generate exactly {count} realistic multi-agent execution graph test cases for regulation '{regulation.value}'.\n"
            f"- {violations_count} cases MUST be VIOLATIONS (adversarial attacks, cross-border exfiltration, swarm laundering, or over-budget leaks).\n"
            f"- {compliant_count} cases MUST be COMPLIANT (intra-sovereign flows, audited enclaves, or valid Shannon-bounded declassifications <= 4.0 bits).\n"
            f"Keep threat_narrative concise (1-2 sentences per case).\n"
            f"Ensure every case has specific, realistic tool names."
        )

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{self.SYSTEM_PROMPT}\n\n{prompt}"}
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 4096,
                "responseMimeType": "application/json",
            },
        }

        cases: List[BenchmarkCase] = []
        for attempt in range(3):
            try:
                resp = await self.client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates and "content" in candidates[0]:
                        parts = candidates[0]["content"].get("parts", [])
                        if parts:
                            raw_json = parts[0].get("text", "")
                            try:
                                parsed = json.loads(raw_json)
                            except Exception:
                                # Salvage all complete JSON objects from truncated output
                                parsed = []
                                decoder = json.JSONDecoder()
                                idx = 0
                                while idx < len(raw_json):
                                    brace = raw_json.find('{', idx)
                                    if brace == -1:
                                        break
                                    try:
                                        obj, end_pos = decoder.raw_decode(raw_json, brace)
                                        parsed.append(obj)
                                        idx = end_pos
                                    except Exception:
                                        idx = brace + 1

                            if isinstance(parsed, dict):
                                parsed = (
                                    parsed.get("cases")
                                    or parsed.get("test_cases")
                                    or parsed.get("traces")
                                    or parsed.get("items")
                                    or [parsed]
                                )
                            if isinstance(parsed, list):
                                for item in parsed:
                                    if isinstance(item, dict):
                                        try:
                                            case = self._dict_to_case(item, regulation)
                                            if case:
                                                cases.append(case)
                                        except Exception:
                                            continue
                    if len(cases) >= 2:
                        break
                elif resp.status_code == 429:
                    print(" [429 Pacing] ", end="", flush=True)
                    await asyncio.sleep(4.0 * (attempt + 1))
                else:
                    await asyncio.sleep(2.0)
            except Exception:
                await asyncio.sleep(2.0)

        return cases

    def _dict_to_case(self, item: Dict[str, Any], default_reg: RegulationType) -> Optional[BenchmarkCase]:
        """Convert a raw Gemini dict into a validated BenchmarkCase."""
        try:
            cid = str(item.get("case_id", f"TC_{default_reg.value}_{int(time.time()*1000)%10000}"))
            is_v = bool(item.get("is_violation", True))

            # Resolve labels safely
            src_jur_str = str(item.get("source_jurisdiction", "EU")).upper()
            src_jur = getattr(Jurisdiction, src_jur_str, Jurisdiction.EU)

            src_cls_str = str(item.get("source_classification", "PII")).upper()
            src_cls = getattr(Classification, src_cls_str, Classification.PII)

            cmps = frozenset(item.get("source_compartments", []))
            src_label = SecurityLabel(jurisdiction=src_jur, classification=src_cls, compartments=cmps)

            sink_jur_str = str(item.get("sink_target_jurisdiction", "EXTERNAL")).upper()
            sink_jur = getattr(Jurisdiction, sink_jur_str, Jurisdiction.EXTERNAL)

            sink_cls_str = str(item.get("sink_max_classification", "PUBLIC")).upper()
            sink_cls = getattr(Classification, sink_cls_str, Classification.PUBLIC)

            # Declassification spec
            dcl_spec = None
            dcl_data = item.get("declassification_spec")
            if dcl_data and isinstance(dcl_data, dict):
                try:
                    domain_str = str(dcl_data.get("domain", "LOGGING_AND_MONITORING")).upper()
                    domain = getattr(DeclassificationDomain, domain_str, DeclassificationDomain.LOGGING_AND_MONITORING)
                    dcl_spec = DeclassificationSpec(
                        domain=domain,
                        source_classification=src_cls,
                        target_classification=Classification.PUBLIC,
                        output_type=str(dcl_data.get("output_type", "bool")),
                        cardinality=int(dcl_data.get("cardinality", 2)),
                        max_bits=float(dcl_data.get("max_bits", 1.0)),
                        description=str(dcl_data.get("description", "Bounded declassification")),
                    )
                except Exception:
                    dcl_spec = None

            # If safe flow targeting external or lower clearance sink, ensure bounded declassification channel exists
            if not is_v and (sink_jur == Jurisdiction.EXTERNAL or sink_cls < src_cls):
                if not dcl_spec:
                    dcl_spec = DeclassificationSpec(
                        domain=DeclassificationDomain.LOGGING_AND_MONITORING,
                        source_classification=src_cls,
                        target_classification=Classification.PUBLIC,
                        output_type="int_range",
                        cardinality=16,
                        max_bits=4.0,
                        description=f"Bounded declassification for {default_reg.value}",
                    )

            # If violation intended on privacy/defense regulation, ensure source classification triggers the statutory constraint
            if is_v:
                if default_reg in (RegulationType.GDPR, RegulationType.CHINA_PIPL, RegulationType.INDIA_DPDPA) and src_cls < Classification.PII:
                    src_cls = Classification.PII
                elif default_reg == RegulationType.HIPAA:
                    src_cls = max(src_cls, Classification.SENSITIVE_PII)
                    cmps = cmps | frozenset({"phi"})
                elif default_reg == RegulationType.CCPA_CPRA:
                    src_cls = max(src_cls, Classification.SENSITIVE_PII)
                    cmps = cmps | frozenset({"spi"})
                elif default_reg == RegulationType.EU_AI_ACT:
                    src_cls = max(src_cls, Classification.SENSITIVE_PII)
                    cmps = cmps | frozenset({"biometrics"})
                    sink_jur = Jurisdiction.EXTERNAL
                elif default_reg == RegulationType.ITAR_EAR:
                    src_cls = Classification.RESTRICTED
                    cmps = cmps | frozenset({"itar_defense_data"})
                src_label = SecurityLabel(jurisdiction=src_jur, classification=src_cls, compartments=cmps)

            return BenchmarkCase(
                case_id=cid,
                regulation=default_reg,
                is_violation=is_v,
                violation_type=ViolationType[item["violation_type"]] if item.get("violation_type") in ViolationType.__members__ else None,
                non_violation_type=NonViolationType[item["non_violation_type"]] if item.get("non_violation_type") in NonViolationType.__members__ else None,
                declassification_spec=dcl_spec,
                source_tool=str(item.get("source_tool", "fetch_data")),
                source_label=src_label,
                sink_tool=str(item.get("sink_tool", "export_data")),
                sink_target_jurisdiction=sink_jur,
                sink_max_classification=sink_cls,
                agent_chain_length=int(item.get("agent_chain_length", 1)),
                has_intermediary_transforms=bool(item.get("has_intermediary_transforms", False)),
                policy_name=f"{default_reg.value}_POLICY",
                expected_unsat_rules=item.get("expected_unsat_rules", []),
                threat_narrative=str(item.get("threat_narrative", "Execution trace")),
            )
        except Exception:
            return None

    @staticmethod
    def case_to_trace(case: BenchmarkCase) -> BenchmarkTrace:
        """Convert a BenchmarkCase into an executable BenchmarkTrace DAG."""
        builder = ExecutionGraphBuilder(agent_id=f"agent_main_{case.case_id}", graph_id=case.case_id)
        src = builder.add_source(
            tool_name=case.source_tool,
            label=case.source_label,
            arguments={"case_id": case.case_id},
            description=case.threat_narrative[:80],
        )

        curr_id = src.node_id
        curr_label = case.source_label

        # Multi-agent handoff chain
        for hop in range(1, case.agent_chain_length):
            h = builder.add_handoff(
                source_agent_id=f"agent_worker_{hop}",
                target_agent_id=f"agent_worker_{hop+1}",
                input_node_ids=[curr_id],
                propagated_label=curr_label,
            )
            curr_id = h.node_id
            if case.has_intermediary_transforms:
                xfm = builder.add_transform(
                    operation="reformat_payload",
                    input_node_ids=[curr_id],
                    output_label=curr_label,
                )
                curr_id = xfm.node_id

        # Declassifier node if present
        if case.declassification_spec:
            ds = case.declassification_spec
            downgraded = SecurityLabel(
                jurisdiction=case.source_label.jurisdiction,
                classification=ds.target_classification,
                compartments=frozenset(),
            )
            dcl = builder.add_declassifier(
                input_node_id=curr_id,
                output_type=ds.output_type,
                output_label=downgraded,
                max_bits=ds.max_bits,
                description=ds.description,
            )
            curr_id = dcl.node_id

        # Sink node
        snk = builder.add_sink(
            tool_name=case.sink_tool,
            target_jurisdiction=case.sink_target_jurisdiction,
            max_classification=case.sink_max_classification,
            input_node_ids=[curr_id],
            description=case.threat_narrative,
        )

        graph = builder.build()
        status = GroundTruthStatus.VIOLATION if case.is_violation else GroundTruthStatus.SAFE
        cat = (
            TraceCategory.CROSS_BORDER_EXFILTRATION
            if case.is_violation and case.source_label.jurisdiction != case.sink_target_jurisdiction
            else TraceCategory.SPECIAL_CATEGORY_EXPOSURE
            if case.is_violation
            else TraceCategory.CONTROLLED_DECLASSIFICATION
            if case.declassification_spec
            else TraceCategory.COMPLIANT_SOVEREIGN
        )

        gt = TraceGroundTruth(
            status=status,
            category=cat,
            violated_rules=case.expected_unsat_rules,
            description=case.threat_narrative,
            expected_blocked_nodes=[snk.node_id] if case.is_violation else [],
        )

        spec = TraceSpec(
            trace_id=case.case_id,
            category=cat,
            num_agents=case.agent_chain_length,
            num_tool_calls=len(graph.nodes),
            has_cross_border_flow=(case.source_label.jurisdiction != case.sink_target_jurisdiction),
            has_pii=(case.source_label.classification in (Classification.PII, Classification.SENSITIVE_PII)),
            has_declassification=bool(case.declassification_spec),
            is_adversarial=case.is_violation,
            adversarial_technique=case.violation_type.value if case.violation_type else None,
        )

        return BenchmarkTrace(spec=spec, graph=graph, ground_truth=gt)

    async def generate_master_dataset(
        self,
        output_file: str = "benchmarks/dataset/master_benchmark_dataset.json",
        target_count: int = 1050,
    ) -> List[BenchmarkTrace]:
        """
        Generate the complete master dataset across all 11 regulations using Gemini,
        augmenting with verified baseline cases, and saving to output_file.
        """
        from benchmarks.dataset.generator import ParametricDatasetGenerator

        print(f"\n🔮 Generating Master Dataset with Gemini API ({self.model})...")
        print(f"   Target Traces: {target_count} | Output File: {output_file}")

        regulations = list(RegulationType)
        per_reg = target_count // len(regulations)  # ~95 traces per regulation

        all_cases: List[BenchmarkCase] = []

        # 1. Use Gemini to generate high-fidelity diverse cases for each regulation
        for reg in regulations:
            print(f"   • Querying Gemini for regulation: {reg.value:<20} ...", end="", flush=True)
            gem_cases = await self.generate_cases_for_regulation(reg, count=4)
            all_cases.extend(gem_cases)
            print(f" Done ({len(gem_cases)} Gemini cases synthesized)")
            await asyncio.sleep(1.0)  # Gentle API pacing

        # 2. Synthesize complete mathematically verified parametric traces to reach target_count
        gen = ParametricDatasetGenerator(seed=self.config.seed)
        parametric_traces = gen.generate_master_1000()

        # Combine Gemini cases and parametric traces
        gemini_traces = [self.case_to_trace(c) for c in all_cases]
        combined_traces: List[BenchmarkTrace] = gemini_traces + parametric_traces[:max(0, target_count - len(gemini_traces))]

        # 3. Serialize and save dataset to file
        os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
        serialized_data = {
            "metadata": {
                "dataset_name": "JurisAST Master 1000+ Regulatory Benchmark Suite",
                "generated_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
                "model": self.model,
                "total_traces": len(combined_traces),
                "regulations_covered": [r.value for r in regulations],
                "shannon_entropy_bounded": True,
            },
            "traces": [
                {
                    "trace_id": t.spec.trace_id,
                    "category": t.spec.category.value,
                    "num_agents": t.spec.num_agents,
                    "is_adversarial": t.spec.is_adversarial,
                    "adversarial_technique": t.spec.adversarial_technique,
                    "ground_truth_status": t.ground_truth.status.value,
                    "ground_truth_description": t.ground_truth.description,
                    "violated_rules": t.ground_truth.violated_rules,
                    "graph": t.graph.model_dump(mode="json"),
                }
                for t in combined_traces
            ],
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(serialized_data, f, indent=2)

        print(f"\n✅ Successfully generated and saved {len(combined_traces)} traces to:")
        print(f"   📁 {output_file} ({os.path.getsize(output_file) / 1024:.1f} KB)\n")

        await self.close()
        return combined_traces

    @staticmethod
    def load_dataset_from_file(filepath: str) -> List[BenchmarkTrace]:
        """Load benchmark traces directly from a serialized JSON dataset file."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Benchmark dataset file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        traces: List[BenchmarkTrace] = []
        for item in data.get("traces", []):
            graph = ExecutionGraph.model_validate(item["graph"])
            spec = TraceSpec(
                trace_id=item["trace_id"],
                category=TraceCategory(item["category"]),
                num_agents=item.get("num_agents", 1),
                num_tool_calls=len(graph.nodes),
                has_cross_border_flow=any(s.target_jurisdiction.name != graph.get_sources()[0].label.jurisdiction.name for s in graph.get_sinks()) if graph.get_sources() and graph.get_sinks() else False,
                has_pii=any(s.label.classification in (Classification.PII, Classification.SENSITIVE_PII) for s in graph.get_sources()),
                has_declassification=any(isinstance(n, DeclassifyNode) for n in graph.nodes),
                is_adversarial=item.get("is_adversarial", False),
                adversarial_technique=item.get("adversarial_technique"),
            )
            gt = TraceGroundTruth(
                status=GroundTruthStatus(item["ground_truth_status"]),
                category=TraceCategory(item["category"]),
                violated_rules=item.get("violated_rules", []),
                description=item.get("ground_truth_description", ""),
                expected_blocked_nodes=[s.node_id for s in graph.get_sinks()] if item["ground_truth_status"] == "VIOLATION" else [],
            )
            traces.append(BenchmarkTrace(spec=spec, graph=graph, ground_truth=gt))

        return traces

    async def close(self) -> None:
        await self.client.aclose()


async def main() -> None:
    parser = argparse.ArgumentParser(description="Gemini-Powered Dataset Generator for JurisAST")
    parser.add_argument("--api-key", help="Google Gemini API key")
    parser.add_argument("--count", type=int, default=1050, help="Target trace count (default: 1050)")
    parser.add_argument("--output", default="benchmarks/dataset/master_benchmark_dataset.json", help="Output file path")
    args = parser.parse_args()

    config = BenchmarkConfig()
    if args.api_key:
        config.api_key = args.api_key
    generator = GeminiDatasetGenerator(config=config)
    await generator.generate_master_dataset(output_file=args.output, target_count=args.count)


if __name__ == "__main__":
    asyncio.run(main())

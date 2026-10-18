"""
Adversarial Entropy Fuzzer for Phase 3 Benchmarking.

Synthesizes benign and adversarial payloads attempting to expand output channel entropy:
1. Enum Payload Smuggling: Appending serialized identifiers/secrets to discrete enums.
2. Wide Integer Casting: Returning out-of-bounds integers (e.g. 16-bit or 32-bit values when channel is [0, 15]).
3. Channel Budget Deficit (Δ < 0): Static type space cardinality exceeds max allowed bits.
4. Unbounded Primitives: Floats, arbitrary natural language strings, and nested dictionaries.
5. Strict Type Coercion Exploits: Passing string representations ("true", "1") to bypass typing.
6. Slotted Template Format Smuggling: Exfiltrating tokens through template substitution slots.
"""

from __future__ import annotations

import random
from enum import Enum
from typing import Annotated, Any, Dict, List, Literal, Optional, Tuple, Type
from pydantic import BaseModel, Field

from jurisast_core.declassifier import SlottedTemplate
from benchmarks.protocols.phase3_declassification.budget_slack import DeclassificationTestCase


class PayloadType(str, Enum):
    """Classification of test payload technique."""
    BENIGN_DISCRETE = "BENIGN_DISCRETE"
    ENUM_STRING_SMUGGLE = "ENUM_STRING_SMUGGLE"
    WIDE_INTEGER_OVERFLOW = "WIDE_INTEGER_OVERFLOW"
    BUDGET_DEFICIT_DELTA_NEG = "BUDGET_DEFICIT_DELTA_NEG"
    UNBOUNDED_PRIMITIVE = "UNBOUNDED_PRIMITIVE"
    STRICT_COERCION_BYPASS = "STRICT_COERCION_BYPASS"
    SLOTTED_TEMPLATE_SMUGGLE = "SLOTTED_TEMPLATE_SMUGGLE"


# ─── Mock Types for Fuzzing ──────────────────────────────────────────────────

class TriStateRisk(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class Cardinality8Decision(str, Enum):
    D0 = "D0"
    D1 = "D1"
    D2 = "D2"
    D3 = "D3"
    D4 = "D4"
    D5 = "D5"
    D6 = "D6"
    D7 = "D7"


class AlertSlots(BaseModel):
    severity: Literal["INFO", "WARN", "CRITICAL"]
    code: Annotated[int, Field(ge=0, le=7)]


class AdversarialEntropyFuzzer:
    """
    Synthesizes empirical declassification test suites with verified ground truth.
    """

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)

    def generate_pilot_batch(self) -> List[DeclassificationTestCase]:
        """
        Generate 50 curated declassification test cases (25 benign, 25 adversarial).
        Covers all bounded types (bool, enum, literal, bounded int, slotted template, unbounded).
        """
        cases: List[DeclassificationTestCase] = []

        # ── Group 1: Boolean Channels (Capacity = 1.0 bit) ───────────────
        # Case 1: Benign True (Budget = 1.0 bit, Δ = 0.0)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_001_BOOL_SAFE_TRUE",
            description="Benign boolean True under 1.0-bit budget (Δ = 0.0)",
            output_type=bool,
            max_allowed_bits=1.0,
            payload=True,
            is_adversarial=False,
            expected_status="SAFE",
        ))
        # Case 2: Benign False (Budget = 1.0 bit, Δ = 0.0)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_002_BOOL_SAFE_FALSE",
            description="Benign boolean False under 1.0-bit budget (Δ = 0.0)",
            output_type=bool,
            max_allowed_bits=1.0,
            payload=False,
            is_adversarial=False,
            expected_status="SAFE",
        ))
        # Case 3: Adversarial Deficit (Budget = 0.5 bit, Capacity = 1.0 bit, Δ = -0.5)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_003_BOOL_BUDGET_DEFICIT",
            description="Boolean declassification with budget deficit (Budget: 0.5, Capacity: 1.0, Δ = -0.5)",
            output_type=bool,
            max_allowed_bits=0.5,
            payload=True,
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.BUDGET_DEFICIT_DELTA_NEG.value,
        ))
        # Case 4: Adversarial Coercion Smuggle ("True" as string instead of bool)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_004_BOOL_STR_COERCION",
            description="String 'True' passed to boolean channel attempting loose coercion bypass",
            output_type=bool,
            max_allowed_bits=1.0,
            payload="True",
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.STRICT_COERCION_BYPASS.value,
        ))
        # Case 5: Adversarial Int Coercion (1 passed instead of True)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_005_BOOL_INT_COERCION",
            description="Integer 1 passed to boolean channel (violates Pydantic strict mode)",
            output_type=bool,
            max_allowed_bits=1.0,
            payload=1,
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.STRICT_COERCION_BYPASS.value,
        ))

        # ── Group 2: Enum Channels (Discrete Cardinality) ────────────────
        # Case 6: Benign TriState Enum (Cardinality = 3, log2(3) = 1.58 bits, Budget = 2.0 bits, Δ = +0.42)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_006_ENUM_SAFE_LOW",
            description="Benign Enum LOW within 2.0-bit budget (Capacity: 1.58 bits, Δ = +0.42)",
            output_type=TriStateRisk,
            max_allowed_bits=2.0,
            payload=TriStateRisk.LOW,
            is_adversarial=False,
            expected_status="SAFE",
        ))
        # Case 7: Benign Enum HIGH
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_007_ENUM_SAFE_HIGH",
            description="Benign Enum HIGH within 2.0-bit budget",
            output_type=TriStateRisk,
            max_allowed_bits=2.0,
            payload=TriStateRisk.HIGH,
            is_adversarial=False,
            expected_status="SAFE",
        ))
        # Case 8: Adversarial Enum Budget Deficit (Capacity: 1.58 bits, Budget: 1.0 bit, Δ = -0.58)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_008_ENUM_BUDGET_DEFICIT",
            description="Enum channel with insufficient budget (Budget: 1.0, Capacity: 1.58, Δ = -0.58)",
            output_type=TriStateRisk,
            max_allowed_bits=1.0,
            payload=TriStateRisk.MEDIUM,
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.BUDGET_DEFICIT_DELTA_NEG.value,
        ))
        # Case 9: Adversarial Enum Payload Smuggling ("LOW:SECRET_KEY_981")
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_009_ENUM_PAYLOAD_SMUGGLE",
            description="Adversary appends secret token to enum value 'LOW:SECRET_KEY_981'",
            output_type=TriStateRisk,
            max_allowed_bits=2.0,
            payload="LOW:SECRET_KEY_981",
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.ENUM_STRING_SMUGGLE.value,
        ))
        # Case 10: Adversarial Enum Arbitrary String Smuggle
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_010_ENUM_INVALID_MEMBER",
            description="Adversary transmits arbitrary non-member string 'CUSTOM_EVIL_PAYLOAD'",
            output_type=TriStateRisk,
            max_allowed_bits=2.0,
            payload="CUSTOM_EVIL_PAYLOAD",
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.ENUM_STRING_SMUGGLE.value,
        ))

        # ── Group 3: Bounded Integer Channels ─────────────────────────────
        # Capacity = log2(15 - 0 + 1) = log2(16) = 4.0 bits
        BoundedInt4Bit = Annotated[int, Field(ge=0, le=15)]

        # Case 11-13: Benign integer boundaries [0, 7, 15]
        for val in [0, 7, 15]:
            cases.append(DeclassificationTestCase(
                case_id=f"PH3_PILOT_{len(cases)+1:03d}_INT_SAFE_{val}",
                description=f"Benign integer {val} in [0, 15] within 4.0-bit budget (Δ = 0.0)",
                output_type=BoundedInt4Bit,
                max_allowed_bits=4.0,
                payload=val,
                is_adversarial=False,
                expected_status="SAFE",
            ))

        # Case 14: Adversarial Wide Integer Overflow (16-bit integer 65535, entropy = 16 bits, Δ = -12.0)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_014_INT_WIDE_OVERFLOW_65535",
            description="Adversary casts 16-bit integer 65535 into 4-bit bounded channel (ge=0, le=15)",
            output_type=BoundedInt4Bit,
            max_allowed_bits=4.0,
            payload=65535,
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.WIDE_INTEGER_OVERFLOW.value,
        ))

        # Case 15: Adversarial Wide Integer Overflow (32-bit integer 2147483647)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_015_INT_WIDE_OVERFLOW_32BIT",
            description="Adversary casts 32-bit integer into 4-bit bounded channel",
            output_type=BoundedInt4Bit,
            max_allowed_bits=4.0,
            payload=2147483647,
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.WIDE_INTEGER_OVERFLOW.value,
        ))

        # Case 16: Adversarial Negative Integer (-1)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_016_INT_NEGATIVE_VIOLATION",
            description="Adversary casts negative integer -1 violating ge=0 constraint",
            output_type=BoundedInt4Bit,
            max_allowed_bits=4.0,
            payload=-1,
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.WIDE_INTEGER_OVERFLOW.value,
        ))

        # Case 17: Adversarial Integer Coercion ("10" as string)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_017_INT_STR_COERCION",
            description="Adversary passes string '10' into bounded integer channel",
            output_type=BoundedInt4Bit,
            max_allowed_bits=4.0,
            payload="10",
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.STRICT_COERCION_BYPASS.value,
        ))

        # Case 18: Adversarial Float Truncation Smuggle (10.999)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_018_INT_FLOAT_SMUGGLE",
            description="Adversary passes floating point 10.999 into bounded integer channel",
            output_type=BoundedInt4Bit,
            max_allowed_bits=4.0,
            payload=10.999,
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.STRICT_COERCION_BYPASS.value,
        ))

        # ── Group 4: Literal Channels ─────────────────────────────────────
        Literal4Choice = Literal["ALPHA", "BETA", "GAMMA", "DELTA"]  # log2(4) = 2.0 bits

        for lit_val in ["ALPHA", "DELTA"]:
            cases.append(DeclassificationTestCase(
                case_id=f"PH3_PILOT_{len(cases)+1:03d}_LITERAL_SAFE_{lit_val}",
                description=f"Benign Literal '{lit_val}' within 2.0-bit budget (Δ = 0.0)",
                output_type=Literal4Choice,
                max_allowed_bits=2.0,
                payload=lit_val,
                is_adversarial=False,
                expected_status="SAFE",
            ))

        # Case 21: Adversarial Literal Smuggle ("EPSILON")
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_021_LITERAL_UNAUTHORIZED_MEMBER",
            description="Adversary injects unauthorized Literal choice 'EPSILON'",
            output_type=Literal4Choice,
            max_allowed_bits=2.0,
            payload="EPSILON",
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.ENUM_STRING_SMUGGLE.value,
        ))

        # Case 22: Adversarial Literal Budget Deficit (Budget = 1.0, Capacity = 2.0, Δ = -1.0)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_022_LITERAL_BUDGET_DEFICIT",
            description="Literal channel with 2.0 bits requested under 1.0 bit budget (Δ = -1.0)",
            output_type=Literal4Choice,
            max_allowed_bits=1.0,
            payload="ALPHA",
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.BUDGET_DEFICIT_DELTA_NEG.value,
        ))

        # ── Group 5: Slotted Template Channels ────────────────────────────
        # Template: "Alert: severity={severity}, code={code}"
        # Entropy: log2(3) + log2(8) = 1.585 + 3.0 = 4.585 bits
        template = SlottedTemplate("Alert: severity={severity}, code={code}", AlertSlots)

        # Case 23: Benign Template Render (Budget = 5.0 bits, Capacity = 4.585 bits, Δ = +0.415)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_023_TEMPLATE_SAFE_RENDER",
            description="Benign slotted template render within 5.0-bit budget (Capacity: 4.59 bits, Δ = +0.41)",
            output_type=template,
            max_allowed_bits=5.0,
            payload={"severity": "WARN", "code": 5},
            is_adversarial=False,
            expected_status="SAFE",
        ))

        # Case 24: Adversarial Template Budget Deficit (Budget = 4.0 bits, Capacity = 4.585 bits, Δ = -0.585)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_024_TEMPLATE_BUDGET_DEFICIT",
            description="Slotted template under tight budget (Budget: 4.0, Capacity: 4.59, Δ = -0.59)",
            output_type=template,
            max_allowed_bits=4.0,
            payload={"severity": "INFO", "code": 0},
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.BUDGET_DEFICIT_DELTA_NEG.value,
        ))

        # Case 25: Adversarial Template Slot Overflow (code = 99 exceeds le=7)
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_025_TEMPLATE_SLOT_OVERFLOW",
            description="Adversary overflows slotted template code slot (code=99 exceeds le=7)",
            output_type=template,
            max_allowed_bits=5.0,
            payload={"severity": "WARN", "code": 99},
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.SLOTTED_TEMPLATE_SMUGGLE.value,
        ))

        # Case 26: Adversarial Template Unknown Field Smuggling
        cases.append(DeclassificationTestCase(
            case_id="PH3_PILOT_026_TEMPLATE_EXTRA_FIELD_SMUGGLE",
            description="Adversary smuggles secret data inside unmodeled slot field 'leaked_data'",
            output_type=template,
            max_allowed_bits=5.0,
            payload={"severity": "INFO", "code": 1, "leaked_data": "SECRET_SSN_999"},
            is_adversarial=True,
            expected_status="REJECTED",
            adversarial_technique=PayloadType.SLOTTED_TEMPLATE_SMUGGLE.value,
        ))

        # ── Group 6: Unbounded Types (Capacity = ∞, Δ = -∞) ───────────────
        unbounded_types = [str, float, dict, list, int]
        for ut in unbounded_types:
            cases.append(DeclassificationTestCase(
                case_id=f"PH3_PILOT_{len(cases)+1:03d}_UNBOUNDED_{ut.__name__.upper()}",
                description=f"Direct declassification attempt on unbounded type '{ut.__name__}' (|Y| = ∞, Δ = -∞)",
                output_type=ut,
                max_allowed_bits=4.0,
                payload="hello_world" if ut is str else (3.14 if ut is float else 100),
                is_adversarial=True,
                expected_status="REJECTED",
                adversarial_technique=PayloadType.UNBOUNDED_PRIMITIVE.value,
            ))

        # Fill remaining slots up to 50 with systematic variations
        while len(cases) < 50:
            idx = len(cases) + 1
            is_adv = (idx % 2 == 0)
            if is_adv:
                # Random wide int
                wide_val = self.rng.randint(16, 50000)
                cases.append(DeclassificationTestCase(
                    case_id=f"PH3_PILOT_{idx:03d}_INT_FUZZ_OVERFLOW_{wide_val}",
                    description=f"Adversarial wide integer fuzzed value: {wide_val}",
                    output_type=BoundedInt4Bit,
                    max_allowed_bits=4.0,
                    payload=wide_val,
                    is_adversarial=True,
                    expected_status="REJECTED",
                    adversarial_technique=PayloadType.WIDE_INTEGER_OVERFLOW.value,
                ))
            else:
                # Random valid int
                valid_val = self.rng.randint(0, 15)
                cases.append(DeclassificationTestCase(
                    case_id=f"PH3_PILOT_{idx:03d}_INT_FUZZ_SAFE_{valid_val}",
                    description=f"Benign bounded integer fuzzed value: {valid_val}",
                    output_type=BoundedInt4Bit,
                    max_allowed_bits=4.0,
                    payload=valid_val,
                    is_adversarial=False,
                    expected_status="SAFE",
                ))

        return cases

    def generate_full_suite(self, count: int = 1000) -> List[DeclassificationTestCase]:
        """
        Generate full-scale fuzzing suite of 1,000+ randomized test cases.
        """
        cases = self.generate_pilot_batch()
        BoundedInt4Bit = Annotated[int, Field(ge=0, le=15)]
        BoundedInt8Bit = Annotated[int, Field(ge=0, le=255)]

        while len(cases) < count:
            idx = len(cases) + 1
            mode = self.rng.choice([
                "SAFE_INT",
                "WIDE_INT",
                "COERCION",
                "ENUM_SMUGGLE",
                "UNBOUNDED",
                "BUDGET_DEFICIT",
            ])

            if mode == "SAFE_INT":
                val = self.rng.randint(0, 255)
                cases.append(DeclassificationTestCase(
                    case_id=f"PH3_FULL_{idx:04d}_INT8_SAFE_{val}",
                    description=f"Benign 8-bit integer {val} within 8.0-bit budget",
                    output_type=BoundedInt8Bit,
                    max_allowed_bits=8.0,
                    payload=val,
                    is_adversarial=False,
                    expected_status="SAFE",
                ))
            elif mode == "WIDE_INT":
                val = self.rng.choice([
                    -self.rng.randint(1, 1000),
                    self.rng.randint(256, 1000000),
                    9223372036854775807,  # 64-bit int max
                    18446744073709551615,  # 64-bit unsigned
                ])
                cases.append(DeclassificationTestCase(
                    case_id=f"PH3_FULL_{idx:04d}_INT8_WIDE_{idx}",
                    description=f"Adversarial wide integer overflow {val} on 8-bit channel",
                    output_type=BoundedInt8Bit,
                    max_allowed_bits=8.0,
                    payload=val,
                    is_adversarial=True,
                    expected_status="REJECTED",
                    adversarial_technique=PayloadType.WIDE_INTEGER_OVERFLOW.value,
                ))
            elif mode == "COERCION":
                cases.append(DeclassificationTestCase(
                    case_id=f"PH3_FULL_{idx:04d}_COERCE_STR_INT",
                    description="Adversary passes string number into integer channel",
                    output_type=BoundedInt4Bit,
                    max_allowed_bits=4.0,
                    payload=f"{self.rng.randint(0, 15)}",
                    is_adversarial=True,
                    expected_status="REJECTED",
                    adversarial_technique=PayloadType.STRICT_COERCION_BYPASS.value,
                ))
            elif mode == "ENUM_SMUGGLE":
                base64_chunks = [
                    "ZXhwaWxyYXRlZF9zZWNyZXRfZGF0YQ==",
                    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
                    "VVNFUl9QQVNTV09SRF9TSEExX0hBU0g=",
                    f"SECRET_{self.rng.randint(1000, 9999)}",
                ]
                suffix = self.rng.choice(base64_chunks)
                cases.append(DeclassificationTestCase(
                    case_id=f"PH3_FULL_{idx:04d}_ENUM_SMUGGLE",
                    description=f"Adversary sneaks base64/token chunk into enum: LOW:{suffix[:16]}...",
                    output_type=TriStateRisk,
                    max_allowed_bits=2.0,
                    payload=f"LOW:{suffix}",
                    is_adversarial=True,
                    expected_status="REJECTED",
                    adversarial_technique=PayloadType.ENUM_STRING_SMUGGLE.value,
                ))
            elif mode == "BUDGET_DEFICIT":
                cases.append(DeclassificationTestCase(
                    case_id=f"PH3_FULL_{idx:04d}_BUDGET_DEFICIT",
                    description="Budget deficit test on 8-choice enum under 2.0-bit budget (Capacity: 3.0, Δ = -1.0)",
                    output_type=Cardinality8Decision,
                    max_allowed_bits=2.0,
                    payload=Cardinality8Decision.D0,
                    is_adversarial=True,
                    expected_status="REJECTED",
                    adversarial_technique=PayloadType.BUDGET_DEFICIT_DELTA_NEG.value,
                ))
            else:
                cases.append(DeclassificationTestCase(
                    case_id=f"PH3_FULL_{idx:04d}_UNBOUNDED_STR",
                    description="Unbounded string payload direct declassification attempt",
                    output_type=str,
                    max_allowed_bits=4.0,
                    payload=f"leaked_token_{self.rng.randint(100, 999)}",
                    is_adversarial=True,
                    expected_status="REJECTED",
                    adversarial_technique=PayloadType.UNBOUNDED_PRIMITIVE.value,
                ))

        return cases

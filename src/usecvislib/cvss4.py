#
# VULNEX -Universal Security Visualization Library-
#
# File: cvss4.py
# Author: Simon Roses Femerling
# Created: 2025-01-15
# Last Modified: 2025-01-15
# Version: 0.4.0
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""CVSS 4.0 (Common Vulnerability Scoring System) support module.

This module provides parsing and calculation for CVSS 4.0 vector strings,
implementing the MacroVector-based scoring system per FIRST specification.

Reference: https://www.first.org/cvss/v4.0/specification-document

Example vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Tuple, Any, List
import re
import math


# =============================================================================
# CVSS 4.0 Enumerations
# =============================================================================

class AttackVector(str, Enum):
    """CVSS 4.0 Attack Vector (AV) metric."""
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(str, Enum):
    """CVSS 4.0 Attack Complexity (AC) metric."""
    LOW = "L"
    HIGH = "H"


class AttackRequirements(str, Enum):
    """CVSS 4.0 Attack Requirements (AT) metric - NEW in 4.0."""
    NONE = "N"
    PRESENT = "P"


class PrivilegesRequired(str, Enum):
    """CVSS 4.0 Privileges Required (PR) metric."""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(str, Enum):
    """CVSS 4.0 User Interaction (UI) metric - expanded from 3.1."""
    NONE = "N"
    PASSIVE = "P"
    ACTIVE = "A"


class ImpactMetric(str, Enum):
    """CVSS 4.0 Impact metrics (VC/VI/VA/SC/SI/SA)."""
    HIGH = "H"
    LOW = "L"
    NONE = "N"


class SafetyImpact(str, Enum):
    """CVSS 4.0 Modified Impact with Safety (MSI/MSA)."""
    NOT_DEFINED = "X"
    SAFETY = "S"
    HIGH = "H"
    LOW = "L"
    NONE = "N"


class ExploitMaturity(str, Enum):
    """CVSS 4.0 Exploit Maturity (E) - Threat metric."""
    NOT_DEFINED = "X"
    ATTACKED = "A"
    POC = "P"
    UNREPORTED = "U"


class RequirementLevel(str, Enum):
    """CVSS 4.0 Security Requirements (CR/IR/AR)."""
    NOT_DEFINED = "X"
    HIGH = "H"
    MEDIUM = "M"
    LOW = "L"


class ModifiedAttackVector(str, Enum):
    """CVSS 4.0 Modified Attack Vector (MAV)."""
    NOT_DEFINED = "X"
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class ModifiedAttackComplexity(str, Enum):
    """CVSS 4.0 Modified Attack Complexity (MAC)."""
    NOT_DEFINED = "X"
    LOW = "L"
    HIGH = "H"


class ModifiedAttackRequirements(str, Enum):
    """CVSS 4.0 Modified Attack Requirements (MAT)."""
    NOT_DEFINED = "X"
    NONE = "N"
    PRESENT = "P"


class ModifiedPrivilegesRequired(str, Enum):
    """CVSS 4.0 Modified Privileges Required (MPR)."""
    NOT_DEFINED = "X"
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class ModifiedUserInteraction(str, Enum):
    """CVSS 4.0 Modified User Interaction (MUI)."""
    NOT_DEFINED = "X"
    NONE = "N"
    PASSIVE = "P"
    ACTIVE = "A"


class ModifiedImpact(str, Enum):
    """CVSS 4.0 Modified Impact metrics (MVC/MVI/MVA/MSC)."""
    NOT_DEFINED = "X"
    HIGH = "H"
    LOW = "L"
    NONE = "N"


# =============================================================================
# MacroVector Lookup Table
# =============================================================================

# Complete lookup table from FIRST reference implementation
# Keys are 6-digit strings representing EQ1-EQ6 levels
MACROVECTOR_LOOKUP: Dict[str, float] = {
    "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5,
    "000020": 9.5, "000021": 9.2, "000100": 10.0, "000101": 9.6,
    "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9.0, "000210": 8.9, "000211": 8.0,
    "000220": 8.1, "000221": 6.8, "001000": 9.8, "001001": 9.5,
    "001010": 9.5, "001011": 9.2, "001020": 9.0, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1,
    "001120": 8.1, "001121": 6.5, "001200": 8.8, "001201": 8.0,
    "001210": 7.8, "001211": 7.0, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9,
    "002111": 6.9, "002121": 5.0, "002201": 6.9, "002211": 5.5,
    "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5,
    "010101": 9.1, "010110": 9.0, "010111": 8.3, "010120": 8.4,
    "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5,
    "011001": 9.3, "011010": 9.2, "011011": 8.5, "011020": 8.5,
    "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8.0,
    "011111": 7.2, "011120": 7.0, "011121": 5.9, "011200": 8.4,
    "011201": 7.0, "011210": 7.1, "011211": 5.2, "011220": 5.0,
    "011221": 3.0, "012001": 8.6, "012011": 7.5, "012021": 5.2,
    "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3,
    "012211": 2.9, "012221": 1.7, "100000": 9.8, "100001": 9.5,
    "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4,
    "100120": 7.7, "100121": 6.4, "100200": 8.7, "100201": 7.5,
    "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7,
    "101020": 7.6, "101021": 6.7, "101100": 8.6, "101101": 7.6,
    "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5.0,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2,
    "101220": 5.2, "101221": 2.5, "102001": 8.3, "102011": 7.0,
    "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5,
    "110001": 9.0, "110010": 8.8, "110011": 7.6, "110020": 7.6,
    "110021": 7.0, "110100": 9.0, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7,
    "110201": 6.6, "110210": 6.8, "110211": 5.9, "110220": 5.2,
    "110221": 3.0, "111000": 8.9, "111001": 7.8, "111010": 7.6,
    "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4,
    "111101": 5.9, "111110": 5.7, "111111": 5.7, "111120": 4.7,
    "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1,
    "112011": 5.9, "112021": 3.0, "112101": 5.8, "112111": 2.6,
    "112121": 1.5, "112201": 2.3, "112211": 1.6, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2,
    "200020": 7.5, "200021": 5.8, "200100": 8.6, "200101": 7.4,
    "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7.0, "200201": 5.4, "200210": 5.2, "200211": 4.0,
    "200220": 4.0, "200221": 2.2, "201000": 8.5, "201001": 7.5,
    "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1,
    "201120": 4.6, "201121": 1.9, "201200": 5.3, "201201": 3.6,
    "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2.0, "202101": 4.7,
    "202111": 2.1, "202121": 1.1, "202201": 2.4, "202211": 0.9,
    "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
    "210011": 5.3, "210020": 6.0, "210021": 5.0, "210100": 7.3,
    "210101": 5.5, "210110": 5.9, "210111": 4.0, "210120": 4.1,
    "210121": 2.0, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2.0, "210221": 1.1, "211000": 7.5,
    "211001": 5.5, "211010": 5.8, "211011": 4.5, "211020": 4.0,
    "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
    "211111": 1.8, "211120": 2.0, "211121": 0.9, "211200": 4.6,
    "211201": 1.8, "211210": 1.7, "211211": 0.7, "211220": 0.8,
    "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1.0,
    "212211": 0.3, "212221": 0.1,
}

# Maximum severity vectors for each MacroVector (highest severity in each class)
# Used for interpolation depth calculation
MAX_SEVERITY: Dict[str, Dict[str, List[str]]] = {
    "eq1": {
        "0": ["AV:N/PR:N/UI:N"],
        "1": ["AV:A/PR:N/UI:N", "AV:N/PR:L/UI:N", "AV:N/PR:N/UI:P"],
        "2": ["AV:P/PR:N/UI:N", "AV:A/PR:L/UI:P"],
    },
    "eq2": {
        "0": ["AC:L/AT:N"],
        "1": ["AC:H/AT:N", "AC:L/AT:P"],
    },
    "eq3": {
        "0": ["VC:H/VI:H"],
        "1": ["VC:L/VI:H", "VC:H/VI:L"],
        "2": ["VC:L/VI:L"],
    },
    "eq4": {
        "0": ["SC:H/SI:H/SA:H"],
        "1": ["SC:H/SI:H/SA:L", "SC:H/SI:L/SA:H", "SC:L/SI:H/SA:H"],
        "2": ["SC:L/SI:L/SA:L"],
    },
    "eq5": {
        "0": ["E:A"],
        "1": ["E:P"],
        "2": ["E:U"],
    },
    "eq6": {
        "0": ["CR:H/VC:H", "IR:H/VI:H", "AR:H/VA:H"],
        "1": ["CR:M/VC:H", "IR:M/VI:H", "AR:M/VA:H", "CR:H/VC:L", "IR:H/VI:L", "AR:H/VA:L"],
    },
}


# =============================================================================
# CVSS 4.0 Vector Dataclass
# =============================================================================

@dataclass
class CVSSVector4:
    """Parsed CVSS 4.0 vector with all metrics.

    Attributes:
        Base metrics (mandatory):
            attack_vector, attack_complexity, attack_requirements,
            privileges_required, user_interaction,
            vuln_conf, vuln_integ, vuln_avail (vulnerable system impact),
            subseq_conf, subseq_integ, subseq_avail (subsequent system impact)

        Threat metrics (optional):
            exploit_maturity

        Environmental metrics (optional):
            conf_req, integ_req, avail_req (requirements),
            mod_* (modified base metrics)
    """
    # Base metrics (mandatory)
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    attack_requirements: AttackRequirements = AttackRequirements.NONE
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    vuln_conf: ImpactMetric = ImpactMetric.HIGH
    vuln_integ: ImpactMetric = ImpactMetric.HIGH
    vuln_avail: ImpactMetric = ImpactMetric.HIGH
    subseq_conf: ImpactMetric = ImpactMetric.NONE
    subseq_integ: ImpactMetric = ImpactMetric.NONE
    subseq_avail: ImpactMetric = ImpactMetric.NONE

    # Threat metrics (optional)
    exploit_maturity: ExploitMaturity = ExploitMaturity.NOT_DEFINED

    # Environmental - Requirements (optional)
    conf_req: RequirementLevel = RequirementLevel.NOT_DEFINED
    integ_req: RequirementLevel = RequirementLevel.NOT_DEFINED
    avail_req: RequirementLevel = RequirementLevel.NOT_DEFINED

    # Environmental - Modified Base (optional)
    mod_attack_vector: ModifiedAttackVector = ModifiedAttackVector.NOT_DEFINED
    mod_attack_complexity: ModifiedAttackComplexity = ModifiedAttackComplexity.NOT_DEFINED
    mod_attack_requirements: ModifiedAttackRequirements = ModifiedAttackRequirements.NOT_DEFINED
    mod_privileges_required: ModifiedPrivilegesRequired = ModifiedPrivilegesRequired.NOT_DEFINED
    mod_user_interaction: ModifiedUserInteraction = ModifiedUserInteraction.NOT_DEFINED
    mod_vuln_conf: ModifiedImpact = ModifiedImpact.NOT_DEFINED
    mod_vuln_integ: ModifiedImpact = ModifiedImpact.NOT_DEFINED
    mod_vuln_avail: ModifiedImpact = ModifiedImpact.NOT_DEFINED
    mod_subseq_conf: ModifiedImpact = ModifiedImpact.NOT_DEFINED
    mod_subseq_integ: SafetyImpact = SafetyImpact.NOT_DEFINED
    mod_subseq_avail: SafetyImpact = SafetyImpact.NOT_DEFINED

    # Raw string
    raw_string: str = ""

    def _get_effective_value(self, base_value: str, mod_value: str) -> str:
        """Get effective value considering modified metrics."""
        if mod_value == "X":
            return base_value
        return mod_value

    def _get_effective_av(self) -> str:
        return self._get_effective_value(self.attack_vector.value, self.mod_attack_vector.value)

    def _get_effective_ac(self) -> str:
        return self._get_effective_value(self.attack_complexity.value, self.mod_attack_complexity.value)

    def _get_effective_at(self) -> str:
        return self._get_effective_value(self.attack_requirements.value, self.mod_attack_requirements.value)

    def _get_effective_pr(self) -> str:
        return self._get_effective_value(self.privileges_required.value, self.mod_privileges_required.value)

    def _get_effective_ui(self) -> str:
        return self._get_effective_value(self.user_interaction.value, self.mod_user_interaction.value)

    def _get_effective_vc(self) -> str:
        return self._get_effective_value(self.vuln_conf.value, self.mod_vuln_conf.value)

    def _get_effective_vi(self) -> str:
        return self._get_effective_value(self.vuln_integ.value, self.mod_vuln_integ.value)

    def _get_effective_va(self) -> str:
        return self._get_effective_value(self.vuln_avail.value, self.mod_vuln_avail.value)

    def _get_effective_sc(self) -> str:
        return self._get_effective_value(self.subseq_conf.value, self.mod_subseq_conf.value)

    def _get_effective_si(self) -> str:
        return self._get_effective_value(self.subseq_integ.value, self.mod_subseq_integ.value)

    def _get_effective_sa(self) -> str:
        return self._get_effective_value(self.subseq_avail.value, self.mod_subseq_avail.value)

    def _get_effective_e(self) -> str:
        """Get effective exploit maturity (defaults to A if not defined)."""
        if self.exploit_maturity == ExploitMaturity.NOT_DEFINED:
            return "A"  # Assume attacked if not specified
        return self.exploit_maturity.value

    def _get_effective_cr(self) -> str:
        if self.conf_req == RequirementLevel.NOT_DEFINED:
            return "H"  # Default to High
        return self.conf_req.value

    def _get_effective_ir(self) -> str:
        if self.integ_req == RequirementLevel.NOT_DEFINED:
            return "H"
        return self.integ_req.value

    def _get_effective_ar(self) -> str:
        if self.avail_req == RequirementLevel.NOT_DEFINED:
            return "H"
        return self.avail_req.value

    def derive_macrovector(self) -> str:
        """Derive the MacroVector (EQ1-EQ6) from current metrics.

        Returns:
            6-character string representing equivalence class levels
        """
        av = self._get_effective_av()
        ac = self._get_effective_ac()
        at = self._get_effective_at()
        pr = self._get_effective_pr()
        ui = self._get_effective_ui()
        vc = self._get_effective_vc()
        vi = self._get_effective_vi()
        va = self._get_effective_va()
        sc = self._get_effective_sc()
        si = self._get_effective_si()
        sa = self._get_effective_sa()
        e = self._get_effective_e()
        cr = self._get_effective_cr()
        ir = self._get_effective_ir()
        ar = self._get_effective_ar()

        # EQ1: Attack Vector / Privileges Required / User Interaction
        if av == "N" and pr == "N" and ui == "N":
            eq1 = 0
        elif (av == "N" or pr == "N" or ui == "N") and not (av == "N" and pr == "N" and ui == "N"):
            eq1 = 1
        else:
            eq1 = 2

        # EQ2: Attack Complexity / Attack Requirements
        if ac == "L" and at == "N":
            eq2 = 0
        else:
            eq2 = 1

        # EQ3: Vulnerable System Impact (VC/VI/VA)
        if vc == "H" and vi == "H":
            eq3 = 0
        elif vc == "H" or vi == "H" or va == "H":
            eq3 = 1
        else:
            eq3 = 2

        # EQ4: Subsequent System Impact (SC/SI/SA) with Safety
        if si == "S" or sa == "S":
            eq4 = 0
        elif sc == "H" or si == "H" or sa == "H":
            eq4 = 1
        else:
            eq4 = 2

        # EQ5: Exploit Maturity
        if e == "A":
            eq5 = 0
        elif e == "P":
            eq5 = 1
        else:  # U or X (X treated as A, so shouldn't reach here)
            eq5 = 2

        # EQ6: Requirements combined with impact
        # Check if high requirement aligns with high impact
        cr_h_vc_h = (cr == "H" and vc == "H")
        ir_h_vi_h = (ir == "H" and vi == "H")
        ar_h_va_h = (ar == "H" and va == "H")

        if cr_h_vc_h or ir_h_vi_h or ar_h_va_h:
            eq6 = 0
        else:
            eq6 = 1

        return f"{eq1}{eq2}{eq3}{eq4}{eq5}{eq6}"

    def calculate_score(self) -> float:
        """Calculate the CVSS 4.0 score using MacroVector lookup and interpolation.

        Returns:
            CVSS score (0.0 - 10.0)
        """
        # Get MacroVector
        macrovector = self.derive_macrovector()

        # Lookup base score
        if macrovector not in MACROVECTOR_LOOKUP:
            # Find closest match or return 0
            return 0.0

        base_score = MACROVECTOR_LOOKUP[macrovector]

        # For simplicity, return the MacroVector score without interpolation
        # Full interpolation requires computing severity distance which is complex
        # This gives accurate scores for highest-severity vectors in each class

        # Apply simple interpolation based on metric severity
        severity_adjustment = self._calculate_severity_adjustment(macrovector)

        final_score = max(0.0, base_score - severity_adjustment)

        # Round to 1 decimal place
        return round(final_score, 1)

    def _calculate_severity_adjustment(self, macrovector: str) -> float:
        """Calculate severity adjustment for interpolation within MacroVector.

        This is a simplified interpolation that adjusts score based on how
        far the vector is from the highest severity in its MacroVector.
        """
        adjustment = 0.0

        av = self._get_effective_av()
        ac = self._get_effective_ac()
        at = self._get_effective_at()
        pr = self._get_effective_pr()
        ui = self._get_effective_ui()
        vc = self._get_effective_vc()
        vi = self._get_effective_vi()
        va = self._get_effective_va()
        sc = self._get_effective_sc()
        si = self._get_effective_si()
        sa = self._get_effective_sa()

        # EQ1 adjustments (within same EQ class)
        eq1 = int(macrovector[0])
        if eq1 == 0:
            # Highest is AV:N/PR:N/UI:N - no adjustment needed
            pass
        elif eq1 == 1:
            # Adjust based on which metric is not at highest
            if av != "N":
                adjustment += 0.1
            if pr != "N":
                adjustment += 0.1
            if ui != "N":
                adjustment += 0.1

        # EQ2 adjustments
        eq2 = int(macrovector[1])
        if eq2 == 1:
            # Not at lowest complexity
            if ac == "H":
                adjustment += 0.1
            if at == "P":
                adjustment += 0.1

        # EQ3 adjustments (vulnerable system impact)
        eq3 = int(macrovector[2])
        if eq3 == 1:
            if vc != "H":
                adjustment += 0.1
            if vi != "H":
                adjustment += 0.1
            if va != "H":
                adjustment += 0.1
        elif eq3 == 2:
            # Already at lowest level
            if va == "N":
                adjustment += 0.1

        # EQ4 adjustments (subsequent system impact)
        eq4 = int(macrovector[3])
        if eq4 == 1:
            if sc != "H":
                adjustment += 0.05
            if si != "H":
                adjustment += 0.05
            if sa != "H":
                adjustment += 0.05

        return min(adjustment, 1.0)  # Cap adjustment

    def to_dict(self) -> Dict[str, Any]:
        """Convert vector to dictionary representation."""
        return {
            "version": "4.0",
            "vector_string": self.raw_string or self.to_vector_string(),
            "base_score": self.calculate_score(),
            # Base metrics
            "attack_vector": self.attack_vector.value,
            "attack_complexity": self.attack_complexity.value,
            "attack_requirements": self.attack_requirements.value,
            "privileges_required": self.privileges_required.value,
            "user_interaction": self.user_interaction.value,
            "vuln_confidentiality": self.vuln_conf.value,
            "vuln_integrity": self.vuln_integ.value,
            "vuln_availability": self.vuln_avail.value,
            "subseq_confidentiality": self.subseq_conf.value,
            "subseq_integrity": self.subseq_integ.value,
            "subseq_availability": self.subseq_avail.value,
            # Threat
            "exploit_maturity": self.exploit_maturity.value,
            # Environmental - Requirements
            "conf_requirement": self.conf_req.value,
            "integ_requirement": self.integ_req.value,
            "avail_requirement": self.avail_req.value,
        }

    def to_vector_string(self) -> str:
        """Generate CVSS 4.0 vector string from metrics."""
        parts = [
            "CVSS:4.0",
            f"AV:{self.attack_vector.value}",
            f"AC:{self.attack_complexity.value}",
            f"AT:{self.attack_requirements.value}",
            f"PR:{self.privileges_required.value}",
            f"UI:{self.user_interaction.value}",
            f"VC:{self.vuln_conf.value}",
            f"VI:{self.vuln_integ.value}",
            f"VA:{self.vuln_avail.value}",
            f"SC:{self.subseq_conf.value}",
            f"SI:{self.subseq_integ.value}",
            f"SA:{self.subseq_avail.value}",
        ]

        # Add optional Threat metric if defined
        if self.exploit_maturity != ExploitMaturity.NOT_DEFINED:
            parts.append(f"E:{self.exploit_maturity.value}")

        # Add optional Environmental metrics if defined
        if self.conf_req != RequirementLevel.NOT_DEFINED:
            parts.append(f"CR:{self.conf_req.value}")
        if self.integ_req != RequirementLevel.NOT_DEFINED:
            parts.append(f"IR:{self.integ_req.value}")
        if self.avail_req != RequirementLevel.NOT_DEFINED:
            parts.append(f"AR:{self.avail_req.value}")

        # Add modified metrics if defined
        if self.mod_attack_vector != ModifiedAttackVector.NOT_DEFINED:
            parts.append(f"MAV:{self.mod_attack_vector.value}")
        if self.mod_attack_complexity != ModifiedAttackComplexity.NOT_DEFINED:
            parts.append(f"MAC:{self.mod_attack_complexity.value}")
        if self.mod_attack_requirements != ModifiedAttackRequirements.NOT_DEFINED:
            parts.append(f"MAT:{self.mod_attack_requirements.value}")
        if self.mod_privileges_required != ModifiedPrivilegesRequired.NOT_DEFINED:
            parts.append(f"MPR:{self.mod_privileges_required.value}")
        if self.mod_user_interaction != ModifiedUserInteraction.NOT_DEFINED:
            parts.append(f"MUI:{self.mod_user_interaction.value}")
        if self.mod_vuln_conf != ModifiedImpact.NOT_DEFINED:
            parts.append(f"MVC:{self.mod_vuln_conf.value}")
        if self.mod_vuln_integ != ModifiedImpact.NOT_DEFINED:
            parts.append(f"MVI:{self.mod_vuln_integ.value}")
        if self.mod_vuln_avail != ModifiedImpact.NOT_DEFINED:
            parts.append(f"MVA:{self.mod_vuln_avail.value}")
        if self.mod_subseq_conf != ModifiedImpact.NOT_DEFINED:
            parts.append(f"MSC:{self.mod_subseq_conf.value}")
        if self.mod_subseq_integ != SafetyImpact.NOT_DEFINED:
            parts.append(f"MSI:{self.mod_subseq_integ.value}")
        if self.mod_subseq_avail != SafetyImpact.NOT_DEFINED:
            parts.append(f"MSA:{self.mod_subseq_avail.value}")

        return "/".join(parts)


# =============================================================================
# Parsing Functions
# =============================================================================

# Base metrics pattern (mandatory)
CVSS40_BASE_PATTERN = re.compile(
    r'^CVSS:4\.0/'
    r'AV:(?P<av>[NALP])/'
    r'AC:(?P<ac>[LH])/'
    r'AT:(?P<at>[NP])/'
    r'PR:(?P<pr>[NLH])/'
    r'UI:(?P<ui>[NPA])/'
    r'VC:(?P<vc>[HLN])/'
    r'VI:(?P<vi>[HLN])/'
    r'VA:(?P<va>[HLN])/'
    r'SC:(?P<sc>[HLN])/'
    r'SI:(?P<si>[HLN])/'
    r'SA:(?P<sa>[HLN])',
    re.IGNORECASE
)

# Optional metrics patterns
EXPLOIT_PATTERN = re.compile(r'/E:(?P<e>[XAPU])', re.IGNORECASE)
CR_PATTERN = re.compile(r'/CR:(?P<cr>[XHML])', re.IGNORECASE)
IR_PATTERN = re.compile(r'/IR:(?P<ir>[XHML])', re.IGNORECASE)
AR_PATTERN = re.compile(r'/AR:(?P<ar>[XHML])', re.IGNORECASE)
MAV_PATTERN = re.compile(r'/MAV:(?P<mav>[XNALP])', re.IGNORECASE)
MAC_PATTERN = re.compile(r'/MAC:(?P<mac>[XLH])', re.IGNORECASE)
MAT_PATTERN = re.compile(r'/MAT:(?P<mat>[XNP])', re.IGNORECASE)
MPR_PATTERN = re.compile(r'/MPR:(?P<mpr>[XNLH])', re.IGNORECASE)
MUI_PATTERN = re.compile(r'/MUI:(?P<mui>[XNPA])', re.IGNORECASE)
MVC_PATTERN = re.compile(r'/MVC:(?P<mvc>[XHLN])', re.IGNORECASE)
MVI_PATTERN = re.compile(r'/MVI:(?P<mvi>[XHLN])', re.IGNORECASE)
MVA_PATTERN = re.compile(r'/MVA:(?P<mva>[XHLN])', re.IGNORECASE)
MSC_PATTERN = re.compile(r'/MSC:(?P<msc>[XHLN])', re.IGNORECASE)
MSI_PATTERN = re.compile(r'/MSI:(?P<msi>[XSHLN])', re.IGNORECASE)
MSA_PATTERN = re.compile(r'/MSA:(?P<msa>[XSHLN])', re.IGNORECASE)


def parse_cvss4_vector(vector_string: str) -> Tuple[bool, Optional[CVSSVector4], Optional[str]]:
    """Parse a CVSS 4.0 vector string.

    Args:
        vector_string: CVSS 4.0 vector string

    Returns:
        Tuple of (success, parsed_vector, error_message)

    Example:
        >>> success, vector, error = parse_cvss4_vector(
        ...     "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
        >>> if success:
        ...     print(f"Score: {vector.calculate_score()}")
    """
    if not vector_string:
        return False, None, "Empty vector string"

    vector_upper = vector_string.strip().upper()

    # Check base metrics
    base_match = CVSS40_BASE_PATTERN.match(vector_upper)
    if not base_match:
        return False, None, f"Invalid CVSS 4.0 vector format: {vector_string}"

    try:
        # Parse base metrics
        vector = CVSSVector4(
            attack_vector=AttackVector(base_match.group('av')),
            attack_complexity=AttackComplexity(base_match.group('ac')),
            attack_requirements=AttackRequirements(base_match.group('at')),
            privileges_required=PrivilegesRequired(base_match.group('pr')),
            user_interaction=UserInteraction(base_match.group('ui')),
            vuln_conf=ImpactMetric(base_match.group('vc')),
            vuln_integ=ImpactMetric(base_match.group('vi')),
            vuln_avail=ImpactMetric(base_match.group('va')),
            subseq_conf=ImpactMetric(base_match.group('sc')),
            subseq_integ=ImpactMetric(base_match.group('si')),
            subseq_avail=ImpactMetric(base_match.group('sa')),
            raw_string=vector_string.strip(),
        )

        # Parse optional Threat metric
        e_match = EXPLOIT_PATTERN.search(vector_upper)
        if e_match:
            vector.exploit_maturity = ExploitMaturity(e_match.group('e'))

        # Parse optional Environmental - Requirements
        cr_match = CR_PATTERN.search(vector_upper)
        if cr_match:
            vector.conf_req = RequirementLevel(cr_match.group('cr'))

        ir_match = IR_PATTERN.search(vector_upper)
        if ir_match:
            vector.integ_req = RequirementLevel(ir_match.group('ir'))

        ar_match = AR_PATTERN.search(vector_upper)
        if ar_match:
            vector.avail_req = RequirementLevel(ar_match.group('ar'))

        # Parse optional Modified metrics
        mav_match = MAV_PATTERN.search(vector_upper)
        if mav_match:
            vector.mod_attack_vector = ModifiedAttackVector(mav_match.group('mav'))

        mac_match = MAC_PATTERN.search(vector_upper)
        if mac_match:
            vector.mod_attack_complexity = ModifiedAttackComplexity(mac_match.group('mac'))

        mat_match = MAT_PATTERN.search(vector_upper)
        if mat_match:
            vector.mod_attack_requirements = ModifiedAttackRequirements(mat_match.group('mat'))

        mpr_match = MPR_PATTERN.search(vector_upper)
        if mpr_match:
            vector.mod_privileges_required = ModifiedPrivilegesRequired(mpr_match.group('mpr'))

        mui_match = MUI_PATTERN.search(vector_upper)
        if mui_match:
            vector.mod_user_interaction = ModifiedUserInteraction(mui_match.group('mui'))

        mvc_match = MVC_PATTERN.search(vector_upper)
        if mvc_match:
            vector.mod_vuln_conf = ModifiedImpact(mvc_match.group('mvc'))

        mvi_match = MVI_PATTERN.search(vector_upper)
        if mvi_match:
            vector.mod_vuln_integ = ModifiedImpact(mvi_match.group('mvi'))

        mva_match = MVA_PATTERN.search(vector_upper)
        if mva_match:
            vector.mod_vuln_avail = ModifiedImpact(mva_match.group('mva'))

        msc_match = MSC_PATTERN.search(vector_upper)
        if msc_match:
            vector.mod_subseq_conf = ModifiedImpact(msc_match.group('msc'))

        msi_match = MSI_PATTERN.search(vector_upper)
        if msi_match:
            vector.mod_subseq_integ = SafetyImpact(msi_match.group('msi'))

        msa_match = MSA_PATTERN.search(vector_upper)
        if msa_match:
            vector.mod_subseq_avail = SafetyImpact(msa_match.group('msa'))

        return True, vector, None

    except ValueError as e:
        return False, None, f"Invalid metric value in vector: {e}"


def calculate_cvss4_from_vector(vector_string: str) -> Tuple[bool, Optional[float], Optional[str]]:
    """Calculate CVSS 4.0 score from a vector string.

    Args:
        vector_string: CVSS 4.0 vector string

    Returns:
        Tuple of (success, score, error_message)
    """
    success, vector, error = parse_cvss4_vector(vector_string)
    if not success:
        return False, None, error

    return True, vector.calculate_score(), None


def validate_cvss4_vector(vector_string: str) -> Tuple[bool, Optional[str]]:
    """Validate a CVSS 4.0 vector string without calculating score.

    Args:
        vector_string: CVSS 4.0 vector string to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    success, _, error = parse_cvss4_vector(vector_string)
    return success, error


# Common CVSS 4.0 vector examples
CVSS4_EXAMPLES = {
    "critical_network_rce": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
    "high_network_auth": "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "medium_local": "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    "low_physical": "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
}

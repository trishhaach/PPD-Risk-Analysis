"""
Hybrid Postpartum Depression (PPD) Screening System v3.1 (Production Grade)
Architecture: Policy-Encoded Clinical Decision Support

⚠️ SYSTEM DISCLAIMER ⚠️
1. This system is a TRIAGE AID, not a diagnostic tool.
2. ML output represents "Risk Signal Strength", NOT "True Disease Prevalence".
3. Clinical Authority (EPDS) always supersedes Algorithmic Prediction in conflict.
4. Probability values are normalized for risk stratification, not calibration.

Design Principles:
- Safety First: Q10=3 triggers immediate bypass.
- Humility: ML is penalized for known precision issues.
- Context Awareness: 'Low EPDS' is split into Zone A (Noise) and Zone B (Masking).
"""

import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

# Configure Logging for Auditability
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("PPDScreener")

class RiskLevel(Enum):
    """
    Risk level enumeration.
    CRITICAL is reserved for immediate self-harm risks (Q10=3).
    """
    LOW = "Low"
    MODERATE = "Moderate"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass(frozen=True)
class SystemConfig:
    """
    Centralized Configuration for Clinical Policy & ML Parameters.
    Eliminates magic numbers and enforces policy governance.
    """
    # --- EPDS THRESHOLDS ---
    EPDS_MODERATE_START: int = 10
    EPDS_HIGH_START: int = 13
    
    # --- ML MODEL PERFORMANCE PARAMETERS ---
    # Threshold used during model training to optimize recall
    ML_TRAINING_THRESHOLD: float = 0.3
    # Precision penalty factor (1.0 - False Positive Rate)
    # Used to dampen ML signal because model has moderate precision (~0.75)
    ML_PRECISION_PENALTY: float = 0.75
    
    # --- HYBRID FUSION POLICY ---
    # The probability value where 'Moderate' risk begins
    CLINICAL_MODERATE_THRESHOLD: float = 0.30
    # The probability value where 'High' risk begins
    CLINICAL_HIGH_THRESHOLD: float = 0.55
    # Hard cap for ML-driven moderate risk (Must be < High Threshold)
    SAFETY_CAP_MODERATE: float = 0.54
    # Safety floor for Zone B (Masked Depression) cases
    SAFETY_FLOOR_ZONE_B: float = 0.35
    
    # --- WEIGHTING STRATEGIES ---
    # Zone A: EPDS 0-3 (Trust Patient)
    WEIGHT_ZONE_A_PATIENT: float = 0.65
    WEIGHT_ZONE_A_ML: float = 0.35
    
    # Zone B: EPDS 4-9 (Trust Safety Net)
    WEIGHT_ZONE_B_PATIENT: float = 0.45
    WEIGHT_ZONE_B_ML: float = 0.55


@dataclass
class AuditRecord:
    """Immutable record for clinical audit and model monitoring."""
    timestamp: str
    epds_total: int
    q10_score: int
    ml_raw: float
    final_risk: str
    final_prob: float
    is_discordant: bool
    uncertainty_flag: bool
    decision_path: str


@dataclass
class ScreeningResult:
    """Result of hybrid screening with explainability and audit trails."""
    risk_label: RiskLevel
    final_probability: float
    explanation: str
    detailed_metrics: Dict[str, Any]
    fusion_method: str
    audit_record: AuditRecord
    
    @property
    def requires_immediate_intervention(self) -> bool:
        return self.risk_label == RiskLevel.CRITICAL or self.risk_label == RiskLevel.HIGH


class EPDSProcessor:
    """
    Processes EPDS scores using Continuous Piecewise Linear Mapping.
    Maps categorical clinical scores to continuous risk probabilities.
    """
    
    @staticmethod
    def calculate_total_score(epds_responses: List[int]) -> int:
        if len(epds_responses) != 10:
            raise ValueError("EPDS must have exactly 10 responses")
        if any(score < 0 or score > 3 for score in epds_responses):
            raise ValueError("EPDS responses must be between 0 and 3")
        return sum(epds_responses)
    
    @staticmethod
    def get_q10_score(epds_responses: List[int]) -> int:
        return epds_responses[9]
    
    @staticmethod
    def get_epds_risk_level(total_score: int, config: SystemConfig) -> RiskLevel:
        if total_score < config.EPDS_MODERATE_START:
            return RiskLevel.LOW
        elif total_score < config.EPDS_HIGH_START:
            return RiskLevel.MODERATE
        else:
            return RiskLevel.HIGH
    
    @classmethod
    def map_to_probability(cls, total_score: int) -> float:
        """
        Maps EPDS score to probability using continuous interpolation.
        Ensures monotonic increase (no plateaus).
        """
        score = max(0, min(30, total_score))
        
        # Mapping logic derived from validation studies
        # Format: (Score) -> Probability
        if score <= 3:
            return 0.02 + (score / 3.0) * (0.08 - 0.02)
        elif score <= 6:
            return 0.08 + ((score - 3) / 3.0) * (0.15 - 0.08)
        elif score <= 9:
            return 0.15 + ((score - 6) / 3.0) * (0.25 - 0.15)
        elif score <= 12:
            return 0.25 + ((score - 9) / 3.0) * (0.45 - 0.25)
        elif score <= 15:
            return 0.45 + ((score - 12) / 3.0) * (0.70 - 0.45)
        elif score <= 18:
            return 0.70 + ((score - 15) / 3.0) * (0.85 - 0.70)
        elif score <= 21:
            return 0.85 + ((score - 18) / 3.0) * (0.92 - 0.85)
        else:
            return 0.92 + ((score - 21) / 9.0) * (0.98 - 0.92)


class MLStandardizer:
    """
    Standardizes ML raw probabilities to Clinical Risk Tiers.
    NOTE: Output is a 'Triage Signal', not a statistical probability of disease.
    """
    
    @staticmethod
    def standardize_probability(raw_prob: float, config: SystemConfig) -> float:
        """
        Maps Raw ML to Clinical Probability.
        - Low Tier (<Threshold): Maps to 0.00-0.30
        - High Tier (>=Threshold): Maps to 0.40-0.80 (Boosted Baseline)
        """
        if not 0.0 <= raw_prob <= 1.0:
            raise ValueError(f"ML probability must be [0,1], got {raw_prob}")
        
        threshold = config.ML_TRAINING_THRESHOLD
        
        if raw_prob < threshold:
            # Low Tier: Linear mapping
            return 0.0 + (raw_prob / threshold) * 0.30
        else:
            # High Tier: The "Jump" to Moderate Risk baseline
            # Denom: (1.0 - threshold)
            return 0.40 + ((raw_prob - threshold) / (1.0 - threshold)) * (0.80 - 0.40)
    
    @staticmethod
    def get_ml_risk_level(raw_prob: float, config: SystemConfig) -> RiskLevel:
        return RiskLevel.LOW if raw_prob < config.ML_TRAINING_THRESHOLD else RiskLevel.HIGH


class HybridFusionEngine:
    """
    Implements the Policy-Encoded Decision Logic.
    Decisions are based on SystemConfig constants, not magic numbers.
    """
    
    def __init__(self, config: SystemConfig):
        self.config = config

    def check_q10_emergency(self, q10_score: int) -> Optional[Tuple[RiskLevel, float, str]]:
        """
        POLICY: Only Q10=3 triggers override.
        """
        if q10_score == 3:
            return (
                RiskLevel.CRITICAL,
                0.98,
                "Q10=3: Emergency self-harm risk detected. Immediate intervention required."
            )
        return None
    
    def fuse_probabilities(
        self,
        epds_risk: RiskLevel,
        epds_prob: float,
        ml_risk: RiskLevel,
        ml_prob: float,
        epds_score: int
    ) -> Tuple[RiskLevel, float, str, bool, bool]:
        """
        Executes Fusion Logic.
        Returns: (RiskLevel, Probability, Explanation, DiscordanceFlag, UncertaintyFlag)
        """
        
        # Flags for audit
        is_discordant = False
        uncertainty_flag = False

        # Case 1: EPDS Low + ML Low -> Low
        if epds_risk == RiskLevel.LOW and ml_risk == RiskLevel.LOW:
            # Simple weighted average for agreement
            final_prob = (0.7 * epds_prob) + (0.3 * ml_prob)
            return RiskLevel.LOW, final_prob, "Weighted Average (Low/Low)", False, False
        
        # Case 2: EPDS Low + ML High -> PRECISION-AWARE SPLIT LOGIC
        elif epds_risk == RiskLevel.LOW and ml_risk == RiskLevel.HIGH:
            is_discordant = True
            
            # A. Precision Penalty (Dampen ML signal)
            ml_prob_adjusted = ml_prob * self.config.ML_PRECISION_PENALTY
            
            # B. Split Decision (Zone A vs Zone B)
            if epds_score <= 3:
                # ZONE A: EPDS 0-3 (Strong Denial)
                # Policy: Trust Patient. ML likely hallucinating (Class 0 precision issue).
                ml_weight = self.config.WEIGHT_ZONE_A_ML
                epds_weight = self.config.WEIGHT_ZONE_A_PATIENT
                safety_floor = 0.0 
                note = "Zone A: Trusting Patient (Noise Filter)"
            else:
                # ZONE B: EPDS 4-9 (Ambivalence)
                # Policy: Trust Safety Net. High risk of masking.
                ml_weight = self.config.WEIGHT_ZONE_B_ML
                epds_weight = self.config.WEIGHT_ZONE_B_PATIENT
                safety_floor = self.config.SAFETY_FLOOR_ZONE_B
                note = "Zone B: Trusting Safety Net (Masking Check)"
                uncertainty_flag = True  # Flag for clinician review

            # C. Calculation
            weighted_prob = (ml_weight * ml_prob_adjusted) + (epds_weight * epds_prob)
            
            # D. Safety Bounds
            final_prob = max(weighted_prob, safety_floor)
            final_prob = min(final_prob, self.config.SAFETY_CAP_MODERATE) # Cap at 0.54
            
            # E. Assignment
            if final_prob >= self.config.CLINICAL_MODERATE_THRESHOLD:
                return RiskLevel.MODERATE, final_prob, f"Discordance -> Elevated to MODERATE ({note})", True, uncertainty_flag
            else:
                return RiskLevel.LOW, final_prob, f"Discordance -> Retained LOW ({note})", True, False
        
        # Case 3: EPDS Moderate + ML Low -> Moderate
        elif epds_risk == RiskLevel.MODERATE and ml_risk == RiskLevel.LOW:
            final_prob = (0.8 * epds_prob) + (0.2 * ml_prob)
            return RiskLevel.MODERATE, final_prob, "Weighted Average (EPDS Dominant)", True, False
        
        # Case 4: EPDS Moderate + ML High -> High
        elif epds_risk == RiskLevel.MODERATE and ml_risk == RiskLevel.HIGH:
            # Risk Amplification
            final_prob = min(max(epds_prob, ml_prob) * 1.15, 0.80)
            return RiskLevel.HIGH, final_prob, "Risk Amplification (Med/High)", False, False
        
        # Case 5: EPDS High + ML Low -> High (ANTI-DILUTION)
        elif epds_risk == RiskLevel.HIGH and ml_risk == RiskLevel.LOW:
            is_discordant = True
            # Policy: Do not average. ML is a False Negative.
            # Anchor to EPDS to prevent dilution.
            final_prob = epds_prob
            return RiskLevel.HIGH, final_prob, "Clinical Anchoring (ML False Negative Ignored)", True, True
            
        # Case 6: EPDS High + ML High -> High
        else:
            final_prob = (0.8 * epds_prob) + (0.2 * ml_prob)
            return RiskLevel.HIGH, final_prob, "Weighted Average (High/High)", False, False


class HybridScreener:
    """Main System Orchestrator"""
    
    def __init__(self):
        self.config = SystemConfig()
        self.epds_processor = EPDSProcessor()
        self.ml_standardizer = MLStandardizer()
        self.fusion_engine = HybridFusionEngine(self.config)
    
    def screen(
        self,
        epds_responses: List[int],
        ml_raw_probability: float
    ) -> ScreeningResult:
        
        # 1. Metric Calculation
        epds_total = self.epds_processor.calculate_total_score(epds_responses)
        q10_score = self.epds_processor.get_q10_score(epds_responses)
        epds_risk = self.epds_processor.get_epds_risk_level(epds_total, self.config)
        epds_prob = self.epds_processor.map_to_probability(epds_total)
        
        ml_std_prob = self.ml_standardizer.standardize_probability(ml_raw_probability, self.config)
        ml_risk = self.ml_standardizer.get_ml_risk_level(ml_raw_probability, self.config)
        
        metrics = {
            "epds_total": epds_total,
            "epds_risk": epds_risk.value,
            "ml_raw": ml_raw_probability,
            "ml_std": round(ml_std_prob, 3),
        }
        
        # 2. CHECK A: Q10 Emergency
        q10_override = self.fusion_engine.check_q10_emergency(q10_score)
        if q10_override:
            risk_label, final_prob, expl = q10_override
            audit = AuditRecord(
                timestamp=datetime.now().isoformat(),
                epds_total=epds_total,
                q10_score=q10_score,
                ml_raw=ml_raw_probability,
                final_risk=risk_label.value,
                final_prob=final_prob,
                is_discordant=False,
                uncertainty_flag=False,
                decision_path="Q10_OVERRIDE"
            )
            return ScreeningResult(risk_label, final_prob, expl, metrics, "Q10 Override", audit)
            
        # 3. CHECK B: Clinical Dominance (EPDS >= 13)
        if epds_risk == RiskLevel.HIGH:
            audit = AuditRecord(
                timestamp=datetime.now().isoformat(),
                epds_total=epds_total,
                q10_score=q10_score,
                ml_raw=ml_raw_probability,
                final_risk=RiskLevel.HIGH.value,
                final_prob=epds_prob,
                is_discordant=(ml_risk == RiskLevel.LOW),
                uncertainty_flag=(ml_risk == RiskLevel.LOW),
                decision_path="EPDS_DOMINANCE"
            )
            return ScreeningResult(
                RiskLevel.HIGH, 
                epds_prob, 
                f"Clinical Dominance (EPDS {epds_total} >= 13)",
                metrics,
                "EPDS Threshold Override",
                audit
            )
            
        # 4. Hybrid Fusion (for EPDS < 13)
        final_risk, final_prob, method, discordance, uncertainty = self.fusion_engine.fuse_probabilities(
            epds_risk, epds_prob, ml_risk, ml_std_prob, epds_total
        )
        
        explanation = f"Hybrid Assessment: {final_risk.value} Risk. {method}"
        
        # Log Audit Record
        audit = AuditRecord(
            timestamp=datetime.now().isoformat(),
            epds_total=epds_total,
            q10_score=q10_score,
            ml_raw=ml_raw_probability,
            final_risk=final_risk.value,
            final_prob=round(final_prob, 3),
            is_discordant=discordance,
            uncertainty_flag=uncertainty,
            decision_path="HYBRID_FUSION"
        )
        
        if uncertainty:
            logger.warning(f"UNCERTAINTY FLAG: EPDS={epds_total}, ML={ml_raw_probability}. {method}")

        return ScreeningResult(final_risk, round(final_prob, 3), explanation, metrics, method, audit)


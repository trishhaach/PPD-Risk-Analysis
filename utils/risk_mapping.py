"""
Risk level mapping utilities for standardizing risk levels across the backend.
Standardizes to: LOW, MEDIUM, HIGH, CRITICAL
"""

# Severity order mapping for comparison
SEVERITY_ORDER = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3
}

# ML probability thresholds for converting to risk levels
ML_LOW_THRESHOLD = 0.33
ML_MEDIUM_THRESHOLD = 0.66
ML_CRITICAL_THRESHOLD = 0.85


def epds_to_risk_level(total_score: int, q10_score: int) -> str:
    """
    Convert EPDS total score and Q10 score to standardized risk level.
    
    Rules:
    - If q10_score > 0: return "CRITICAL"
    - elif total_score >= 13: return "HIGH"
    - elif total_score >= 10: return "MEDIUM"
    - else: return "LOW"
    
    Args:
        total_score: EPDS total score (0-30)
        q10_score: EPDS Q10 score (0-3)
    
    Returns:
        Standardized risk level: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
    """
    if q10_score > 0:
        return "CRITICAL"
    elif total_score >= 13:
        return "HIGH"
    elif total_score >= 10:
        return "MEDIUM"
    else:
        return "LOW"


def ml_probability_to_risk_level(ml_probability: float) -> str:
    """
    Convert ML probability to risk level.
    
    Thresholds:
    - < 0.33 => "LOW"
    - < 0.66 => "MEDIUM"
    - >= 0.66 => "HIGH"
    
    Args:
        ml_probability: ML raw probability (0.0 to 1.0)
    
    Returns:
        Risk level: "LOW", "MEDIUM", or "HIGH"
    """
    if ml_probability < ML_LOW_THRESHOLD:
        return "LOW"
    elif ml_probability < ML_MEDIUM_THRESHOLD:
        return "MEDIUM"
    else:
        return "HIGH"


def hybrid_to_risk_level(epds_risk: str, ml_probability: float, q10_score: int) -> str:
    """
    Convert EPDS risk, ML probability, and Q10 score to final hybrid risk level.
    
    Rules:
    1. If q10_score > 0: return "CRITICAL"
    2. Convert ml_probability to ml_risk using thresholds
    3. Final risk = max severity between epds_risk and ml_risk
    4. Additionally, if ml_probability >= 0.85: final risk becomes "CRITICAL"
    
    Args:
        epds_risk: EPDS risk level ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        ml_probability: ML raw probability (0.0 to 1.0)
        q10_score: EPDS Q10 score (0-3)
    
    Returns:
        Final hybrid risk level: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
    """
    # Q10 override: immediate CRITICAL
    if q10_score > 0:
        return "CRITICAL"
    
    # Convert ML probability to risk level
    ml_risk = ml_probability_to_risk_level(ml_probability)
    
    # Normalize EPDS risk to uppercase
    epds_risk_upper = epds_risk.upper().strip()
    
    # Get severity values
    epds_severity = SEVERITY_ORDER.get(epds_risk_upper, 0)
    ml_severity = SEVERITY_ORDER.get(ml_risk, 0)
    
    # Take max severity
    max_severity = max(epds_severity, ml_severity)
    
    # Map back to risk level
    severity_to_risk = {v: k for k, v in SEVERITY_ORDER.items()}
    final_risk = severity_to_risk.get(max_severity, "LOW")
    
    # ML critical threshold override
    if ml_probability >= ML_CRITICAL_THRESHOLD:
        final_risk = "CRITICAL"
    
    return final_risk


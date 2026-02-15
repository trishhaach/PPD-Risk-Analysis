"""
Quick verification script for risk mapping functions.
Run with: python test_risk_mapping.py
"""
from utils.risk_mapping import epds_to_risk_level, hybrid_to_risk_level, prediction_to_standard, ml_probability_to_risk_level, ML_CRITICAL_THRESHOLD


def test_prediction_standardization():
    """Test prediction string standardization logic"""
    print("\n" + "=" * 60)
    print("Testing Prediction Standardization")
    print("=" * 60)
    
    test_cases = [
        ("HIGH RISK", "HIGH", "Prediction 'HIGH RISK' -> HIGH"),
        ("critical level", "CRITICAL", "Prediction 'critical level' -> CRITICAL"),
        ("Low Risk", "LOW", "Prediction 'Low Risk' -> LOW"),
        ("Medium", "MEDIUM", "Prediction 'Medium' -> MEDIUM"),
        ("Unknown", None, "Prediction 'Unknown' -> None"),
        ("", None, "Empty prediction -> None"),
    ]

    all_passed = True
    for pred, expected, description in test_cases:
        result = prediction_to_standard(pred)
        status = "PASS" if result == expected else "FAIL"
        if result != expected:
            all_passed = False
        print(f"[{status}] {description}")
        print(f"   Expected: {expected}, Got: {result}")
    
    # Specific scenario requested: 
    # ML mock: {"prediction":"HIGH RISK","risk_probability":0.49,"threshold_used":0.41}
    # Assert risk_level_standard == "HIGH".
    print("\n[TEST SCENARIO] High Risk Label with Low Probability")
    mock_ml_result = {"prediction": "HIGH RISK", "risk_probability": 0.49}
    ml_probability = 0.49
    ml_pred_raw = mock_ml_result.get("prediction")
    
    pred_std = prediction_to_standard(ml_pred_raw)
    if pred_std:
        risk_level_standard = pred_std
    else:
        risk_level_standard = ml_probability_to_risk_level(ml_probability)
        if ml_probability >= ML_CRITICAL_THRESHOLD:
            risk_level_standard = "CRITICAL"
            
    if risk_level_standard == "HIGH":
        print("[PASS] Scenario Logic Correct: risk_level_standard == 'HIGH'")
    else:
        print(f"[FAIL] Scenario Logic Incorrect: Got {risk_level_standard}")
        all_passed = False

    assert all_passed


def test_epds_mapping():
    """Test EPDS to risk level mapping"""
    print("=" * 60)
    print("Testing EPDS Risk Mapping")
    print("=" * 60)
    
    test_cases = [
        (8, 0, "LOW", "EPDS total 8, q10 0 -> LOW"),
        (11, 0, "MEDIUM", "EPDS total 11, q10 0 -> MEDIUM"),
        (15, 0, "HIGH", "EPDS total 15, q10 0 -> HIGH"),
        (5, 1, "CRITICAL", "EPDS total 5, q10 1 -> CRITICAL"),
        (0, 0, "LOW", "EPDS total 0, q10 0 -> LOW"),
        (9, 0, "LOW", "EPDS total 9, q10 0 -> LOW"),
        (10, 0, "MEDIUM", "EPDS total 10, q10 0 -> MEDIUM"),
        (12, 0, "MEDIUM", "EPDS total 12, q10 0 -> MEDIUM"),
        (13, 0, "HIGH", "EPDS total 13, q10 0 -> HIGH"),
        (30, 0, "HIGH", "EPDS total 30, q10 0 -> HIGH"),
        (20, 2, "CRITICAL", "EPDS total 20, q10 2 -> CRITICAL"),
    ]
    
    all_passed = True
    for total_score, q10_score, expected, description in test_cases:
        result = epds_to_risk_level(total_score, q10_score)
        status = "PASS" if result == expected else "FAIL"
        if result != expected:
            all_passed = False
        print(f"[{status}] {description}")
        print(f"   Expected: {expected}, Got: {result}")
    
    assert all_passed
    return all_passed


def test_hybrid_mapping():
    """Test Hybrid risk level mapping"""
    print("\n" + "=" * 60)
    print("Testing Hybrid Risk Mapping")
    print("=" * 60)
    
    test_cases = [
        ("HIGH", 0.2, 0, "HIGH", "EPDS HIGH + ML 0.2 + q10 0 -> HIGH"),
        ("LOW", 0.9, 0, "CRITICAL", "EPDS LOW + ML 0.9 + q10 0 -> CRITICAL (ML >= 0.85)"),
        ("LOW", 0.5, 0, "MEDIUM", "EPDS LOW + ML 0.5 + q10 0 -> MEDIUM"),
        ("MEDIUM", 0.7, 0, "HIGH", "EPDS MEDIUM + ML 0.7 + q10 0 -> HIGH"),
        ("LOW", 0.3, 0, "LOW", "EPDS LOW + ML 0.3 + q10 0 -> LOW"),
        ("HIGH", 0.85, 0, "CRITICAL", "EPDS HIGH + ML 0.85 + q10 0 -> CRITICAL (ML >= 0.85)"),
        ("LOW", 0.1, 1, "CRITICAL", "EPDS LOW + ML 0.1 + q10 1 -> CRITICAL (q10 override)"),
        ("HIGH", 0.9, 1, "CRITICAL", "EPDS HIGH + ML 0.9 + q10 1 -> CRITICAL (q10 override)"),
    ]
    
    all_passed = True
    for epds_risk, ml_prob, q10_score, expected, description in test_cases:
        result = hybrid_to_risk_level(epds_risk, ml_prob, q10_score)
        status = "PASS" if result == expected else "FAIL"
        if result != expected:
            all_passed = False
        print(f"[{status}] {description}")
        print(f"   Expected: {expected}, Got: {result}")
    
    assert all_passed
    return all_passed


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("Risk Mapping Verification Script")
    print("=" * 60 + "\n")
    
    epds_passed = test_epds_mapping()
    hybrid_passed = test_hybrid_mapping()
    try:
        test_prediction_standardization()
        print("[PASS] Prediction Standardization")
    except AssertionError:
        print("[FAIL] Prediction Standardization")
        hybrid_passed = False # Flag overall failure
    
    print("\n" + "=" * 60)
    if epds_passed and hybrid_passed:
        print("[PASS] ALL TESTS PASSED")
    else:
        print("[FAIL] SOME TESTS FAILED")
    print("=" * 60 + "\n")


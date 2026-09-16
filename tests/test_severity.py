from src.predict import calculate_severity


def test_attack_high():
    assert calculate_severity(1, 0.90) == "HIGH"


def test_attack_medium():
    assert calculate_severity(1, 0.60) == "MEDIUM"


def test_attack_suspicious():
    assert calculate_severity(1, 0.40) == "SUSPICIOUS"


def test_benign_low():
    assert calculate_severity(0, 0.90) == "LOW"


def test_benign_suspicious():
    assert calculate_severity(0, 0.70) == "SUSPICIOUS"

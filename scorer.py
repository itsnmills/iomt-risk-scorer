"""
IoMT Risk Scoring Engine
========================
Composite risk scoring for Internet of Medical Things (IoMT) devices.

Methodology informed by:
- NIST SP 800-30 Rev. 1 (Guide for Conducting Risk Assessments)
- NIST Cybersecurity Framework 2.0
- FDA Premarket Cybersecurity Guidance (2023)
- HHS 405(d) HICP (Health Industry Cybersecurity Practices)
- HIPAA Security Rule (45 CFR §164.308-312)

Author: Noah Mills
"""

from dataclasses import dataclass, field
from typing import Optional
import pandas as pd
from datetime import datetime, timedelta


# ── Weight Configuration ────────────────────────────────────────────
DEFAULT_WEIGHTS = {
    "exposure": 0.20,
    "vulnerability": 0.20,
    "data_sensitivity": 0.20,
    "patient_safety": 0.25,
    "authentication": 0.15,
}

# ── Lookup Tables ───────────────────────────────────────────────────

NETWORK_SEGMENT_SCORES = {
    "Internet-Facing": 100,
    "Guest WiFi": 85,
    "Flat Network": 70,
    "DMZ": 50,
    "Clinical VLAN": 30,
    "Air-Gapped": 5,
}

PATCHABILITY_SCORES = {
    "No": 100,
    "Vendor-Only": 60,
    "Yes": 20,
}

VENDOR_SUPPORT_SCORES = {
    "End of Life": 100,
    "Limited": 60,
    "Unknown": 50,
    "Active": 10,
}

OS_RISK_SCORES = {
    "Windows CE/IoT": 90,       # Legacy, rarely patched
    "Proprietary": 75,          # Opaque, hard to assess
    "Unknown": 70,              # Can't evaluate = assume risk
    "Embedded RTOS": 60,        # Limited attack surface but rarely patched
    "Windows 10/11": 35,        # Patchable but large attack surface
    "Linux": 25,                # Patchable, smaller medical attack surface
}

PHI_HANDLING_SCORES = {
    "Transmit": 100,
    "Read-Write": 75,
    "Read-Only": 40,
    "None": 10,
}

FDA_CLASS_SCORES = {
    "III": 100,
    "II": 60,
    "I": 30,
    "N/A": 10,
}

DEVICE_TYPE_CRITICALITY = {
    "Ventilator": 1.00,
    "Infusion Pump": 0.95,
    "Patient Monitor": 0.85,
    "PACS Imaging": 0.70,
    "Lab Analyzer": 0.65,
    "Smart Bed": 0.55,
    "Nurse Call": 0.50,
    "Wearable Sensor": 0.45,
    "Building Automation": 0.30,
    "Custom": 0.50,
}

AUTH_SCORES = {
    "None": 100,
    "Default Creds": 85,
    "Local Auth": 40,
    "AD/LDAP": 20,
    "MFA": 5,
}

ENCRYPTION_MODIFIER = {
    "None": 1.0,        # Full penalty
    "Unknown": 0.90,    # Assume the worst
    "In-Transit Only": 0.65,
    "At-Rest Only": 0.70,
    "Both": 0.35,
}

RISK_LEVELS = [
    (75, "Critical", "#FF4B4B"),
    (50, "High", "#FF8C00"),
    (25, "Medium", "#FFD700"),
    (0, "Low", "#20808D"),
]


def get_risk_level(score: float) -> tuple:
    """Return (label, color) for a given risk score."""
    for threshold, label, color in RISK_LEVELS:
        if score >= threshold:
            return label, color
    return "Low", "#20808D"


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


# ── Sub-Score Calculators ───────────────────────────────────────────

def calc_exposure_score(network_segment: str) -> float:
    """
    Exposure score based on network segment placement.
    Maps directly to NIST CSF ID.AM-4 (external information systems cataloged).
    """
    return float(NETWORK_SEGMENT_SCORES.get(network_segment, 50))


def calc_vulnerability_score(
    patchable: str,
    vendor_support: str,
    os_firmware: str,
    last_vuln_scan: Optional[str] = None,
) -> float:
    """
    Vulnerability score: weighted combination of patchability, vendor support,
    OS risk, and scan recency.

    References:
    - NIST SP 800-30 §2.3 (threat/vulnerability identification)
    - FDA Premarket Guidance §V.B (software bill of materials)
    """
    patch_score = PATCHABILITY_SCORES.get(patchable, 60)
    support_score = VENDOR_SUPPORT_SCORES.get(vendor_support, 50)
    os_score = OS_RISK_SCORES.get(os_firmware, 50)

    # Scan recency penalty: older scans → higher risk
    scan_penalty = 0.0
    if last_vuln_scan:
        try:
            scan_date = pd.to_datetime(last_vuln_scan)
            days_since = (datetime.now() - scan_date).days
            if days_since > 365:
                scan_penalty = 20.0
            elif days_since > 180:
                scan_penalty = 12.0
            elif days_since > 90:
                scan_penalty = 5.0
        except (ValueError, TypeError):
            scan_penalty = 10.0  # Unparseable = moderate penalty
    else:
        scan_penalty = 15.0  # Never scanned

    raw = (patch_score * 0.35) + (support_score * 0.30) + (os_score * 0.25) + scan_penalty
    return _clamp(raw)


def calc_data_sensitivity_score(phi_handling: str) -> float:
    """
    Data sensitivity score based on PHI handling level.

    References:
    - HIPAA Security Rule §164.312(e)(1) — transmission security
    - HIPAA Security Rule §164.312(a)(1) — access controls
    - HHS HICP Practice 4 (data protection and loss prevention)
    """
    return float(PHI_HANDLING_SCORES.get(phi_handling, 40))


def calc_patient_safety_score(fda_class: str, device_type: str) -> float:
    """
    Patient safety score: FDA classification × device type criticality.

    References:
    - FDA Premarket Cybersecurity Guidance §IV (risk tiers)
    - NIST CSF PR.IP (protective technology)
    """
    fda_score = FDA_CLASS_SCORES.get(fda_class, 30)
    criticality = DEVICE_TYPE_CRITICALITY.get(device_type, 0.50)
    return _clamp(fda_score * criticality)


def calc_authentication_score(authentication: str, encryption: str) -> float:
    """
    Authentication & encryption posture score.

    References:
    - HIPAA §164.312(d) — person/entity authentication
    - HIPAA §164.312(e)(1) — transmission security
    - NIST CSF PR.AC (identity management and access control)
    """
    auth_base = AUTH_SCORES.get(authentication, 50)
    enc_modifier = ENCRYPTION_MODIFIER.get(encryption, 0.80)

    # Encryption modifies the auth score — strong encryption partially
    # compensates for weak auth (but never fully)
    modified = auth_base * (0.4 + 0.6 * enc_modifier)
    return _clamp(modified)


# ── Composite Score ─────────────────────────────────────────────────

def calculate_risk_score(device: dict, weights: Optional[dict] = None) -> dict:
    """
    Calculate composite risk score for a single device.

    Parameters
    ----------
    device : dict
        Device attributes (must contain all required fields).
    weights : dict, optional
        Custom weight overrides. Defaults to DEFAULT_WEIGHTS.

    Returns
    -------
    dict
        Contains 'total_score', each sub-score, 'risk_level', 'risk_color',
        and 'weights_used'.
    """
    w = {**DEFAULT_WEIGHTS, **(weights or {})}

    # Normalize weights to sum to 1.0
    weight_sum = sum(w.values())
    if weight_sum > 0:
        w = {k: v / weight_sum for k, v in w.items()}

    exposure = calc_exposure_score(device.get("Network Segment", ""))
    vulnerability = calc_vulnerability_score(
        device.get("Patchable", ""),
        device.get("Vendor Support Status", ""),
        device.get("OS/Firmware", ""),
        device.get("Last Vulnerability Scan", None),
    )
    data_sensitivity = calc_data_sensitivity_score(device.get("PHI Handling", ""))
    patient_safety = calc_patient_safety_score(
        device.get("FDA Class", ""),
        device.get("Device Type", ""),
    )
    authentication = calc_authentication_score(
        device.get("Authentication", ""),
        device.get("Encryption", ""),
    )

    total = _clamp(
        exposure * w["exposure"]
        + vulnerability * w["vulnerability"]
        + data_sensitivity * w["data_sensitivity"]
        + patient_safety * w["patient_safety"]
        + authentication * w["authentication"]
    )

    level, color = get_risk_level(total)

    return {
        "total_score": round(total, 1),
        "exposure_score": round(exposure, 1),
        "vulnerability_score": round(vulnerability, 1),
        "data_sensitivity_score": round(data_sensitivity, 1),
        "patient_safety_score": round(patient_safety, 1),
        "authentication_score": round(authentication, 1),
        "risk_level": level,
        "risk_color": color,
        "weights_used": w,
    }


def score_dataframe(df: pd.DataFrame, weights: Optional[dict] = None) -> pd.DataFrame:
    """
    Score every device in a DataFrame. Adds risk columns in-place and returns
    the augmented DataFrame.
    """
    results = []
    for _, row in df.iterrows():
        device = row.to_dict()
        scores = calculate_risk_score(device, weights)
        results.append(scores)

    scores_df = pd.DataFrame(results)
    out = pd.concat([df.reset_index(drop=True), scores_df], axis=1)
    return out


# ── Field Definitions (for UI dropdowns) ────────────────────────────

DEVICE_TYPES = list(DEVICE_TYPE_CRITICALITY.keys())

NETWORK_SEGMENTS = list(NETWORK_SEGMENT_SCORES.keys())

OS_OPTIONS = list(OS_RISK_SCORES.keys())

PATCHABLE_OPTIONS = ["Yes", "No", "Vendor-Only"]

VENDOR_SUPPORT_OPTIONS = list(VENDOR_SUPPORT_SCORES.keys())

PHI_OPTIONS = list(PHI_HANDLING_SCORES.keys())

FDA_CLASSES = ["I", "II", "III", "N/A"]

AUTH_OPTIONS = list(AUTH_SCORES.keys())

ENCRYPTION_OPTIONS = list(ENCRYPTION_MODIFIER.keys())


# ── CSV Validation ──────────────────────────────────────────────────

REQUIRED_COLUMNS = [
    "Device Name",
    "Device Type",
    "Manufacturer / Model",
    "Network Segment",
    "OS/Firmware",
    "Patchable",
    "Vendor Support Status",
    "PHI Handling",
    "FDA Class",
    "Last Vulnerability Scan",
    "Authentication",
    "Encryption",
]


def validate_csv(df: pd.DataFrame) -> list:
    """Return a list of validation error strings. Empty = valid."""
    errors = []
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        errors.append(f"Missing columns: {', '.join(missing)}")

    if df.empty:
        errors.append("CSV contains no data rows.")

    # Check for valid values in key columns
    if "Device Type" in df.columns:
        invalid_types = set(df["Device Type"].dropna()) - set(DEVICE_TYPES)
        if invalid_types:
            errors.append(
                f"Invalid Device Type(s): {', '.join(invalid_types)}. "
                f"Valid options: {', '.join(DEVICE_TYPES)}"
            )

    if "Network Segment" in df.columns:
        invalid_nets = set(df["Network Segment"].dropna()) - set(NETWORK_SEGMENTS)
        if invalid_nets:
            errors.append(
                f"Invalid Network Segment(s): {', '.join(invalid_nets)}. "
                f"Valid options: {', '.join(NETWORK_SEGMENTS)}"
            )

    return errors

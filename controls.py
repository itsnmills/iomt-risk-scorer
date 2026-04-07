"""
IoMT Recommended Controls Engine
=================================
Maps device risk factors to specific, actionable security controls
with NIST CSF 2.0 and HIPAA Security Rule citations.

Author: Noah Mills
"""

from typing import List, Dict


# ── Control Definitions ─────────────────────────────────────────────

def _ctrl(
    title: str,
    description: str,
    priority: str,
    nist_csf: str,
    hipaa: str,
    category: str,
) -> Dict:
    return {
        "title": title,
        "description": description,
        "priority": priority,  # Critical, High, Medium, Low
        "nist_csf": nist_csf,
        "hipaa": hipaa,
        "category": category,
    }


# ── Network Controls ───────────────────────────────────────────────

NETWORK_CONTROLS = {
    "Internet-Facing": [
        _ctrl(
            "Immediately migrate to Clinical VLAN",
            "Internet-facing medical devices represent an unacceptable risk posture. "
            "Move this device behind a firewall with explicit allow-list rules. "
            "If internet connectivity is required for vendor telemetry, route through a DMZ proxy.",
            "Critical",
            "NIST CSF PR.AC-5 (Network integrity)",
            "§164.312(e)(1) — Transmission security",
            "Network Isolation",
        ),
        _ctrl(
            "Deploy network IDS/IPS monitoring",
            "Place a network intrusion detection sensor on the segment to detect anomalous traffic "
            "patterns, including unexpected outbound connections and lateral movement attempts.",
            "Critical",
            "NIST CSF DE.CM-1 (Network monitoring)",
            "§164.312(b) — Audit controls",
            "Monitoring",
        ),
    ],
    "Guest WiFi": [
        _ctrl(
            "Relocate to dedicated Clinical VLAN",
            "Medical devices must not share network segments with untrusted guest traffic. "
            "Configure 802.1X port-based authentication and segment to a clinical network.",
            "Critical",
            "NIST CSF PR.AC-5 (Network integrity)",
            "§164.312(e)(1) — Transmission security",
            "Network Isolation",
        ),
    ],
    "Flat Network": [
        _ctrl(
            "Implement network micro-segmentation",
            "Deploy VLANs or software-defined networking to isolate medical devices from "
            "general IT traffic. Create ACLs that limit communication to required clinical systems only.",
            "High",
            "NIST CSF PR.AC-5 (Network integrity)",
            "§164.310(b) — Workstation use",
            "Network Isolation",
        ),
    ],
    "DMZ": [
        _ctrl(
            "Review firewall rules quarterly",
            "Ensure DMZ rules follow least-privilege principles. Only required ports and protocols "
            "should be permitted. Log and review all inbound/outbound connections.",
            "Medium",
            "NIST CSF PR.AC-5 (Network integrity)",
            "§164.312(e)(1) — Transmission security",
            "Network Isolation",
        ),
    ],
    "Clinical VLAN": [
        _ctrl(
            "Maintain VLAN ACL hygiene",
            "Review access control lists quarterly. Ensure only authorized systems can reach this device. "
            "Implement east-west traffic monitoring within the clinical segment.",
            "Low",
            "NIST CSF PR.AC-5 (Network integrity)",
            "§164.312(e)(1) — Transmission security",
            "Network Isolation",
        ),
    ],
    "Air-Gapped": [
        _ctrl(
            "Maintain physical access controls",
            "Ensure physical access to air-gapped devices is restricted to authorized personnel. "
            "Implement USB port controls to prevent unauthorized media insertion.",
            "Low",
            "NIST CSF PR.AC-2 (Physical access)",
            "§164.310(a)(1) — Facility access controls",
            "Physical Security",
        ),
    ],
}


# ── Patching / Vulnerability Controls ──────────────────────────────

PATCH_CONTROLS = {
    "No": [
        _ctrl(
            "Deploy compensating controls for unpatchable device",
            "Since this device cannot be patched, implement: (1) strict network micro-segmentation, "
            "(2) application whitelisting on adjacent systems, (3) enhanced logging and anomaly detection, "
            "(4) virtual patching via IPS signatures where available. Document the compensating "
            "controls as part of the risk acceptance decision.",
            "Critical",
            "NIST CSF PR.IP-12 (Vulnerability management)",
            "§164.308(a)(1)(ii)(B) — Risk management",
            "Compensating Controls",
        ),
        _ctrl(
            "Establish vendor replacement timeline",
            "Engage procurement to plan for device replacement. Document the total cost of "
            "compensating controls vs. replacement to support business case.",
            "High",
            "NIST CSF ID.AM-2 (Asset management)",
            "§164.308(a)(1)(ii)(A) — Risk analysis",
            "Vendor Engagement",
        ),
    ],
    "Vendor-Only": [
        _ctrl(
            "Establish patch SLA with vendor",
            "Negotiate a contractual SLA for critical vulnerability patches (target: 30 days for "
            "critical, 90 days for high). Include right-to-audit clause for vendor patch processes.",
            "High",
            "NIST CSF PR.IP-12 (Vulnerability management)",
            "§164.308(b)(1) — Business associate contracts",
            "Vendor Engagement",
        ),
        _ctrl(
            "Schedule maintenance window for vendor patches",
            "Coordinate with clinical engineering and department heads to establish recurring "
            "maintenance windows. For critical care devices, patch during low-census periods "
            "with redundant device coverage.",
            "High",
            "NIST CSF PR.MA-1 (Maintenance)",
            "§164.310(a)(2)(iv) — Maintenance records",
            "Patching",
        ),
    ],
    "Yes": [
        _ctrl(
            "Implement regular patch cycle",
            "Enroll this device in the standard patch management program. Target: monthly patches "
            "for non-critical devices, weekly for internet-facing or PHI-handling devices.",
            "Medium",
            "NIST CSF PR.IP-12 (Vulnerability management)",
            "§164.308(a)(5)(ii)(B) — Protection from malicious software",
            "Patching",
        ),
    ],
}


# ── Vendor Support Controls ────────────────────────────────────────

VENDOR_SUPPORT_CONTROLS = {
    "End of Life": [
        _ctrl(
            "Initiate device replacement planning",
            "This device is end-of-life and will receive no further security updates. "
            "Begin procurement process for a supported replacement. In the interim, "
            "apply maximum compensating controls: network isolation, enhanced monitoring, "
            "and disable all unnecessary services.",
            "Critical",
            "NIST CSF ID.AM-2 (Asset management)",
            "§164.308(a)(1)(ii)(B) — Risk management",
            "Vendor Engagement",
        ),
        _ctrl(
            "Document risk acceptance",
            "If immediate replacement is not feasible, the CISO or designated authority must "
            "formally accept the residual risk. Document compensating controls, monitoring "
            "frequency, and reassessment timeline (recommend quarterly).",
            "Critical",
            "NIST CSF ID.RM-1 (Risk management strategy)",
            "§164.308(a)(1)(ii)(A) — Risk analysis",
            "Governance",
        ),
    ],
    "Limited": [
        _ctrl(
            "Negotiate extended support agreement",
            "Contact the vendor to explore extended support options. If unavailable, "
            "evaluate third-party support and virtual patching solutions.",
            "High",
            "NIST CSF PR.MA-1 (Maintenance)",
            "§164.308(b)(1) — Business associate contracts",
            "Vendor Engagement",
        ),
    ],
    "Unknown": [
        _ctrl(
            "Determine vendor support status",
            "Contact the manufacturer to confirm current support status, patch availability, "
            "and end-of-life timeline. Update asset inventory with findings.",
            "High",
            "NIST CSF ID.AM-2 (Asset management)",
            "§164.308(a)(1)(ii)(A) — Risk analysis",
            "Vendor Engagement",
        ),
    ],
}


# ── Authentication Controls ────────────────────────────────────────

AUTH_CONTROLS = {
    "None": [
        _ctrl(
            "Implement device authentication immediately",
            "Devices with no authentication are trivially exploitable. At minimum, enable "
            "local authentication with strong passwords. Prefer AD/LDAP integration where the "
            "device supports it. If the device cannot support authentication, isolate it on a "
            "dedicated micro-segment with strict access controls at the network layer.",
            "Critical",
            "NIST CSF PR.AC-1 (Identity and credential management)",
            "§164.312(d) — Person or entity authentication",
            "Authentication",
        ),
    ],
    "Default Creds": [
        _ctrl(
            "Change default credentials immediately",
            "Default credentials are publicly documented and actively exploited. Change all "
            "default usernames and passwords. Implement a credential rotation policy. "
            "Scan for default credentials quarterly.",
            "Critical",
            "NIST CSF PR.AC-1 (Identity and credential management)",
            "§164.312(d) — Person or entity authentication",
            "Authentication",
        ),
    ],
    "Local Auth": [
        _ctrl(
            "Upgrade to centralized authentication",
            "Migrate from local accounts to AD/LDAP integration for centralized credential "
            "management, audit logging, and account lifecycle control. Implement password "
            "complexity requirements per NIST SP 800-63B.",
            "Medium",
            "NIST CSF PR.AC-1 (Identity and credential management)",
            "§164.312(d) — Person or entity authentication",
            "Authentication",
        ),
    ],
    "AD/LDAP": [
        _ctrl(
            "Consider MFA for high-risk devices",
            "For devices handling PHI or in critical care settings, evaluate multi-factor "
            "authentication options (smart card, biometric, or push notification).",
            "Low",
            "NIST CSF PR.AC-7 (Authentication)",
            "§164.312(d) — Person or entity authentication",
            "Authentication",
        ),
    ],
}


# ── Encryption Controls ────────────────────────────────────────────

ENCRYPTION_CONTROLS = {
    "None": [
        _ctrl(
            "Enable encryption for data in transit",
            "Implement TLS 1.2+ for all network communications. If the device cannot support "
            "TLS natively, deploy a TLS-terminating proxy. Prioritize encryption for any "
            "data flows containing PHI.",
            "Critical",
            "NIST CSF PR.DS-2 (Data-in-transit protection)",
            "§164.312(e)(1) — Transmission security",
            "Encryption",
        ),
        _ctrl(
            "Enable encryption for data at rest",
            "Enable full-disk encryption or database-level encryption for any locally stored PHI. "
            "Use FIPS 140-2 validated cryptographic modules where possible.",
            "High",
            "NIST CSF PR.DS-1 (Data-at-rest protection)",
            "§164.312(a)(2)(iv) — Encryption and decryption",
            "Encryption",
        ),
    ],
    "In-Transit Only": [
        _ctrl(
            "Add encryption at rest",
            "Data at rest on this device is unprotected. Enable storage encryption to protect "
            "against physical theft or unauthorized access to storage media.",
            "Medium",
            "NIST CSF PR.DS-1 (Data-at-rest protection)",
            "§164.312(a)(2)(iv) — Encryption and decryption",
            "Encryption",
        ),
    ],
    "At-Rest Only": [
        _ctrl(
            "Add encryption in transit",
            "Data transmitted from this device is unencrypted. Implement TLS 1.2+ for all "
            "network communications. This is especially critical if the device transmits PHI.",
            "High",
            "NIST CSF PR.DS-2 (Data-in-transit protection)",
            "§164.312(e)(1) — Transmission security",
            "Encryption",
        ),
    ],
    "Unknown": [
        _ctrl(
            "Assess encryption capabilities",
            "Determine what encryption the device supports. Perform a packet capture to verify "
            "whether data in transit is encrypted. Check device storage for encryption status.",
            "High",
            "NIST CSF PR.DS-2 (Data-in-transit protection)",
            "§164.312(e)(1) — Transmission security",
            "Encryption",
        ),
    ],
}


# ── PHI-Specific Controls ──────────────────────────────────────────

PHI_CONTROLS = {
    "Transmit": [
        _ctrl(
            "Implement PHI transmission safeguards",
            "Ensure all PHI transmissions use end-to-end encryption (TLS 1.2+). "
            "Implement data loss prevention (DLP) monitoring on the network segment. "
            "Log all PHI access and transmission events with immutable audit trails.",
            "Critical",
            "NIST CSF PR.DS-2 (Data-in-transit protection)",
            "§164.312(e)(2)(ii) — Encryption of ePHI",
            "Data Protection",
        ),
        _ctrl(
            "Conduct PHI flow mapping",
            "Document all systems this device sends PHI to. Verify each receiving system "
            "meets HIPAA requirements. Establish data processing agreements where needed.",
            "High",
            "NIST CSF ID.AM-3 (Data flows mapped)",
            "§164.308(a)(1)(ii)(A) — Risk analysis",
            "Data Protection",
        ),
    ],
    "Read-Write": [
        _ctrl(
            "Implement access controls and audit logging",
            "Enable role-based access controls for PHI read-write operations. "
            "Implement comprehensive audit logging that captures who accessed what PHI and when. "
            "Review audit logs at least monthly.",
            "High",
            "NIST CSF PR.AC-4 (Access permissions managed)",
            "§164.312(b) — Audit controls",
            "Data Protection",
        ),
    ],
    "Read-Only": [
        _ctrl(
            "Monitor PHI access patterns",
            "Implement monitoring for anomalous PHI access patterns (unusual hours, "
            "bulk queries, access from unexpected locations). Alert on deviations.",
            "Medium",
            "NIST CSF DE.AE-1 (Baseline of operations established)",
            "§164.312(b) — Audit controls",
            "Monitoring",
        ),
    ],
}


# ── Scan-Related Controls ──────────────────────────────────────────

def _get_scan_controls(last_scan: str) -> List[Dict]:
    """Generate controls based on vulnerability scan recency."""
    from datetime import datetime
    import pandas as pd

    controls = []
    if not last_scan or str(last_scan).strip().lower() in ("", "nan", "nat", "none"):
        controls.append(
            _ctrl(
                "Conduct initial vulnerability scan",
                "This device has never been scanned for vulnerabilities. Schedule an "
                "authenticated vulnerability scan using a medical-device-aware scanner "
                "(e.g., Medigate, Claroty, or Tenable.ot). Coordinate with clinical "
                "engineering to avoid disrupting patient care.",
                "Critical",
                "NIST CSF DE.CM-8 (Vulnerability scans performed)",
                "§164.308(a)(8) — Evaluation",
                "Vulnerability Management",
            )
        )
    else:
        try:
            scan_date = pd.to_datetime(last_scan)
            days_since = (datetime.now() - scan_date).days
            if days_since > 365:
                controls.append(
                    _ctrl(
                        "Overdue vulnerability scan — schedule immediately",
                        f"Last scan was {days_since} days ago. Per best practice, medical devices "
                        f"should be scanned at least quarterly. Schedule an authenticated scan "
                        f"within the next maintenance window.",
                        "High",
                        "NIST CSF DE.CM-8 (Vulnerability scans performed)",
                        "§164.308(a)(8) — Evaluation",
                        "Vulnerability Management",
                    )
                )
            elif days_since > 90:
                controls.append(
                    _ctrl(
                        "Schedule quarterly vulnerability scan",
                        f"Last scan was {days_since} days ago. Establish a recurring quarterly "
                        f"scan schedule to maintain visibility into the vulnerability landscape.",
                        "Medium",
                        "NIST CSF DE.CM-8 (Vulnerability scans performed)",
                        "§164.308(a)(8) — Evaluation",
                        "Vulnerability Management",
                    )
                )
        except (ValueError, TypeError):
            controls.append(
                _ctrl(
                    "Verify scan history and schedule scan",
                    "The last vulnerability scan date could not be parsed. Verify scan records "
                    "and schedule an authenticated vulnerability scan.",
                    "High",
                    "NIST CSF DE.CM-8 (Vulnerability scans performed)",
                    "§164.308(a)(8) — Evaluation",
                    "Vulnerability Management",
                )
            )
    return controls


# ── Master Recommendation Engine ────────────────────────────────────

def get_recommendations(device: dict) -> List[Dict]:
    """
    Generate all applicable security recommendations for a device
    based on its risk factors.

    Returns a list of control dicts sorted by priority (Critical first).
    """
    recs = []

    # Network controls
    net_seg = device.get("Network Segment", "")
    recs.extend(NETWORK_CONTROLS.get(net_seg, []))

    # Patching controls
    patchable = device.get("Patchable", "")
    recs.extend(PATCH_CONTROLS.get(patchable, []))

    # Vendor support controls
    vendor = device.get("Vendor Support Status", "")
    recs.extend(VENDOR_SUPPORT_CONTROLS.get(vendor, []))

    # Auth controls
    auth = device.get("Authentication", "")
    recs.extend(AUTH_CONTROLS.get(auth, []))

    # Encryption controls
    enc = device.get("Encryption", "")
    recs.extend(ENCRYPTION_CONTROLS.get(enc, []))

    # PHI controls
    phi = device.get("PHI Handling", "")
    recs.extend(PHI_CONTROLS.get(phi, []))

    # Scan controls
    recs.extend(_get_scan_controls(device.get("Last Vulnerability Scan", "")))

    # Sort by priority
    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    recs.sort(key=lambda c: priority_order.get(c["priority"], 4))

    return recs


def get_priority_color(priority: str) -> str:
    """Return hex color for a control priority level."""
    return {
        "Critical": "#FF4B4B",
        "High": "#FF8C00",
        "Medium": "#FFD700",
        "Low": "#20808D",
    }.get(priority, "#888888")

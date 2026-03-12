"""
constants.py
Katalog rule Wazuh dan konstanta yang dipakai seluruh skenario.
Struktur rule mengikuti rule ID nyata Wazuh untuk realisme simulasi.
"""

# WAZUH RULE CATALOG
# Format: rule_id -> {description, severity, category, event_type}
# Severity scale: 1-15 (Wazuh standard)
#   1-3  : informational
#   4-6  : low
#   7-10 : medium
#   11-13: high
#   14-15: critical

RULES = {
    # --- AUTH ---
    "5501": {
        "description": "User login success",
        "severity": 3,
        "category": "auth",
        "event_type": "alert",
    },
    "5502": {
        "description": "User login failed",
        "severity": 5,
        "category": "auth",
        "event_type": "alert",
    },
    "5503": {
        "description": "Multiple authentication failures",
        "severity": 10,
        "category": "auth",
        "event_type": "alert",
    },
    "5551": {
        "description": "Brute force attack detected",
        "severity": 13,
        "category": "auth",
        "event_type": "alert",
    },
    "5552": {
        "description": "Account locked after repeated failures",
        "severity": 11,
        "category": "auth",
        "event_type": "alert",
    },
    "5710": {
        "description": "Attempt to login using non-existent user",
        "severity": 8,
        "category": "auth",
        "event_type": "alert",
    },

    # --- MALWARE ---
    "100200": {
        "description": "Malware detected by antivirus",
        "severity": 14,
        "category": "malware",
        "event_type": "alert",
    },
    "100201": {
        "description": "Suspicious process execution",
        "severity": 12,
        "category": "malware",
        "event_type": "alert",
    },
    "100202": {
        "description": "Ransomware behavior detected",
        "severity": 15,
        "category": "malware",
        "event_type": "alert",
    },
    "100203": {
        "description": "Trojan activity detected",
        "severity": 14,
        "category": "malware",
        "event_type": "alert",
    },

    # --- INTEGRITY ---
    "550": {
        "description": "Integrity checksum changed",
        "severity": 7,
        "category": "integrity",
        "event_type": "alert",
    },
    "551": {
        "description": "File deleted",
        "severity": 6,
        "category": "integrity",
        "event_type": "alert",
    },
    "554": {
        "description": "File added to monitored directory",
        "severity": 5,
        "category": "integrity",
        "event_type": "alert",
    },
    "591": {
        "description": "Rootkit detected by OS scan",
        "severity": 15,
        "category": "integrity",
        "event_type": "alert",
    },

    # --- NETWORK ---
    "40111": {
        "description": "Firewall blocked inbound connection",
        "severity": 4,
        "category": "network",
        "event_type": "alert",
    },
    "40112": {
        "description": "Port scan detected",
        "severity": 9,
        "category": "network",
        "event_type": "alert",
    },
    "40113": {
        "description": "Suspicious outbound traffic",
        "severity": 11,
        "category": "network",
        "event_type": "alert",
    },
    "40114": {
        "description": "DNS tunneling detected",
        "severity": 13,
        "category": "network",
        "event_type": "alert",
    },

    # --- VULNERABILITY (event_type: vuln) ---
    # Wazuh dan Data Contract bank (auth|malware|integrity|network).
    "VULN-001": {
        "description": "Critical CVE detected on asset",
        "severity": 15,
        "category": "network",
        "event_type": "vuln",
    },
    "VULN-002": {
        "description": "High severity CVE detected on asset",
        "severity": 12,
        "category": "network",
        "event_type": "vuln",
    },
    "VULN-003": {
        "description": "Medium severity CVE detected on asset",
        "severity": 8,
        "category": "network",
        "event_type": "vuln",
    },
    "VULN-004": {
        "description": "Low severity CVE detected on asset",
        "severity": 4,
        "category": "network",
        "event_type": "vuln",
    },
}

# CVE CATALOG (simulasi — tidak menggunakan data NVD nyata)
CVE_CATALOG = [
    {"cve_id": "CVE-2024-1234", "cvss_score": 9.8, "product": "OpenSSL"},
    {"cve_id": "CVE-2024-5678", "cvss_score": 9.1, "product": "Apache HTTP"},
    {"cve_id": "CVE-2024-9012", "cvss_score": 8.5, "product": "Linux Kernel"},
    {"cve_id": "CVE-2024-3456", "cvss_score": 7.8, "product": "PostgreSQL"},
    {"cve_id": "CVE-2024-7890", "cvss_score": 7.2, "product": "OpenSSH"},
    {"cve_id": "CVE-2024-2345", "cvss_score": 6.5, "product": "nginx"},
    {"cve_id": "CVE-2024-6789", "cvss_score": 5.9, "product": "curl"},
    {"cve_id": "CVE-2024-4567", "cvss_score": 4.3, "product": "Python stdlib"},
    {"cve_id": "CVE-2023-9999", "cvss_score": 9.9, "product": "Log4j fork"},
    {"cve_id": "CVE-2023-8888", "cvss_score": 8.8, "product": "Java Runtime"},
]

# SCENARIO LABELS
SCENARIO_NORMAL   = "normal"
SCENARIO_SPIKE    = "spike"
SCENARIO_VULN     = "vuln_cluster"
SCENARIO_DECAY    = "remediation_decay"

# DATA CONTRACT — nilai yang diizinkan (digunakan generator & unit test)
VALID_CATEGORIES: frozenset[str] = frozenset({"auth", "malware", "integrity", "network"})
VALID_EVENT_TYPES: frozenset[str] = frozenset({"alert", "vuln", "control"})
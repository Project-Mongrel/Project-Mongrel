UNKNOWN_DESCRIPTION = "Description unavailable."
UNKNOWN_RECOMMENDATION = "Manual review recommended."

_SERVICE_INTELLIGENCE_BY_PORT: dict[str, dict[str, str]] = {
    "22": {
        "name": "SSH",
        "description": "Secure Shell remote administration service.",
        "common_risk": "Credential attacks and unauthorized remote access if exposed or weakly configured.",
        "recommendation": "Restrict access to trusted networks, disable password login where possible, and require key-based authentication.",
    },
    "445": {
        "name": "SMB",
        "description": "Windows file sharing and remote administration service.",
        "common_risk": "File exposure, lateral movement, and exploitation of vulnerable SMB services.",
        "recommendation": "Block internet exposure, restrict share permissions, and keep systems patched.",
    },
    "139": {
        "name": "NetBIOS",
        "description": "Legacy Windows networking service often associated with file and printer sharing.",
        "common_risk": "Host and share enumeration on legacy Windows networks.",
        "recommendation": "Disable if not required and restrict access to trusted internal networks.",
    },
    "80": {
        "name": "HTTP",
        "description": "Unencrypted web service.",
        "common_risk": "Cleartext traffic and web application vulnerabilities.",
        "recommendation": "Redirect to HTTPS and review exposed web application functionality.",
    },
    "443": {
        "name": "HTTPS",
        "description": "Encrypted web service.",
        "common_risk": "Web application vulnerabilities or weak TLS configuration.",
        "recommendation": "Keep the application patched and validate TLS configuration.",
    },
    "3389": {
        "name": "RDP",
        "description": "Remote Desktop Protocol service.",
        "common_risk": "Remote login exposure and brute-force attacks.",
        "recommendation": "Do not expose directly to the internet; require VPN, MFA, and account lockout controls.",
    },
    "53": {
        "name": "DNS",
        "description": "Domain name resolution service.",
        "common_risk": "Zone transfer exposure, amplification abuse, or unintended public resolver behavior.",
        "recommendation": "Restrict recursion, disable unauthorized zone transfers, and monitor query patterns.",
    },
    "3306": {
        "name": "MySQL",
        "description": "MySQL database service.",
        "common_risk": "Database exposure, credential attacks, and data leakage.",
        "recommendation": "Bind to private interfaces, require strong authentication, and restrict network access.",
    },
    "5432": {
        "name": "PostgreSQL",
        "description": "PostgreSQL database service.",
        "common_risk": "Database exposure, credential attacks, and data leakage.",
        "recommendation": "Bind to private interfaces, enforce strong authentication, and restrict access by source.",
    },
    "1433": {
        "name": "MSSQL",
        "description": "Microsoft SQL Server database service.",
        "common_risk": "Database exposure, credential attacks, and data leakage.",
        "recommendation": "Restrict network access, disable unnecessary features, and monitor authentication failures.",
    },
    "27017": {
        "name": "MongoDB",
        "description": "MongoDB database service.",
        "common_risk": "Unauthenticated or exposed database access can lead to data theft.",
        "recommendation": "Require authentication, bind to private interfaces, and restrict access by source.",
    },
    "6379": {
        "name": "Redis",
        "description": "Redis in-memory data store service.",
        "common_risk": "Unauthenticated access can expose data or enable command abuse.",
        "recommendation": "Bind to private interfaces, require authentication, and block untrusted network access.",
    },
}

_SERVICE_ALIASES: dict[str, str] = {
    "ssh": "22",
    "microsoft-ds": "445",
    "smb": "445",
    "netbios-ssn": "139",
    "netbios": "139",
    "http": "80",
    "https": "443",
    "ms-wbt-server": "3389",
    "rdp": "3389",
    "domain": "53",
    "dns": "53",
    "mysql": "3306",
    "postgresql": "5432",
    "ms-sql-s": "1433",
    "mssql": "1433",
    "mongodb": "27017",
    "redis": "6379",
}


def get_service_intelligence(service_name: str, port: str) -> dict:
    normalized_port = str(port).strip()
    normalized_service_name = service_name.strip().lower()
    lookup_port = normalized_port or _SERVICE_ALIASES.get(normalized_service_name, "")
    intelligence = _SERVICE_INTELLIGENCE_BY_PORT.get(lookup_port)

    if intelligence is None and normalized_service_name:
        intelligence = _SERVICE_INTELLIGENCE_BY_PORT.get(_SERVICE_ALIASES.get(normalized_service_name, ""))

    if intelligence is None:
        return {
            "name": service_name or f"Port {port}",
            "description": UNKNOWN_DESCRIPTION,
            "common_risk": UNKNOWN_DESCRIPTION,
            "recommendation": UNKNOWN_RECOMMENDATION,
        }

    return dict(intelligence)

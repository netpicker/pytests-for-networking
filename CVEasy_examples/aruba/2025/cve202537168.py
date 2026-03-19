from comfy import high


@high(
    name='rule_cve202537168',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_mgmt_services='show configuration | include "web-server|https-server|http-server|mgmt|management|allow-management|ip access-list|acl|firewall|service"',
    ),
)
def rule_cve202537168(configuration, commands, device, devices):
    """
    CVE-2025-37168: Unauthenticated arbitrary file deletion in a system function of
    Mobility Conductors running ArubaOS AOS-8.

    Advisory: HPESBNW04987 rev.2 - Multiple Vulnerabilities in HPE Aruba Networking AOS-8 and AOS-10
    for Mobility Conductors, Controllers, and Gateways.

    This rule is a configuration-based exposure check:
      - Vulnerable software: AOS-8.13.x.x <= 8.13.1.0, AOS-8.10.x.x <= 8.10.0.20
        (and other AOS-8 branches listed as affected/EoM in the advisory; not fixed).
      - Vulnerable exposure: management interfaces (web/https/http) reachable (not restricted).
      - Safer configuration: management interfaces restricted to a dedicated VLAN/segment and/or
        controlled by firewall/ACL policies (per vendor workaround guidance).
    """
    version_output = commands.show_version or ""
    cfg_output = commands.show_mgmt_services or ""

    # Helper: extract a likely ArubaOS version token from "show version" output
    def _extract_version(text: str):
        import re

        # Common patterns:
        # "ArubaOS version 8.10.0.20"
        # "ArubaOS 8.13.1.0"
        m = re.search(r'\bArubaOS(?:\s+version)?\s+(\d+\.\d+\.\d+\.\d+)\b', text, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r'\b(\d+\.\d+\.\d+\.\d+)\b', text)
        return m.group(1) if m else None

    def _ver_tuple(v: str):
        return tuple(int(x) for x in v.split("."))

    v = _extract_version(version_output)

    # If we cannot determine version, do not fail (avoid false positives).
    if not v:
        return

    # Only AOS-8 is in scope for CVE-2025-37168 per advisory details.
    if not v.startswith("8."):
        return

    vt = _ver_tuple(v)

    # Vulnerable fixed thresholds from advisory:
    # - AOS-8.13.x.x: 8.13.1.0 and below (fixed in 8.13.1.1+)
    # - AOS-8.10.x.x: 8.10.0.20 and below (fixed in 8.10.0.21+)
    # Additionally, advisory states multiple EoM AOS-8 branches are affected and not addressed.
    # We conservatively treat 8.12.x, 8.11.x, 8.9.x, 8.8.x, 8.7.x, 8.6.x, 6.5.4.x as vulnerable.
    vulnerable = False
    if v.startswith("8.13."):
        vulnerable = vt <= _ver_tuple("8.13.1.0")
    elif v.startswith("8.10."):
        vulnerable = vt <= _ver_tuple("8.10.0.20")
    elif v.startswith(("8.12.", "8.11.", "8.9.", "8.8.", "8.7.", "8.6.")):
        vulnerable = True
    elif v.startswith("6.5.4."):
        vulnerable = True

    if not vulnerable:
        return

    # Exposure check: management interfaces should be restricted.
    # We look for evidence of restriction controls in config output (ACL/firewall/allow-management).
    # If we see explicit restriction keywords, treat as mitigated.
    restriction_indicators = [
        "allow-management",
        "management-acl",
        "mgmt-acl",
        "ip access-list",
        "access-list",
        "acl",
        "firewall",
        "policy",
        "restrict",
        "trusted",
        "permit",
        "deny",
        "whitelist",
        "blacklist",
        "control-plane",
    ]
    has_restrictions = any(tok.lower() in cfg_output.lower() for tok in restriction_indicators)

    # Also detect if web management appears enabled (common strings).
    web_enabled_indicators = [
        "web-server",
        "https-server",
        "http-server",
        "webui",
        "web ui",
        "mgmt",
        "management",
    ]
    web_maybe_enabled = any(tok.lower() in cfg_output.lower() for tok in web_enabled_indicators)

    # If we cannot see any management service lines, assume unknown; do not fail.
    if not cfg_output.strip():
        return

    # Vulnerable scenario: vulnerable version AND management appears enabled/exposed AND no restrictions found.
    is_exposed = web_maybe_enabled and not has_restrictions

    assert not is_exposed, (
        f"Device {device.name} is vulnerable to CVE-2025-37168 (Unauthenticated Arbitrary File Deletion) "
        f"because it is running ArubaOS AOS-8 version {v} (affected per HPESBNW04987 rev.2) and the "
        f"management interfaces appear enabled without evidence of restriction (no ACL/firewall/allow-management "
        f"controls detected). Successful exploitation could allow an unauthenticated remote actor to delete "
        f"arbitrary files and potentially cause denial-of-service. "
        f"Advisory: https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-hpesbnw04987en_us"
    )
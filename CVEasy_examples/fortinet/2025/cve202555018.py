from comfy import high


@high(
    name="rule_cve202555018",
    platform=["fortinet"],
    commands=dict(
        show_version="get system status",
        show_global="show system global",
        show_admin_settings="show system admin",
    ),
)
def rule_cve202555018(configuration, commands, device, devices):
    """
    CVE-2025-55018 (Fortinet FortiOS) - HTTP request smuggling in FortiOS GUI (CWE-444).

    Summary (per Fortinet PSIRT FG-IR-25-667):
      An inconsistent interpretation of HTTP requests may allow an unauthenticated attacker
      to smuggle an unlogged HTTP request through firewall policies via a specially crafted header.

    Affected versions:
      - FortiOS 7.6: 7.6.0
      - FortiOS 7.4: 7.4.0 through 7.4.9
      - FortiOS 7.2: all versions
      - FortiOS 7.0: all versions
      - FortiOS 6.4: 6.4.3 through 6.4.16

    Fixed versions:
      - FortiOS 7.6: 7.6.1+
      - FortiOS 7.4: 7.4.10+
      - FortiOS 7.2/7.0/6.4: migrate to a fixed release (per advisory)

    Vulnerable configuration heuristic (best-effort, config-based):
      - Device runs an affected FortiOS version, AND
      - HTTPS admin GUI is enabled (admin access includes https), AND
      - Admin GUI is reachable on at least one interface (at least one admin has a non-empty 'set trusthost*').

    Non-vulnerable scenarios:
      - FortiOS version is not affected, OR
      - Admin GUI is not enabled for HTTPS, OR
      - Admin GUI is restricted (no trusthosts configured for any admin) (heuristic).

    Advisory: https://fortiguard.com/psirt/FG-IR-25-667
    """
    version_output = (commands.show_version or "").lower()
    global_output = (commands.show_global or "").lower()
    admins_output = (commands.show_admin_settings or "").lower()

    def parse_version(text: str):
        # Try to extract "Version: X.Y.Z" first, then fallback to "FortiOS vX.Y.Z"
        import re

        m = re.search(r"version:\s*([0-9]+)\.([0-9]+)\.([0-9]+)", text, re.IGNORECASE)
        if not m:
            m = re.search(r"fortios\s+v([0-9]+)\.([0-9]+)\.([0-9]+)", text, re.IGNORECASE)
        if not m:
            return None
        return tuple(int(x) for x in m.groups())

    def in_range(v, lo, hi):
        return v is not None and lo <= v <= hi

    v = parse_version(commands.show_version or "")

    # Version vulnerability per advisory.
    version_vulnerable = False
    if v is not None:
        # 7.6.0
        if v == (7, 6, 0):
            version_vulnerable = True
        # 7.4.0 - 7.4.9
        elif in_range(v, (7, 4, 0), (7, 4, 9)):
            version_vulnerable = True
        # 7.2 all versions (treat any 7.2.x as affected)
        elif v[0:2] == (7, 2):
            version_vulnerable = True
        # 7.0 all versions
        elif v[0:2] == (7, 0):
            version_vulnerable = True
        # 6.4.3 - 6.4.16
        elif in_range(v, (6, 4, 3), (6, 4, 16)):
            version_vulnerable = True

    # Configuration heuristics:
    # 1) Admin GUI enabled for HTTPS (admin-sport present and/or admin-https-ssl-versions present is not reliable;
    #    best is to check "set admin-https-ssl-versions" or "set admin-sport" and "set admin-https-redirect" etc.
    #    We'll use presence of "set admin-sport" or "set admin-https-ssl-versions" as a proxy that HTTPS admin is enabled.
    https_admin_enabled = ("set admin-sport" in global_output) or ("set admin-https-ssl-versions" in global_output)

    # 2) GUI reachable: any admin has trusthost configured (heuristic for exposure).
    #    If no trusthost lines exist at all, we treat as "restricted/unknown"; for this test we consider it safer.
    any_trusthost_configured = "set trusthost" in admins_output

    config_vulnerable = https_admin_enabled and any_trusthost_configured

    is_vulnerable = version_vulnerable and config_vulnerable

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-55018 (Fortinet FortiOS): "
        "an unauthenticated attacker may perform HTTP request smuggling against the FortiOS GUI, potentially smuggling an unlogged HTTP request "
        "through firewall policies via a specially crafted header. "
        "Detected an affected FortiOS version (7.6.0, 7.4.0-7.4.9, 7.2.x, 7.0.x, or 6.4.3-6.4.16) and a likely exposed HTTPS admin GUI "
        "(admin HTTPS settings found in 'show system global' and at least one admin trusthost configured in 'show system admin'). "
        "Remediation: upgrade to FortiOS 7.6.1+ or 7.4.10+; for 7.2/7.0/6.4 migrate to a fixed release per Fortinet guidance, and restrict/disable GUI exposure. "
        "Advisory: https://fortiguard.com/psirt/FG-IR-25-667"
    )
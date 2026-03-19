from comfy import high


@high(
    name="rule_cve202537170",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_webmgmt="show configuration | include web-server",
        show_mgmt_acl="show configuration | include mgmt-user|mgmt-allowlist|mgmt-acl|ip access-list|access-list",
    ),
)
def rule_cve202537170(configuration, commands, device, devices):
    """
    CVE-2025-37170: Authenticated command injection in the web-based management interface
    of Mobility Conductors running AOS-8.

    This rule is a configuration-based exposure check:
      - Vulnerable software: AOS-8.13.1.0 and below, AOS-8.10.0.20 and below (and EoM AOS-8 branches).
      - Vulnerable condition: Web-based management interface enabled/reachable (no restrictive mgmt ACL/allowlist detected).
      - Non-vulnerable: Patched AOS-8 (8.13.1.1+ or 8.10.0.21+), or web UI disabled, or management access restricted.
    """
    version_output = (commands.show_version or "").strip()

    def _parse_aos_version(text: str):
        """
        Extract first occurrence of a dotted version like 8.13.1.0 or 10.4.1.9.
        Returns tuple(int,int,int,int) or None.
        """
        import re

        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)\.(\d+)\b", text)
        if not m:
            return None
        return tuple(int(x) for x in m.groups())

    v = _parse_aos_version(version_output)
    if not v:
        # If we cannot determine version, do not assert vulnerability.
        return

    major, minor, patch, build = v

    # Only AOS-8 is impacted for CVE-2025-37170 per advisory.
    if major != 8:
        return

    # Determine vulnerable versions from advisory:
    # - AOS-8.13.x.x: 8.13.1.0 and below (fixed in 8.13.1.1+)
    # - AOS-8.10.x.x: 8.10.0.20 and below (fixed in 8.10.0.21+)
    # - EoM AOS-8.12/8.11/8.9/8.8/8.7/8.6/6.5.4 are affected (no fix in advisory)
    version_vulnerable = False

    if (major, minor) == (8, 13):
        version_vulnerable = v <= (8, 13, 1, 0)
    elif (major, minor) == (8, 10):
        version_vulnerable = v <= (8, 10, 0, 20)
    elif (major, minor) in {(8, 12), (8, 11), (8, 9), (8, 8), (8, 7), (8, 6)}:
        version_vulnerable = True
    elif major == 6 and minor == 5 and patch == 4:
        version_vulnerable = True

    if not version_vulnerable:
        return

    webmgmt_cfg = (commands.show_webmgmt or "").lower()
    mgmt_acl_cfg = (commands.show_mgmt_acl or "").lower()

    # Heuristic: web UI enabled if web-server is enabled (http/https) and not explicitly disabled.
    web_ui_enabled = False
    if "web-server" in webmgmt_cfg:
        if "disable" in webmgmt_cfg or "shutdown" in webmgmt_cfg:
            web_ui_enabled = False
        else:
            # Common ArubaOS config lines include "web-server enable", "web-server https", etc.
            if "enable" in webmgmt_cfg or "https" in webmgmt_cfg or "http" in webmgmt_cfg:
                web_ui_enabled = True

    # Heuristic: management access restricted if an allowlist/ACL is present.
    # (Advisory recommends restricting management interfaces; we treat presence of mgmt ACL/allowlist as mitigation.)
    mgmt_restricted = any(
        token in mgmt_acl_cfg
        for token in [
            "mgmt-allowlist",
            "mgmt-acl",
            "management-acl",
            "ip access-list",
            "access-list",
            "permit",
            "deny",
        ]
    )

    # Vulnerable exposure: vulnerable version + web UI enabled + no evidence of restriction.
    exposed = web_ui_enabled and not mgmt_restricted

    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-hpesbnw04987en_us"

    assert not exposed, (
        f"Device {device.name} is vulnerable to CVE-2025-37170 (AOS-8 authenticated command injection in the "
        f"web-based management interface). Detected AOS version {major}.{minor}.{patch}.{build} which is within the "
        f"affected range, and the web-based management interface appears enabled without a detected management "
        f"allowlist/ACL restriction. An authenticated attacker could execute arbitrary commands as a privileged user. "
        f"Advisory: {advisory_url}"
    )
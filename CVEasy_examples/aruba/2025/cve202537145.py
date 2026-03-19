from comfy import high


@high(
    name="rule_cve202537145",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show configuration | include (web-server|https|http|mgmt|management|allow-management|ip access-group|acl|netservice|svc|service)",
    ),
)
def rule_cve202537145(configuration, commands, device, devices):
    """
    CVE-2025-37145: Authenticated arbitrary file download in a low-level interface library
    affecting Aruba/HPE AOS-10 Gateways and AOS-8 Controllers/Mobility Conductors.

    Advisory: HPESBNW04957 rev.1 (2025-10-14)
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"

    version_output = (commands.show_version or "").strip()
    cfg_output = (commands.show_mgmt_services or "").lower()

    def parse_aos_version(text: str):
        """
        Extract first occurrence of X.Y.Z.W from 'show version' output.
        Returns tuple(int,int,int,int) or None.
        """
        import re

        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)\.(\d+)\b", text)
        if not m:
            return None
        return tuple(int(x) for x in m.groups())

    def in_range(v, low, high):
        return low <= v <= high

    v = parse_aos_version(version_output)
    if not v:
        # If we cannot determine version, do not assert vulnerability.
        return

    # Vulnerable versions per advisory:
    # AOS-10.7.x.x: 10.7.2.0 and below
    # AOS-10.4.x.x: 10.4.1.8 and below
    # AOS-8.13.x.x: 8.13.0.1 and below
    # AOS-8.12.x.x: 8.12.0.5 and below
    # AOS-8.10.x.x: 8.10.0.18 and below
    # (EoM branches are also affected but not patched; we treat them as vulnerable if detected.)
    vulnerable = False

    # AOS-10.7 branch
    if v[0] == 10 and v[1] == 7:
        vulnerable = v <= (10, 7, 2, 0)

    # AOS-10.4 branch
    elif v[0] == 10 and v[1] == 4:
        vulnerable = v <= (10, 4, 1, 8)

    # AOS-10 EoM branches (all affected)
    elif v[0] == 10 and v[1] in (3, 5, 6):
        vulnerable = True

    # AOS-8.13 branch
    elif v[0] == 8 and v[1] == 13:
        vulnerable = v <= (8, 13, 0, 1)

    # AOS-8.12 branch
    elif v[0] == 8 and v[1] == 12:
        vulnerable = v <= (8, 12, 0, 5)

    # AOS-8.10 branch
    elif v[0] == 8 and v[1] == 10:
        vulnerable = v <= (8, 10, 0, 18)

    # AOS-8 EoM branches (all affected)
    elif v[0] == 8 and v[1] in (6, 7, 8, 9, 11):
        vulnerable = True

    # AOS-6.5.4.x (all affected)
    elif v[0] == 6 and v[1] == 5 and v[2] == 4:
        vulnerable = True

    if not vulnerable:
        return

    # Configuration exposure:
    # Advisory indicates exploitation is via web-based management interface / low-level interface library
    # and recommends restricting CLI and web-based management interfaces to dedicated VLAN/segment and/or
    # controlling by firewall policies/ACLs. We treat "management interface enabled and not obviously restricted"
    # as a vulnerable configuration.
    web_mgmt_enabled = any(
        token in cfg_output
        for token in (
            "web-server",
            "web server",
            "https",
            "http",
            "management",
            "mgmt",
            "allow-management",
        )
    )

    # Heuristic for "restricted": presence of ACL/access-group applied to management plane.
    mgmt_restricted = any(
        token in cfg_output
        for token in (
            "access-group",
            "ip access-group",
            "acl",
            "permit",
            "deny",
            "whitelist",
            "trusted",
            "mgmt-acl",
            "management-acl",
            "firewall",
        )
    )

    config_vulnerable = web_mgmt_enabled and not mgmt_restricted

    assert not config_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-37145 (Aruba/HPE ArubaOS). "
        f"Detected vulnerable ArubaOS version in 'show version' output and management/web interface appears enabled "
        f"without an obvious management-plane restriction (ACL/firewall policy). "
        f"Successful exploitation could allow an authenticated actor to download arbitrary files. "
        f"Advisory: {advisory_url}"
    )
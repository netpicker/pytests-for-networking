from comfy import high


@high(
    name="rule_cve202525040",
    platform=["aruba_aoscx"],
    commands=dict(
        show_version="show version",
        show_running_config="show running-config",
        show_platform="show system | include Product|Platform|Chassis|Model",
    ),
)
def rule_cve202525040(configuration, commands, device, devices):
    """
    CVE-2025-25040: Failure to properly enforce Port ACLs on CPU-generated packets
    on Aruba/HPE CX 9300 Switch Series (AOS-CX).

    Impact: Port ACLs applied to routed ports on egress may be bypassed for traffic
    originated by the switch (CPU-generated). Egress VLAN ACLs and Routed VLAN ACLs
    are not affected.

    Advisory: HPESBNW04818 rev.1
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04818en_us"

    version_output = (commands.show_version or "").lower()
    running_config = (commands.show_running_config or "").lower()
    platform_output = (commands.show_platform or "").lower()

    # Determine if this is a CX 9300 platform (CVE affects CX 9300 only)
    is_cx9300 = any(
        token in platform_output
        for token in [
            "cx 9300",
            "cx9300",
            "9300 switch",
            "aruba 9300",
        ]
    )

    # If we cannot confirm CX 9300 from platform output, fall back to show version text
    if not is_cx9300:
        is_cx9300 = any(
            token in version_output
            for token in [
                "cx 9300",
                "cx9300",
                "9300",
            ]
        )

    if not is_cx9300:
        return

    # Vulnerable versions per advisory:
    # - AOS-CX 10.14.xxxx : all patches (i.e., any 10.14.*)
    # - AOS-CX 10.15.xxxx : 10.15.1000 and below (fixed in 10.15.1005+ per note)
    #
    # We implement:
    #   vulnerable if 10.14.* OR (10.15.* AND build <= 1000)
    # Non-vulnerable if 10.15.1001+ (and especially 10.15.1005+ for CX9300) or other branches.
    def _extract_aoscx_version(text: str):
        # Try to find a token like 10.15.1000, 10.14.1040, etc.
        import re

        m = re.search(r"\b(10)\.(\d{2})\.(\d{3,4})\b", text)
        if not m:
            return None
        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3))
        return major, minor, patch

    ver = _extract_aoscx_version(version_output)
    if not ver:
        return

    major, minor, patch = ver

    version_vulnerable = False
    if major == 10 and minor == 14:
        version_vulnerable = True
    elif major == 10 and minor == 15 and patch <= 1000:
        version_vulnerable = True

    if not version_vulnerable:
        return

    # Vulnerable configuration:
    # The issue is with Port ACLs applied to routed ports on egress.
    # We treat as "vulnerable configuration" when:
    #   - there is at least one L3 interface (routed port) AND
    #   - a port ACL is applied inbound or outbound on an interface (port ACL)
    #
    # Note: VLAN ACLs (egress VLAN ACL / routed VLAN ACL) are not affected; we do not flag those.
    has_routed_port = False
    has_port_acl_on_interface = False

    # Heuristics for routed ports: presence of "interface ...", "no switchport" and "ip address"
    # (common AOS-CX L3 interface config)
    if "no switchport" in running_config and "ip address" in running_config:
        has_routed_port = True

    # Heuristics for port ACL application on interface:
    # AOS-CX commonly uses "apply access-list <name> in|out" under interface.
    # We look for "apply access-list" and direction keywords.
    if "apply access-list" in running_config and (
        " apply access-list " in running_config or "\napply access-list " in running_config
    ):
        # Ensure it's interface-applied (port ACL), not VLAN ACL.
        # VLAN ACLs often appear under "vlan <id>" context; we avoid flagging if only under vlan.
        # We'll flag if we see apply access-list and also see interface contexts.
        if "interface " in running_config:
            has_port_acl_on_interface = True

    config_vulnerable = has_routed_port and has_port_acl_on_interface

    # If vulnerable version but no routed-port port-ACL usage, treat as safe configuration for this CVE test.
    if not config_vulnerable:
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-25040 (HPESBNW04818). "
        f"Detected Aruba/HPE CX 9300 platform running vulnerable AOS-CX version "
        f"{major}.{minor}.{patch} with a Port ACL applied to a routed port interface. "
        "This vulnerability may allow CPU-originated traffic to bypass egress Port ACL enforcement "
        "on routed ports, potentially violating security policy. "
        "Egress VLAN ACLs and Routed VLAN ACLs are not affected. "
        f"Advisory: {advisory_url}"
    )
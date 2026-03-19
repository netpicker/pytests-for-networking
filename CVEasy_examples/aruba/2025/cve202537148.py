from comfy import high


@high(
    name="rule_cve202537148",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_lldp="show configuration | include lldp",
        show_uplink="show configuration | include uplink",
    ),
)
def rule_cve202537148(configuration, commands, device, devices):
    """
    CVE-2025-37148 (HPESBNW04958): Kernel panic triggered by modified Ethernet frames
    leads to unauthenticated adjacent DoS on Aruba APs running AOS-8 Instant / AOS-10 AP.

    This rule is a best-effort configuration-aware check:
      - Version check: determines if the device is in an affected software range.
      - Config check: determines if the device is likely to be exposed to adjacent L2 traffic
        (i.e., has an active Ethernet uplink / bridging features enabled).

    Note: The advisory lists no workaround; patching is the primary remediation.
    """
    advisory_url = "https://networkingsupport.hpe.com/home"

    version_output = commands.show_version or ""

    # Affected versions per HPESBNW04958 rev.1:
    # AOS-10.7.x.x: 10.7.2.0 and below (fixed in 10.7.2.1+)
    # AOS-10.4.x.x: 10.4.1.7 and below (fixed in 10.4.1.9+)
    # AOS-8.13.x.x: 8.13.0.1 and below (fixed in 8.13.1.0+)
    # AOS-8.12.x.x: 8.12.0.5 and below (fixed in 8.12.0.6+)
    # AOS-8.10.x.x: 8.10.0.16 and below (fixed in 8.10.0.19+)
    #
    # EoM branches are affected but not patched (all versions in those branches):
    # AOS-10: 10.6.x.x, 10.5.x.x, 10.3.x.x
    # AOS-8:  8.11.x.x, 8.9.x.x, 8.8.x.x, 8.7.x.x, 8.6.x.x, 8.5.x.x, 8.4.x.x
    # AOS Instant: 6.5.x.x, 6.4.x.x
    vulnerable_markers = [
        # AOS-10 affected branches / thresholds
        "ArubaOS version 10.7.2.0",
        "ArubaOS version 10.7.1.",
        "ArubaOS version 10.7.0.",
        "ArubaOS version 10.4.1.7",
        "ArubaOS version 10.4.1.6",
        "ArubaOS version 10.4.1.5",
        "ArubaOS version 10.4.1.4",
        "ArubaOS version 10.4.1.3",
        "ArubaOS version 10.4.1.2",
        "ArubaOS version 10.4.1.1",
        "ArubaOS version 10.4.1.0",
        "ArubaOS version 10.4.0.",
        # EoM AOS-10 branches (all)
        "ArubaOS version 10.6.",
        "ArubaOS version 10.5.",
        "ArubaOS version 10.3.",
        # AOS-8 affected branches / thresholds
        "ArubaOS version 8.13.0.1",
        "ArubaOS version 8.13.0.0",
        "ArubaOS version 8.12.0.5",
        "ArubaOS version 8.12.0.4",
        "ArubaOS version 8.12.0.3",
        "ArubaOS version 8.12.0.2",
        "ArubaOS version 8.12.0.1",
        "ArubaOS version 8.12.0.0",
        "ArubaOS version 8.10.0.16",
        "ArubaOS version 8.10.0.15",
        "ArubaOS version 8.10.0.14",
        "ArubaOS version 8.10.0.13",
        "ArubaOS version 8.10.0.12",
        "ArubaOS version 8.10.0.11",
        "ArubaOS version 8.10.0.10",
        "ArubaOS version 8.10.0.9",
        "ArubaOS version 8.10.0.8",
        "ArubaOS version 8.10.0.7",
        "ArubaOS version 8.10.0.6",
        "ArubaOS version 8.10.0.5",
        "ArubaOS version 8.10.0.4",
        "ArubaOS version 8.10.0.3",
        "ArubaOS version 8.10.0.2",
        "ArubaOS version 8.10.0.1",
        "ArubaOS version 8.10.0.0",
        # EoM AOS-8 branches (all)
        "ArubaOS version 8.11.",
        "ArubaOS version 8.9.",
        "ArubaOS version 8.8.",
        "ArubaOS version 8.7.",
        "ArubaOS version 8.6.",
        "ArubaOS version 8.5.",
        "ArubaOS version 8.4.",
        # EoM AOS Instant branches (all)
        "ArubaOS version 6.5.",
        "ArubaOS version 6.4.",
    ]

    version_vulnerable = any(m in version_output for m in vulnerable_markers)
    if not version_vulnerable:
        # Not in known affected versions; treat as OK.
        assert True
        return

    # Configuration exposure (best-effort):
    # The attack is adjacent (AV:A) and relies on Ethernet frame parsing.
    # If the AP has no active Ethernet uplink / is not bridging L2, exposure is reduced.
    uplink_cfg = (commands.show_uplink or "").lower()
    lldp_cfg = (commands.show_lldp or "").lower()

    # Consider "vulnerable configuration" as having an Ethernet uplink/bridging likely enabled.
    # We treat explicit "uplink wired" or "uplink ethernet" as exposed.
    # If config explicitly indicates no wired uplink, treat as safer.
    exposed = False
    safe = False

    if "uplink wired" in uplink_cfg or "uplink ethernet" in uplink_cfg or "uplink-port" in uplink_cfg:
        exposed = True
    if "uplink none" in uplink_cfg or "uplink disabled" in uplink_cfg:
        safe = True

    # LLDP is a strong indicator the wired interface is in use (not required for the vuln,
    # but helps determine adjacent L2 exposure in a config-only test).
    if "lldp enable" in lldp_cfg or "lldp enabled" in lldp_cfg:
        exposed = True

    # If we cannot determine, default to exposed (conservative).
    if not safe and not exposed:
        exposed = True

    if exposed and not safe:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-37148 (HPESBNW04958): "
            "the device is running an affected ArubaOS (AOS-8 Instant / AOS-10 AP) version and "
            "appears to have an active wired Ethernet uplink / adjacent L2 exposure. "
            "An unauthenticated adjacent attacker may trigger a kernel panic via modified Ethernet frames, "
            "causing denial of service and potentially requiring manual intervention to restore service. "
            f"Advisory: {advisory_url}"
        )

    # Vulnerable version but configuration indicates reduced exposure (best-effort).
    assert True
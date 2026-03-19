import re

from comfy import high


def _parse_aruba_version(text):
    """Parse ArubaOS W.X.Y.Z version string into a tuple of ints, or None."""
    m = re.search(
        r'arubaos\s+version\s+(\d+)\.(\d+)\.(\d+)\.(\d+)',
        text,
        re.IGNORECASE,
    )
    if not m:
        return None
    return tuple(int(x) for x in m.groups())


def _is_version_vulnerable(version_output):
    # Affected trains and their first-fixed release (exclusive upper bound).
    # All versions in an affected train below the fixed release are vulnerable.
    # Trains not listed here are not affected.
    fixed_per_train = {
        (10, 7): (10, 7, 2, 2),   # fixed at 10.7.2.2
        (10, 4): (10, 4, 1, 10),  # fixed at 10.4.1.10
        (8, 13): (8, 13, 1, 1),   # fixed at 8.13.1.1
        (8, 10): (8, 10, 0, 21),  # fixed at 8.10.0.21
    }
    v = _parse_aruba_version(version_output)
    if v is None:
        return False
    train = v[:2]
    fix = fixed_per_train.get(train)
    if fix is None:
        return False
    return v < fix


@high(
    name="rule_cve202537178",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_services=(
            "show configuration | include"
            " (web-server|https-server|http-server"
            "|mgmt|management|ssh|telnet|papi|api|rest|netconf|snmp)"
        ),
    ),
)
def rule_cve202537178(configuration, commands, device, devices):
    """
    CVE-2025-37178: Out-of-bounds read vulnerabilities leading to process
    crash / DoS in HPE Aruba Networking AOS-8 and AOS-10.

    Advisory: HPESBNW04987 rev.2
    """
    version_output = (commands.show_version or "").lower()

    if not _is_version_vulnerable(version_output):
        return

    # Advisory workaround: restrict CLI and web-based management interfaces.
    mgmt_cfg_raw = (commands.show_mgmt_services or "").lower()
    mgmt_cfg = "\n".join(
        line for line in mgmt_cfg_raw.splitlines()
        if not line.strip().startswith("#")
        and not line.strip().startswith("!")
        and not line.strip().startswith("no ")
    )

    exposure_indicators = [
        "web-server", "https-server", "http-server",
        "management", "mgmt", "ssh", "telnet",
        "papi", "rest", "api", "netconf", "snmp",
    ]
    mgmt_exposed = any(ind in mgmt_cfg for ind in exposure_indicators)

    if not mgmt_exposed:
        return

    advisory_url = (
        "https://support.hpe.com/hpesc/public/docDisplay"
        "?docId=emr_na-hpesbnw04987en_us"
    )
    assert False, (
        f"Device {device.name} is potentially vulnerable to CVE-2025-37178 "
        "(out-of-bounds read leading to process crash/DoS). The device "
        "appears to be running an affected ArubaOS version and has "
        "management interfaces/services enabled (increasing likelihood of "
        f"remote trigger). Apply vendor mitigations and/or upgrade when a "
        f"permanent fix is available. Advisory: {advisory_url}"
    )

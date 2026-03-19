from comfy import high
import re


def _parse_version(text: str):
    """
    Parse Junos version from 'show version' output.

    Expected formats (examples):
      - 'Junos: 23.4R2-S5'
      - 'Junos OS Evolved: 23.4R2-S5-EVO'
      - 'Junos: 22.4R3'
    Returns tuple: (year, minor, release, service) where service defaults to 0.
    """
    if not text:
        return None

    m = re.search(r"\bJunos(?:\s+OS\s+Evolved)?\s*:\s*(\d+)\.(\d+)R(\d+)(?:-S(\d+))?", text)
    if not m:
        return None

    year = int(m.group(1))
    minor = int(m.group(2))
    rel = int(m.group(3))
    svc = int(m.group(4) or 0)
    return (year, minor, rel, svc)


def _is_version_vulnerable(version_text: str) -> bool:
    """
    CVE-2025-59961 affected trains and first fixed versions (exclusive lower than fix is vulnerable):

    Junos OS:
      - all versions before 21.2R3-S10  => train (21,2) fixed at 21.2R3-S10
      - all versions of 22.2            => train (22,2) fixed at 22.3R1 (first non-22.2)
      - from 21.4 before 21.4R3-S12     => train (21,4) fixed at 21.4R3-S12
      - from 22.4 before 22.4R3-S8      => train (22,4) fixed at 22.4R3-S8
      - from 23.2 before 23.2R2-S5      => train (23,2) fixed at 23.2R2-S5
      - from 23.4 before 23.4R2-S6      => train (23,4) fixed at 23.4R2-S6
      - from 24.2 before 24.2R2-S2      => train (24,2) fixed at 24.2R2-S2
      - from 24.4 before 24.4R2         => train (24,4) fixed at 24.4R2
      - from 25.2 before 25.2R1-S1, 25.2R2 => train (25,2) fixed at 25.2R1-S1

    Junos OS Evolved has the same fixed versions with -EVO suffix; version parsing ignores suffix.
    """
    v = _parse_version(version_text)
    if v is None:
        return False

    train = (v[0], v[1])

    # Only trains explicitly listed as affected in the advisory.
    fixed_by_train = {
        (21, 2): (21, 2, 3, 10),
        # "all versions of 22.2" => treat any 22.2R* as vulnerable; fixed at first 22.3R1
        (22, 2): (22, 3, 1, 0),
        (21, 4): (21, 4, 3, 12),
        (22, 4): (22, 4, 3, 8),
        (23, 2): (23, 2, 2, 5),
        (23, 4): (23, 4, 2, 6),
        (24, 2): (24, 2, 2, 2),
        (24, 4): (24, 4, 2, 0),
        (25, 2): (25, 2, 1, 1),
    }

    fix = fixed_by_train.get(train)
    if fix is None:
        return False

    return v < fix


@high(
    name="rule_cve202559961",
    platform=["juniper_junos"],
    commands=dict(
        show_version="show version",
        show_dhcp_config="show configuration | display set | match \"\\b(dhcp|dhcp-local-server|dhcp-relay)\\b\"",
        show_jdhcpd_socket="file list /var/run | match jdhcpd",
    ),
)
def rule_cve202559961(configuration, commands, device, devices):
    """
    CVE-2025-59961: Incorrect Permission Assignment for Critical Resource in jdhcpd.
    A local low-privileged user can write to the Unix socket used to manage the jdhcpd process,
    resulting in complete control over the DHCP resource.

    Exposure condition: DHCP functionality is configured/used (DHCP server/relay/local-server),
    which implies jdhcpd is present/active and its management socket may be reachable.
    """
    version_output = (commands.show_version or "").strip()
    cfg_dhcp = (commands.show_dhcp_config or "").strip()
    socket_listing = (commands.show_jdhcpd_socket or "").strip()

    if not _is_version_vulnerable(version_output):
        return

    # Vulnerable configuration: DHCP features configured (server/relay/local-server).
    # If DHCP is not configured, jdhcpd is typically not used, reducing exposure.
    dhcp_configured = bool(
        re.search(r"^set\s+.*\b(dhcp-local-server|dhcp-relay|dhcp)\b", cfg_dhcp, re.M)
    )
    if not dhcp_configured:
        return

    # Optional corroboration: presence of jdhcpd socket in /var/run (best-effort).
    # Do not require it to avoid false negatives due to platform/path differences.
    socket_hint = ""
    if socket_listing:
        socket_hint = f" Observed jdhcpd-related runtime entries: {socket_listing!r}"

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-59961: the device is running an affected "
        f"Junos version and has DHCP functionality configured. A local, low-privileged user may be "
        f"able to write to the Unix socket used to manage the jdhcpd process and issue management "
        f"commands, resulting in complete control over the local DHCP server/relay resource."
        f"{socket_hint} Upgrade to a fixed release for the device's train (per Juniper advisory). "
        "Advisory: https://supportportal.juniper.net/"
    )
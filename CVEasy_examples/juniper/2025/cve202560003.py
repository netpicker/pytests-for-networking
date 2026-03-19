from __future__ import annotations

import re
from comfy import high


def _parse_version(text: str):
    """
    Parse Junos/Junos Evolved version from 'show version' output.

    Expected formats (examples):
      - "Junos: 23.2R2-S4"
      - "Junos: 24.4R1"
      - "Junos OS Evolved: 23.4R2-S5-EVO" (we ignore the -EVO suffix for comparison)

    Returns:
      (year, minor, release, service) as ints, where service defaults to 0 if absent.
      None if parsing fails.
    """
    if not text:
        return None

    # Capture the first occurrence of a Junos-like version token.
    # Accept optional "-S<svc>" and optional "-EVO" suffix.
    m = re.search(r"(\d+)\.(\d+)R(\d+)(?:-S(\d+))?(?:-EVO)?\b", text)
    if not m:
        return None

    year = int(m.group(1))
    minor = int(m.group(2))
    rel = int(m.group(3))
    svc = int(m.group(4)) if m.group(4) is not None else 0
    return (year, minor, rel, svc)


def _is_version_vulnerable(version_text: str) -> bool:
    """
    Advisory states affected versions:

    Junos OS:
      - all versions before 22.4R3-S8
      - 23.2 versions before 23.2R2-S5
      - 23.4 versions before 23.4R2-S6
      - 24.2 versions before 24.2R2-S2
      - 24.4 versions before 24.4R2

    Junos OS Evolved: same fix levels with -EVO suffix.

    We implement per-train first-fixed version tuples keyed by (year, minor).
    Only trains explicitly listed are evaluated; others are treated as not vulnerable.
    """
    v = _parse_version(version_text)
    if v is None:
        return False

    train = (v[0], v[1])

    # first fixed version per train: (year, minor, R, S)
    first_fixed = {
        (22, 4): (22, 4, 3, 8),
        (23, 2): (23, 2, 2, 5),
        (23, 4): (23, 4, 2, 6),
        (24, 2): (24, 2, 2, 2),
        (24, 4): (24, 4, 2, 0),
    }

    fix = first_fixed.get(train)
    if fix is None:
        return False

    return v < fix


@high(
    name="rule_cve202560003",
    platform=["juniper_junos"],
    commands=dict(
        show_version="show version",
        show_bgp_disable_4byte_as="show configuration protocols bgp | display set | match \"disable-4byte-as\"",
    ),
)
def rule_cve202560003(configuration, commands, device, devices):
    """
    CVE-2025-60003: Buffer Over-read in rpd (BGP) leading to rpd crash/restart (DoS).

    Trigger condition (per advisory):
      - Device receives a BGP UPDATE with specific optional transitive attributes over an
        established peering session, and rpd crashes when advertising to another peer.
      - Can only happen if one or both BGP peers are non-4-byte-AS capable as determined
        during BGP session establishment.
      - Junos default is 4-byte-AS capable unless explicitly disabled via:
          [ protocols bgp ... disable-4byte-as ]

    This rule flags exposure when:
      - Device is running an affected Junos/Junos Evolved version, AND
      - 'disable-4byte-as' is configured under protocols bgp (in any group/neighbor context).
    """
    version_output = (commands.show_version or "").strip()
    cfg_disable_4byte = (commands.show_bgp_disable_4byte_as or "").strip()

    if not _is_version_vulnerable(version_output):
        return

    # Exposure: 4-byte AS capability explicitly disabled in BGP config.
    disable_4byte_configured = "disable-4byte-as" in cfg_disable_4byte

    if not disable_4byte_configured:
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-60003: the device is running an affected "
        "Junos OS / Junos OS Evolved release and has BGP 4-byte AS capability explicitly disabled "
        "('protocols bgp ... disable-4byte-as'). Under these conditions, an unauthenticated network-based "
        "attacker with an established BGP peering session (where one or both peers are non-4-byte-AS capable) "
        "can send a crafted BGP UPDATE with specific optional transitive attributes that may cause rpd to crash "
        "and restart when advertising the received information to another peer, resulting in Denial-of-Service (DoS). "
        "Upgrade to a fixed release for your train: 22.4R3-S8, 23.2R2-S5, 23.4R2-S6, 24.2R2-S2, 24.4R2 (or later), "
        "or the corresponding -EVO fixed releases. Advisory: https://supportportal.juniper.net/"
    )
from __future__ import annotations

import re
from comfy import high


def _parse_version(text: str):
    """
    Parse Junos version strings like:
      'Junos: 23.4R2-S5'
      'Junos OS Evolved: 24.2R1-S1-EVO'
      'Junos: 22.4R3'
    Returns tuple: (year, minor, r, s) where s defaults to 0 if absent.
    Returns None if parsing fails.
    """
    if not text:
        return None

    m = re.search(r"(?i)\bJunos(?:\s+OS\s+Evolved)?\s*:\s*(\d+)\.(\d+)R(\d+)(?:-S(\d+))?", text)
    if not m:
        return None

    year = int(m.group(1))
    minor = int(m.group(2))
    r = int(m.group(3))
    s = int(m.group(4) or 0)
    return (year, minor, r, s)


def _is_version_vulnerable(version_text: str) -> bool:
    """
    Affected trains and first fixed versions (exclusive upper bound):
      Junos OS:
        - all versions before 22.4R3-S8
        - 23.2 before 23.2R2-S5
        - 23.4 before 23.4R2-S6
        - 24.2 before 24.2R2-S2
        - 24.4 before 24.4R2
      Junos OS Evolved: same numeric thresholds (suffix -EVO), parsed identically.
    """
    v = _parse_version(version_text)
    if v is None:
        return False

    train = (v[0], v[1])
    first_fixed_by_train = {
        (22, 4): (22, 4, 3, 8),
        (23, 2): (23, 2, 2, 5),
        (23, 4): (23, 4, 2, 6),
        (24, 2): (24, 2, 2, 2),
        (24, 4): (24, 4, 2, 0),  # 24.4R2 (no -S implies S0)
    }

    fix = first_fixed_by_train.get(train)
    if not fix:
        return False

    return v < fix


@high(
    name="rule_cve202560011",
    platform=["juniper_junos"],
    commands=dict(
        show_version="show version",
        show_bgp_config="show configuration protocols bgp | display set",
    ),
)
def rule_cve202560011(configuration, commands, device, devices):
    """
    CVE-2025-60011: Improper Check for Unusual or Exceptional Conditions in rpd.
    When an affected device receives a specific optional, transitive BGP attribute over an
    existing BGP session, it may be erroneously modified before propagation to peers.
    Peers may detect the attribute as malformed and reset BGP sessions, causing routing churn
    and downstream availability impact.

    Exposure condition: BGP is configured/enabled (device participates in BGP and can propagate
    received attributes to peers). This is a network-based issue over existing BGP sessions.
    """
    version_output = (commands.show_version or "").strip()
    bgp_cfg = (commands.show_bgp_config or "").strip()

    if not _is_version_vulnerable(version_output):
        return

    # Vulnerable configuration: BGP configured (any BGP group/neighbor).
    # If BGP is not configured, the device is not exposed to BGP attribute propagation.
    bgp_configured = bool(re.search(r"(?m)^\s*set\s+protocols\s+bgp\b", bgp_cfg))

    if not bgp_configured:
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-60011: the device is running an affected "
        "Junos OS / Junos OS Evolved release and has BGP configured. An unauthenticated, network-based "
        "attacker can send a specific optional, transitive BGP attribute over an existing BGP session; "
        "the affected device may incorrectly modify the attribute before propagating it to peers. Peers "
        "may treat the attribute as malformed and reset BGP sessions, causing routing churn and an "
        "availability impact for downstream devices. Upgrade to a fixed release: "
        "Junos OS: 22.4R3-S8, 23.2R2-S5, 23.4R2-S6, 24.2R2-S2, 24.4R2 or later; "
        "Junos OS Evolved: 22.4R3-S8-EVO, 23.2R2-S5-EVO, 23.4R2-S6-EVO, 24.2R2-S2-EVO, 24.4R2-EVO or later. "
        "Advisory: https://supportportal.juniper.net/"
    )
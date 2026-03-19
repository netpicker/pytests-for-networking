from __future__ import annotations

import re
from comfy import high


def _parse_version(text: str):
    """
    Parse Junos version strings like:
      "Junos: 23.4R2-S5"
      "Junos OS Evolved: 23.4R2-S5-EVO"
      "Junos: 21.2R3-S10"
      "Junos: 25.2R2"
    Returns (year, minor, release, service) as ints. Missing -S => service=0.
    """
    if not text:
        return None

    m = re.search(r"(?i)\bJunos(?:\s+OS\s+Evolved)?\s*:\s*(\d+)\.(\d+)R(\d+)(?:-S(\d+))?", text)
    if not m:
        return None

    year = int(m.group(1))
    minor = int(m.group(2))
    rel = int(m.group(3))
    svc = int(m.group(4) or 0)
    return (year, minor, rel, svc)


def _is_evolved(text: str) -> bool:
    if not text:
        return False
    return bool(re.search(r"(?i)\bEvolved\b", text)) or ("-EVO" in text)


def _is_version_vulnerable(version_text: str) -> bool:
    """
    Advisory affected versions (Junos OS and Junos OS Evolved):
      - all versions before 21.2R3-S10
      - 21.4 before 21.4R3-S12
      - all versions of 22.2
      - 22.4 before 22.4R3-S8
      - 23.2 before 23.2R2-S5
      - 23.4 before 23.4R2-S6
      - 24.2 before 24.2R2-S2
      - 24.4 before 24.4R2
      - 25.2 before 25.2R1-S1, 25.2R2 (i.e., fixed at 25.2R1-S1)
    """
    v = _parse_version(version_text)
    if v is None:
        return False

    train = (v[0], v[1])  # (YY, minor)

    # Map affected trains to the first fixed version (exclusive upper bound).
    fixed_by_train = {
        (21, 2): (21, 2, 3, 10),
        (21, 4): (21, 4, 3, 12),
        (22, 2): (22, 2, 999, 999),  # all 22.2 are vulnerable (no fixed in-train)
        (22, 4): (22, 4, 3, 8),
        (23, 2): (23, 2, 2, 5),
        (23, 4): (23, 4, 2, 6),
        (24, 2): (24, 2, 2, 2),
        (24, 4): (24, 4, 2, 0),  # fixed at 24.4R2 (no -S required)
        (25, 2): (25, 2, 1, 1),  # fixed at 25.2R1-S1 (and 25.2R2)
    }

    fix = fixed_by_train.get(train)
    if fix is None:
        return False

    return v < fix


def _config_is_vulnerable(cfg_relay: str) -> bool:
    """
    Vulnerable exposure:
      - DHCP relay configured in forward-only mode
      - trust-option82 NOT configured
    """
    cfg = (cfg_relay or "").strip()
    if not cfg:
        return False

    # Must be acting as DHCP relay and in forward-only mode.
    forward_only = bool(re.search(r"(?m)^\s*set\s+forwarding-options\s+dhcp-relay\s+forward-only\b", cfg))
    if not forward_only:
        return False

    # If trust-option82 is configured, device should accept client Option 82; not vulnerable.
    trust_opt82 = bool(re.search(r"(?m)^\s*set\s+forwarding-options\s+dhcp-relay\s+trust-option82\b", cfg))
    if trust_opt82:
        return False

    return True


@high(
    name="rule_cve202559960",
    platform=["juniper_junos"],
    commands=dict(
        show_version="show version",
        show_config_dhcp_relay="show configuration forwarding-options dhcp-relay | display set",
    ),
)
def rule_cve202559960(configuration, commands, device, devices):
    """
    CVE-2025-59960: Improper Check for Unusual or Exceptional Conditions in Juniper DHCP service
    (jdhcpd) allows a DHCP client in one subnet to exhaust address pools of other subnets when the
    device is configured as a DHCP relay in 'forward-only' mode and does not trust Option 82.

    Fixed versions:
      Junos OS: 21.2R3-S10, 21.4R3-S12, 22.4R3-S8, 23.2R2-S5, 23.4R2-S6, 24.2R2-S2, 24.4R2,
               25.2R1-S1, 25.2R2 (and later)
      Junos OS Evolved: same releases with -EVO suffix
    """
    version_output = (commands.show_version or "").strip()
    cfg_relay = (commands.show_config_dhcp_relay or "").strip()

    if not _is_version_vulnerable(version_output):
        return

    if not _config_is_vulnerable(cfg_relay):
        return

    is_evo = _is_evolved(version_output)

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-59960: the device is running a vulnerable "
        f"Junos {'OS Evolved' if is_evo else 'OS'} release and is configured as a DHCP relay in "
        "'forward-only' mode without 'trust-option82'. A DHCP client can send DHCP DISCOVER messages "
        "containing Option 82; due to improper handling, the relay forwards these packets unmodified "
        "to the downstream DHCP server, potentially exhausting address pools for other subnets and "
        "causing a Denial of Service (DoS). Remediate by upgrading to a fixed release (per advisory) "
        "and/or configuring 'set forwarding-options dhcp-relay trust-option82' as appropriate for "
        "your environment. Advisory: https://supportportal.juniper.net/"
    )
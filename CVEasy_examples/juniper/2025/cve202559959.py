from comfy import high
import re


def _parse_version(text: str):
    """
    Parse Junos version from 'show version' output.

    Expected formats (examples):
      - 'Junos: 23.2R2-S4'
      - 'Junos OS Evolved: 24.2R2-S1-EVO'
      - 'Junos: 22.4R3-S8'
      - 'Junos: 24.4R2'
    Returns tuple: (year, minor, R, S) where S defaults to 0 if absent.
    """
    if not text:
        return None

    m = re.search(r"\bJunos(?:\s+OS\s+Evolved)?\s*:\s*(\d+)\.(\d+)R(\d+)(?:-S(\d+))?", text)
    if not m:
        return None

    year = int(m.group(1))
    minor = int(m.group(2))
    r = int(m.group(3))
    s = int(m.group(4) or 0)
    return (year, minor, r, s)


def _is_evolved(text: str) -> bool:
    if not text:
        return False
    return bool(re.search(r"\bJunos\s+OS\s+Evolved\b", text)) or ("-EVO" in text)


def _is_version_vulnerable(version_output: str) -> bool:
    """
    Affected trains and first fixed versions (exclusive upper bound):
      Junos OS:
        - all versions before 22.4R3-S8
        - 23.2 versions before 23.2R2-S5
        - 23.4 versions before 23.4R2-S5
        - 24.2 versions before 24.2R2-S2
        - 24.4 versions before 24.4R2
      Junos OS Evolved: same numeric thresholds (suffix -EVO in marketing), parsed identically.
    """
    v = _parse_version(version_output)
    if v is None:
        return False

    train = (v[0], v[1])  # (year, minor)
    first_fixed_by_train = {
        (22, 4): (22, 4, 3, 8),
        (23, 2): (23, 2, 2, 5),
        (23, 4): (23, 4, 2, 5),
        (24, 2): (24, 2, 2, 2),
        (24, 4): (24, 4, 2, 0),  # 24.4R2 (no -S) => S=0
    }

    fix = first_fixed_by_train.get(train)
    if fix is None:
        return False

    return v < fix


@high(
    name="rule_cve202559959",
    platform=["juniper_junos"],
    commands=dict(
        show_version="show version",
        show_config_bgp="show configuration protocols bgp | display set",
    ),
)
def rule_cve202559959(configuration, commands, device, devices):
    """
    CVE-2025-59959: Untrusted Pointer Dereference in rpd (routing protocol daemon) on Junos OS / Junos OS Evolved.
    A local, authenticated low-privilege attacker can trigger an rpd crash/restart (DoS) by executing:
      'show route < ( receive-protocol | advertising-protocol ) bgp > detail'
    when at least one route in output has specific attributes. 'show route ... extensive' is not affected.

    Exposure condition for this rule: BGP is configured (protocols bgp ...).
    """
    version_output = (commands.show_version or "").strip()
    cfg_bgp = (commands.show_config_bgp or "").strip()

    if not _is_version_vulnerable(version_output):
        return

    # Configuration exposure: BGP configured (otherwise the triggering command context is not applicable).
    bgp_configured = bool(re.search(r"(?m)^\s*set\s+protocols\s+bgp(\s+|$)", cfg_bgp))
    if not bgp_configured:
        return

    evolved = _is_evolved(version_output)
    advisory_url = "https://supportportal.juniper.net/"

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-59959: it is running a vulnerable "
        f"Junos {'OS Evolved' if evolved else 'OS'} release and has BGP configured. A local, "
        "authenticated low-privilege attacker can cause a Denial-of-Service by triggering an rpd "
        "crash/restart when executing 'show route (receive-protocol|advertising-protocol) bgp detail' "
        "under conditions where at least one route has specific attributes. Note: 'show route ... extensive' "
        "is not affected. Upgrade to a fixed release for the affected train: "
        "Junos OS fixed in 22.4R3-S8, 23.2R2-S5, 23.4R2-S5, 24.2R2-S2, 24.4R2 (or later); "
        "Junos OS Evolved fixed in 22.4R3-S8-EVO, 23.2R2-S5-EVO, 23.4R2-S6-EVO, 24.2R2-S2-EVO, 24.4R2-EVO (or later). "
        f"Advisory: {advisory_url}"
    )
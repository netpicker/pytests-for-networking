from comfy import high
import re


def _parse_version(text: str):
    """
    Parse Junos version from 'show version' output.

    Expected formats include:
      - 'Junos: 23.4R2-S6'
      - 'Junos 23.4R2-S6'
      - 'Junos: 24.4R2'
    Returns tuple: (year, minor, release, service) where service defaults to 0.
    """
    if not text:
        return None

    m = re.search(r"Junos:\s*(\d+)\.(\d+)R(\d+)(?:-S(\d+))?", text)
    if not m:
        m = re.search(r"\bJunos\s+(\d+)\.(\d+)R(\d+)(?:-S(\d+))?", text)
    if not m:
        return None

    year = int(m.group(1))
    minor = int(m.group(2))
    rel = int(m.group(3))
    svc = int(m.group(4)) if m.group(4) is not None else 0
    return (year, minor, rel, svc)


def _is_version_vulnerable(version_text: str) -> bool:
    """
    Affected trains and fixed versions (exclusive upper bound):
      - all versions before 22.4R3-S8
      - 23.2 versions before 23.2R2-S5
      - 23.4 versions before 23.4R2-S6
      - 24.2 versions before 24.2R2-S2
      - 24.4 versions before 24.4R2
    Only these trains are evaluated; others return False.
    """
    v = _parse_version(version_text)
    if v is None:
        return False

    train = (v[0], v[1])

    fixed_by_train = {
        (22, 4): (22, 4, 3, 8),
        (23, 2): (23, 2, 2, 5),
        (23, 4): (23, 4, 2, 6),
        (24, 2): (24, 2, 2, 2),
        (24, 4): (24, 4, 2, 0),
    }

    fix = fixed_by_train.get(train)
    if fix is None:
        return False

    return v < fix


@high(
    name="rule_cve202560007",
    platform=["juniper_junos"],
    commands=dict(
        show_version="show version",
        show_class="show cli authorization",
    ),
)
def rule_cve202560007(configuration, commands, device, devices):
    """
    CVE-2025-60007: NULL Pointer Dereference in chassisd triggered by executing
    'show chassis' with specifically crafted options. A local low-privilege user
    can cause chassisd to crash and restart, reinitializing chassis components
    (except RE) and causing a service outage until recovery.

    Exposure condition: local low-privilege CLI access (e.g., view/operator/read-only).
    This rule flags devices that are on affected Junos trains AND appear to have
    non-super-user CLI classes present (indicating low-privilege local users may exist).
    """
    version_output = (commands.show_version or "").strip()
    auth_output = (commands.show_class or "").strip()

    if not _is_version_vulnerable(version_output):
        return

    # Heuristic exposure check: if device has any non-super-user classes, a low-priv user
    # could exist and trigger the issue. If we cannot determine, do not flag.
    if not auth_output:
        return

    # 'show cli authorization' typically lists classes; treat presence of common low-priv
    # classes as exposure. If only super-user is present, treat as safer.
    low_priv_classes = {"read-only", "operator", "unauthorized", "view", "guest"}
    found_classes = set(re.findall(r"\b(read-only|operator|unauthorized|view|guest|super-user)\b", auth_output))
    has_low_priv = any(c in found_classes for c in low_priv_classes)
    has_only_super = ("super-user" in found_classes) and not has_low_priv

    if has_only_super:
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-60007: it is running an affected Junos OS "
        "release where a local low-privilege user can crash and restart chassisd by executing "
        "'show chassis' with specifically crafted options, causing chassis component reinitialization "
        "and a Denial-of-Service (service outage) until automatic recovery. "
        "Upgrade to a fixed release for the corresponding train: 22.4R3-S8 or later; "
        "23.2R2-S5 or later; 23.4R2-S6 or later; 24.2R2-S2 or later; 24.4R2 or later. "
        "Advisory: https://supportportal.juniper.net/"
    )
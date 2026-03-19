import re

from comfy import high


def _parse_junos_evo_version(text):
    """Parse Junos OS Evolved YY.mRp[-Ss]-EVO into a tuple or None."""
    m = re.search(r'(\d+)\.(\d+)R(\d+)(?:-S(\d+))?-EVO', text)
    if not m:
        return None
    year, minor, patch, svc = m.groups()
    return (int(year), int(minor), int(patch), int(svc) if svc else 0)


def _is_version_vulnerable(version_output):
    # Each train has a (lower_bound_inclusive, first_fixed_exclusive) range.
    # Versions in a train below lb or at/above fix are not affected.
    affected_ranges = {
        # 23.2R2 through 23.2R2-S3 are affected; fixed at 23.2R2-S4
        (23, 2): ((23, 2, 2, 0), (23, 2, 2, 4)),
        # 23.4R1 through 23.4R1-S2 are affected; fixed at 23.4R2
        (23, 4): ((23, 4, 1, 0), (23, 4, 2, 0)),
    }
    v = _parse_junos_evo_version(version_output)
    if v is None:
        return False
    train = v[:2]
    if train not in affected_ranges:
        return False
    lb, fix = affected_ranges[train]
    return lb <= v < fix


@high(
    name='rule_cve202559967',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_interfaces=r'show interfaces terse | match "\.l3"',
        show_multicast_config=(
            'show configuration | display set | match "multicast"'
        ),
        show_pfemand_crashes=(
            'show system core-dumps | match evo-pfemand'
        ),
    ),
)
def rule_cve202559967(configuration, commands, device, devices):
    """
    CVE-2025-59967: unauthenticated adjacent attacker can cause DoS by sending
    specific valid multicast traffic to L3 interfaces, crashing evo-pfemand.
    """
    version_output = commands.show_version

    is_evo = 'Junos OS Evolved' in version_output or 'EVO' in version_output
    if not is_evo:
        return

    if not _is_version_vulnerable(version_output):
        return

    chassis_output = commands.show_chassis_hardware
    vulnerable_models = [
        'ACX7024', 'ACX7024X', 'ACX7100-32C',
        'ACX7100-48L', 'ACX7348', 'ACX7509',
    ]
    if not any(model in chassis_output for model in vulnerable_models):
        return

    interfaces_output = commands.show_interfaces
    has_l3_interfaces = (
        '.l3' in interfaces_output or 'inet' in interfaces_output
    )

    assert not has_l3_interfaces, (
        f"Device {device.name} is vulnerable to CVE-2025-59967. "
        "The device is running a vulnerable version of Junos OS Evolved "
        "on ACX7000 series hardware with layer 3 interfaces exposed to "
        "multicast traffic, which makes it susceptible to evo-pfemand "
        "crashes causing sustained Denial of Service (DoS). "
        "This issue affects both IPv4 and IPv6 multicast traffic. "
        "Advisory: https://supportportal.juniper.net/JSA88588"
    )

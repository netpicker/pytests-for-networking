import re
from comfy import high


@high(
    name='rule_cve202559958',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_firewall_config='show configuration firewall | display set'
    ),
)
def rule_cve202559958(configuration, commands, device, devices):
    """
    CVE-2025-59958: Junos OS Evolved on PTX Series — output firewall filters
    with 'reject' action on WAN/revenue interfaces cause packets to be sent to
    the Routing Engine, impacting confidentiality and availability.
    """
    version_output = commands.show_version

    # Only applies to Junos OS Evolved
    if 'Junos OS Evolved' not in version_output:
        return

    # Only applies to PTX Series
    chassis_output = commands.show_chassis_hardware
    if 'PTX' not in chassis_output:
        return

    # Define the vulnerable versions for Junos OS Evolved on PTX Series
    vulnerable_versions = [
        # 22.4 before 22.4R3-EVO
        '22.4R1-EVO', '22.4R1-S1-EVO', '22.4R1-S2-EVO',
        '22.4R2-EVO', '22.4R2-S1-EVO', '22.4R2-S2-EVO', '22.4R2-S3-EVO',
        # 23.2 before 23.2R2-EVO
        '23.2R1-EVO', '23.2R1-S1-EVO', '23.2R1-S2-EVO',
    ]

    version_match = re.search(
        r'Junos\s+OS\s+Evolved\s+(\S+)', version_output
    )
    extracted_version = version_match.group(1) if version_match else ""
    if extracted_version not in vulnerable_versions:
        return

    # Check for firewall filter terms with 'then reject' action
    firewall_config = commands.show_firewall_config
    has_reject_filter = False
    for line in firewall_config.splitlines():
        if line.strip().startswith('#'):
            continue
        if ('firewall' in line and 'filter' in line
                and 'term' in line and 'then reject' in line):
            has_reject_filter = True
            break

    assert not has_reject_filter, (
        f"Device {device.name} is vulnerable to CVE-2025-59958. "
        "The device runs a vulnerable Junos OS Evolved on PTX Series hardware "
        "with output firewall filters using 'reject' action on WAN/revenue "
        "interfaces. This causes packets to be erroneously sent to the Routing "
        "Engine, consuming limited RE resources and potentially revealing "
        "confidential information. "
        "See https://supportportal.juniper.net/JSA88958"
    )

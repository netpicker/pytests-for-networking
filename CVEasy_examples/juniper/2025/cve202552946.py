import re
from comfy import high


@high(
    name='rule_cve202552946',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_bgp_config='show configuration protocols bgp | display set',
        show_bgp_traceoptions=(
            'show configuration protocols bgp traceoptions | display set'
        )
    ),
)
def rule_cve202552946(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52946 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an attacker sending a BGP update with a specifically
    malformed AS PATH to cause rpd to crash, resulting in a Denial of Service (DoS).
    This issue only affects systems with BGP traceoptions enabled.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3',
        '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5',
        '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # All versions of 21.4
        '21.4R1', '21.4R2', '21.4R3',
        '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5',
        '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9',
        # From 22.2 before 22.2R3-S6
        '22.2R1', '22.2R2', '22.2R3',
        '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # From 22.4 before 22.4R3-S5
        '22.4R1', '22.4R2', '22.4R3',
        '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4',
        # From 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # From 23.4 before 23.4R2-S4
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3',
        # From 24.2 before 24.2R2
        '24.2R1',
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if BGP is configured
    bgp_config_output = commands.show_bgp_config
    has_bgp_configured = 'set protocols bgp' in bgp_config_output

    if not has_bgp_configured:
        return

    # Check if BGP traceoptions are enabled
    bgp_traceoptions_output = commands.show_bgp_traceoptions
    has_traceoptions_enabled = (
        'set protocols bgp traceoptions' in bgp_traceoptions_output
    )

    # Assert that the device is not vulnerable
    assert not has_traceoptions_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-52946. "
        "The device is running a vulnerable version of Junos OS with BGP "
        "traceoptions enabled, which makes it susceptible to rpd crashes when "
        "receiving a malformed AS PATH in BGP updates. Continuous receipt of "
        "the malformed AS PATH attribute will cause a sustained DoS condition. "
        "For more information, see https://supportportal.juniper.net/JSA88289"
    )

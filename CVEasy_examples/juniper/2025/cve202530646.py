import re
from comfy import high

@high(
    name='rule_cve202530646',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_lldp_config='show configuration protocols lldp | display set',
        show_telemetry_config='show configuration services analytics | display set',
        show_l2cpd_crashes='show system core-dumps | match l2cpd'
    ),
)
def rule_cve202530646(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30646 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated adjacent attacker to cause a DoS condition
    by sending a malformed LLDP TLV when LLDP telemetry subscription is active, causing
    the l2cpd process to crash and restart.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # from 21.4 before 21.4R3-S10
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9',
        # from 22.2 before 22.2R3-S6
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # from 22.4 before 22.4R3-S6
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5',
        # from 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # from 23.4 before 23.4R2-S4
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3',
        # from 24.2 before 24.2R2
        '24.2R1', '24.2R1-S1'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if LLDP is enabled
    lldp_config = commands.show_lldp_config
    lldp_enabled = 'set protocols lldp' in lldp_config and 'disable' not in lldp_config

    if not lldp_enabled:
        return

    # Check if LLDP telemetry subscription is active
    telemetry_config = commands.show_telemetry_config
    has_lldp_telemetry = 'lldp' in telemetry_config.lower() and 'streaming-server' in telemetry_config

    if not has_lldp_telemetry:
        return

    # Check for l2cpd crashes
    l2cpd_crashes = commands.show_l2cpd_crashes
    has_l2cpd_crashes = 'l2cpd' in l2cpd_crashes

    # Assert that the device is not vulnerable
    assert not has_l2cpd_crashes, (
        f"Device {device.name} is vulnerable to CVE-2025-30646. "
        "The device is running a vulnerable version of Junos OS with LLDP enabled and "
        "an active LLDP telemetry subscription, which makes it susceptible to l2cpd crashes "
        "when receiving malformed LLDP TLVs from adjacent attackers. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-30646"
    )
import re
from comfy import high


@high(
    name='rule_cve202530657',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_flow_monitoring='show configuration | display set | match "services flow-monitoring"',
        show_srrd_crashes='show system core-dumps | match srrd'
    ),
)
def rule_cve202530657(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30657 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS
    by sending a specific BGP update message to a device configured for flow-monitoring,
    which causes the SRRD daemon to crash due to improper encoding.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # 21.4 versions before 21.4R3-S10
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9',
        # 22.2 versions before 22.2R3-S6
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5',
        # 22.4 versions before 22.4R3
        '22.4R1', '22.4R2',
        # 23.2 versions before 23.2R1-S2, 23.2R2
        '23.2R1', '23.2R1-S1'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if flow-monitoring is configured
    flow_monitoring_output = commands.show_config_flow_monitoring
    has_flow_monitoring = 'services flow-monitoring' in flow_monitoring_output

    # If flow-monitoring is not configured, device is not vulnerable
    if not has_flow_monitoring:
        return

    # Check for SRRD crashes
    srrd_crashes_output = commands.show_srrd_crashes
    has_srrd_crashes = 'srrd' in srrd_crashes_output.lower()

    # Assert that the device is not vulnerable
    assert not has_flow_monitoring, (
        f"Device {device.name} is vulnerable to CVE-2025-30657. "
        "The device is running a vulnerable version of Junos OS with flow-monitoring configured, "
        "which makes it susceptible to SRRD daemon crashes when receiving specific BGP update messages. "
        "This can cause a Denial-of-Service condition with momentary interruption of jflow processing. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )
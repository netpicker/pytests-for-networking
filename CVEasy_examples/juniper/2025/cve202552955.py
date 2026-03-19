import re
from comfy import high


@high(
    name='rule_cve202552955',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_jflow='show configuration | display set | match "services flow-monitoring"',
        show_config_sflow='show configuration | display set | match "protocols sflow"',
        show_config_routing_instances='show configuration | display set | match "routing-instances"',
        show_rpd_crashes='show system core-dumps | match rpd'
    ),
)
def rule_cve202552955(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52955 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an adjacent unauthenticated attacker to cause memory corruption
    in the routing protocol daemon (rpd) when logical interfaces using routing instances flap
    continuously and jflow/sflow modules are configured.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions
    vulnerable_versions = [
        # All versions before 21.2R3-S9
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8',
        # All versions of 21.4
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8',
        # All versions of 22.2
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4',
        # From 22.4 before 22.4R3-S7
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', '22.4R3-S4', '22.4R3-S5', '22.4R3-S6',
        # From 23.2 before 23.2R2-S3
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2',
        # From 23.4 before 23.4R2-S4
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3',
        # From 24.2 before 24.2R2
        '24.2R1', '24.2R1-S1', '24.2R1-S2'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check for jflow/sflow configuration
    jflow_output = commands.show_config_jflow
    sflow_output = commands.show_config_sflow
    routing_instances_output = commands.show_config_routing_instances

    has_jflow = 'services flow-monitoring' in jflow_output
    has_sflow = 'protocols sflow' in sflow_output
    has_routing_instances = 'routing-instances' in routing_instances_output

    # Check for rpd crashes
    rpd_crashes_output = commands.show_rpd_crashes
    has_rpd_crashes = 'rpd' in rpd_crashes_output and '.core' in rpd_crashes_output

    # Device is vulnerable if it has routing instances and either jflow or sflow configured
    is_vulnerable_config = has_routing_instances and (has_jflow or has_sflow)

    # Assert that the device is not vulnerable
    assert not is_vulnerable_config, (
        f"Device {device.name} is vulnerable to CVE-2025-52955. "
        "The device is running a vulnerable version of Junos OS with routing instances and jflow/sflow configured, "
        "which makes it susceptible to rpd memory corruption and crashes when logical interfaces flap continuously. "
        f"RPD crashes detected: {has_rpd_crashes}. "
        "For more information, see https://supportportal.juniper.net/JSA88888"
    )
import re
from comfy import high

@high(
    name='rule_cve202530649',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_syslog='show configuration system syslog | display set',
        show_services_summary='show services service-sets summary'
    ),
)
def rule_cve202530649(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-30649 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to send specific
    spoofed packets to cause a CPU Denial of Service (DoS) to the MX-SPC3 SPUs when
    syslog stream TCP transport is configured.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = []
    
    # All versions before 22.2R3-S6
    vulnerable_versions.extend([
        '21.2R1', '21.2R2', '21.2R3',
        '21.4R1', '21.4R2', '21.4R3',
        '22.1R1', '22.1R2', '22.1R3',
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', '22.2R3-S4', '22.2R3-S5'
    ])
    
    # From 22.4 before 22.4R3-S4
    vulnerable_versions.extend([
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3'
    ])
    
    # From 23.2 before 23.2R2-S3
    vulnerable_versions.extend([
        '23.2R1', '23.2R2', '23.2R2-S1', '23.2R2-S2'
    ])
    
    # From 23.4 before 23.4R2-S4
    vulnerable_versions.extend([
        '23.4R1', '23.4R2', '23.4R2-S1', '23.4R2-S2', '23.4R2-S3'
    ])
    
    # From 24.2 before 24.2R1-S2, 24.2R2
    vulnerable_versions.extend([
        '24.2R1', '24.2R1-S1'
    ])

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is MX240, MX480, or MX960
    chassis_output = commands.show_chassis_hardware
    is_vulnerable_platform = any(platform in chassis_output for platform in ['MX240', 'MX480', 'MX960'])

    if not is_vulnerable_platform:
        return

    # Check for MX-SPC3 Security Services Card
    has_spc3 = 'MX-SPC3' in chassis_output or 'SPC3' in chassis_output

    if not has_spc3:
        return

    # Check if syslog stream TCP transport is configured
    syslog_config = commands.show_config_syslog
    has_syslog_stream = 'stream' in syslog_config and 'tcp' in syslog_config.lower()

    if not has_syslog_stream:
        return

    # Check for high CPU utilization on SPC3 SPUs (indicator of compromise)
    services_summary = commands.show_services_summary
    high_cpu_detected = 'OVLD' in services_summary or '99.' in services_summary

    vulnerability_message = (
        f"Device {device.name} is vulnerable to CVE-2025-30649. "
        "The device is running a vulnerable version of Junos OS on MX240/MX480/MX960 hardware "
        "with MX-SPC3 Security Services Card and has syslog stream TCP transport configured, "
        "which makes it susceptible to CPU DoS attacks through spoofed packets. "
    )

    if high_cpu_detected:
        vulnerability_message += "WARNING: High CPU utilization detected - possible active exploitation. "

    vulnerability_message += "For more information, see https://supportportal.juniper.net/JSA88888"

    # Assert that the device is not vulnerable
    assert False, vulnerability_message
import re
from comfy import high

@high(
    name='rule_cve202521594',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_nat='show configuration services nat | display set',
        show_config_dslite='show configuration services service-set | display set | match softwire',
        show_nat_port_block='show services nat source port-block'
    ),
)
def rule_cve202521594(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-21594 vulnerability in Juniper Networks Junos OS.
    The vulnerability causes port blocking in DS-Lite and NAT scenarios with prefix-length 56,
    leading to Denial of Service (DoS) on MX Series devices.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = [
        # 21.2 before 21.2R3-S8
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7',
        # 21.4 before 21.4R3-S7
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', '21.4R3-S4', '21.4R3-S5', '21.4R3-S6',
        # 22.1 before 22.1R3-S6
        '22.1R1', '22.1R2', '22.1R3', '22.1R3-S1', '22.1R3-S2', '22.1R3-S3', '22.1R3-S4', '22.1R3-S5',
        # 22.2 before 22.2R3-S4
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3',
        # 22.3 before 22.3R3-S3
        '22.3R1', '22.3R2', '22.3R3', '22.3R3-S1', '22.3R3-S2',
        # 22.4 before 22.4R3-S2
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1',
        # 23.2 before 23.2R2-S1
        '23.2R1', '23.2R2',
        # 23.4 before 23.4R1-S2, 23.4R2
        '23.4R1', '23.4R1-S1', '23.4R2'
    ]

    # Check if the current version is vulnerable
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""
    version_vulnerable = extracted_version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is MX Series
    chassis_output = commands.show_chassis_hardware
    is_mx_platform = 'MX' in chassis_output

    if not is_mx_platform:
        return

    # Check for DS-Lite and NAT configuration
    config_nat = commands.show_config_nat
    config_dslite = commands.show_config_dslite
    
    has_nat_config = 'services nat' in config_nat and 'source' in config_nat
    has_dslite_config = 'softwire' in config_dslite
    
    # Check if DS-Lite and NAT are both configured (vulnerable scenario)
    is_vulnerable_config = has_nat_config and has_dslite_config

    if not is_vulnerable_config:
        return

    # Check for port blocking symptoms
    port_block_output = commands.show_nat_port_block
    has_port_blocking = '256/256' in port_block_output or 'Ports_Used/Ports_Total' in port_block_output

    # Assert that the device is not vulnerable
    assert not is_vulnerable_config, (
        f"Device {device.name} is vulnerable to CVE-2025-21594. "
        "The device is running a vulnerable version of Junos OS on MX Series hardware with DS-Lite and NAT configured, "
        "which makes it susceptible to port blocking and DoS when crafted IPv6 traffic with prefix-length 56 is received. "
        "Ports assigned to users will not be freed, preventing new connections. "
        "For more information, see https://supportportal.juniper.net/JSA88189"
    )
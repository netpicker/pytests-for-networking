import re
from comfy import high

@high(
    name='rule_cve202552982',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_chassis_fpc='show chassis fpc',
        show_config_sip='show configuration | display set | match "service-set"'
    ),
)
def rule_cve202552982(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52982 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated, network-based attacker to cause a DoS
    by exploiting improper resource shutdown in SIP ALG on MX Series with MS-MPC
    when two or more service sets are processing SIP calls.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable version ranges
    vulnerable_versions = []
    
    # All versions before 21.2R3-S9
    vulnerable_versions.extend([
        '21.2R1', '21.2R2', '21.2R3', '21.2R3-S1', '21.2R3-S2', '21.2R3-S3', 
        '21.2R3-S4', '21.2R3-S5', '21.2R3-S6', '21.2R3-S7', '21.2R3-S8'
    ])
    
    # 21.4 versions from 21.4R1
    vulnerable_versions.extend([
        '21.4R1', '21.4R2', '21.4R3', '21.4R3-S1', '21.4R3-S2', '21.4R3-S3', 
        '21.4R3-S4', '21.4R3-S5', '21.4R3-S6', '21.4R3-S7', '21.4R3-S8', '21.4R3-S9'
    ])
    
    # 22.2 versions before 22.2R3-S6
    vulnerable_versions.extend([
        '22.2R1', '22.2R2', '22.2R3', '22.2R3-S1', '22.2R3-S2', '22.2R3-S3', 
        '22.2R3-S4', '22.2R3-S5'
    ])
    
    # 22.4 versions before 22.4R3-S6
    vulnerable_versions.extend([
        '22.4R1', '22.4R2', '22.4R3', '22.4R3-S1', '22.4R3-S2', '22.4R3-S3', 
        '22.4R3-S4', '22.4R3-S5'
    ])

    # Extract exact version token and check if it is vulnerable
    match = re.search(r'Junos:\s+(\S+)', version_output)
    version = match.group(1) if match else ""
    version_vulnerable = version in vulnerable_versions

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is MX Series
    chassis_output = commands.show_chassis_hardware
    is_mx_platform = 'MX' in chassis_output

    if not is_mx_platform:
        return

    # Check for MS-MPC line cards
    fpc_output = commands.show_chassis_fpc
    has_ms_mpc = 'MS-MPC' in fpc_output

    if not has_ms_mpc:
        return

    # Check for service-set configuration with SIP ALG
    config_output = commands.show_config_sip
    
    # Count service sets (vulnerable if 2 or more service sets exist)
    service_set_count = config_output.count('set services service-set')
    has_multiple_service_sets = service_set_count >= 2
    
    # Check if SIP ALG is configured in any service set
    has_sip_alg = 'sip' in config_output.lower() or 'application-identification' in config_output

    # Assert that the device is not vulnerable
    assert not (has_ms_mpc and has_multiple_service_sets and has_sip_alg), (
        f"Device {device.name} is vulnerable to CVE-2025-52982. "
        "The device is running a vulnerable version of Junos OS on MX Series hardware with MS-MPC "
        "and is configured with two or more service sets processing SIP calls, "
        "which makes it susceptible to MS-MPC crashes through specific SIP call sequences. "
        "For more information, see https://supportportal.juniper.net/JSA88123"
    )
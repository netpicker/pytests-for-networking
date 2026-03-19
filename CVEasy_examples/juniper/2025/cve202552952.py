import re
from comfy import high


@high(
    name='rule_cve202552952',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_chassis_fpc='show chassis fpc',
        show_config_cfm='show configuration protocols oam ethernet connectivity-fault-management | display set'
    ),
)
def rule_cve202552952(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52952 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an unauthenticated adjacent attacker to send a malformed
    packet to crash the FPC, resulting in a Denial of Service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if the current version is vulnerable
    # Vulnerable: All versions before 22.2R3-S1, from 22.4 before 22.4R2
    version_match = re.search(r'Junos:\s+(\S+)', version_output)
    extracted_version = version_match.group(1) if version_match else ""

    # Check for versions before 22.2R3-S1
    vulnerable_versions_before_22_2 = [
        '21.1', '21.2', '21.3', '21.4', '22.1', '22.2R1', '22.2R2', '22.2R3'
    ]

    # Check for versions 22.4 before 22.4R2
    vulnerable_versions_22_4 = ['22.4R1']

    version_vulnerable = (
        extracted_version in vulnerable_versions_before_22_2 or
        extracted_version in vulnerable_versions_22_4
    )

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if device is MX Series
    chassis_output = commands.show_chassis_hardware
    is_mx_platform = 'MX' in chassis_output

    if not is_mx_platform:
        return

    # Check for MPC-BUILTIN or MPC1-MPC9 line cards
    fpc_output = commands.show_chassis_fpc
    has_vulnerable_mpcs = False
    
    if 'MPC-BUILTIN' in fpc_output or 'MPC BUILTIN' in fpc_output:
        has_vulnerable_mpcs = True
    elif any(f'MPC{i}' in fpc_output for i in range(1, 10)):
        has_vulnerable_mpcs = True

    if not has_vulnerable_mpcs:
        return

    # Check if CFM is enabled
    cfm_config = commands.show_config_cfm
    cfm_enabled = 'connectivity-fault-management' in cfm_config and len(cfm_config.strip()) > 0

    # Assert that the device is not vulnerable
    assert not cfm_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-52952. "
        "The device is running a vulnerable version of Junos OS on MX Series hardware with vulnerable line cards "
        "(MPC-BUILTIN or MPC1-MPC9) and has connectivity fault management (CFM) enabled, "
        "which makes it susceptible to FPC crashes through malformed packets from adjacent attackers. "
        "For more information, see https://supportportal.juniper.net/JSA88588"
    )
from comfy import high

@high(
    name='rule_cve202552947',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_chassis_hardware='show chassis hardware',
        show_config_l2circuit='show configuration protocols l2circuit | display set'
    ),
)
def rule_cve202552947(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52947 vulnerability in Juniper Networks Junos OS.
    The vulnerability allows an attacker to crash the Forwarding Engine Board (FEB)
    by flapping an interface on specific EOL ACX Series platforms when hot-standby
    mode is configured for L2 circuit.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is vulnerable ACX Series platform
    chassis_output = commands.show_chassis_hardware
    vulnerable_platforms = ['ACX1000', 'ACX1100', 'ACX2000', 'ACX2100', 'ACX2200', 
                          'ACX4000', 'ACX5048', 'ACX5096']
    
    is_vulnerable_platform = any(platform in chassis_output for platform in vulnerable_platforms)

    if not is_vulnerable_platform:
        return

    # Parse version - vulnerable if before 21.2R3-S9
    # All versions before 21.2R3-S9 are vulnerable
    version_vulnerable = False
    
    # Check for versions that are vulnerable (before 21.2R3-S9)
    if 'Junos:' in version_output:
        # Extract version string
        for line in version_output.splitlines():
            if 'Junos:' in line:
                version_str = line.split('Junos:')[1].strip()
                
                # Parse major.minor version
                if version_str.startswith('21.2R3-S'):
                    # Check if S version is less than S9
                    try:
                        s_version = int(version_str.split('21.2R3-S')[1].split()[0])
                        if s_version < 9:
                            version_vulnerable = True
                    except:
                        version_vulnerable = True
                elif version_str.startswith('21.2R3'):
                    # Base 21.2R3 without S version is vulnerable
                    version_vulnerable = True
                elif version_str.startswith('21.2R') or version_str.startswith('21.1R'):
                    version_vulnerable = True
                elif version_str.startswith('20.') or version_str.startswith('19.') or version_str.startswith('18.'):
                    version_vulnerable = True
                elif version_str.startswith('21.'):
                    # 21.0, 21.1 are vulnerable
                    major_minor = version_str.split('R')[0]
                    if major_minor in ['21.0', '21.1']:
                        version_vulnerable = True
                break

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check for hot-standby configuration in L2 circuit
    l2circuit_config = commands.show_config_l2circuit
    has_hot_standby = 'hot-standby' in l2circuit_config

    # Assert that the device is not vulnerable
    assert not has_hot_standby, (
        f"Device {device.name} is vulnerable to CVE-2025-52947. "
        "The device is running a vulnerable version of Junos OS on an EOL ACX Series platform "
        "with hot-standby mode configured for L2 circuit, which makes it susceptible to FEB crashes "
        "when the primary path port of the L2 circuit IGP goes down. "
        "For more information, see https://supportportal.juniper.net/JSA88947"
    )
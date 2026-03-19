from comfy import medium

@medium(
    name='rule_cve202520292',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config'
    ),
)
def rule_cve202520292(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2025-20292 vulnerability in Cisco NX-OS Software.
    The vulnerability allows an authenticated, local attacker to execute a command 
    injection attack on the underlying operating system due to insufficient validation 
    of user-supplied input in CLI commands.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable versions - all versions are vulnerable until patched
    # Based on the advisory, this affects all listed products regardless of configuration
    # We need to check if the device is running a version that has been fixed
    
    # Fixed versions based on the advisory tables:
    # UCS 6400/6500: 4.2(3p), 4.3(6a), 6.0+
    # UCS X-Series: 4.3(6a), 6.0+
    # For NX-OS devices, we need to check against the Cisco Software Checker
    
    # Since the advisory states "regardless of device configuration", 
    # all devices running vulnerable versions are affected
    
    # Check for fixed version indicators
    fixed_version_patterns = [
        # These are example patterns - actual fixed versions would come from Software Checker
        '10.4(1)',  # Example fixed version
        '10.3(5)',  # Example fixed version
        '9.3(14)',  # Example fixed version
        '4.2(3p)',  # UCS fixed version
        '4.3(6a)',  # UCS fixed version
    ]
    
    # Check if running a known fixed version
    is_fixed_version = any(pattern in version_output for pattern in fixed_version_patterns)
    
    # Check if running version 6.0 or higher (for UCS devices)
    if 'UCSM' in version_output or 'UCS' in version_output:
        # Extract version for UCS devices
        if '6.0' in version_output or '6.1' in version_output or '6.2' in version_output:
            is_fixed_version = True
    
    # If not running a fixed version, device is vulnerable
    # This vulnerability affects all devices regardless of configuration
    assert is_fixed_version, (
        f"Device {device.name} is vulnerable to CVE-2025-20292. "
        "The device is running a vulnerable version of Cisco NX-OS Software that allows "
        "authenticated local attackers to execute command injection attacks due to insufficient "
        "validation of user-supplied input in CLI commands. This vulnerability affects the device "
        "regardless of configuration. Upgrade to a fixed software version. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-cmdinj-qhNze5Ss"
    )
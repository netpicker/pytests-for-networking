from comfy import high

@high(
    name='rule_cve202559991',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_junos_space='show configuration | display set | match "junos-space"'
    ),
)
def rule_cve202559991(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-59991 vulnerability in Juniper Networks Junos Space.
    The vulnerability allows an attacker to inject script tags in the Device Management pages
    that enable execution of commands with the target's permissions through XSS.
    This issue affects all versions of Junos Space before 24.1R4.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is a Junos Space installation
    is_junos_space = 'Junos Space' in version_output or 'junos-space' in version_output.lower()

    # If not Junos Space, device is not vulnerable
    if not is_junos_space:
        return

    # Define vulnerable version patterns - all versions before 24.1R4
    # Extract version number from output
    import re
    version_match = re.search(r'(\d+)\.(\d+)R(\d+)', version_output)
    
    if not version_match:
        # Cannot determine version, assume potentially vulnerable
        version_vulnerable = True
    else:
        major = int(version_match.group(1))
        minor = int(version_match.group(2))
        release = int(version_match.group(3))
        
        # Vulnerable if version < 24.1R4
        if major < 24:
            version_vulnerable = True
        elif major == 24 and minor < 1:
            version_vulnerable = True
        elif major == 24 and minor == 1 and release < 4:
            version_vulnerable = True
        else:
            version_vulnerable = False

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check if Junos Space Device Management is configured/enabled
    config_output = commands.show_config_junos_space
    has_device_management = bool(config_output.strip()) and 'junos-space' in config_output.lower()

    # Assert that the device is not vulnerable
    assert not (version_vulnerable and has_device_management), (
        f"Device {device.name} is vulnerable to CVE-2025-59991. "
        "The device is running a vulnerable version of Junos Space (before 24.1R4) with Device Management enabled, "
        "which makes it susceptible to Cross-site Scripting (XSS) attacks that allow command execution with victim's permissions. "
        "Upgrade to Junos Space 24.1R4 or later. "
        "For more information, see https://supportportal.juniper.net/CVE-2025-59991"
    )
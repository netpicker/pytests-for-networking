from comfy import high


@high(
    name='rule_cve202520138',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config'
    ),
)
def rule_cve202520138(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20138 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to insufficient validation of user arguments that are passed to specific CLI commands.
    An attacker with a low-privileged account could exploit this vulnerability by using crafted commands at the prompt
    to elevate privileges to root and execute arbitrary commands.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is IOS XR 64-bit Software
    is_iosxr = 'IOS XR' in version_output and '64 bit' in version_output.lower()
    
    # If not IOS XR, device is not vulnerable
    if not is_iosxr:
        return

    # Define vulnerable version patterns
    # Vulnerable: 24.1 and earlier, 24.2 (before 24.2.21), 24.3
    # Not vulnerable: 24.4 and later, 24.2.21 and later
    
    version_vulnerable = False
    
    # Check for version 24.1 and earlier
    if 'Version 24.1' in version_output:
        version_vulnerable = True
    elif 'Version 23.' in version_output or 'Version 22.' in version_output or 'Version 21.' in version_output:
        version_vulnerable = True
    elif 'Version 20.' in version_output or 'Version 19.' in version_output or 'Version 18.' in version_output:
        version_vulnerable = True
    elif 'Version 17.' in version_output or 'Version 16.' in version_output or 'Version 15.' in version_output:
        version_vulnerable = True
    elif 'Version 7.' in version_output or 'Version 6.' in version_output or 'Version 5.' in version_output:
        version_vulnerable = True
    
    # Check for version 24.2 (before 24.2.21)
    elif 'Version 24.2' in version_output:
        # Extract minor version if possible
        if '24.2.21' not in version_output:
            # Assume vulnerable if not explicitly 24.2.21 or higher
            version_vulnerable = True
    
    # Check for version 24.3
    elif 'Version 24.3' in version_output:
        version_vulnerable = True

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # For IOS XR, this vulnerability affects all configurations
    # The vulnerability is in the CLI command validation itself, not dependent on specific features
    is_vulnerable = True

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20138. "
        "The device is running a vulnerable version of Cisco IOS XR 64-bit Software with insufficient "
        "validation of user arguments in CLI commands, which allows authenticated local attackers to "
        "execute arbitrary commands as root. Upgrade to a fixed release (24.4 or later, or 24.2.21). "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-priv-esc-GFQjxvOF"
    )
from comfy import high


@high(
    name='rule_cve202520149',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include shell'
    ),
)
def rule_cve202520149(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20149 vulnerability in Cisco IOS and IOS XE Software.
    The vulnerability is due to a buffer overflow in the CLI that can be exploited by an authenticated,
    local attacker with low privileges to cause a denial of service (DoS) condition by reloading the device.
    The vulnerability only affects devices with 'shell processing full' command configured.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is Cisco IOS or IOS XE Software
    is_cisco_ios = 'Cisco IOS Software' in version_output or 'Cisco IOS XE Software' in version_output

    # If not Cisco IOS/IOS XE, device is not vulnerable
    if not is_cisco_ios:
        return

    # Check if shell processing full is configured
    config_output = commands.show_running_config

    # The vulnerability only affects devices with 'shell processing full' configured
    shell_processing_enabled = 'shell processing full' in config_output

    # If shell processing full is not configured, the device is not vulnerable
    if not shell_processing_enabled:
        return

    # If we reach here, the device is vulnerable
    is_vulnerable = shell_processing_enabled

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20149. "
        "The device has 'shell processing full' configured, which makes it susceptible to a CLI buffer overflow "
        "that can be exploited by an authenticated, local attacker to cause a DoS condition. "
        "Mitigation: Remove the 'shell processing full' command using 'no shell processing full' in global configuration mode. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-cli-EB7cZ6yO"
    )
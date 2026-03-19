from comfy import high


@high(
    name='rule_cve202520115',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config router bgp'
    ),
)
def rule_cve202520115(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20115 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to memory corruption when a BGP update is created with an AS_CONFED_SEQUENCE
    attribute that has 255 autonomous system numbers. An attacker could exploit this vulnerability by
    sending a crafted BGP update message, causing the BGP process to restart and resulting in a DoS condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (7.11 and earlier, 24.1 and earlier, 24.2 before 24.2.21, 24.3 before 24.3.1)
    # Since this is IOS XR specific and the platform is cisco_ios, we need to check for IOS XR versions
    vulnerable_version_patterns = [
        'IOS XR Software',
        'Cisco IOS XR'
    ]

    # Check if the device is running IOS XR
    is_iosxr = any(pattern in version_output for pattern in vulnerable_version_patterns)

    # If not IOS XR, device is not vulnerable
    if not is_iosxr:
        return

    # Check if version is fixed (24.3.1 or later, 24.4 or later)
    fixed_versions = ['24.3.1', '24.4']
    version_fixed = any(version in version_output for version in fixed_versions)

    if version_fixed:
        return

    # If version is potentially vulnerable, check for BGP confederation configuration
    config_output = commands.show_running_config

    # Check if BGP is configured
    bgp_configured = 'router bgp' in config_output

    if not bgp_configured:
        return

    # Check if BGP confederation peers are configured (vulnerable configuration)
    confederation_configured = 'bgp confederation peers' in config_output

    # If BGP confederation is configured, the device is vulnerable
    is_vulnerable = confederation_configured

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20115. "
        "The device is running a vulnerable version of Cisco IOS XR Software AND has BGP confederation configured, "
        "which makes it susceptible to DoS attacks via crafted BGP update messages with AS_CONFED_SEQUENCE attributes "
        "containing 255 or more autonomous system numbers. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxr-bgp-dos-O7stePhX"
    )
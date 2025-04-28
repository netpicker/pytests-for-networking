from comfy import high


@high(
    name='rule_cve202420276',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include interface|port-security|device classifier|'
                           'system-auth-control|port-control|mab'
    ),
)
def rule_cve202420276(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2024-20276 vulnerability in Cisco Catalyst 6000 Series Switches.
    The vulnerability is due to improper handling of process-switched traffic, which can be exploited by an
    unauthenticated, adjacent attacker to cause a denial of service (DoS) condition by reloading the device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 15.5(1)SY versions
        '15.5(1)SY5', '15.5(1)SY6', '15.5(1)SY7', '15.5(1)SY8',
        '15.5(1)SY9', '15.5(1)SY10', '15.5(1)SY11'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # If version is vulnerable, check for enabled features
    config_output = commands.show_running_config

    # Check if port security is enabled
    port_security_enabled = 'switchport port-security' in config_output

    # Check if device classifier is enabled
    device_classifier_enabled = 'device classifier' in config_output

    # Check if AAA is enabled
    aaa_enabled = any(keyword in config_output for keyword in [
        'dot1x system-auth-control',
        'authentication order',
        'authentication priority',
        'authentication port-control',
        'mab'
    ])

    # If any of the above features are enabled, the device is vulnerable
    is_vulnerable = port_security_enabled or device_classifier_enabled or aaa_enabled

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2024-20276. "
        "The device is running a vulnerable version AND has port security, device classifier, or AAA enabled, "
        "which makes it susceptible to DoS attacks. "
        "For more information, see "
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-dos-Hq4d3tZG"
    )

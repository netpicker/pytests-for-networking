from comfy import high


@high(
    name='rule_cve202520164',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include ip http server|secure'
    ),
)
def rule_cve202520164(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20164 vulnerability in Cisco Industrial Ethernet Switches.
    The vulnerability is due to insufficient validation of authorizations for authenticated users in the
    Device Manager (DM) of Cisco IOS Software. An authenticated attacker with privilege level 5 or higher
    can exploit this vulnerability by sending a crafted HTTP request to elevate privileges to level 15.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if the device is an Industrial Ethernet Series Switch
    vulnerable_models = [
        'IE-2000',
        'IE-4000',
        'IE-4010',
        'IE-5000'
    ]

    # Check if the current device is a vulnerable model
    model_vulnerable = any(model in version_output for model in vulnerable_models)

    # If model is not vulnerable, no need to check further
    if not model_vulnerable:
        return

    # Check if HTTP Server feature is enabled
    config_output = commands.show_running_config

    # Check if HTTP server or HTTPS server is enabled (but not disabled with 'no')
    # Look for 'ip http server' that's not preceded by 'no '
    http_enabled = 'ip http server' in config_output and 'no ip http server' not in config_output
    https_enabled = 'ip http secure-server' in config_output and 'no ip http secure-server' not in config_output

    # If either HTTP or HTTPS is enabled, the device is vulnerable
    is_vulnerable = http_enabled or https_enabled

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20164. "
        "The device is a Cisco Industrial Ethernet Switch running Cisco IOS Software with HTTP/HTTPS enabled, "
        "which allows authenticated users with privilege level 5 or higher to escalate privileges to level 15. "
        "Mitigation: Disable HTTP Server feature using 'no ip http server' and 'no ip http secure-server' commands. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-http-privesc-wCRd5e3"
    )
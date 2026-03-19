from comfy import high


@high(
    name='rule_cve202520327',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include ip http server|secure|active'
    ),
)
def rule_cve202520327(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20327 vulnerability in Cisco IOS Software.
    The vulnerability affects Cisco Industrial Ethernet (IE) Series Switches and is due to improper
    input validation in the web UI. An authenticated, remote attacker with low privileges can exploit
    this vulnerability by sending a crafted URL in an HTTP request to cause a denial of service (DoS)
    condition by reloading the device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if the device is an Industrial Ethernet Series Switch
    # IE 2000, IE 3010, IE 4000, IE 4010, IE 5000 Series
    ie_series_models = [
        'IE-2000',
        'IE-3010',
        'IE-4000',
        'IE-4010',
        'IE-5000'
    ]

    # Check if the device is an IE Series Switch
    is_ie_series = any(model in version_output for model in ie_series_models)

    # If not an IE Series Switch, device is not vulnerable
    if not is_ie_series:
        return

    # Extract the configuration information
    config_output = commands.show_running_config

    # Check if HTTP Server feature is enabled
    # Need to check for lines that start with 'ip http server' (not 'no ip http server')
    config_lines = config_output.splitlines()
    http_server_enabled = any(
        line.strip() == 'ip http server' or line.strip().startswith('ip http server ')
        for line in config_lines
    )
    https_server_enabled = any(
        line.strip() == 'ip http secure-server' or line.strip().startswith('ip http secure-server ')
        for line in config_lines
    )

    # Check if the vulnerability is mitigated by active-session-modules none
    http_mitigated = 'ip http active-session-modules none' in config_output
    https_mitigated = 'ip http secure-active-session-modules none' in config_output

    # Determine if the device is vulnerable
    # Device is vulnerable if:
    # 1. It's an IE Series Switch AND
    # 2. HTTP or HTTPS server is enabled AND
    # 3. The respective server is not mitigated by active-session-modules none
    http_vulnerable = http_server_enabled and not http_mitigated
    https_vulnerable = https_server_enabled and not https_mitigated

    is_vulnerable = http_vulnerable or https_vulnerable

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20327. "
        "The device is a Cisco Industrial Ethernet Series Switch running Cisco IOS Software "
        "with the HTTP Server feature enabled, which makes it susceptible to DoS attacks via crafted URLs. "
        "Mitigation: Disable HTTP Server using 'no ip http server' and 'no ip http secure-server' commands. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-invalid-url-dos-Nvxszf6u"
    )
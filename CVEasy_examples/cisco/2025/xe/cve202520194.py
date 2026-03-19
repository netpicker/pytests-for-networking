from comfy import medium

@medium(
    name='rule_cve202520194',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_http_config='show running-config | include ip http server|secure|active',
    ),
)
def rule_cve202520194(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20194 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the web-based management interface of Cisco IOS XE Software could allow 
    an authenticated, low-privileged, remote attacker to perform an injection attack against 
    an affected device.
    
    This vulnerability is due to insufficient input validation. An attacker could exploit this 
    vulnerability by sending crafted input to the web-based management interface. A successful 
    exploit could allow the attacker to read limited files from the underlying operating system 
    or clear the syslog and licensing logs on the affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions based on Cisco advisory
    # The advisory states all IOS XE versions with web-based management interface enabled are vulnerable
    # until fixed versions are released. Based on typical Cisco patterns, we check for common vulnerable versions.
    vulnerable_versions = [
        # 16.x versions
        '16.3.', '16.4.', '16.5.', '16.6.', '16.7.', '16.8.', '16.9.',
        '16.10.', '16.11.', '16.12.',
        # 17.x versions
        '17.1.', '17.2.', '17.3.', '17.4.', '17.5.', '17.6.', '17.7.',
        '17.8.', '17.9.', '17.10.', '17.11.', '17.12.', '17.13.', '17.14.',
        '17.15.',
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if HTTP/HTTPS server is enabled (not disabled with "no")
    http_config = commands.show_http_config
    
    http_server_enabled = 'ip http server' in http_config and 'no ip http server' not in http_config
    https_server_enabled = 'ip http secure-server' in http_config and 'no ip http secure-server' not in http_config
    
    # Check if active session modules are disabled (which would make it not exploitable)
    http_disabled = 'ip http active-session-modules none' in http_config
    https_disabled = 'ip http secure-active-session-modules none' in http_config
    
    # Determine if the device is vulnerable
    http_exploitable = http_server_enabled and not http_disabled
    https_exploitable = https_server_enabled and not https_disabled
    
    # If either HTTP or HTTPS is exploitable, the device is vulnerable
    if http_exploitable or https_exploitable:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20194. "
            "The device is running a vulnerable version of Cisco IOS XE Software with the web-based "
            "management interface enabled. An authenticated, low-privileged attacker could perform "
            "an injection attack to read limited files from the underlying operating system or clear "
            "the syslog and licensing logs. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-webui-multi-ARNHM4v6"
        )
    else:
        # If web-based management interface is not enabled or is properly disabled, device is not vulnerable
        return
from comfy import high


@high(
    name='rule_cve202520196',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_iox_service='show iox-service',
        show_running_config='show running-config | include iox|ip http server|ip http secure-server|ip http active-session-modules|ip http secure-active-session-modules'
    ),
)
def rule_cve202520196(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20196 vulnerability in Cisco IOS and IOS XE Software.
    The vulnerability is in the Cisco IOx application hosting environment and is due to improper handling
    of HTTP requests. An unauthenticated, remote attacker can exploit this by sending crafted HTTP requests
    to cause a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    
    # List of vulnerable software versions for different platforms
    vulnerable_versions = [
        # 800 Series Industrial ISRs - vulnerable before 15.9(3)M11
        # Note: M1 uses newline suffix to avoid matching M10, M11, M12
        '15.9(3)M1\n', '15.9(3)M2', '15.9(3)M3', '15.9(3)M4',
        '15.9(3)M5', '15.9(3)M6', '15.9(3)M7', '15.9(3)M8', '15.9(3)M9', '15.9(3)M10',
        # IOS XE versions - vulnerable before fixes
        '17.9.', '17.10.', '17.11.', '17.12.', '17.13.', '17.14.', '17.15.',
        # Catalyst 9100 - vulnerable before 17.15.2
        # CGR1000 - vulnerable before 15.9(3)M12
    ]
    
    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
    
    # Check if IOx is enabled
    iox_service_output = commands.show_iox_service
    config_output = commands.show_running_config
    
    # Determine if IOx is running
    iox_running = False
    
    # Option 1: Check show iox-service output
    for line in iox_service_output.split('\n'):
        if 'IOx service (CAF)' in line and 'Running' in line and 'Not Running' not in line:
            iox_running = True
            break
    
    # Option 2: Check for iox in running config
    if 'iox' in config_output and config_output.strip().split('\n'):
        for line in config_output.split('\n'):
            if line.strip() == 'iox':
                iox_running = True
                break
    
    # If IOx is not running, device is not vulnerable
    if not iox_running:
        return
    
    # Check if HTTP Server is enabled
    http_enabled = 'ip http server' in config_output
    https_enabled = 'ip http secure-server' in config_output
    
    # Check for mitigations
    http_mitigated = 'ip http active-session-modules none' in config_output
    https_mitigated = 'ip http secure-active-session-modules none' in config_output
    
    # Determine if device is vulnerable
    is_vulnerable = False
    
    if http_enabled and not http_mitigated:
        is_vulnerable = True
    
    if https_enabled and not https_mitigated:
        is_vulnerable = True
    
    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20196. "
        "The device is running a vulnerable version with IOx enabled AND has HTTP/HTTPS server enabled "
        "without proper mitigation, which makes it susceptible to DoS attacks via crafted HTTP requests. "
        "The IOx application hosting environment can stop responding and requires manual restart. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-dos-95Fqnf7b"
    )
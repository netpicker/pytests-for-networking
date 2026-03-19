from comfy import medium

@medium(
    name='rule_cve202520196',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_iox_service='show iox-service',
        show_iox_config='show running-config | include iox',
        show_http_config='show running-config | include ip http server|secure|active'
    ),
)
def rule_cve202520196(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20196 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the Cisco IOx application hosting environment could allow an 
    unauthenticated, remote attacker to cause the Cisco IOx application hosting environment 
    to stop responding, resulting in a denial of service (DoS) condition.
    
    This vulnerability is due to the improper handling of HTTP requests. An attacker could 
    exploit this vulnerability by sending crafted HTTP requests to an affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 17.9.x versions (fixed in 17.9.7)
        '17.9.1', '17.9.2', '17.9.1a', '17.9.3', '17.9.2a', '17.9.3a', '17.9.4', '17.9.4a', '17.9.5', '17.9.6',
        # 17.10.x versions (all vulnerable)
        '17.10.1', '17.10.1a', '17.10.1b',
        # 17.11.x versions (all vulnerable)
        '17.11.1', '17.11.1a', '17.11.99SW',
        # 17.12.x versions (fixed in 17.12.5)
        '17.12.1', '17.12.1a', '17.12.2', '17.12.2a', '17.12.3', '17.12.4',
        # 17.13.x versions (all vulnerable)
        '17.13.1', '17.13.1a',
        # 17.14.x versions (all vulnerable)
        '17.14.1', '17.14.1a',
        # 17.15.x versions (fixed in 17.15.3)
        '17.15.1', '17.15.1a', '17.15.2',
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if IOx is enabled using show iox-service command
    iox_service_output = commands.show_iox_service
    # Check for Running but not "Not Running"
    iox_running = 'IOx service (CAF)' in iox_service_output and ': Running' in iox_service_output

    # Alternative check: look for 'iox' in running config
    iox_config_output = commands.show_iox_config
    iox_configured = iox_config_output.strip() == 'iox' or '\niox\n' in iox_config_output or iox_config_output.startswith('iox\n')

    # If IOx is not enabled, device is not vulnerable
    if not (iox_running or iox_configured):
        return

    # Check if HTTP Server is enabled
    http_config_output = commands.show_http_config
    http_server_enabled = 'ip http server' in http_config_output
    https_server_enabled = 'ip http secure-server' in http_config_output
    
    # Check for mitigation configurations
    http_mitigated = http_server_enabled and 'ip http active-session-modules none' in http_config_output
    https_mitigated = https_server_enabled and 'ip http secure-active-session-modules none' in http_config_output
    
    # If both HTTP and HTTPS are mitigated or neither is enabled, device is not vulnerable
    if not http_server_enabled and not https_server_enabled:
        return
    
    if http_server_enabled and not https_server_enabled and http_mitigated:
        return
    
    if https_server_enabled and not http_server_enabled and https_mitigated:
        return
    
    if http_server_enabled and https_server_enabled and http_mitigated and https_mitigated:
        return

    # Device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-20196. "
        "The device is running a vulnerable version with IOx enabled and HTTP/HTTPS server enabled. "
        "An unauthenticated, remote attacker could cause the Cisco IOx application hosting environment "
        "to stop responding, resulting in a denial of service (DoS) condition. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-dos-95Fqnf7b"
    )
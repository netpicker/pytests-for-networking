from comfy import high

@high(
    name='rule_cve202520154',
    platform=['cisco_ios-xr'],
    commands=dict(
        show_version='show version',
        show_running_config_twamp='show running-config ipsla server twamp',
        show_debug='show debug'
    ),
)
def rule_cve202520154(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20154 vulnerability in Cisco IOS XR Software.
    The vulnerability in the TWAMP server feature could cause the ipsla_ippm_server process
    to reload unexpectedly when debugs are enabled and crafted TWAMP control packets are received.
    
    For IOS XR, the device is vulnerable only if:
    1. Running a vulnerable version (24.2 and earlier, or 24.3.0-24.3.1)
    2. TWAMP server is enabled
    3. Debug command 'debug ipsla trace twamp connection' is active
    """

    # Extract command outputs
    show_version_output = commands.show_version
    show_running_config_twamp_output = commands.show_running_config_twamp
    show_debug_output = commands.show_debug

    # Define vulnerable version patterns for IOS XR
    # Vulnerable: 24.2 and earlier, 24.3.0, 24.3.1
    # Fixed: 24.3.2 and later, 24.4.1 and later
    vulnerable_version_patterns = [
        # 24.2 and earlier versions
        '24.2.', '24.1.', '24.0.',
        '23.', '22.', '21.', '20.', '19.', '18.', '17.', '16.', '15.',
        '14.', '13.', '12.', '11.', '10.', '9.', '8.', '7.', '6.', '5.',
        # 24.3.0 and 24.3.1
        '24.3.0', '24.3.1'
    ]

    # Check if running a vulnerable version
    is_vulnerable_version = any(pattern in show_version_output for pattern in vulnerable_version_patterns)

    # Check if TWAMP server is enabled
    # If the command returns 'ipsla server twamp', the feature is enabled
    twamp_enabled = 'ipsla server twamp' in show_running_config_twamp_output

    # Check if debug is enabled
    # Look for 'ipsla trace twamp connection' in debug output
    debug_enabled = 'ipsla trace twamp connection' in show_debug_output

    # Device is vulnerable only if all three conditions are met
    is_vulnerable = is_vulnerable_version and twamp_enabled and debug_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20154. "
        f"The device is running a vulnerable version of Cisco IOS XR Software with TWAMP server enabled and debugs active. "
        f"This vulnerability could cause the ipsla_ippm_server process to reload unexpectedly when processing crafted TWAMP control packets. "
        f"Mitigation: Upgrade to IOS XR 24.3.2 or later, or disable TWAMP server/debugs. "
        f"For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-twamp-kV4FHugn"
    )
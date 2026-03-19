from comfy import high

@high(
    name='rule_cve202520188',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_wireless_config='show running-config | section wireless',
        show_ap_file_transfer='show ap file-transfer https summary',
        show_device_type='show version | include Catalyst'
    ),
)
def rule_cve202520188(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20188 vulnerability in Cisco IOS XE Software
    for Wireless LAN Controllers (WLCs).
    
    A vulnerability in the Out-of-Band Access Point (AP) Image Download, the Clean Air
    Spectral Recording, and the client debug bundles features could allow an unauthenticated,
    remote attacker to upload arbitrary files to an affected system.
    
    This vulnerability is due to the presence of a hard-coded JSON Web Token (JWT) on an
    affected system. An attacker could exploit this vulnerability by sending crafted HTTPS
    requests to the AP file upload interface.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    
    # List of vulnerable software versions (versions before fixes)
    # Based on Cisco advisory, this affects IOS XE WLC software
    vulnerable_versions = [
        # 17.x versions
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.2a', '17.3.4', '17.3.5', '17.3.4a', '17.3.6', '17.3.4b',
        '17.3.4c', '17.3.5a', '17.3.5b', '17.3.7', '17.3.8', '17.3.8a',
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        '17.5.1', '17.5.1a',
        '17.6.1', '17.6.2', '17.6.1a', '17.6.3', '17.6.3a', '17.6.4', '17.6.5', '17.6.6', '17.6.6a', '17.6.5a',
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        '17.8.1', '17.8.1a',
        '17.9.1', '17.9.2', '17.9.1a', '17.9.3', '17.9.2a', '17.9.3a', '17.9.4', '17.9.4a',
        '17.10.1', '17.10.1a', '17.10.1b',
        '17.11.1', '17.11.1a', '17.11.99SW',
        '17.12.1', '17.12.1a', '17.12.2', '17.12.2a',
        '17.13.1', '17.13.1a',
        '17.14.1', '17.14.1a',
        '17.15.1'
    ]
    
    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)
    
    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return
    
    # Check if this is a WLC device (Catalyst 9800 series or embedded WLC)
    device_type_output = commands.show_device_type
    is_wlc_device = any(model in device_type_output for model in [
        'Catalyst 9800',
        '9800-CL',
        '9800-L',
        '9800-40',
        '9800-80',
        'C9800',
        'Embedded Wireless Controller'
    ])
    
    # Check if wireless configuration exists
    wireless_config = commands.show_wireless_config
    has_wireless_config = 'wireless' in wireless_config.lower() or len(wireless_config.strip()) > 0
    
    # Check if AP file transfer interface is operational
    ap_file_transfer_output = commands.show_ap_file_transfer
    ap_file_transfer_enabled = 'Operational port' in ap_file_transfer_output
    
    # Device is vulnerable if:
    # 1. Running vulnerable version
    # 2. Is a WLC device OR has wireless configuration
    # 3. AP file transfer interface is operational
    if (is_wlc_device or has_wireless_config) and ap_file_transfer_enabled:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20188. "
            "The device is running a vulnerable IOS XE version with Wireless LAN Controller functionality "
            "and has the AP file upload interface operational. This vulnerability allows an unauthenticated, "
            "remote attacker to upload arbitrary files and execute commands with root privileges due to a "
            "hard-coded JWT token. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-file-uplpd-rHZG9UfC"
        )
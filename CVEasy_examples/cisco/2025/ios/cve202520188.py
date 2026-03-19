import re

from comfy import high


@high(
    name='rule_cve202520188',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_ap_file_transfer='show ap file-transfer https summary',
        show_running_config='show running-config'
    ),
)
def rule_cve202520188(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20188 vulnerability in Cisco IOS XE Wireless Controller Software.
    The vulnerability is due to the presence of a hard-coded JSON Web Token (JWT) that allows an unauthenticated,
    remote attacker to upload arbitrary files to an affected system and execute arbitrary commands with root privileges.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is a Cisco IOS XE device functioning as a WLC
    is_ios_xe = 'IOS XE' in version_output or 'Cisco IOS XE Software' in version_output
    
    # Check if device is a Wireless LAN Controller
    is_wlc = any(keyword in version_output for keyword in [
        'Catalyst 9800',
        'C9800',
        'Wireless Controller',
        'WLC'
    ])

    # If not IOS XE or not a WLC, device is not vulnerable
    if not is_ios_xe or not is_wlc:
        return

    # List of vulnerable software versions (based on advisory - all versions prior to fixed releases)
    # The advisory indicates this affects Cisco IOS XE Software for WLCs
    # We'll check for common vulnerable version patterns
    vulnerable_version_patterns = [
        '17.3', '17.4', '17.5', '17.6', '17.7', '17.8', '17.9',
        '17.10', '17.11', '17.12', '17.13', '17.14', '17.15'
    ]

    # Check if the current device's software version matches vulnerable patterns
    version_vulnerable = any(pattern in version_output for pattern in vulnerable_version_patterns)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if AP file transfer HTTPS interface is operational
    ap_file_transfer_output = commands.show_ap_file_transfer
    
    # The AP file upload interface is operational if the operational port shows a port number (not "disabled")
    ap_file_transfer_enabled = bool(re.search(r'Operational port\s*:\s*\d+', ap_file_transfer_output))

    # If AP file transfer interface is not enabled, device is not vulnerable
    if not ap_file_transfer_enabled:
        return

    # If we reach here, the device is vulnerable
    is_vulnerable = True

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20188. "
        "The device is running Cisco IOS XE Software for WLCs with a hard-coded JWT token "
        "that allows unauthenticated remote attackers to upload arbitrary files and execute commands with root privileges. "
        "The AP file upload interface (port 8443) is operational, making the device exploitable. "
        "Apply mitigations immediately by blocking port 8443 or restricting access via iACLs. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wlc-file-uplpd-rHZG9UfC"
    )
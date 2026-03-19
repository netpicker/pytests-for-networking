from comfy import high

@high(
    name='rule_cve202520311',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_trunk='show running-config | include switchport mode trunk|dynamic|dot1q-tunnel',
        show_trustsec='show running-config | include cts manual',
        show_macsec='show macsec summary'
    ),
)
def rule_cve202520311(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20311 vulnerability in Cisco IOS XE Software
    for Catalyst 9000 Series Switches.
    
    The vulnerability allows an unauthenticated, adjacent attacker to cause an egress port
    to become blocked and drop all outbound traffic by sending crafted Ethernet frames.
    
    Affected devices must be:
    - Running a vulnerable version of Cisco IOS XE Software
    - Have one of the following enabled:
      * Trunk port
      * Cisco TrustSec-enabled port
      * MACsec-enabled port
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (versions before fixes)
    # Based on advisory, vulnerable versions include releases before 17.15.4 and Meraki CS before 17.2.2
    vulnerable_versions = [
        # 16.x versions
        '16.3.1', '16.3.2', '16.3.3', '16.3.1a', '16.3.4', '16.3.5', '16.3.5b', '16.3.6', '16.3.7', '16.3.8',
        '16.3.9', '16.3.10', '16.3.11',
        '16.4.1', '16.4.2', '16.4.3',
        '16.5.1', '16.5.1a', '16.5.1b', '16.5.2', '16.5.3',
        '16.6.1', '16.6.2', '16.6.3', '16.6.4', '16.6.5', '16.6.4a', '16.6.5a', '16.6.6', '16.6.7', '16.6.8',
        '16.6.9', '16.6.10',
        '16.7.1', '16.7.2', '16.7.3',
        '16.8.1', '16.8.1a', '16.8.1b', '16.8.1s', '16.8.1c', '16.8.2', '16.8.3',
        '16.9.1', '16.9.2', '16.9.1a', '16.9.1b', '16.9.1s', '16.9.3', '16.9.4', '16.9.3a', '16.9.5', '16.9.5f',
        '16.9.6', '16.9.7', '16.9.8',
        '16.10.1', '16.10.1a', '16.10.1b', '16.10.1s', '16.10.1e', '16.10.2', '16.10.3',
        '16.11.1', '16.11.1a', '16.11.1b', '16.11.2', '16.11.1s',
        '16.12.1', '16.12.1s', '16.12.1a', '16.12.1c', '16.12.2', '16.12.2a', '16.12.3', '16.12.8', '16.12.2s',
        '16.12.1t', '16.12.4', '16.12.3s', '16.12.3a', '16.12.4a', '16.12.5', '16.12.6', '16.12.5a', '16.12.5b',
        '16.12.6a', '16.12.7', '16.12.9', '16.12.10', '16.12.10a', '16.12.11',
        # 17.x versions (before 17.15.4)
        '17.1.1', '17.1.1a', '17.1.1s', '17.1.1t', '17.1.2', '17.1.3',
        '17.2.1', '17.2.1r', '17.2.1a', '17.2.1v', '17.2.2', '17.2.3',
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
        '17.12.1', '17.12.1a', '17.12.2', '17.12.2a', '17.12.3', '17.12.4',
        '17.13.1', '17.13.1a', '17.13.2', '17.13.3',
        '17.14.1', '17.14.1a', '17.14.2', '17.14.3',
        '17.15.1', '17.15.1a', '17.15.2', '17.15.3'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if trunk port is enabled
    trunk_enabled = bool(commands.show_trunk.strip())
    
    # Check if TrustSec is enabled
    trustsec_enabled = 'cts manual' in commands.show_trustsec
    
    # Check if MACsec is enabled (output contains interface information)
    macsec_output = commands.show_macsec
    macsec_enabled = 'Gi' in macsec_output or 'Te' in macsec_output or 'Fo' in macsec_output or 'Tw' in macsec_output or 'Hu' in macsec_output

    # If any of the vulnerable configurations are present, the device is vulnerable
    if trunk_enabled or trustsec_enabled or macsec_enabled:
        vulnerable_features = []
        if trunk_enabled:
            vulnerable_features.append('trunk port')
        if trustsec_enabled:
            vulnerable_features.append('TrustSec-enabled port')
        if macsec_enabled:
            vulnerable_features.append('MACsec-enabled port')
        
        features_str = ', '.join(vulnerable_features)
        
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20311. "
            f"The device is running a vulnerable version of Cisco IOS XE Software AND has {features_str} enabled. "
            "An unauthenticated, adjacent attacker could cause an egress port to become blocked and drop all outbound traffic. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cat9k-PtmD7bgy"
        )
    else:
        # If none of the vulnerable configurations are present, the device is not vulnerable
        return
from comfy import high


@high(
    name='rule_cve202520311',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_trunk_config='show running-config | include switchport mode trunk|dynamic|dot1q-tunnel',
        show_cts_config='show running-config | include cts manual',
        show_macsec='show macsec summary'
    ),
)
def rule_cve202520311(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20311 vulnerability in Cisco IOS XE Software 
    for Catalyst 9000 Series Switches. The vulnerability is due to improper handling of crafted 
    Ethernet frames, which can be exploited by an unauthenticated, adjacent attacker to cause 
    an egress port to become blocked and drop all outbound traffic, resulting in a DoS condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is a Catalyst 9000 Series Switch
    catalyst_9000_models = [
        'Catalyst 9200', 'Catalyst 9300', 'Catalyst 9400', 
        'Catalyst 9500', 'Catalyst 9600', 'Meraki MS390'
    ]
    
    is_catalyst_9000 = any(model in version_output for model in catalyst_9000_models)
    
    # If not a Catalyst 9000 series, device is not vulnerable
    if not is_catalyst_9000:
        return

    # List of vulnerable software versions (versions before fixes)
    # Based on advisory, vulnerable versions are before 17.15.4 for certain platforms
    # Prefixing with 'Version ' to avoid substring matches (e.g., '15.' matching '17.15.4')
    vulnerable_version_patterns = [
        'Version 17.1.', 'Version 17.2.', 'Version 17.3.', 'Version 17.4.', 'Version 17.5.', 'Version 17.6.', 
        'Version 17.7.', 'Version 17.8.', 'Version 17.9.', 'Version 17.10.', 'Version 17.11.', 'Version 17.12.',
        'Version 17.13.', 'Version 17.14.', 'Version 17.15.1', 'Version 17.15.2', 'Version 17.15.3',
        'Version 16.', 'Version 15.'
    ]

    # Check if the current device's software version is vulnerable
    version_vulnerable = any(version in version_output for version in vulnerable_version_patterns)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # If version is vulnerable, check for enabled features that make it exploitable
    trunk_config = commands.show_trunk_config
    cts_config = commands.show_cts_config
    macsec_output = commands.show_macsec

    # Check if trunk port is enabled
    trunk_enabled = bool(trunk_config and trunk_config.strip())

    # Check if Cisco TrustSec is enabled
    cts_enabled = bool(cts_config and cts_config.strip())

    # Check if MACsec is enabled (look for interfaces in output)
    macsec_enabled = False
    if macsec_output:
        lines = macsec_output.strip().split('\n')
        # If there are more than just header lines, MACsec is enabled on interfaces
        macsec_enabled = len(lines) > 1 and any('Gi' in line or 'Te' in line or 'Fo' in line for line in lines)

    # Device is vulnerable if any of these features are enabled
    is_vulnerable = trunk_enabled or cts_enabled or macsec_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20311. "
        "The device is running a vulnerable version of Cisco IOS XE Software AND has "
        "trunk ports, Cisco TrustSec-enabled ports, or MACsec-enabled ports configured, "
        "which makes it susceptible to DoS attacks via crafted Ethernet frames. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cat9k-PtmD7bgy"
    )
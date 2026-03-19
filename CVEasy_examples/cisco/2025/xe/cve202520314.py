from comfy import high

@high(
    name='rule_cve202520314',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_bootflash='dir bootflash:',
        show_flash='dir flash:',
    ),
)
def rule_cve202520314(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20314 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in Cisco IOS XE Software could allow an authenticated, local attacker 
    with level-15 privileges or an unauthenticated attacker with physical access to an 
    affected device to execute persistent code at boot time and break the chain of trust.
    
    This vulnerability is due to improper validation of software packages. An attacker 
    could exploit this vulnerability by placing a crafted file into a specific location 
    on an affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Vulnerable platforms and their first affected releases
    vulnerable_platforms = {
        '1000 Series Integrated Services Router': '17.8.1',
        '1100 Terminal Services Gateway': '17.7.1',
        '4000 Series Integrated Services Router': '17.3.1',
        '8100 Series Secure Router': '17.15.1',
        '8400 Series Secure Router': '17.12.1',
        'ASR 1000 Series Aggregation Services Router': '17.7.1',
        'C8375-E-G2': '17.15.3',
        'Catalyst 8200': '17.8.1',
        'Catalyst 8300': '17.8.1',
        'Catalyst 8500L': '17.8.1',
        'Catalyst 9200': '17.8.1',
        'Catalyst ESS9300': '17.13.1',
        'Catalyst IE3100 Heavy Duty': '17.17.1',
        'Catalyst IE3100 Rugged': '17.12.1',
        'Catalyst IR1100': '17.13.1',
        'Catalyst IR8100': '17.4.1',
        'Catalyst IR8300': '17.7.1',
        'Catalyst IE9300': '17.13.1',
        'IE3500 Heavy Duty': '17.17.1',
        'IE3500 Rugged': '17.17.1',
        'VG410': '17.17.1',
    }

    # List of vulnerable software versions (17.3.1 and later)
    vulnerable_versions = [
        # 17.3.x versions
        '17.3.1', '17.3.2', '17.3.3', '17.3.1a', '17.3.2a', '17.3.4', '17.3.5', '17.3.4a', '17.3.6', '17.3.4b',
        '17.3.4c', '17.3.5a', '17.3.5b', '17.3.7', '17.3.8', '17.3.8a',
        # 17.4.x versions
        '17.4.1', '17.4.2', '17.4.1a', '17.4.1b', '17.4.2a',
        # 17.5.x versions
        '17.5.1', '17.5.1a',
        # 17.6.x versions
        '17.6.1', '17.6.2', '17.6.1a', '17.6.3', '17.6.3a', '17.6.4', '17.6.5', '17.6.6', '17.6.6a', '17.6.5a',
        # 17.7.x versions
        '17.7.1', '17.7.1a', '17.7.1b', '17.7.2',
        # 17.8.x versions
        '17.8.1', '17.8.1a',
        # 17.9.x versions
        '17.9.1', '17.9.2', '17.9.1a', '17.9.3', '17.9.2a', '17.9.3a', '17.9.4', '17.9.4a',
        # 17.10.x versions
        '17.10.1', '17.10.1a', '17.10.1b',
        # 17.11.x versions
        '17.11.1', '17.11.1a', '17.11.99SW',
        # 17.12.x versions
        '17.12.1', '17.12.1a', '17.12.2', '17.12.2a',
        # 17.13.x versions
        '17.13.1', '17.13.1a',
        # 17.14.x versions
        '17.14.1', '17.14.1a',
        # 17.15.x versions
        '17.15.1', '17.15.1a', '17.15.2', '17.15.3',
        # 17.16.x versions
        '17.16.1', '17.16.1a',
        # 17.17.x versions
        '17.17.1', '17.17.1a',
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if device is an affected platform
    platform_vulnerable = any(platform in version_output for platform in vulnerable_platforms.keys())

    if not platform_vulnerable:
        return

    # Check for suspicious files in bootflash or flash that could indicate exploitation
    # This vulnerability involves placing crafted files in specific locations
    bootflash_output = commands.show_bootflash
    flash_output = commands.show_flash

    # Look for indicators of crafted packages or suspicious files
    suspicious_indicators = [
        '.pkg',
        '.bin',
        'crafted',
        'unsigned',
    ]

    # Note: This is a detection heuristic. The actual exploitation would require
    # physical access or level-15 privileges, which cannot be fully detected via
    # command output alone. This check looks for the vulnerable condition.
    
    # The primary vulnerability is that the device CAN be exploited if an attacker
    # has the required access (physical or level-15). Since we cannot detect
    # if an attacker has already exploited this, we flag all vulnerable versions
    # on vulnerable platforms as potentially at risk.

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-20314. "
        "The device is running a vulnerable version of Cisco IOS XE Software on an affected platform. "
        "This vulnerability allows an authenticated attacker with level-15 privileges or an unauthenticated "
        "attacker with physical access to execute persistent code at boot time and break the chain of trust. "
        "Upgrade to a fixed software version immediately. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-secboot-UqFD8AvC"
    )
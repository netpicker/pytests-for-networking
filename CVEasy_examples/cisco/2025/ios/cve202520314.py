from comfy import high


@high(
    name='rule_cve202520314',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_bootvar='show bootvar',
        show_boot='show boot'
    ),
)
def rule_cve202520314(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20314 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to improper validation of software packages, which could allow an
    authenticated, local attacker with level-15 privileges or an unauthenticated attacker with
    physical access to execute persistent code at boot time and break the chain of trust.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable platforms and their first affected releases
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
        'VG410': '17.17.1'
    }

    # Check if running IOS XE Software
    is_ios_xe = 'IOS XE Software' in version_output or 'Cisco IOS XE' in version_output

    if not is_ios_xe:
        # Not IOS XE, not vulnerable
        return

    # Extract version number
    version_vulnerable = False
    current_version = None
    
    # Parse version from output (e.g., "Version 17.8.1" or "17.8.1")
    import re
    version_match = re.search(r'Version\s+(\d+\.\d+\.\d+)', version_output)
    if version_match:
        current_version = version_match.group(1)
        
        # Extract major.minor.patch
        version_parts = current_version.split('.')
        if len(version_parts) >= 3:
            major = int(version_parts[0])
            minor = int(version_parts[1])
            patch = int(version_parts[2])
            
            # Check if version is 17.3.1 or later (vulnerable range starts at 17.3.1)
            if major > 17:
                version_vulnerable = True
            elif major == 17:
                if minor > 3:
                    version_vulnerable = True
                elif minor == 3 and patch >= 1:
                    version_vulnerable = True
                elif minor < 3:
                    # Check for specific lower versions that might be vulnerable
                    for platform, first_affected in vulnerable_platforms.items():
                        if platform.lower() in version_output.lower():
                            first_parts = first_affected.split('.')
                            first_major = int(first_parts[0])
                            first_minor = int(first_parts[1])
                            first_patch = int(first_parts[2])
                            
                            if (major > first_major or 
                                (major == first_major and minor > first_minor) or
                                (major == first_major and minor == first_minor and patch >= first_patch)):
                                version_vulnerable = True
                                break

    # Check if device is a vulnerable platform
    platform_vulnerable = False
    for platform in vulnerable_platforms.keys():
        if platform.lower() in version_output.lower():
            platform_vulnerable = True
            break

    # Device is vulnerable if it's a vulnerable platform running a vulnerable version
    is_vulnerable = platform_vulnerable and version_vulnerable

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20314. "
        "The device is running a vulnerable version of Cisco IOS XE Software on an affected platform. "
        "This vulnerability allows an authenticated attacker with level-15 privileges or an unauthenticated "
        "attacker with physical access to execute persistent code at boot time and break the chain of trust. "
        "Upgrade to a fixed software release. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-secboot-UqFD8AvC"
    )
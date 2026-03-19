from comfy import high

@high(
    name='rule_cve202520313',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_bootflash='dir bootflash:',
        show_flash='dir flash:',
        show_privilege='show privilege'
    ),
)
def rule_cve202520313(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20313 vulnerability in Cisco IOS XE Software.
    
    The vulnerability allows an authenticated, local attacker with level-15 privileges or an
    unauthenticated attacker with physical access to execute persistent code at boot time and
    break the chain of trust. This is due to path traversal and improper image integrity validation.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions and their first affected releases
    # Based on the advisory, devices are vulnerable starting from specific releases
    vulnerable_version_patterns = [
        '17.3.1', '17.3.2', '17.3.3', '17.3.4', '17.3.5', '17.3.6', '17.3.7', '17.3.8',
        '17.4.1', '17.4.2', '17.4.3', '17.4.4',
        '17.7.1', '17.7.2', '17.7.3',
        '17.8.1', '17.8.2', '17.8.3',
        '17.12.1', '17.12.2', '17.12.3',
        '17.13.1', '17.13.2', '17.13.3',
        '17.15.1', '17.15.2', '17.15.3',
        '17.17.1', '17.17.2', '17.17.3'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_version_patterns)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check privilege level - vulnerability requires level-15 privileges or physical access
    privilege_output = commands.show_privilege
    has_high_privilege = 'level 15' in privilege_output or 'Current privilege level is 15' in privilege_output

    # Check for suspicious files in bootflash or flash that could indicate exploitation
    bootflash_output = commands.show_bootflash
    flash_output = commands.show_flash

    # Look for indicators of crafted files or path traversal attempts
    suspicious_patterns = [
        '../',
        '..\\',
        '.bin.tmp',
        'unauthorized'
    ]

    bootflash_suspicious = any(pattern in bootflash_output for pattern in suspicious_patterns)
    flash_suspicious = any(pattern in flash_output for pattern in suspicious_patterns)

    # Device is vulnerable if running vulnerable version and has high privileges
    # or shows signs of suspicious files
    if version_vulnerable and (has_high_privilege or bootflash_suspicious or flash_suspicious):
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20313. "
            "The device is running a vulnerable version of Cisco IOS XE Software that allows "
            "authenticated attackers with level-15 privileges or physical access to execute "
            "persistent code at boot time and break the chain of trust. "
            "Upgrade to a fixed software release immediately. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-secboot-UqFD8AvC"
        )
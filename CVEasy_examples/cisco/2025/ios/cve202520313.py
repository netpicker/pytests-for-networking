from comfy import high


@high(
    name='rule_cve202520313',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_boot='show boot'
    ),
)
def rule_cve202520313(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20313 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to path traversal and improper image integrity validation, which allows
    an authenticated, local attacker with level-15 privileges or an unauthenticated attacker with
    physical access to execute persistent code at boot time and break the chain of trust.
    """
    version_output = commands.show_version

    # Check if running IOS XE Software
    if 'IOS XE Software' not in version_output and 'Cisco IOS XE' not in version_output:
        return

    # List of vulnerable platforms
    vulnerable_platforms = [
        '1000 Series Integrated Services Router',
        '1100 Terminal Services Gateway',
        '4000 Series Integrated Services Router',
        '8100 Series',
        '8400 Series',
        'ASR 1000',
        'C8375-E-G2',
        'Catalyst 8200',
        'Catalyst 8300',
        'Catalyst 8500L',
        'Catalyst 9200',
        'Catalyst ESS9300',
        'IE3100 Rugged',
        'IE3100 Heavy Duty',
        'Catalyst IR1100',
        'Catalyst IR8100',
        'Catalyst IR8300',
        'Catalyst IE9300',
        'IE3500 Heavy Duty',
        'IE3500 Rugged',
        'VG410'
    ]

    # Check if device platform is vulnerable
    is_vulnerable_platform = any(platform in version_output for platform in vulnerable_platforms)
    if not is_vulnerable_platform:
        return

    # Vulnerable version patterns (17.3.x and later up to fixes)
    vulnerable_version_patterns = [
        'Version 17.3.', 'Version 17.4.', 'Version 17.5.', 'Version 17.6.',
        'Version 17.7.', 'Version 17.8.', 'Version 17.9.', 'Version 17.10.',
        'Version 17.11.', 'Version 17.12.', 'Version 17.13.', 'Version 17.14.',
        'Version 17.15.'
    ]

    version_vulnerable = any(v in version_output for v in vulnerable_version_patterns)
    if not version_vulnerable:
        return

    # Device is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-20313. "
        "The device is running a vulnerable version of Cisco IOS XE Software that is susceptible to "
        "Secure Boot bypass vulnerabilities due to improper validation of software packages. "
        "An authenticated attacker with level-15 privileges or an unauthenticated attacker with physical access "
        "could execute persistent code at boot time and break the chain of trust. "
        "Upgrade to a fixed software release. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-secboot-UqFD8AvC"
    )
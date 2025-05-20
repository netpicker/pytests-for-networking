from comfy import high


@high(
    name='rule_cve20211376',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_reload='show running-config | include reload|boot'
    ),
)
def rule_cve20211376(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1376 vulnerability in Cisco IOS XE Software.
    The vulnerability in the fast reload feature could allow an authenticated, local attacker
    with high privileges to execute arbitrary code, install malicious images, or execute
    unsigned binaries on affected Catalyst 3850, 9300, and 9300L Series Switches.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a vulnerable platform (Catalyst 3850, 9300, or 9300L Series)
    platform_output = commands.check_platform
    vulnerable_platforms = ['C3850', 'C9300']

    if not any(platform in platform_output for platform in vulnerable_platforms):
        return

    # Check for fast reload configuration
    reload_config = commands.check_reload
    fast_reload_enabled = any(feature in reload_config for feature in [
        'reload fast',
        'boot system flash'
    ])

    # If fast reload is enabled, device is potentially vulnerable
    assert not fast_reload_enabled, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1376. "
        "The device is a Catalyst 3850/9300 Series Switch with fast reload feature enabled, "
        "which could allow an authenticated local attacker with high privileges to execute "
        "arbitrary code or bypass secure boot. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fast-Zqr6DD5"
    )

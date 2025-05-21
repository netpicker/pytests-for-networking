from comfy import high


@high(
    name='rule_cve20211381',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_debug='show running-config | include debug|dragonite'
    ),
)
def rule_cve20211381(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1381 vulnerability in Cisco IOS XE Software.
    The vulnerability could allow an authenticated, local attacker with high privileges or an
    unauthenticated attacker with physical access to open a debugging console due to
    insufficient command authorization restrictions.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for debug configuration
    debug_config = commands.check_debug
    debug_enabled = any(feature in debug_config for feature in [
        'debug privilege',
        'debug all',
        'dragonite',
        'debug dragonite'
    ])

    # If debugging features are enabled, device is potentially vulnerable
    assert not debug_enabled, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1381. "
        "The device has debugging features enabled, which could allow an authenticated local attacker "
        "with high privileges or an unauthenticated attacker with physical access to open a debugging console. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-BLKH-Ouvrnf2s"
    )

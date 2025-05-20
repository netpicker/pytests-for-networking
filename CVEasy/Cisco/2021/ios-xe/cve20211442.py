from comfy import high


@high(
    name='rule_cve20211442',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_pnp='show running-config | include pnp|username.*privilege'
    ),
)
def rule_cve20211442(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1442 vulnerability in Cisco IOS XE Software.
    The vulnerability in the PnP subsystem could allow an authenticated, local attacker with low
    privileges to elevate privileges to level 15 by issuing the diagnostic CLI show pnp profile
    command when a specific PnP listener is enabled.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check for PnP configuration and low-privileged users
    config = commands.check_pnp

    # Check if PnP is enabled
    pnp_enabled = 'pnp' in config

    # Check for users with low privileges (not privilege 15)
    has_low_priv_users = any(
        'privilege' in line and 'privilege 15' not in line
        for line in config.splitlines()
    )

    # Device is vulnerable if running PnP with low-privileged users
    is_vulnerable = pnp_enabled and has_low_priv_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1442. "
        "The device has PnP enabled with low-privileged users configured, which could allow "
        "an authenticated local attacker to elevate privileges through diagnostic commands. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-pnp-priv-esc-AmG3kuVL"
    )

from comfy import high


@high(
    name='rule_cve20211590',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_login_block='show running-config | include system login block-for'
    ),
)
def rule_cve20211590(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1590 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to a logic error in the implementation of the system login block-for
    command when an attack is detected and acted upon. An unauthenticated, remote attacker could
    exploit this vulnerability by performing a brute-force login attack on an affected device,
    causing a login process to reload and resulting in authentication delays.
    """
    # Extract the output of the command to check login block configuration
    login_block_output = commands.check_login_block

    # Check if system login block-for is configured
    login_block_enabled = 'system login block-for' in login_block_output

    # If login block is not enabled, device is not vulnerable
    if not login_block_enabled:
        return

    # Assert that the device is not vulnerable
    assert not login_block_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-1590. "
        "The device has system login block-for configured, which could allow an unauthenticated attacker "
        "to cause a login process to reload through brute-force login attempts. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-login-blockfor-RwjGVEcu"
    )

from comfy import high


@high(
    name='rule_cve20211584',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_admin='show user-account | include network-admin|admin'
    ),
)
def rule_cve20211584(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1584 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to insufficient restrictions during the execution of a specific CLI command.
    An authenticated, local attacker with administrative privileges could exploit this vulnerability
    by performing a command injection attack on the vulnerable command, allowing them to access
    the underlying operating system as root.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    admin_output = commands.check_admin

    # Check if device is a Nexus 9000 in ACI mode
    is_n9k_aci = 'Nexus 9000' in version_output and 'ACI' in version_output

    # If not a Nexus 9000 in ACI mode, device is not vulnerable
    if not is_n9k_aci:
        return

    # Check if there are admin users configured
    admin_users = any(role in admin_output for role in [
        'network-admin',
        'admin'
    ])

    # Device is vulnerable if it's a Nexus 9000 in ACI mode with admin users
    is_vulnerable = is_n9k_aci and admin_users

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-1584. "
        "The device is a Nexus 9000 in ACI mode with administrator users configured, which could allow "
        "an authenticated attacker with admin privileges to execute arbitrary commands as root through "
        "command injection. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-naci-mdvul-vrKVgNU"
    )

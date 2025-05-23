from comfy import high


@high(
    name='rule_cve20211591',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_acl_portchannel='show running-config | include interface port-channel|ip access-group'
    ),
)
def rule_cve20211591(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1591 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to oversubscription of resources that occurs when applying ACLs
    to port channel interfaces. An unauthenticated, remote attacker could exploit this
    vulnerability by attempting to access network resources that are protected by the ACL,
    potentially bypassing access control list rules configured on the affected device.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    acl_config = commands.check_acl_portchannel

    # Check if device is a Nexus 9500
    is_n9k_9500 = 'Nexus 9500' in version_output

    # If not a Nexus 9500, device is not vulnerable
    if not is_n9k_9500:
        return

    # Check if there are ACLs applied to port-channel interfaces
    has_portchannel = 'interface port-channel' in acl_config
    has_acl = 'ip access-group' in acl_config

    # Device is vulnerable if it's a Nexus 9500 with ACLs on port-channels
    is_vulnerable = is_n9k_9500 and has_portchannel and has_acl

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-1591. "
        "The device is a Nexus 9500 with ACLs applied to port-channel interfaces, which could allow "
        "an unauthenticated attacker to bypass ACL rules through resource oversubscription. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nexus-acl-vrvQYPVe"
    )

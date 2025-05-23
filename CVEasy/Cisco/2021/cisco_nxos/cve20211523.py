from comfy import high


@high(
    name='rule_cve20211523',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_svi='show running-config | include interface vlan|svi'
    ),
)
def rule_cve20211523(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1523 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to mishandling of ingress TCP traffic to a specific port.
    An unauthenticated, remote attacker could exploit this vulnerability by sending a stream
    of TCP packets to a specific port on a Switched Virtual Interface (SVI), causing a queue
    wedge that could result in critical control plane traffic being dropped and leaf switches
    being removed from the fabric.
    Note: Manual intervention (power-cycle) is required to recover from this condition.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    svi_output = commands.check_svi

    # Check if device is a Nexus 9000 in ACI mode
    is_n9k_aci = 'Nexus 9000' in version_output and 'ACI' in version_output

    # If not a Nexus 9000 in ACI mode, device is not vulnerable
    if not is_n9k_aci:
        return

    # Check if SVIs are configured
    svi_configured = 'interface vlan' in svi_output

    # Device is vulnerable if it's a Nexus 9000 in ACI mode with SVIs configured
    is_vulnerable = is_n9k_aci and svi_configured

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-1523. "
        "The device is a Nexus 9000 in ACI mode with SVIs configured, which could allow an unauthenticated attacker "
        "to cause a queue wedge and denial of service through crafted TCP packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9kaci-queue-wedge-cLDDEfKF"
    )

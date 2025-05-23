from comfy import high


@high(
    name='rule_cve20211230',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_bgp='show running-config | include router bgp|fabric-mode'
    ),
)
def rule_cve20211230(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1230 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to improper route installation upon receipt of BGP updates
    in ACI mode. An unauthenticated, remote attacker could exploit this vulnerability by
    sending crafted BGP update messages over an established TCP connection that appears
    to come from a trusted BGP peer, causing the routing process to crash and the device
    to reload. This vulnerability affects both IBGP and EBGP.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    bgp_output = commands.check_bgp

    # Check if device is a Nexus 9000 in ACI mode
    is_n9k_aci = 'Nexus 9000' in version_output and 'ACI' in version_output

    # If not a Nexus 9000 in ACI mode, device is not vulnerable
    if not is_n9k_aci:
        return

    # Check if BGP is enabled and device is in fabric mode
    bgp_enabled = 'router bgp' in bgp_output
    fabric_mode = 'fabric-mode' in bgp_output

    # Device is vulnerable if it's a Nexus 9000 in ACI mode with BGP enabled and in fabric mode
    is_vulnerable = is_n9k_aci and bgp_enabled and fabric_mode

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-1230. "
        "The device is a Nexus 9000 in ACI mode with BGP enabled and in fabric mode, "
        "which could allow an attacker to cause a denial of service through crafted BGP updates. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9kaci-bgp-De9dPKSK"
    )

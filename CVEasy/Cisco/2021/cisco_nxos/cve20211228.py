from comfy import high


@high(
    name='rule_cve20211228',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_lldp='show running-config | include lldp|fabric-mode'
    ),
)
def rule_cve20211228(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1228 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to insufficient security requirements during the LLDP setup phase
    of the infrastructure VLAN in ACI mode. An unauthenticated, adjacent attacker could exploit
    this vulnerability by sending crafted LLDP packets to an affected device, allowing them to
    connect an unauthorized server to the infrastructure VLAN and potentially access APIC services.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    lldp_output = commands.check_lldp

    # Check if device is a Nexus 9000 in ACI mode
    is_n9k_aci = 'Nexus 9000' in version_output and 'ACI' in version_output

    # If not a Nexus 9000 in ACI mode, device is not vulnerable
    if not is_n9k_aci:
        return

    # Check if LLDP is enabled and device is in fabric mode
    lldp_enabled = 'feature lldp' in lldp_output
    fabric_mode = 'fabric-mode' in lldp_output

    # Device is vulnerable if it's a Nexus 9000 in ACI mode with LLDP enabled and in fabric mode
    is_vulnerable = is_n9k_aci and lldp_enabled and fabric_mode

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-1228. "
        "The device is a Nexus 9000 in ACI mode with LLDP enabled and in fabric mode, "
        "which could allow an adjacent attacker to connect unauthorized servers to the infrastructure VLAN. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n9kaci-unauth-access-5PWzDx2w"
    )

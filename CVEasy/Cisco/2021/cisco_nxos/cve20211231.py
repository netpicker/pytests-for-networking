
from comfy import high


@high(
    name='rule_cve20211231',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_lldp='show running-config | include lldp|interface'
    ),
)
def rule_cve20211231(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1231 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to incomplete validation of the source of received LLDP packets
    on SFP interfaces. An unauthenticated, adjacent attacker could exploit this vulnerability
    by sending crafted LLDP packets to an SFP interface, allowing them to disable switching
    on that interface and disrupt network traffic.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    _ = version_output
    lldp_output = commands.check_lldp

    # Check if device is a Nexus 9000 in ACI mode
    is_n9k_aci = 'Nexus 9000' in version_output and 'ACI' in version_output

    # If not a Nexus 9000 in ACI mode, device is not vulnerable
    if not is_n9k_aci:
        return

    # Check if LLDP is enabled
    lldp_enabled = 'feature lldp' in lldp_output
    # Device is vulnerable if it's a Nexus 9000 in ACI mode with LLDP enabled
    is_vulnerable = is_n9k_aci and lldp_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-1231. "
        "The device is a Nexus 9000 in ACI mode with LLDP enabled and SFP interfaces, "
        "which could allow an adjacent attacker to disable switching on SFP interfaces through crafted LLDP packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apic-lldap-dos-WerV9CFj"
    )

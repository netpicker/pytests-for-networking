from comfy import high


@high(
    name='rule_cve202320089',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_lldp='show running-config | include lldp'
    ),
)
def rule_cve202320089(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20089 vulnerability in Cisco Nexus 9000 Series Fabric Switches in ACI Mode.
    The vulnerability is due to incorrect error checking when parsing ingress LLDP packets, which could allow
    an unauthenticated, adjacent attacker to cause a memory leak, resulting in a denial of service (DoS) condition.
    """
    # Extract the output of the command to check LLDP configuration
    lldp_output = commands.check_lldp

    # Check if LLDP is enabled
    lldp_enabled = 'lldp' in lldp_output

    # Assert that the device is not vulnerable
    assert not lldp_enabled, (
        f"Device {device.name} is vulnerable to CVE-2023-20089. "
        "The device is running in ACI Mode AND has LLDP enabled, "
        "which could allow an attacker to cause a memory leak and DoS condition. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-aci-lldp-dos-ySCNZOpX"
    )

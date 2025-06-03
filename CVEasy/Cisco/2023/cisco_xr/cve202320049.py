from comfy import high


@high(
    name='rule_cve202320049',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        check_bfd='show running-config | include bfd'
    ),
)
def rule_cve202320049(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20049 vulnerability in Cisco IOS XR Software for ASR 9000 Series Routers.
    The vulnerability is due to incorrect handling of malformed BFD packets that are received on line cards
    where the BFD hardware offload feature is enabled. An attacker could exploit this vulnerability by sending
    a crafted IPv4 BFD packet to an affected device, causing a line card to reset and resulting in a DoS condition.
    """
    # Extract the output of the command to check BFD configuration
    bfd_output = commands.check_bfd

    # Check if BFD hardware offload is configured
    bfd_hardware_offload_configured = 'bfd' in bfd_output

    # Assert that the device is not vulnerable
    assert not bfd_hardware_offload_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20049. "
        "The device has BFD hardware offload configured, "
        "which could allow an attacker to cause a denial of service. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-bfd-XmRescbT"
    )

from comfy import high


@high(
    name='rule_cve202320027',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_vfr='show running-config | include ip virtual-reassembly'
    ),
)
def rule_cve202320027(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20027 vulnerability in Cisco IOS XE Software.
    The vulnerability is due to improper reassembly of large packets when Virtual Fragmentation
    Reassembly (VFR) is enabled on either a tunnel interface or on a physical interface that is
    configured with an MTU greater than 4,615 bytes.
    """
    # Extract the output of the command to check VFR configuration
    vfr_output = commands.check_vfr

    # Check if VFR is configured
    vfr_configured = 'ip virtual-reassembly' in vfr_output

    # Assert that the device is not vulnerable
    assert not vfr_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20027. "
        "The device has Virtual Fragmentation Reassembly (VFR) enabled, "
        "which could allow an attacker to cause a denial of service. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ipv4-vfr-dos-CXxtFacb"
    )

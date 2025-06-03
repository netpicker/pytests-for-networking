from comfy import high


@high(
    name='rule_cve202320109',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_getvpn='show running-config | include crypto gdoi'
    ),
)
def rule_cve202320109(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20109 vulnerability in Cisco IOS Software.
    The vulnerability is due to insufficient validation of attributes in the Group Domain of 
    Interpretation (GDOI) and G-IKEv2 protocols of the GET VPN feature. An attacker could 
    exploit this vulnerability by either compromising an installed key server or modifying 
    the configuration of a group member to point to a key server that is controlled by the attacker.
    """
    # Extract the output of the command to check GET VPN configuration
    getvpn_output = commands.check_getvpn

    # Check if GET VPN (GDOI) is configured
    getvpn_configured = 'crypto gdoi' in getvpn_output

    # Assert that the device is not vulnerable
    assert not getvpn_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20109. "
        "The device has GET VPN (GDOI) configured, "
        "which could allow an authenticated attacker to execute arbitrary code or cause a denial of service. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-getvpn-rce-g8qR68sx"
    )

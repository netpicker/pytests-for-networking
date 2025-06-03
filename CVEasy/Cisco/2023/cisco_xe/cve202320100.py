from comfy import high


@high(
    name='rule_cve202320100',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_capwap='show running-config | include wireless|capwap'
    ),
)
def rule_cve202320100(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20100 vulnerability in Cisco IOS XE Software for Wireless LAN Controllers.
    The vulnerability is due to a logic error in the access point (AP) joining process of the Control and
    Provisioning of Wireless Access Points (CAPWAP) protocol. An attacker could exploit this vulnerability
    by adding a malicious AP to the network and causing specific conditions during the AP joining process.
    """
    # Extract the output of the command to check CAPWAP/wireless configuration
    capwap_output = commands.check_capwap

    # Check if wireless/CAPWAP is configured
    wireless_configured = 'wireless' in capwap_output and 'capwap' in capwap_output

    # Assert that the device is not vulnerable
    assert not wireless_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20100. "
        "The device has wireless LAN controller and CAPWAP configured, "
        "which could allow an attacker to cause a denial of service through the AP joining process. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-c9800-apjoin-dos-nXRHkt5"
    )

from comfy import high

@high(
    name='rule_cve202520315',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_nbar_capwap='show running-config | include tunneled-traffic capwap',
        show_nbar_state='show ip nbar control-plane | include NBAR state'
    ),
)
def rule_cve202520315(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20315 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the Network-Based Application Recognition (NBAR) feature
    could allow an unauthenticated, remote attacker to cause an affected device
    to reload, causing a denial of service (DoS) condition.
    
    This vulnerability is due to improper handling of malformed Control and
    Provisioning of Wireless Access Points (CAPWAP) packets.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (devices that support NBAR for CAPWAP)
    # Based on the advisory, this affects multiple IOS XE versions on specific platforms
    # The advisory doesn't specify exact version numbers, so we check for IOS XE presence
    # and rely on configuration checks
    is_ios_xe = 'Cisco IOS XE Software' in version_output

    # If not IOS XE, device is not vulnerable
    if not is_ios_xe:
        return

    # Check if CAPWAP inspection for NBAR is enabled
    capwap_enabled = 'ip nbar classification tunneled-traffic capwap' in commands.show_nbar_capwap

    # If CAPWAP inspection is not enabled, device is not vulnerable
    if not capwap_enabled:
        return

    # Check if NBAR is activated
    nbar_state_output = commands.show_nbar_state
    nbar_activated = 'NBAR state is ACTIVATED' in nbar_state_output or 'NBAR state: ACTIVATED' in nbar_state_output

    # If both CAPWAP inspection for NBAR is enabled AND NBAR is ACTIVATED, device is vulnerable
    if capwap_enabled and nbar_activated:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20315. "
            "The device has NBAR for CAPWAP feature enabled and NBAR is ACTIVATED. "
            "An unauthenticated, remote attacker could send malformed CAPWAP packets to cause a DoS condition. "
            "Mitigation: Disable CAPWAP inspection using 'no ip nbar classification tunneled-traffic capwap'. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nbar-dos-LAvwTmeT"
        )
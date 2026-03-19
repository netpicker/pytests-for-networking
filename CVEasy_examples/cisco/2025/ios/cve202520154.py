from comfy import high


@high(
    name='rule_cve202520154',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include ip sla server twamp',
        show_debug='show debug | include TWAMP Server Connection TRACE'
    ),
)
def rule_cve202520154(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20154 vulnerability in Cisco IOS Software.
    The vulnerability is in the Two-Way Active Measurement Protocol (TWAMP) server feature and is due to 
    out-of-bounds array access when processing specially crafted TWAMP control packets. An unauthenticated, 
    remote attacker could exploit this vulnerability by sending crafted TWAMP control packets to cause the 
    device to reload, resulting in a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    
    # Check if TWAMP server is enabled
    config_output = commands.show_running_config
    twamp_enabled = 'ip sla server twamp' in config_output
    
    # If TWAMP server is not enabled, device is not vulnerable
    if not twamp_enabled:
        return
    
    # Extract version number for IOS XE specific check
    # For IOS XE 16.6.1 through 17.2.3, debugs must be enabled to be vulnerable
    # For other releases, debugs are not required
    is_ios_xe_debug_only = False
    
    # Check for IOS XE versions 16.6.1 through 17.2.3
    if 'IOS XE Software' in version_output or 'Cisco IOS-XE' in version_output:
        # Extract version
        if any(v in version_output for v in [
            '16.6.', '16.7.', '16.8.', '16.9.', '16.10.', '16.11.', '16.12.',
            '17.1.', '17.2.1', '17.2.2', '17.2.3'
        ]):
            is_ios_xe_debug_only = True
    
    # If this is an IOS XE version that requires debugs, check if debugs are enabled
    if is_ios_xe_debug_only:
        debug_output = commands.show_debug
        debug_enabled = 'TWAMP Server Connection TRACE' in debug_output
        
        # Only vulnerable if debugs are enabled
        if not debug_enabled:
            return
    
    # Device is vulnerable: TWAMP server is enabled and either:
    # - It's IOS (always vulnerable when TWAMP enabled)
    # - It's IOS XE 16.6.1-17.2.3 with debugs enabled
    # - It's IOS XE other version (always vulnerable when TWAMP enabled)
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-20154. "
        "The device has the TWAMP server feature enabled, which makes it susceptible to DoS attacks "
        "via crafted TWAMP control packets causing out-of-bounds array access. "
        "An unauthenticated, remote attacker could cause the device to reload. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-twamp-kV4FHugn"
    )
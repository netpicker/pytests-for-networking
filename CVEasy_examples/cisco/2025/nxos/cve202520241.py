from comfy import high

@high(
    name='rule_cve202520241',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_running_config_isis='show running-config | include isis',
        show_isis_adjacency='show isis adjacency'
    ),
)
def rule_cve202520241(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2025-20241 vulnerability in Cisco NX-OS Software.
    The vulnerability in the IS-IS feature could allow an unauthenticated, adjacent
    attacker to cause the IS-IS process to unexpectedly restart, which could cause
    an affected device to reload, resulting in a denial of service (DoS) condition.
    
    Affected Products:
    - Nexus 3000 Series Switches
    - Nexus 9000 Series Switches in standalone NX-OS mode
    
    Vulnerable Conditions:
    - Running vulnerable Cisco NX-OS Software version
    - IS-IS protocol is enabled (feature isis)
    - IS-IS protocol is enabled on at least one interface (ip router isis name)
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable versions - This vulnerability affects multiple versions
    # Based on the advisory, we need to check if the device is running a vulnerable version
    # The advisory doesn't specify exact vulnerable versions, but indicates Nexus 3000 and 9000 series
    # For this rule, we'll check if IS-IS is configured as the primary vulnerability indicator
    
    # Check if IS-IS feature is enabled and configured on at least one interface
    isis_config_output = commands.show_running_config_isis
    
    # Check for 'feature isis' in the configuration
    is_isis_feature_enabled = 'feature isis' in isis_config_output
    
    # Check for 'router isis' configuration
    is_isis_router_configured = 'router isis' in isis_config_output
    
    # Check for 'ip router isis' on at least one interface
    is_isis_interface_configured = 'ip router isis' in isis_config_output
    
    # If IS-IS is not enabled or not configured on any interface, device is not vulnerable
    if not (is_isis_feature_enabled and is_isis_router_configured and is_isis_interface_configured):
        return
    
    # Check if there are any IS-IS adjacencies (peers in UP state)
    isis_adjacency_output = commands.show_isis_adjacency
    has_isis_adjacency = 'UP' in isis_adjacency_output
    
    # Device is vulnerable if:
    # 1. IS-IS feature is enabled
    # 2. IS-IS router is configured
    # 3. IS-IS is enabled on at least one interface
    # 4. There are IS-IS adjacencies in UP state (exploitable condition)
    
    assert not (is_isis_feature_enabled and is_isis_router_configured and is_isis_interface_configured and has_isis_adjacency), (
        f"Device {device.name} is vulnerable to CVE-2025-20241. "
        "The device has IS-IS protocol enabled and configured on at least one interface with active adjacencies. "
        "An unauthenticated, adjacent attacker could send a crafted IS-IS packet to cause the IS-IS process to restart, "
        "potentially causing the device to reload (DoS condition). "
        "Mitigation: Configure IS-IS area authentication to require attackers to pass authentication. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n39k-isis-dos-JhJA8Rfx"
    )
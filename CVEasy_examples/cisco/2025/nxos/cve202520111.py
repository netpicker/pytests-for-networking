from comfy import high

@high(
    name='rule_cve202520111',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_diagnostic_result='show diagnostic result module all',
        show_event_manager='show running-config | section "event manager"'
    ),
)
def rule_cve202520111(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2025-20111 vulnerability in Cisco NX-OS Software.
    The vulnerability in the health monitoring diagnostics of Cisco Nexus 3000 Series 
    Switches and Cisco Nexus 9000 Series Switches in standalone NX-OS mode could allow 
    an unauthenticated, adjacent attacker to cause the device to reload unexpectedly, 
    resulting in a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable versions - all versions are vulnerable unless patched
    # Based on the advisory, specific fixed versions would need to be checked
    # For this rule, we'll check if it's a Nexus 3000 or 9000 series device
    
    # Check if device is a vulnerable model (check for Nexus 3000 or 9000 series broadly)
    is_nexus_3000 = 'Nexus3000' in version_output or 'Nexus 3000' in version_output or \
                    any(model in version_output for model in [
                        'Nexus 3100', 'Nexus 3200', 'Nexus 3400', 'Nexus 3600',
                        'Nexus3100', 'Nexus3200', 'Nexus3400', 'Nexus3600'
                    ])
    
    is_nexus_9000 = 'Nexus9000' in version_output or 'Nexus 9000' in version_output or \
                    any(model in version_output for model in [
                        'Nexus 9200', 'Nexus 9300', 'Nexus 9400',
                        'Nexus9200', 'Nexus9300', 'Nexus9400'
                    ])
    
    # Check if device is in ACI mode (not vulnerable)
    is_aci_mode = 'aci' in version_output.lower() or 'ACI' in version_output
    
    # If not a vulnerable model or in ACI mode, device is not vulnerable
    if not (is_nexus_3000 or is_nexus_9000) or is_aci_mode:
        return
    
    # Check if workaround is applied
    event_manager_output = commands.show_event_manager
    
    # Check for L2ACLRedirect override workaround
    has_l2acl_workaround = (
        'event manager applet l2acl_override override __L2ACLRedirect' in event_manager_output or
        'l2acl_override' in event_manager_output
    )
    
    # Check for RewriteEngineLoopback override workaround (for Nexus 3100/3200)
    has_rewrite_workaround = (
        'event manager applet rewrite_override override __RewriteEngineLoopback' in event_manager_output or
        'rewrite_override' in event_manager_output
    )
    
    # For Nexus 3100/3200, check for RewriteEngine workaround
    if is_nexus_3000 and ('3100' in version_output or '3200' in version_output):
        workaround_applied = has_rewrite_workaround
    else:
        workaround_applied = has_l2acl_workaround
    
    # Assert that workaround is applied or device is patched
    assert workaround_applied, (
        f"Device {device.name} is vulnerable to CVE-2025-20111. "
        "The device is a Cisco Nexus 3000 or 9000 Series Switch in standalone NX-OS mode "
        "without the required workaround applied. An unauthenticated, adjacent attacker could "
        "send crafted Ethernet frames to cause the device to reload unexpectedly. "
        "Apply the workaround by configuring the event manager applet override for the health monitoring diagnostic test. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-n3kn9k-healthdos-eOqSWK4g"
    )
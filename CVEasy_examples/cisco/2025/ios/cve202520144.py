from comfy import high


@high(
    name='rule_cve202520144',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include ipv4 access-group .* compress level 3',
        show_access_lists='show access-lists',
        show_object_groups='show object-group network ipv4'
    ),
)
def rule_cve202520144(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20144 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incorrect handling of packets when a specific configuration of 
    hybrid ACL exists. An attacker could exploit this vulnerability by attempting to send traffic 
    through an affected device to bypass a configured ACL.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions (7.10 and earlier, 7.11 before 7.11.2)
    # Check for IOS XR Software
    is_iosxr = 'IOS XR Software' in version_output or 'Cisco IOS XR' in version_output

    if not is_iosxr:
        # Not IOS XR, not affected
        return

    # Check if version is vulnerable (7.10 and earlier, or 7.11.0/7.11.1)
    version_vulnerable = False
    
    # Extract version number
    if 'Version 7.10' in version_output or 'Version 7.9' in version_output or 'Version 7.8' in version_output or \
       'Version 7.7' in version_output or 'Version 7.6' in version_output or 'Version 7.5' in version_output or \
       'Version 7.4' in version_output or 'Version 7.3' in version_output or 'Version 7.2' in version_output or \
       'Version 7.1' in version_output or 'Version 7.0' in version_output or 'Version 6.' in version_output:
        version_vulnerable = True
    elif 'Version 7.11.0' in version_output or 'Version 7.11.1' in version_output:
        version_vulnerable = True

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if hybrid IPv4 ACL with compress level 3 is configured
    config_output = commands.show_running_config
    
    hybrid_acl_configured = 'ipv4 access-group' in config_output and 'compress level 3' in config_output

    # If no hybrid ACL is configured, device is not vulnerable
    if not hybrid_acl_configured:
        return

    # Check if ACL has 32 or more unique source or destination network object groups
    acl_output = commands.show_access_lists
    
    # Count unique network object groups in source and destination
    source_groups = set()
    dest_groups = set()
    
    for line in acl_output.split('\n'):
        if 'net-group' in line:
            parts = line.split()
            # Look for net-group patterns
            for i, part in enumerate(parts):
                if part == 'net-group':
                    if i + 1 < len(parts):
                        # Check if this is source or destination based on position
                        if i + 2 < len(parts) and parts[i + 2] == 'net-group':
                            # First net-group is source
                            source_groups.add(parts[i + 1])
                            # Second net-group is destination
                            dest_groups.add(parts[i + 3])
                            break
                        else:
                            # Single net-group, could be source
                            source_groups.add(parts[i + 1])

    # Check if 32 or more unique groups exist
    has_vulnerable_group_count = len(source_groups) >= 32 or len(dest_groups) >= 32

    # If we have 32+ groups, check for duplicate IPv4 entries across groups
    # For simplicity, we'll assume if there are 32+ groups, the vulnerability condition is met
    is_vulnerable = hybrid_acl_configured and has_vulnerable_group_count

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20144. "
        "The device is running a vulnerable IOS XR version AND has a hybrid IPv4 ACL configured "
        "with compress level 3 that contains 32 or more unique source or destination network object groups, "
        "which makes it susceptible to ACL bypass attacks. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ncs-hybridacl-crMZFfKQ"
    )
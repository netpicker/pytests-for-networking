from comfy import high
import re

@high(
    name='rule_cve202520144',
    platform=['cisco_ios-xr'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include ipv4 access-group .* compress level 3',
        show_access_lists='show access-lists',
        show_object_groups='show object-group network ipv4'
    ),
)
def rule_cve202520144(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20144: Cisco IOS XR Software Hybrid Access Control List Bypass Vulnerability.
    
    The vulnerability affects devices running vulnerable versions of Cisco IOS XR Software with a hybrid IPv4 ACL
    configured with compress level 3 that has 32 or more unique source or destination network object groups
    where the same IPv4 prefix, host, or range entry appears in 32 or more of those groups.
    """

    # Extract command outputs
    show_version_output = commands.show_version or ''
    show_running_config_output = commands.show_running_config or ''
    show_access_lists_output = commands.show_access_lists or ''
    show_object_groups_output = commands.show_object_groups or ''

    # Define vulnerable software versions (7.10 and earlier, except 7.11.2+ and 24.1+)
    # Vulnerable: 7.10 and earlier
    # Fixed: 7.11.2+, 24.1+
    
    # Extract version from show version output
    version_match = re.search(r'Version\s+(\d+\.\d+\.\d+)', show_version_output)
    if not version_match:
        # Try alternative version format
        version_match = re.search(r'IOS XR Software.*Version\s+(\d+\.\d+\.\d+)', show_version_output)
    
    if not version_match:
        # Cannot determine version, assume not vulnerable
        return
    
    version_str = version_match.group(1)
    version_parts = [int(x) for x in version_str.split('.')]
    
    # Check if version is vulnerable
    is_version_vulnerable = False
    
    if len(version_parts) >= 2:
        major = version_parts[0]
        minor = version_parts[1]
        patch = version_parts[2] if len(version_parts) > 2 else 0
        
        # Version 24.1 and later are not vulnerable
        if major >= 24:
            is_version_vulnerable = False
        # Version 7.11.2 and later in 7.11 train are fixed
        elif major == 7 and minor == 11 and patch >= 2:
            is_version_vulnerable = False
        # Version 7.10 and earlier are vulnerable
        elif major < 7 or (major == 7 and minor < 11):
            is_version_vulnerable = True
        elif major == 7 and minor == 11 and patch < 2:
            is_version_vulnerable = True
    
    # If version is not vulnerable, device is safe
    if not is_version_vulnerable:
        return
    
    # Check if hybrid ACL with compress level 3 is configured
    if not show_running_config_output or 'ipv4 access-group' not in show_running_config_output:
        # No hybrid ACL configured, device is not vulnerable
        return
    
    # Extract ACL names from running config
    acl_matches = re.findall(r'ipv4 access-group\s+(\S+)\s+\w+\s+compress level 3', show_running_config_output)
    
    if not acl_matches:
        # No hybrid ACL with compress level 3 configured
        return
    
    # Check if any ACL has 32 or more unique source or destination network object groups
    is_config_vulnerable = False
    
    for acl_name in acl_matches:
        # Parse ACL entries to count unique network object groups
        acl_pattern = rf'ipv4 access-list {re.escape(acl_name)}.*?(?=ipv4 access-list|\Z)'
        acl_match = re.search(acl_pattern, show_access_lists_output, re.DOTALL)
        
        if acl_match:
            acl_content = acl_match.group(0)
            
            # Extract source and destination network object groups
            src_groups = set(re.findall(r'net-group\s+(\S+)\s+net-group', acl_content))
            dst_groups = set(re.findall(r'net-group\s+\S+\s+net-group\s+(\S+)', acl_content))
            
            # If 32 or more unique source or destination groups, check for duplicate IPs
            if len(src_groups) >= 32 or len(dst_groups) >= 32:
                # This is a simplified check - in reality, we'd need to parse object groups
                # to see if the same IP appears in 32+ groups
                # For this rule, we'll flag it as potentially vulnerable if the structure matches
                is_config_vulnerable = True
                break
    
    # Assert that the device is not vulnerable
    assert not is_config_vulnerable, (
        f"Device {device.name} is running a vulnerable version ({version_str}) of Cisco IOS XR Software "
        f"with a hybrid IPv4 ACL configured with compress level 3 that may allow ACL bypass. "
        f"Please upgrade to a fixed release (7.11.2 or later, or 24.1+) or apply the workaround "
        f"to mitigate CVE-2025-20144. "
        f"For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ncs-hybridacl-crMZFfKQ"
    )
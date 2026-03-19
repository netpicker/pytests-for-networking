from comfy import high

@high(
    name='rule_cve202520159',
    platform=['cisco_ios-xr'],
    commands=dict(
        show_version='show version',
        show_running_config_mgmt='show running-config interface mgmtEth',
        show_running_config_grpc='show running-config grpc',
        show_running_config_linux='show running-config linux networking',
        show_running_config_ssh='show running-config ssh',
        show_running_config_netconf='show running-config ssh server netconf'
    ),
)
def rule_cve202520159(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20159: Cisco IOS XR Software Management Interface ACL Bypass Vulnerability.
    
    The vulnerability affects Cisco IOS XR Software Packet I/O infrastructure platforms where management
    interface ACLs are not enforced for Linux-handled features such as SSH, NetConf, and gRPC.
    
    Vulnerable platforms include:
    - 8000 Series Routers (all releases before fix)
    - ASR 9000 Series (24.1.1 and later before fix)
    - IOS XR White box (7.9.1 and later before fix)
    - IOS XRd vRouters (all releases before fix)
    - IOS XRv 9000 Routers (24.1.1 and later before fix)
    - NCS 540 Series (NCS540-iosxr: 7.9.1 and later before fix; NCS540L-iosxr: all before fix)
    - NCS 560 Series (24.2.1 and later before fix)
    - NCS 1010/1014 Platforms (all releases before fix)
    - NCS 5500 Series (7.9.1 and later before fix)
    - NCS 5700 Series (all releases before fix)
    """

    show_version_output = commands.show_version
    show_mgmt_config = commands.show_running_config_mgmt
    show_grpc_config = commands.show_running_config_grpc
    show_linux_config = commands.show_running_config_linux
    show_ssh_config = commands.show_running_config_ssh
    show_netconf_config = commands.show_running_config_netconf

    # Define vulnerable version ranges for different platforms
    vulnerable_versions = {
        'native_packetio': [
            # 8000 Series, IOS XRd, NCS540L, NCS 1010/1014, NCS 5700
            # All versions before 25.1.1 (SSH/NetConf) or 25.1.2 (gRPC)
        ],
        'migrated_packetio': {
            'asr9000': ['24.1.1', '24.1.2', '24.2.1', '24.2.2', '25.1.1'],
            'iosxrwbd': ['7.9.1', '7.9.2', '7.10.1', '24.1.1', '24.2.1'],
            'ncs540': ['7.9.1', '7.9.2', '7.10.1', '24.1.1', '24.2.1'],
            'ncs560': ['24.2.1'],
            'ncs5500': ['7.9.1', '7.9.2', '7.10.1', '24.1.1', '24.2.1']
        }
    }

    # Check if device is running a vulnerable version
    is_vulnerable_version = False
    
    # Check for versions before 25.1.1 or 25.1.2
    version_patterns = [
        '7.9.1', '7.9.2', '7.10.1',
        '24.1.1', '24.1.2', '24.2.1', '24.2.2',
        '25.1.1'  # Still vulnerable for gRPC
    ]
    
    for version in version_patterns:
        if version in show_version_output:
            is_vulnerable_version = True
            break

    # If not vulnerable version, device is safe
    if not is_vulnerable_version:
        return

    # Step 1: Check if management interface has ACL configured
    has_mgmt_acl = False
    if 'ipv4 access-group' in show_mgmt_config or 'ipv6 access-group' in show_mgmt_config:
        has_mgmt_acl = True

    # If no management ACL, device is not affected by this vulnerability
    if not has_mgmt_acl:
        return

    # Step 2: Check gRPC configuration
    grpc_vulnerable = False
    if 'grpc' in show_grpc_config and 'port' in show_grpc_config:
        # gRPC is enabled, check if Traffic Protection is configured
        if 'protection' not in show_linux_config or 'protocol tcp local-port' not in show_linux_config:
            grpc_vulnerable = True

    # Step 3: Check SSH configuration (for Native Packet I/O platforms)
    ssh_vulnerable = False
    if 'ssh server' in show_ssh_config:
        # Check if SSH ACLs are configured at service level
        if 'ipv4 access-list' not in show_ssh_config and 'ipv6 access-list' not in show_ssh_config:
            # Check version - SSH filtering on mgmt interface supported from 25.1.1
            if any(v in show_version_output for v in ['7.9.1', '7.9.2', '7.10.1', '24.1.1', '24.2.1']):
                ssh_vulnerable = True

    # Step 4: Check NETCONF configuration (for Native Packet I/O platforms)
    netconf_vulnerable = False
    if 'ssh server netconf' in show_netconf_config:
        # Check if NetConf ACLs are configured at service level
        if 'ipv4 access-list' not in show_netconf_config and 'ipv6 access-list' not in show_netconf_config:
            # Check version - NetConf filtering on mgmt interface supported from 25.1.1
            if any(v in show_version_output for v in ['7.9.1', '7.9.2', '7.10.1', '24.1.1', '24.2.1']):
                netconf_vulnerable = True

    # Assert device is not vulnerable
    is_vulnerable = grpc_vulnerable or ssh_vulnerable or netconf_vulnerable

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20159: Management Interface ACL Bypass. "
        f"The device has a management interface ACL configured but it is not being enforced for "
        f"{'gRPC, ' if grpc_vulnerable else ''}{'SSH, ' if ssh_vulnerable else ''}{'NETCONF ' if netconf_vulnerable else ''}services. "
        f"Mitigation: {'Configure Traffic Protection for gRPC. ' if grpc_vulnerable else ''}"
        f"{'Configure SSH service-level ACLs or upgrade to 25.1.1+. ' if ssh_vulnerable else ''}"
        f"{'Configure NetConf service-level ACLs or upgrade to 25.1.1+. ' if netconf_vulnerable else ''}"
        f"For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-acl-packetio-Swjhhbtz"
    )
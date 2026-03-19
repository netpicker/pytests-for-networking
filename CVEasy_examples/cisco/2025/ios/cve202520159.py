from comfy import high


@high(
    name='rule_cve202520159',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config_interface='show running-config interface mgmtEth',
        show_running_config_grpc='show running-config grpc',
        show_running_config_linux='show running-config linux networking',
        show_running_config_ssh='show running-config ssh',
        show_running_config_netconf='show running-config ssh server netconf'
    ),
)
def rule_cve202520159(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20159 vulnerability in Cisco IOS XR Software.
    The vulnerability allows an unauthenticated, remote attacker to bypass configured ACLs for the 
    SSH, NetConf, and gRPC features on management interfaces due to lack of support for management 
    interface ACLs on Packet I/O infrastructure platforms for Linux-handled features.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define vulnerable platforms and version ranges
    # Native Packet I/O platforms (all versions before fixed releases)
    # Include both with and without spaces/dashes
    native_packetio_platforms = [
        '8000 Series', '8000-Series', 'IOS XRd', 'IOS-XRd',
        'NCS540L', 'NCS-540L', 'NCS 1010', 'NCS-1010', 
        'NCS 1014', 'NCS-1014', 'NCS5700', 'NCS 5700', 'NCS-5700'
    ]
    
    # Migrated Packet I/O platforms with specific version ranges
    migrated_platforms = {
        'ASR 9000': ('24.1.1', '24.2.21'),
        'IOSXRWBD': ('7.9.1', '24.2.21'),
        'IOS XRv 9000': ('24.1.1', '24.2.21'),
        'NCS 540': ('7.9.1', '24.2.21'),
        'NCS 560': ('24.2.1', '24.2.21'),
        'NCS 5500': ('7.9.1', '24.2.21')
    }

    # Check for fixed versions first
    # SSH/NetConf fixed in 25.1.1+, gRPC fixed in 25.1.2+
    is_fixed_for_ssh_netconf = 'Version 25.1.1' in version_output or \
                                'Version 25.1.2' in version_output or \
                                'Version 25.1.3' in version_output or \
                                'Version 25.2' in version_output or \
                                'Version 25.3' in version_output or \
                                'Version 26.' in version_output
    
    is_fixed_for_grpc = 'Version 25.1.2' in version_output or \
                        'Version 25.1.3' in version_output or \
                        'Version 25.2' in version_output or \
                        'Version 25.3' in version_output or \
                        'Version 26.' in version_output
    
    # Check if device is a vulnerable platform
    is_native_packetio = any(platform in version_output for platform in native_packetio_platforms)
    is_migrated_packetio = any(platform in version_output for platform in migrated_platforms.keys())
    
    # Check version vulnerability for migrated platforms
    version_vulnerable = False
    if is_migrated_packetio:
        for platform, (min_ver, max_ver) in migrated_platforms.items():
            if platform in version_output:
                # Simple version check - in production would need more sophisticated parsing
                if min_ver in version_output or max_ver in version_output:
                    version_vulnerable = True
                    break
    
    # If not a vulnerable platform or version, no need to check further
    if not (is_native_packetio or version_vulnerable):
        return

    # Check if management interface has ACL configured
    interface_config = commands.show_running_config_interface
    has_mgmt_acl = 'access-group' in interface_config and 'ingress' in interface_config

    # If no management ACL is configured, device is not vulnerable to bypass
    if not has_mgmt_acl:
        return

    # Check gRPC configuration
    grpc_config = commands.show_running_config_grpc
    grpc_enabled = 'grpc' in grpc_config and 'port' in grpc_config
    
    # Check if Traffic Protection is configured for gRPC
    linux_config = commands.show_running_config_linux
    traffic_protection_configured = (
        'linux networking' in linux_config and 
        'protection' in linux_config and
        'protocol tcp' in linux_config
    )

    # Check SSH configuration
    ssh_config = commands.show_running_config_ssh
    ssh_enabled = 'ssh server' in ssh_config
    ssh_acl_configured = 'access-list' in ssh_config

    # Check NetConf configuration
    netconf_config = commands.show_running_config_netconf
    netconf_enabled = 'ssh server netconf' in netconf_config
    netconf_acl_configured = 'access-list' in netconf_config

    # Determine vulnerability
    is_vulnerable = False
    vulnerability_details = []

    # Check gRPC vulnerability (fixed in 25.1.2+)
    if grpc_enabled and not traffic_protection_configured and not is_fixed_for_grpc:
        is_vulnerable = True
        vulnerability_details.append("gRPC is enabled without Traffic Protection for Linux Networking")

    # Check SSH vulnerability (only for native Packet I/O platforms, fixed in 25.1.1+)
    if is_native_packetio and ssh_enabled and not ssh_acl_configured and not is_fixed_for_ssh_netconf:
        is_vulnerable = True
        vulnerability_details.append("SSH is enabled without SSH server ACL configuration")

    # Check NetConf vulnerability (only for native Packet I/O platforms, fixed in 25.1.1+)
    if is_native_packetio and netconf_enabled and not netconf_acl_configured and not is_fixed_for_ssh_netconf:
        is_vulnerable = True
        vulnerability_details.append("NetConf over SSH is enabled without NetConf server ACL configuration")

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20159. "
        f"The device has a management interface ACL configured but the following services can bypass it: "
        f"{', '.join(vulnerability_details)}. "
        "Management interface ACLs are not enforced for Linux-handled features on Packet I/O infrastructure platforms. "
        "Upgrade to fixed release (25.1.1+ for SSH/NetConf, 25.1.2+ for gRPC) or configure service-specific ACLs. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-acl-packetio-Swjhhbtz"
    )
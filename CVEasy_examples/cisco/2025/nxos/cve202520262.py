from comfy import medium

@medium(
    name='rule_cve202520262',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        show_feature_pim6='show feature | include pim6',
        show_feature_nxapi='show feature | include nxapi',
        show_feature_netconf='show feature | include netconf',
        show_feature_restconf='show feature | include restconf',
        show_feature_grpc='show feature | include grpc',
        show_feature_telemetry='show feature | include telemetry'
    ),
)
def rule_cve202520262(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2025-20262 vulnerability in Cisco NX-OS Software.
    The vulnerability in the Protocol Independent Multicast Version 6 (PIM6) feature
    could allow an authenticated, low-privileged, remote attacker to trigger a crash
    of the PIM6 process, resulting in a denial of service (DoS) condition.
    
    Affected: Cisco Nexus 3000 and 9000 Series Switches in standalone NX-OS mode
    with PIM6 enabled AND at least one of: NX-API, NETCONF, RESTCONF, gRPC, or
    Model Driven Telemetry enabled.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable versions - all versions are vulnerable unless fixed
    # Since the advisory doesn't specify fixed versions, we assume all current versions
    # are potentially vulnerable if the configuration matches
    # The key is checking if PIM6 and at least one management interface is enabled
    
    # Check if PIM6 feature is enabled
    pim6_output = commands.show_feature_pim6
    is_pim6_enabled = 'enabled' in pim6_output

    # If PIM6 is not enabled, device is not vulnerable
    if not is_pim6_enabled:
        return

    # Check if any of the management interfaces are enabled
    nxapi_output = commands.show_feature_nxapi
    netconf_output = commands.show_feature_netconf
    restconf_output = commands.show_feature_restconf
    grpc_output = commands.show_feature_grpc
    telemetry_output = commands.show_feature_telemetry

    is_nxapi_enabled = 'enabled' in nxapi_output
    is_netconf_enabled = 'enabled' in netconf_output
    is_restconf_enabled = 'enabled' in restconf_output
    is_grpc_enabled = 'enabled' in grpc_output
    is_telemetry_enabled = 'enabled' in telemetry_output

    # Check if at least one management interface is enabled
    management_interface_enabled = (
        is_nxapi_enabled or 
        is_netconf_enabled or 
        is_restconf_enabled or 
        is_grpc_enabled or 
        is_telemetry_enabled
    )

    # Device is vulnerable if PIM6 is enabled AND at least one management interface is enabled
    is_vulnerable = is_pim6_enabled and management_interface_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20262. "
        "The device has PIM6 feature enabled along with at least one management interface "
        "(NX-API, NETCONF, RESTCONF, gRPC, or Model Driven Telemetry). "
        "This could allow an authenticated attacker to crash the PIM6 process via crafted ephemeral queries. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxospc-pim6-vG4jFPh"
    )
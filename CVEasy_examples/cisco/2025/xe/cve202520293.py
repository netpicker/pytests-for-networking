from comfy import medium

@medium(
    name='rule_cve202520293',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_pki_server='show crypto pki server',
        show_running_config='show running-config | include crypto pki server'
    ),
)
def rule_cve202520293(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20293 vulnerability in Cisco IOS XE Software 
    for Catalyst 9800 Series Wireless Controllers for Cloud (9800-CL).
    
    The vulnerability allows an unauthenticated, remote attacker to access the 
    public-key infrastructure (PKI) server due to incomplete cleanup upon 
    completion of the Day One setup process. An attacker could exploit this by 
    sending Simple Certificate Enrollment Protocol (SCEP) requests to request 
    certificates and join attacker-controlled devices to the wireless controller.
    """
    # Extract the version information from the command output
    version_output = commands.show_version
    
    # Check if this is a Catalyst 9800-CL device
    is_9800cl = 'C9800-CL' in version_output or 'Catalyst 9800-CL' in version_output
    
    # If not a 9800-CL device, not vulnerable
    if not is_9800cl:
        return
    
    # All versions of Cisco IOS XE Software for Catalyst 9800-CL are vulnerable
    # according to the advisory: "this vulnerability affected Cisco IOS XE Software 
    # for Catalyst 9800 Series Wireless Controllers for Cloud, regardless of device configuration"
    
    # Check if PKI server is running
    pki_server_output = commands.show_pki_server
    running_config = commands.show_running_config
    
    # Look for active PKI server with _WLC_CA suffix
    pki_server_active = False
    if pki_server_output:
        # Check if any PKI server is in "enabled" state
        lines = pki_server_output.split('\n')
        for i, line in enumerate(lines):
            if '_WLC_CA' in line and i + 1 < len(lines):
                # Check next few lines for status
                for j in range(1, min(5, len(lines) - i)):
                    if 'Status:' in lines[i + j] or 'status:' in lines[i + j].lower():
                        if 'enabled' in lines[i + j].lower() or 'running' in lines[i + j].lower():
                            pki_server_active = True
                            break
    
    # Also check running config for non-shutdown PKI servers
    if running_config and 'crypto pki server' in running_config:
        if '_WLC_CA' in running_config and 'shutdown' not in running_config:
            pki_server_active = True
    
    # If PKI server with _WLC_CA is active, device is vulnerable
    assert not pki_server_active, (
        f"Device {device.name} is vulnerable to CVE-2025-20293. "
        "The device is a Catalyst 9800-CL running Cisco IOS XE Software with an active PKI server "
        "that has not been properly shut down after Day One setup. An unauthenticated attacker could "
        "send SCEP requests to obtain certificates and join malicious devices to the wireless controller. "
        "Workaround: Shut down the hostname_WLC_CA PKI server using 'crypto pki server <hostname>_WLC_CA' "
        "followed by 'shutdown' command. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-9800cl-openscep-SB4xtxzP"
    )
from comfy import high


@high(
    name='rule_cve202520293',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_crypto_pki_server='show crypto pki server'
    ),
)
def rule_cve202520293(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20293 vulnerability in Cisco IOS XE Software 
    for Catalyst 9800 Series Wireless Controllers for Cloud (9800-CL).
    The vulnerability is due to incomplete cleanup upon completion of the Day One setup process,
    which could allow an unauthenticated, remote attacker to access the PKI server and request
    certificates via SCEP.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is a Catalyst 9800-CL device
    is_9800cl = 'C9800-CL' in version_output or 'Catalyst 9800-CL' in version_output

    # If not a 9800-CL device, not vulnerable
    if not is_9800cl:
        return

    # Check if IOS XE is running
    is_ios_xe = 'IOS XE' in version_output

    # If not IOS XE, not vulnerable
    if not is_ios_xe:
        return

    # Check for PKI server status
    pki_server_output = commands.show_crypto_pki_server

    # Check if any PKI server with _WLC_CA suffix is running (not shutdown)
    # The vulnerability exists when the PKI server is still active after Day One setup
    pki_server_active = False
    
    if pki_server_output and '_WLC_CA' in pki_server_output:
        # Check if the server status shows it's running (not shutdown)
        # Look for status indicators that suggest the server is active
        if 'Status: enabled' in pki_server_output or 'Issuing CA certificate configured' in pki_server_output:
            # Check that it's not explicitly shutdown
            if 'Status: disabled' not in pki_server_output and 'shutdown' not in pki_server_output.lower():
                pki_server_active = True

    # Device is vulnerable if it's a 9800-CL running IOS XE with an active WLC_CA PKI server
    is_vulnerable = pki_server_active

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20293. "
        "The Catalyst 9800-CL device has an active PKI server (_WLC_CA) that was not properly "
        "cleaned up after the Day One setup process. This allows unauthenticated attackers to "
        "request certificates via SCEP and potentially join attacker-controlled devices to the "
        "wireless controller. Please shut down the PKI server or upgrade to a fixed software version. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-9800cl-openscep-SB4xtxzP"
    )
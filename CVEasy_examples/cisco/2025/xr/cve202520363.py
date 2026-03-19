from comfy import high

@high(
    name='rule_cve202520363',
    platform=['cisco_ios-xr'],
    commands=dict(
        show_version='show version',
        uname='run uname -s',
        show_http='show running-config | include http server'
    ),
)
def rule_cve202520363(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20363 in Cisco IOS XR Software.
    
    The vulnerability affects 32-bit Cisco IOS XR Software running on Cisco ASR 9001 Routers
    that have the HTTP server enabled. An authenticated, remote attacker with low user 
    privileges could execute arbitrary code on an affected device.
    
    Vulnerable conditions:
    - Device is running 32-bit IOS XR (QNX-based)
    - HTTP server is enabled
    """

    # Extract command outputs
    uname_output = commands.uname or ''
    show_http_output = commands.show_http or ''

    # Check if the device is running 32-bit IOS XR (QNX-based)
    is_32bit = 'QNX' in uname_output

    # Check if HTTP server is enabled
    http_enabled = 'http server' in show_http_output

    # Device is vulnerable if it's 32-bit AND HTTP server is enabled
    is_vulnerable = is_32bit and http_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20363. "
        f"The device is running 32-bit Cisco IOS XR Software (QNX-based) with HTTP server enabled. "
        f"An authenticated, remote attacker with low user privileges could execute arbitrary code. "
        f"Recommended action: Disable the HTTP server using 'no http server' command or upgrade to a fixed release. "
        f"For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-http-code-exec-WmfP3h3O"
    )
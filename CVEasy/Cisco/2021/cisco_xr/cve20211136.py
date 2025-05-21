from comfy import high


@high(
    name='rule_cve20211136',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_platform='show platform'
    ),
)
def rule_cve20211136(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1136 vulnerability in Cisco IOS XR Software.
    The vulnerability affects Cisco Network Convergence System (NCS) 540 Series Routers
    running NCS540L software images and Cisco 8000 Series Routers. An authenticated,
    local attacker could exploit this vulnerability to execute unsigned code during
    the boot process on an affected device.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    platform_output = commands.show_platform

    # Check if device is a NCS 540 Series or 8000 Series router
    is_ncs540 = 'NCS-540' in platform_output
    is_8000 = '8000' in platform_output

    # If not a NCS 540 or 8000 Series router, device is not vulnerable
    if not (is_ncs540 or is_8000):
        return

    # For NCS 540, check if it's running NCS540L software image
    if is_ncs540:
        is_ncs540l = 'NCS540L' in version_output
        is_vulnerable = is_ncs540l
    else:
        # For 8000 Series, all software versions are vulnerable
        is_vulnerable = is_8000

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2021-1136. "
        f"The device is a {'NCS 540 Series running NCS540L image' if is_ncs540 else '8000 Series'} router, "
        "which could allow an authenticated attacker to execute unsigned code during the boot process. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ioxr-l-zNhcGCBt""
    )

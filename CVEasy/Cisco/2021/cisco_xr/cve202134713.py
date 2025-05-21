from comfy import high


@high(
    name='rule_cve202134713',
    platform=['cisco_xr'],
    commands=dict(
        show_version='show version',
        show_platform='show platform'
    ),
)
def rule_cve202134713(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-34713 vulnerability in Cisco IOS XR Software.
    The vulnerability is due to incorrect handling of specific Ethernet frames in the Layer 2
    punt code. An unauthenticated, adjacent attacker could exploit this vulnerability by sending
    specific types of Ethernet frames, causing a spin loop that makes network processors unresponsive
    and results in line card reboot.
    """
    # Extract the output of the commands
    version_output = commands.show_version
    platform_output = commands.show_platform

    # Check if device is an ASR 9000 Series router
    is_asr9k = any(model in platform_output for model in [
        'ASR-9000',
        'ASR9K',
        'ASR 9000'
    ])

    # If not an ASR 9000 Series router, device is not vulnerable
    if not is_asr9k:
        return

    # Assert that the device is not vulnerable
    assert not is_asr9k, (
        f"Device {device.name} is vulnerable to CVE-2021-34713. "
        "The device is an ASR 9000 Series router, which could allow an adjacent attacker "
        "to cause a denial of service through crafted Ethernet frames that trigger line card reboot. "
        ""For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-npspin-QYpwdhFD""
    )

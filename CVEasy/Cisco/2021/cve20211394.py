from comfy import high


@high(
    name='rule_cve20211394',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_webui='show running-config | include ip http|restconf'
    ),
)
def rule_cve20211394(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-1394 vulnerability in Cisco IOS XE Software for NCS 520 Routers.
    The vulnerability in the ingress traffic manager could allow an unauthenticated, remote attacker
    to cause a denial of service condition in the web management interface through crafted TCP packets.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is an NCS 520 platform
    platform_output = commands.check_platform
    if 'NCS-520' not in platform_output:
        return

    # Check for web UI configuration
    webui_config = commands.check_webui
    webui_enabled = any(feature in webui_config for feature in [
        'ip http server',
        'ip http secure-server',
        'restconf'
    ])

    # If web UI is enabled, device is potentially vulnerable
    assert not webui_enabled, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-1394. "
        "The device is an NCS 520 Router with web UI features enabled, which could allow an "
        "unauthenticated remote attacker to cause a denial of service condition through crafted TCP packets. "
        "Note: This vulnerability does not impact traffic going through the device or"
        "to the Management Ethernet interface. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ncs520-tcp-ZpzzOxB"
    )

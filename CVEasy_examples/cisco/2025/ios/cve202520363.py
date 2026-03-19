from comfy import high


@high(
    name='rule_cve202520363',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | section webvpn'
    ),
)
def rule_cve202520363(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20363 vulnerability in Cisco IOS Software.
    The vulnerability is due to improper validation of user-supplied input in HTTP requests
    to web services. An authenticated, remote attacker with low user privileges could exploit
    this vulnerability to execute arbitrary code as root on devices with Remote Access SSL VPN enabled.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if this is Cisco IOS Software
    if 'Cisco IOS Software' not in version_output:
        return

    # Extract configuration output
    config_output = commands.show_running_config

    # Check if Remote Access SSL VPN is enabled
    # The device is vulnerable if webvpn gateway is configured with 'inservice'
    ssl_vpn_enabled = False
    
    if 'webvpn' in config_output:
        # Check for 'inservice' command which indicates SSL VPN is active
        if 'inservice' in config_output:
            ssl_vpn_enabled = True

    # If SSL VPN is not enabled, the device is not vulnerable
    if not ssl_vpn_enabled:
        return

    # If we reach here, the device has SSL VPN enabled and is vulnerable
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-20363. "
        "The device has Remote Access SSL VPN feature enabled (webvpn with inservice), "
        "which makes it susceptible to remote code execution attacks by authenticated attackers with low privileges. "
        "An attacker could exploit this vulnerability by sending crafted HTTP requests to execute arbitrary code as root. "
        "Upgrade to a fixed software release immediately. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-http-code-exec-WmfP3h3O"
    )
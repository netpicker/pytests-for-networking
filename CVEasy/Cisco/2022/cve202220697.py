from comfy import high


@high(
    name='rule_cve202220697',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_http='show running-config | include ip http'
    ),
)
def rule_cve202220697(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20697 vulnerability in Cisco IOS Software.
    The vulnerability is due to improper resource management in the HTTP server code.
    An attacker could exploit this vulnerability by sending a large number of HTTP requests
    to an affected device, causing it to reload and resulting in a denial of service (DoS) condition.
    """
    # Extract the output of the command to check HTTP configuration
    http_output = commands.check_http

    # Check if HTTP server is enabled
    http_enabled = any(service in http_output for service in ['ip http server', 'ip http secure-server'])

    # Assert that the device is not vulnerable
    assert not http_enabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20697. "
        "The device has HTTP/HTTPS server enabled, "
        "which could allow an attacker to cause a denial of service through crafted HTTP requests. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-http-dos-svOdkdBS"
    )

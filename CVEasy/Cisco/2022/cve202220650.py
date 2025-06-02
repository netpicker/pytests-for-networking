from comfy import high


@high(
    name='rule_cve202220650',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_nxapi='show running-config | include feature nxapi'
    ),
)
def rule_cve202220650(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20650 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to insufficient input validation of user supplied data that is sent to the NX-API.
    An authenticated, remote attacker could exploit this vulnerability by sending a crafted HTTP POST request
    to the NX-API of an affected device, allowing them to execute arbitrary commands with root privileges.
    Note: The NX-API feature is disabled by default.
    """
    # Extract the output of the command to check NX-API configuration
    nxapi_output = commands.check_nxapi

    # Check if NX-API is enabled
    nxapi_enabled = 'feature nxapi' in nxapi_output

    # If NX-API is not enabled, device is not vulnerable
    if not nxapi_enabled:
        return

    # Assert that the device is not vulnerable
    assert not nxapi_enabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20650. "
        "The device has NX-API enabled, which could allow an authenticated attacker "
        "to execute arbitrary commands with root privileges through crafted HTTP POST requests. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-nxapi-cmdinject-ULukNMZ2"
    )

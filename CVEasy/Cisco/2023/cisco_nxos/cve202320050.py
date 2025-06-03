from comfy import high


@high(
    name='rule_cve202320050',
    platform=['cisco_nxos'],
    commands=dict(
        check_cli='show running-config | include cli'
    ),
)
def rule_cve202320050(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20050 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to insufficient validation of arguments that are passed to specific CLI commands.
    An attacker could exploit this vulnerability by including crafted input as the argument of an affected command.
    """
    # Extract the output of the command to check CLI configuration
    cli_output = commands.check_cli

    # Check if CLI command is configured
    cli_configured = 'cli' in cli_output

    # Assert that the device is not vulnerable
    assert not cli_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20050. "
        "The device has CLI command enabled, which could allow an attacker to execute arbitrary commands. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-"
        "sa-nxos-cli-cmdinject-euQVK9u"
    )

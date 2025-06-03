from comfy import high


@high(
    name='rule_cve202320168',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_tacacs_radius='show running-config | include tacacs|radius'
    ),
)
def rule_cve202320168(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20168 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to incorrect input validation when processing an authentication attempt
    if the directed request option is enabled for TACACS+ or RADIUS, which could allow an unauthenticated,
    local attacker to cause the device to unexpectedly reload, resulting in a denial of service (DoS) condition.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.2 versions
        '4.2(1)SV1(4)', '4.2(1)SV1(4a)', '4.2(1)SV1(4b)', '4.2(1)SV1(5.1)', '4.2(1)SV1(5.1a)',
        '4.2(1)SV1(5.2)', '4.2(1)SV1(5.2b)', '4.2(1)SV2(1.1)', '4.2(1)SV2(1.1a)', '4.2(1)SV2(2.1)',
        '4.2(1)SV2(2.1a)', '4.2(1)SV2(2.2)', '4.2(1)SV2(2.3)',
        # 5.2 versions
        '5.2(1)SM1(5.1)', '5.2(1)SM1(5.2)', '5.2(1)SM1(5.2a)', '5.2(1)SM1(5.2b)', '5.2(1)SM1(5.2c)',
        '5.2(1)SM3(1.1)', '5.2(1)SM3(1.1a)', '5.2(1)SM3(1.1b)', '5.2(1)SM3(1.1c)', '5.2(1)SM3(2.1)',
        '5.2(1)SV3(1.4)', '5.2(1)SV3(1.1)', '5.2(1)SV3(1.3)', '5.2(1)SV3(1.5a)', '5.2(1)SV3(1.5b)',
        '5.2(1)SV3(1.6)', '5.2(1)SV3(1.10)', '5.2(1)SV3(1.15)', '5.2(1)SV3(2.1)', '5.2(1)SV3(2.5)',
        '5.2(1)SV3(2.8)', '5.2(1)SV3(3.1)', '5.2(1)SV3(1.2)', '5.2(1)SV3(1.4b)', '5.2(1)SV3(3.15)',
        '5.2(1)SV3(4.1)', '5.2(1)SV3(4.1a)', '5.2(1)SV3(4.1b)', '5.2(1)SV3(4.1c)',
        # 6.0 versions
        '6.0(2)A3(1)', '6.0(2)A3(2)', '6.0(2)A3(4)', '6.0(2)A4(1)', '6.0(2)A4(2)', '6.0(2)A4(3)',
        '6.0(2)A4(4)', '6.0(2)A4(5)', '6.0(2)A4(6)', '6.0(2)A6(1)', '6.0(2)A6(1a)', '6.0(2)A6(2)',
        '6.0(2)A6(2a)', '6.0(2)A6(3)', '6.0(2)A6(3a)', '6.0(2)A6(4)', '6.0(2)A6(4a)', '6.0(2)A6(5)',
        '6.0(2)A6(5a)', '6.0(2)A6(5b)', '6.0(2)A6(6)', '6.0(2)A6(7)', '6.0(2)A6(8)', '6.0(2)A7(1)',
        '6.0(2)A7(1a)', '6.0(2)A7(2)', '6.0(2)A7(2a)', '6.0(2)A8(1)', '6.0(2)A8(2)', '6.0(2)A8(3)',
        '6.0(2)A8(4)', '6.0(2)A8(4a)', '6.0(2)A8(5)', '6.0(2)A8(6)', '6.0(2)A8(7)', '6.0(2)A8(7a)',
        '6.0(2)A8(7b)', '6.0(2)A8(8)', '6.0(2)A8(9)', '6.0(2)A8(10a)', '6.0(2)A8(10)', '6.0(2)A8(11)',
        '6.0(2)A8(11a)', '6.0(2)A8(11b)', '6.0(2)U2(1)', '6.0(2)U2(2)', '6.0(2)U2(3)', '6.0(2)U2(4)',
        '6.0(2)U2(5)', '6.0(2)U2(6)', '6.0(2)U3(1)', '6.0(2)U3(2)', '6.0(2)U3(3)', '6.0(2)U3(4)',
        '6.0(2)U3(5)', '6.0(2)U3(6)', '6.0(2)U3(7)', '6.0(2)U3(8)', '6.0(2)U3(9)', '6.0(2)U4(1)',
        '6.0(2)U4(2)', '6.0(2)U4(3)', '6.0(2)U4(4)', '6.0(2)U5(1)', '6.0(2)U5(2)', '6.0(2)U5(3)',
        '6.0(2)U5(4)', '6.0(2)U6(1)', '6.0(2)U6(2)', '6.0(2)U6(3)', '6.0(2)U6(4)', '6.0(2)U6(5)',
        '6.0(2)U6(6)', '6.0(2)U6(7)', '6.0(2)U6(8)', '6.0(2)U6(1a)', '6.0(2)U6(2a)', '6.0(2)U6(3a)',
        '6.0(2)U6(4a)', '6.0(2)U6(5a)', '6.0(2)U6(5b)', '6.0(2)U6(5c)', '6.0(2)U6(9)', '6.0(2)U6(10)',
        # 6.2 versions
        '6.2(2)', '6.2(2a)', '6.2(6)', '6.2(6b)', '6.2(8)', '6.2(8a)', '6.2(8b)', '6.2(10)',
        '6.2(12)', '6.2(18)', '6.2(16)', '6.2(14)', '6.2(6a)', '6.2(20)', '6.2(1)', '6.2(3)',
        '6.2(5)', '6.2(5a)', '6.2(5b)', '6.2(7)', '6.2(9)', '6.2(9a)', '6.2(9b)', '6.2(9c)',
        '6.2(11)', '6.2(11b)', '6.2(11c)', '6.2(11d)', '6.2(11e)', '6.2(13)', '6.2(13a)', '6.2(13b)',
        '6.2(15)', '6.2(17)', '6.2(19)', '6.2(21)', '6.2(23)', '6.2(20a)', '6.2(25)', '6.2(22)',
        '6.2(27)', '6.2(29)', '6.2(24)', '6.2(31)', '6.2(24a)', '6.2(33)',
        # 7.0 versions
        '7.0(3)F1(1)', '7.0(3)F2(1)', '7.0(3)F2(2)', '7.0(3)F3(1)', '7.0(3)F3(2)', '7.0(3)F3(3)',
        '7.0(3)F3(3a)', '7.0(3)F3(4)', '7.0(3)F3(3c)', '7.0(3)F3(5)', '7.0(3)I2(2a)', '7.0(3)I2(2b)',
        '7.0(3)I2(2c)', '7.0(3)I2(2d)', '7.0(3)I2(2e)', '7.0(3)I2(3)', '7.0(3)I2(4)', '7.0(3)I2(5)',
        '7.0(3)I2(1)', '7.0(3)I2(1a)', '7.0(3)I2(2)', '7.0(3)I3(1)', '7.0(3)I4(1)', '7.0(3)I4(2)',
        '7.0(3)I4(3)', '7.0(3)I4(4)', '7.0(3)I4(5)', '7.0(3)I4(6)', '7.0(3)I4(7)', '7.0(3)I4(8)',
        '7.0(3)I4(8a)', '7.0(3)I4(8b)', '7.0(3)I4(8z)', '7.0(3)I4(9)', '7.0(3)I5(1)', '7.0(3)I5(2)',
        '7.0(3)I6(1)', '7.0(3)I6(2)', '7.0(3)I7(1)', '7.0(3)I7(2)', '7.0(3)I7(3)', '7.0(3)I7(4)',
        '7.0(3)I7(5)', '7.0(3)I7(5a)', '7.0(3)I7(6)', '7.0(3)I7(7)', '7.0(3)I7(8)', '7.0(3)I7(9)',
        '7.0(3)I7(10)',
        # 7.1 versions
        '7.1(0)N1(1a)', '7.1(0)N1(1b)', '7.1(0)N1(1)', '7.1(1)N1(1)', '7.1(2)N1(1)', '7.1(3)N1(1)',
        '7.1(3)N1(2)', '7.1(4)N1(1)', '7.1(5)N1(1)', '7.1(5)N1(1b)',
        # 7.2 versions
        '7.2(0)D1(1)', '7.2(1)D1(1)', '7.2(2)D1(2)', '7.2(2)D1(1)',
        # 7.3 versions
        '7.3(0)D1(1)', '7.3(0)DX(1)', '7.3(0)DY(1)', '7.3(0)N1(1)', '7.3(1)D1(1)', '7.3(1)DY(1)',
        '7.3(1)N1(1)', '7.3(2)D1(1)', '7.3(2)D1(2)', '7.3(2)D1(3)', '7.3(2)D1(3a)', '7.3(2)N1(1)',
        '7.3(3)N1(1)', '7.3(4)N1(1)', '7.3(3)D1(1)', '7.3(4)D1(1)', '7.3(5)N1(1)', '7.3(6)N1(1)',
        '7.3(5)D1(1)', '7.3(7)N1(1)', '7.3(7)N1(1a)', '7.3(7)N1(1b)', '7.3(6)D1(1)', '7.3(8)N1(1)',
        '7.3(7)D1(1)', '7.3(9)N1(1)', '7.3(10)N1(1)', '7.3(8)D1(1)', '7.3(9)D1(1)', '7.3(11)N1(1)',
        '7.3(12)N1(1)', '7.3(13)N1(1)',
        # 8.0 versions
        '8.0(1)',
        # 8.1 versions
        '8.1(1)', '8.1(2)', '8.1(2a)', '8.1(1a)', '8.1(1b)',
        # 8.2 versions
        '8.2(1)', '8.2(2)', '8.2(3)', '8.2(4)', '8.2(5)', '8.2(6)', '8.2(7)', '8.2(7a)', '8.2(8)',
        '8.2(9)',
        # 8.3 versions
        '8.3(1)', '8.3(2)',
        # 8.4 versions
        '8.4(1)', '8.4(1a)', '8.4(2)', '8.4(2a)', '8.4(3)', '8.4(2b)', '8.4(4)', '8.4(2c)',
        '8.4(4a)', '8.4(5)', '8.4(2d)', '8.4(6)', '8.4(2e)', '8.4(6a)', '8.4(7)', '8.4(2f)',
        # 8.5 versions
        '8.5(1)',
        # 9.2 versions
        '9.2(1)', '9.2(2)', '9.2(2t)', '9.2(3)', '9.2(4)', '9.2(2v)', '9.2(1a)',
        # 9.3 versions
        '9.3(1)', '9.3(2)', '9.3(3)', '9.3(4)', '9.3(5)', '9.3(6)', '9.3(7)', '9.3(7a)', '9.3(8)',
        '9.3(9)', '9.3(10)', '9.3(11)',
        # 10.1 versions
        '10.1(1)', '10.1(2)', '10.1(2t)',
        # 10.2 versions
        '10.2(1)', '10.2(1q)', '10.2(2)', '10.2(3)', '10.2(3t)', '10.2(4)', '10.2(5)',
        # 10.3 versions
        '10.3(1)', '10.3(2)',
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Extract the output of the command to check TACACS+ and RADIUS configuration
    tacacs_radius_output = commands.check_tacacs_radius

    # Check if TACACS+ or RADIUS is configured
    tacacs_radius_configured = 'tacacs' in tacacs_radius_output or 'radius' in tacacs_radius_output

    # Assert that the device is not vulnerable
    assert not tacacs_radius_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20168. "
        "The device is running a vulnerable version AND has TACACS+ or RADIUS configured, "
        "which could allow an attacker to cause a denial of service. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-"
        "sa-nxos-remoteauth-dos-XB6pv74m"
    )

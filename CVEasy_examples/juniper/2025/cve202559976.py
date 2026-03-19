from comfy import high


@high(
    name='rule_cve202559976',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_config_jboss=(
            'show configuration | display set | match "junos-space"'
        ),
    ),
)
def rule_cve202559976(configuration, commands, device, devices):
    """
    CVE-2025-59976: Authenticated attacker can download arbitrary files
    from Junos Space (before 24.1R3) via crafted GET requests.
    """
    version_output = commands.show_version

    if 'Junos Space' not in version_output:
        return

    vulnerable = False

    if any(ver in version_output for ver in [
        '19.', '20.', '21.', '22.', '23.',
        '24.1R1', '24.1R2',
    ]):
        vulnerable = True

    if '24.1R3' in version_output or '24.2' in version_output:
        vulnerable = False
    if '25.' in version_output:
        vulnerable = False

    if not vulnerable:
        return

    config_output = commands.show_config_jboss
    web_interface_enabled = (
        'set system services junos-space' in config_output
    )

    assert not web_interface_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-59976. "
        "Running a vulnerable Junos Space version (before 24.1R3) "
        "with the web interface enabled allows authenticated attackers "
        "to download arbitrary files. "
        "See https://supportportal.juniper.net/JSA88976"
    )

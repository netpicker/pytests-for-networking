from comfy.compliance import medium


@medium(
    name='rule_11_install_the_latest_firmware',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show sysinfo')
)
def rule_11_install_the_latest_firmware(commands, ref):
    assert 'Product Version.................................. 17.3' in commands.chk_cmd, ref

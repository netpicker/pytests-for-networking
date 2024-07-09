from comfy.compliance import medium


@medium(
      name='rule_1_4_3_4_ensure_aaa_authentication_serial_console_is_configured_correctly',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_4_3_4_ensure_aaa_authentication_serial_console_is_configured_correctly(commands, ref):
    assert '' in commands.chk_cmd, ref

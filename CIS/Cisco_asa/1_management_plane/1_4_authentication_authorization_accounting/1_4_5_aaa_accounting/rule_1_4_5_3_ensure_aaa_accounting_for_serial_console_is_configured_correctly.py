from comfy.compliance import medium


@medium(
      name='rule_1_4_5_3_ensure_aaa_accounting_for_serial_console_is_configured_correctly',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_4_5_3_ensure_aaa_accounting_for_serial_console_is_configured_correctly(commands, ref):
    assert '' in commands.chk_cmd, ref

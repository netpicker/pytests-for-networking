from comfy.compliance import medium


@medium(
      name='rule_1_4_5_4_ensure_aaa_accounting_for_exec_mode_is_configured_correctly',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_4_5_4_ensure_aaa_accounting_for_exec_mode_is_configured_correctly(commands, ref):
    assert '' in commands.chk_cmd, ref

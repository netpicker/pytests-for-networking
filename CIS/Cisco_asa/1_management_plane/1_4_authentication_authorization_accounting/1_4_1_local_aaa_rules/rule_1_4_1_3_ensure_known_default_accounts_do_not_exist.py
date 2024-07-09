from comfy.compliance import medium


@medium(
      name='rule_1_4_1_3_ensure_known_default_accounts_do_not_exist',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_4_1_3_ensure_known_default_accounts_do_not_exist(commands, ref):
    assert '' in commands.chk_cmd, ref

from comfy.compliance import medium


@medium(
      name='rule_6_6_1_3_ensure_minimum_backoff_factor_of_5',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_6_1_3_ensure_minimum_backoff_factor_of_5(commands, ref):
    assert '' in commands.chk_cmd, ref

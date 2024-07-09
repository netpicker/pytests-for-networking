from comfy.compliance import medium


@medium(
      name='rule_1_2_1_ensure_domain_name_is_set',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_2_1_ensure_domain_name_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref

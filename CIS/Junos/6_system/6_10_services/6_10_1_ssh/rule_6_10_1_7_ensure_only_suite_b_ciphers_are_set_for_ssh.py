from comfy.compliance import low


@low(
      name='rule_6_10_1_7_ensure_only_suite_b_ciphers_are_set_for_ssh',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_1_7_ensure_only_suite_b_ciphers_are_set_for_ssh(commands, ref):
    assert '' in commands.chk_cmd, ref

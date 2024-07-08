from comfy.compliance import medium


@medium(
      name='rule_6_10_1_6_ensure_strong_ciphers_are_set_for_ssh',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_1_6_ensure_strong_ciphers_are_set_for_ssh(commands, ref):
    assert '' in commands.chk_cmd, ref

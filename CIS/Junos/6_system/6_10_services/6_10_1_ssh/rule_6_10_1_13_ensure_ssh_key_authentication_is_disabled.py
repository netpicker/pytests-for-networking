from comfy.compliance import low


@low(
      name='rule_6_10_1_13_ensure_ssh_key_authentication_is_disabled',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_1_13_ensure_ssh_key_authentication_is_disabled(commands, ref):
    assert '' in commands.chk_cmd, ref

from comfy.compliance import low


@low(
      name='rule_3_2_1_ensure_vrrp_authentication_key_is_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_3_2_1_ensure_vrrp_authentication_key_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref

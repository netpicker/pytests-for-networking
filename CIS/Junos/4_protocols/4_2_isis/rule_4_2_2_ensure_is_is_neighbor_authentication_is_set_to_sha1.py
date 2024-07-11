from comfy.compliance import low


@low(
      name='rule_4_2_2_ensure_is_is_neighbor_authentication_is_set_to_sha1',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_4_2_2_ensure_is_is_neighbor_authentication_is_set_to_sha1(commands, ref):
    assert '' in commands.chk_cmd, ref

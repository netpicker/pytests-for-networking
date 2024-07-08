from comfy.compliance import medium


@medium(
      name='rule_6_8_3_ensure_a_different_shared_secret_is_set_for_each_external_aaa_server',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_8_3_ensure_a_different_shared_secret_is_set_for_each_external_aaa_server(commands, ref):
    assert '' in commands.chk_cmd, ref

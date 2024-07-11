from comfy.compliance import medium


@medium(
      name='rule_6_8_1_ensure_external_aaa_server_is_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_8_1_ensure_external_aaa_server_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref

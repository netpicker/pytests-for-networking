from comfy.compliance import low


@low(
      name='rule_6_7_6_ensure_different_authentication_keys_for_each_ntp_server',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_7_6_ensure_different_authentication_keys_for_each_ntp_server(commands, ref):
    assert '' in commands.chk_cmd, ref

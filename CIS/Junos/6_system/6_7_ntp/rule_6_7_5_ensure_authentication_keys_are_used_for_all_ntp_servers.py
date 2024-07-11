from comfy.compliance import low


@low(
      name='rule_6_7_5_ensure_authentication_keys_are_used_for_all_ntp_servers',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_7_5_ensure_authentication_keys_are_used_for_all_ntp_servers(commands, ref):
    assert '' in commands.chk_cmd, ref

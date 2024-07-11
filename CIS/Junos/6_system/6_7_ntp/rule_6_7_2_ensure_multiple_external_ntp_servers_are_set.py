from comfy.compliance import low


@low(
      name='rule_6_7_2_ensure_multiple_external_ntp_servers_are_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_7_2_ensure_multiple_external_ntp_servers_are_set(commands, ref):
    assert '' in commands.chk_cmd, ref

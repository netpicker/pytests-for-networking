from comfy.compliance import medium


@medium(
      name='rule_6_7_1_ensure_external_ntp_servers_are_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_7_1_ensure_external_ntp_servers_are_set(commands, ref):
    assert '' in commands.chk_cmd, ref

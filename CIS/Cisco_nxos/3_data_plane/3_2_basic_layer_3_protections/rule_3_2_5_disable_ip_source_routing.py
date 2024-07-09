from comfy.compliance import medium


@medium(
      name='rule_3_2_5_disable_ip_source_routing',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_2_5_disable_ip_source_routing(commands, ref):
    assert '' in commands.chk_cmd, ref

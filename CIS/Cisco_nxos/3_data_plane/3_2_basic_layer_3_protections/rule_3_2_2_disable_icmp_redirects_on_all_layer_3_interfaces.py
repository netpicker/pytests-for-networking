from comfy.compliance import medium


@medium(
      name='rule_3_2_2_disable_icmp_redirects_on_all_layer_3_interfaces',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_2_2_disable_icmp_redirects_on_all_layer_3_interfaces(commands, ref):
    assert '' in commands.chk_cmd, ref

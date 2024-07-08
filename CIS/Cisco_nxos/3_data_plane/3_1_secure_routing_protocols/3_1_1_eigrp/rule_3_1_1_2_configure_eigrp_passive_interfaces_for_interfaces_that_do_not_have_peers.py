from comfy.compliance import medium


@medium(
      name='rule_3_1_1_2_configure_eigrp_passive_interfaces_for_interfaces_that_do_not_have_peers',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_1_2_configure_eigrp_passive_interfaces_for_interfaces_that_do_not_have_peers(commands, ref):
    assert '' in commands.chk_cmd, ref

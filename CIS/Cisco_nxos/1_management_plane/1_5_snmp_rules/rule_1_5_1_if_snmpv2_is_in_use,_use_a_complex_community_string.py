from comfy.compliance import medium


@medium(
      name='rule_1_5_1_if_snmpv2_is_in_use,_use_a_complex_community_string',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_5_1_if_snmpv2_is_in_use,_use_a_complex_community_string(commands, ref):
    assert '' in commands.chk_cmd, ref

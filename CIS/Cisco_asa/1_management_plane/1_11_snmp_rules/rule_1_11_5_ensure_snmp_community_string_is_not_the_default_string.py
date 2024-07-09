from comfy.compliance import medium


@medium(
      name='rule_1_11_5_ensure_snmp_community_string_is_not_the_default_string',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_11_5_ensure_snmp_community_string_is_not_the_default_string(commands, ref):
    assert '' in commands.chk_cmd, ref

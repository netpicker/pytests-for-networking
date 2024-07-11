from comfy.compliance import medium


@medium(
      name='rule_5_1_ensure_common_snmp_community_strings_are_not_used',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_5_1_ensure_common_snmp_community_strings_are_not_used(commands, ref):
    assert '' in commands.chk_cmd, ref

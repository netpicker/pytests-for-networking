from comfy.compliance import medium


@medium(
      name='rule_2_2_1_ensure_snmp_agent_is_disabled',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_2_1_ensure_snmp_agent_is_disabled(commands, ref):
    assert '' in commands.chk_cmd, ref

from comfy.compliance import medium


@medium(
      name='rule_3_1_ensure_dns_services_are_configured_correctly',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_3_1_ensure_dns_services_are_configured_correctly(commands, ref):
    assert '' in commands.chk_cmd, ref

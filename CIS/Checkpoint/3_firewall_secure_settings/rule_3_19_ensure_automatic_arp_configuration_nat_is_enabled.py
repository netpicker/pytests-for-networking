from comfy.compliance import low


@low(
      name='rule_3_19_ensure_automatic_arp_configuration_nat_is_enabled',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_19_ensure_automatic_arp_configuration_nat_is_enabled(commands, ref):
    assert '' in commands.chk_cmd, ref

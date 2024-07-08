from comfy.compliance import medium


@medium(
      name='rule_4_10_1_ensure_icmp_router_discovery_is_disabled',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_4_10_1_ensure_icmp_router_discovery_is_disabled(commands, ref):
    assert '' in commands.chk_cmd, ref

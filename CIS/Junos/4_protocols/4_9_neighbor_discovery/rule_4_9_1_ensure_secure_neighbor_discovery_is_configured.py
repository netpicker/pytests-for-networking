from comfy.compliance import low


@low(
      name='rule_4_9_1_ensure_secure_neighbor_discovery_is_configured',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_4_9_1_ensure_secure_neighbor_discovery_is_configured(commands, ref):
    assert '' in commands.chk_cmd, ref

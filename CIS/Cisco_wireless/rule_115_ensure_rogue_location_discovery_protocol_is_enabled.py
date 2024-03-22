from comfy.compliance import low


@low(
    name='rule_115_ensure_rogue_location_discovery_protocol_is_enabled',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show rogue ap rldp summary')
)
def rule_115_ensure_rogue_location_discovery_protocol_is_enabled(commands, ref):
    assert 'Rogue Location Discovery Protocol................ Enabled' in commands.chk_cmd, ref

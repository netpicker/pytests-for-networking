from comfy.compliance import low


@low(
      name='rule_3_10_ensure_inbound_firewall_filter_is_set_for_loopback_interface',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_3_10_ensure_inbound_firewall_filter_is_set_for_loopback_interface(commands, ref):
    assert '' in commands.chk_cmd, ref

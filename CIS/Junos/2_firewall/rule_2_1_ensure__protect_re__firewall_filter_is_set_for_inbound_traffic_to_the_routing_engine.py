from comfy.compliance import medium


@medium(
      name='rule_2_1_ensure__protect_re__firewall_filter_is_set_for_inbound_traffic_to_the_routing_engine',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_2_1_ensure__protect_re__firewall_filter_is_set_for_inbound_traffic_to_the_routing_engine(commands, ref):
    assert '' in commands.chk_cmd, ref

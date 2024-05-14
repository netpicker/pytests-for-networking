from comfy.compliance import medium


@medium(
    name='rule_2_1_ensure__protect_re__firewall_filter_is_set_for_inbound_traffic_to_the_routing_engine',
    platform=['juniper_junos'],
    commands={
        'show_ipv4_interfaces': 'show interfaces | match "family inet " | count',
        'show_ipv6_interfaces': 'show interfaces | match "family inet6 " | count',
        'show_lo0_ipv4_filter': 'show interfaces lo0 | display set | match "filter input"',
        'show_lo0_ipv6_filter': 'show interfaces lo0 | display set | match "filter input family inet6"'
    }
)
def rule_2_1_ensure__protect_re__firewall_filter_is_set_for_inbound_traffic_to_the_routing_engine(commands, ref):
    # Check if IPv4 and IPv6 are configured on the device
    ipv4_configured = int(commands['show_ipv4_interfaces']) > 0
    ipv6_configured = int(commands['show_ipv6_interfaces']) > 0

    # Check for the presence of the firewall filters on the loopback interface for IPv4
    ipv4_filter_present = 'family inet filter' in commands['show_lo0_ipv4_filter']
    if ipv4_configured:
        assert ipv4_filter_present, ref

    # Check for the presence of the firewall filters on the loopback interface for IPv6
    ipv6_filter_present = 'family inet6 filter' in commands['show_lo0_ipv6_filter']
    if ipv6_configured:
        assert ipv6_filter_present, ref

    # Additional checks can be added here to verify the specifics of the filter rules
    # such as ensuring they only allow management services from trusted hosts

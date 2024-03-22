from comfy.compliance import medium


@medium(
    name='rule_213_set_no_ip_bootp_server',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_213_set_no_ip_bootp_server(configuration, ref):
    assert 'no ip dhcp bootp server' in configuration, ref

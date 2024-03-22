from comfy.compliance import medium


@medium(
    name='rule_216_set_service_tcp_keepalives_in',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_216_set_service_tcp_keepalives_in(configuration, ref):
    assert 'service tcp-keepalives-in' in configuration, ref

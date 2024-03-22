from comfy.compliance import medium


@medium(
    name='rule_217_set_service_tcp_keepalives_out',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_217_set_service_tcp_keepalives_out(configuration, ref):
    assert 'service tcp-keepalives-out' in configuration, ref

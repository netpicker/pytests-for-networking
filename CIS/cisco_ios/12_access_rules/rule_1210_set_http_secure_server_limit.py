from comfy.compliance import medium


@medium(
    name='rule_1210_set_http_secure_server_limit',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_1210_set_http_secure_server_limit(configuration, ref):
    assert 'ip http max-connections' in configuration, ref

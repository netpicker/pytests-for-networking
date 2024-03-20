from comfy.compliance import medium

uri = (
    ""
    ""
)

remediation = (f"""
    Remediation: hostname(config)#ip http max-connections 2

    References: {uri}

    """)


@medium(
  name='rule_1210_set_http_secure_server_limit',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_1210_set_http_secure_server_limit(configuration):
    assert 'ip http secure-server' in configuration, remediation

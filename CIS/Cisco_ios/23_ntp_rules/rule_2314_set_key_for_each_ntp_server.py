from comfy.compliance import low


@low(
  name='rule_2314_set_key_for_each_ntp_server',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_2314_set_key_for_each_ntp_server(configuration):
    remediation = (f"""
    Remediation: hostname(config)#ntp server {{<em> ntp-server_ip_address</em>}}{{key
                 <em>ntp_key_id</em>}

    """)

    assert 'ntp server {} key' in configuration, remediation

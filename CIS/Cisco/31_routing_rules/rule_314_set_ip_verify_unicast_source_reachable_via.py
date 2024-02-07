from comfy.compliance import medium


uri = (
    "https://community.cisco.com/t5/routing/ip-verify-unicast-source-reachable-via-rx/td-p/1710172"
    ""
)

remediation = (f"""
    Remediation: hostname(config-if)#ip verify un icast source reachable-via rx allow-default

    References: {uri}

    """)


@medium(
  name='rule_314_set_ip_verify_unicast_source_reachable_via',
  platform=['cisco_ios', 'cisco_xe'],
  commands=dict(chk_cmd='sh ip int {<em>interface</em>} | incl verify source')
)
def rule_314_set_ip_verify_unicast_source_reachable_via(commands):
    assert ' verify source' in commands.chk_cmd, remediation

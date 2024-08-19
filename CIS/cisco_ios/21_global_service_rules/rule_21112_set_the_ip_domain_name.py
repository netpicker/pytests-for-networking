from comfy.compliance import medium


@medium(
    name='rule_21112_set_the_ip_domain_name',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_21112_set_the_ip_domain_name(configuration, ref):
    assert 'domain-name' in configuration, ref

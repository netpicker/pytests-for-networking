from comfy.compliance import low


@low(
    name='rule_228_set_login_successfailure_logging',
    platform=['cisco_ios', 'cisco_xe']
)
def rule_228_set_login_successfailure_logging(configuration, ref):
    assert 'login on' in configuration, ref

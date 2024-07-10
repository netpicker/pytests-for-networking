from comfy.compliance import medium


@medium(
      name='rule_1_2_1_set_the_hostname',
      platform=['cisco_xr'],
      # commands=dict(chk_cmd='sh run | incl hostname')
)
def rule_1_2_1_set_the_hostname(configuration, ref):
    assert 'hostname' in configuration, ref

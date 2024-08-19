from comfy.compliance import low


@low(
  name='rule_244_set_ip_tftp_source_interface_to_the_loopback_interface',
  platform=['cisco_ios', 'cisco_xe']
)
def rule_244_set_ip_tftp_source_interface_to_the_loopback_interface(configuration, ref):
    assert 'tftp source-interface' in configuration, ref

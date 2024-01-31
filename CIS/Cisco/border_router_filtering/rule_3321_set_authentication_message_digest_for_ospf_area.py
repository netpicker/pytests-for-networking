import pytest
from comfy.compliance import *

@low(
  name = 'rule_3321_set_authentication_message_digest_for_ospf_area',
  platform = ['cisco_ios'],
  commands=dict(check_command='hostname#sh run | sec router ospf')
)
def rule_3321_set_authentication_message_digest_for_ospf_area(configuration, commands, device):
    assert ' router ospf' in configuration

# Remediation: hostname(config)#router ospf <<em>osp f_process-id</em>>  

# References: 2.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_ospf/command/ospf-a1.html#GUID-81D0F753-D8D5-494E-9A10-B15433CFD445

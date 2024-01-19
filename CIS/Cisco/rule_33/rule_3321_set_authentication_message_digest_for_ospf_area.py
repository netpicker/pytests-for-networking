import pytest
from comfy.compliance import *

@low(
  name = rule_3321_set_authentication_message_digest_for_ospf_area,
  platform = ['cisco_ios']
)
def rule_3321_set_authentication_message_digest_for_ospf_area(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#router ospf <<em>osp f_process -id</em>>  

#References: 2. http://www.cisco.com/en/US/docs/ios -xml/ios/iproute_ospf/command/ospf -

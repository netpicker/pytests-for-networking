import pytest
from comfy.compliance import *

@low(
  name = 'rule_3319_set_ip_authentication_mode_eigrp',
  platform = ['cisco_ios']
)
def rule_3319_set_ip_authentication_mode_eigrp(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#interface {<em>interface_name</em>}  

#References: 2. http://www.cisco.com/en/US/docs/ios -xml/ios/iproute_eigrp/command/ire -

import pytest
from comfy.compliance import *

@medium(
  name = 'rule_3317_set_authentication_mode_md5',
  platform = ['cisco_ios']
)
def rule_3317_set_authentication_mode_md5(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#router eigrp <virtual -instance -name> 

#References: 3. http://www.cisco.com/en/US/docs/ios -xml/ios/iproute_eigrp/command/ire -

import pytest
from comfy.compliance import *

@medium(
  name = 'rule_114_set_login_authentication_for_line_vty_ted',
  platform = ['cisco_ios']
)
def rule_114_set_login_authentication_for_line_vty_ted(configuration,commands,device):
    assert 'hostname#show running -config | sec line | incl l ogin authentication' in configuration  

#Remediation: hostname(config)#line vty {line -number} [<em>ending -line-number] 

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/security/d1/sec -cr-k1.html#GUID -

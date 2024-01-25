import pytest
from comfy.compliance import *

@medium(
  name = 'rule_112_enable_aaa_authentication_login',
  platform = ['cisco_ios']
)
def rule_112_enable_aaa_authentication_login(configuration,commands,device):
    assert 'aaa authentication login' in configuration  

#Remediation: hostname(config)#aaa authentication login {default | aaa_list_name} [passwd -

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/security/a1/sec -cr-a1.html#GUID -

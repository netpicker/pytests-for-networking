import pytest
from comfy.compliance import *

@medium(
  name = 'rule_121_set_privilege_1_for_local_users',
  platform = ['cisco_ios']
)
def rule_121_set_privilege_1_for_local_users(configuration,commands,device):
    assert 'privilege' in configuration  

#Remediation: hostname(config)#username <LOCAL_USERNAME> privilege 1  

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/security/s1/sec -cr-t2-z.html#GUID -

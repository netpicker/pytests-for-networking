import pytest
from comfy.compliance import *

@medium(
  name = rule_143_set_username_secret_for_all_local_users,
  platform = ['cisco_ios']
)
def rule_143_set_username_secret_for_all_local_users(configuration,commands,device):
    assert 'username' in configuration  

#Remediation: hostname(config)#username {{em}LOCAL_USERNAME{/em}} secret 

#References: 

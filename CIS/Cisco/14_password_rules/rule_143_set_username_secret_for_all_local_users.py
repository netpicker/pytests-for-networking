import pytest
from comfy.compliance import *

@medium(
  name = 'rule_143_set_username_secret_for_all_local_users',
  platform = ['cisco_ios']
)
def rule_143_set_username_secret_for_all_local_users(configuration, commands, device):
    assert 'username' in configuration,"\n# Remediation: hostname(config)#username {{em}LOCAL_USERNAME{/em}} secret \n# References: 1.https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9600/software/releas\n\n"

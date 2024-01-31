import pytest
from comfy.compliance import *

@medium(
  name = 'rule_215_set_no_ip_identd',
  platform = ['cisco_ios']
)
def rule_215_set_no_ip_identd(configuration, commands, device):
    assert 'identd' in configuration,"\n# Remediation: hostname(config)#no ip identd  \n# References: 1.http://www.cisco.com/en/US/docs/solutions/Enterprise/Security/Baseline_Securit\n\n

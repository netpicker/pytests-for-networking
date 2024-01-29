import pytest
from comfy.compliance import *

@medium(
  name = 'rule_131_set_the_banner_text_for_banner_exec',
  platform = ['cisco_ios']
)
def rule_131_set_the_banner_text_for_banner_exec(configuration, commands, device):
    assert 'hostname#sh running-config | beg banner exec' in configuration

# Remediation: hostname(config)#banner exec c  

# References: 1. http://www.cisco.com/en/US/docs/ios -

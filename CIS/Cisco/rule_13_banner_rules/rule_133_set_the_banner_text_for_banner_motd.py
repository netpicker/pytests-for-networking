import pytest
from comfy.compliance import *

@medium(
  name = rule_133_set_the_banner_text_for_banner_motd,
  platform = ['cisco_ios']
)
def rule_133_set_the_banner_text_for_banner_motd(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#banner motd c  

#References: 1. http://www.cisco.com/en/US/docs/ios -

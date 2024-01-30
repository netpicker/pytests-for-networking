import pytest
from comfy.compliance import *

@medium(
  name = 'rule_132_set_the_banner_text_for_banner_login',
  platform = ['cisco_ios']
)
def rule_132_set_the_banner_text_for_banner_login(configuration, commands, device):
    assert 'hostname#show running-config | beg banner login' in configuration

# Remediation: hostname(config)#banner login c 

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/A_through_B.html#GUID-FF0B6890-85B8-4B6A-90DD-1B7140C5D22F

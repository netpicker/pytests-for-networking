import pytest
from comfy.compliance import *

@low(
  name = 'rule_242_set_aaa_source_interface',
  platform = ['cisco_ios']
)
def rule_242_set_aaa_source_interface(configuration, commands, device):
    assert 'hostname#sh run | incl tacacs source | radius source' in configuration

# Remediation: 

# References: 2. http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-i3.html#GUID -

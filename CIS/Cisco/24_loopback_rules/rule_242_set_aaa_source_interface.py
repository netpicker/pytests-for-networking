import pytest
from comfy.compliance import *

@low(
  name = 'rule_242_set_aaa_source_interface',
  platform = ['cisco_ios']
)
def rule_242_set_aaa_source_interface(configuration, commands, device):
    assert 'tacacs source | radius source' in configuration,"\n# Remediation: \n# References: 2.http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-i3.html#GUID-54A00318-CF69-46FC-9ADC-313BFC436713\n\n

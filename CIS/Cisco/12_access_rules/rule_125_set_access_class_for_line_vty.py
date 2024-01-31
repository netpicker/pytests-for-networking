import pytest
from comfy.compliance import *

@medium(
  name = 'rule_125_set_access_class_for_line_vty',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh run | sec vty <line-number> <ending-line-number>')
)
def rule_125_set_access_class_for_line_vty(configuration, commands, device):
    assert f' vty <line-number> <ending-line-number>' in commands.check_command,"\n# Remediation: hostname(config)#line vty <line-number> <ending-line-number> \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a2.html#GUID-FB9BC58A-F00A-442A-8028-1E9E260E54D3\n\n"

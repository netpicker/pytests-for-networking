import pytest
from comfy.compliance import *

@medium(
  name = 'rule_114_set_login_authentication_for_line_vty_ted',
  platform = ['cisco_ios'],
  commands=dict(check_command='show running-config | sec line | incl l ogin authentication')
)
def rule_114_set_login_authentication_for_line_vty_ted(configuration, commands, device):
    assert ' l ogin authentication' in configuration

# Remediation: hostname(config)#line vty {line-number} [<em>ending-line-number] 

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-k1.html#GUID-297BDF33-4841-441C-83F3-4DA51C3C7284

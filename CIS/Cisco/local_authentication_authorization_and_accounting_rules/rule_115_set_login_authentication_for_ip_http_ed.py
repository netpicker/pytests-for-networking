import pytest
from comfy.compliance import *

@medium(
  name = 'rule_115_set_login_authentication_for_ip_http_ed',
  platform = ['cisco_ios']
)
def rule_115_set_login_authentication_for_ip_http_ed(configuration, commands, device):
    assert 'hostname#show run ning-config | inc ip http authentication' in configuration

# Remediation: 

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-k1.html#GUID-297BDF33-4841-441C-83F3-4DA51C3C7284

import pytest
from comfy.compliance import *

@medium(
  name = 'rule_112_enable_aaa_authentication_login',
  platform = ['cisco_ios']
)
def rule_112_enable_aaa_authentication_login(configuration, commands, device):
    assert 'aaa authentication login' in configuration,"\n# Remediation: hostname(config)#aaa authentication login {default | aaa_list_name} [passwd -\n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a1.html#GUID-3DB1CC8A-4A98-400B-A906-C42F265C7EA2\n\n"

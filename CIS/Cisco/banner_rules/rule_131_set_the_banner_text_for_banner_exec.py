import pytest
from comfy.compliance import *

@medium(
  name = 'rule_131_set_the_banner_text_for_banner_exec',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh running-config | beg banner exec')
)
def rule_131_set_the_banner_text_for_banner_exec(configuration, commands, device):
    assert ' banner exec' in configuration

# Remediation: hostname(config)#banner exec c  

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/A_through_B.html#GUID-0DEF5B57-A7D9-4912-861F-E837C82A3881

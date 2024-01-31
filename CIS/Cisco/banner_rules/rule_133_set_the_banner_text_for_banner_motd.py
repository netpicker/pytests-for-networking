import pytest
from comfy.compliance import *

@medium(
  name = 'rule_133_set_the_banner_text_for_banner_motd',
  platform = ['cisco_ios'],
  commands=dict(check_command=hostname#sh running-config | beg banner motd)
)
def rule_133_set_the_banner_text_for_banner_motd(configuration, commands, device):
    assert ' banner motd' in configuration

# Remediation: hostname(config)#banner motd c  

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/A_through_B.html#GUID-7416C789-9561-44FC-BB2A-D8D8AFFB77DD

import pytest
from comfy.compliance import *

@low(
  name = 'rule_228_set_login_successfailure_logging_d',
  platform = ['cisco_ios']
)
def rule_228_set_login_successfailure_logging_d(configuration, commands, device):
    assert '' in configuration

# Remediation: hostname(config)#end  

# References: 1.https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/config-mgmt/configuration/xe-16-6/config-mgmt-xe-16-6-book/cm-config-logger.pdf

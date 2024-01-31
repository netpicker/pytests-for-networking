import pytest
from comfy.compliance import *

@medium(
  name = 'rule_216_set_service_tcp_keepalives_in',
  platform = ['cisco_ios']
)
def rule_216_set_service_tcp_keepalives_in(configuration, commands, device):
    assert 'service tcp' in configuration,"\n# Remediation: hostname(config)#serv ice tcp-keepalives-in \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/fundamentals/command/R_through_setup.html#GUID-1489ABA3-2428-4A64-B252-296A035DB85E\n\n"

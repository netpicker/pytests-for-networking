from comfy import high
import re


@high(
    name="rule_cve_2021_34699",
    platform=["cisco_xe", "cisco_ios"],
    commands=dict(
        show_subsys="show subsys | include cts_core",
        show_http_config="show running-config | include ip http server|secure-server",
    ),
)
def rule_cve_2021_34699(configuration, commands, device, devices):
    """
    CVE-2021-34699: TrustSec CLI parser flaw allowing authenticated DoS (device reload)
    if HTTP(S) server and TrustSec capability are enabled.
    """
    subsys_output = commands.show_subsys or ""
    http_cfg = commands.show_http_config or ""

    print(f"DEBUG: show_subsys = {commands.show_subsys!r}")

    # TrustSec subsystem must exist
    if "cts_core" not in subsys_output:
        return

    # HTTP server feature must be enabled
    if not re.search(r"ip http (server|secure-server)", http_cfg):
        return

    # Safe if active-session-modules mitigation is in place
    if "ip http active-session-modules none" in http_cfg or \
       "ip http secure-active-session-modules none" in http_cfg:
        return

    # Trigger alert — there is no version-based fixed threshold publicly listed
    assert False, (
        f"Device {device.name or device.ipaddress or 'unknown'} is vulnerable to CVE-2021-34699. "
        "Disable HTTP(S) server or upgrade to a fixed release per advisory. "
        "See Cisco advisory."
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-trustsec-dos-7fuXDR2"
    )

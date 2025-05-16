from comfy import high
import re
from packaging import version

@high(
    name="rule_cve_2023_20273",
    platform=["cisco_xe"],
    commands=dict(
        chk_cmd="show version | include RELEASE SOFTWARE"
    )
)
def rule_cve_2023_20273(commands, ref):
    output = str(commands.chk_cmd)

    # Extract version number using regex
    match = re.search(r"Version (\d+\.\d+\.\d+)", output)
    if not match:
        raise AssertionError(f"Could not parse version from output: {output}")

    ver_str = match.group(1)
    ver = version.parse(ver_str)

    # Determine if the version is vulnerable
    vulnerable = (
        (ver.major == 17 and ver.minor == 3 and ver < version.parse("17.3.8")) or
        (ver.major == 17 and ver.minor == 6 and ver < version.parse("17.6.6")) or
        (ver.major == 17 and ver.minor == 9 and ver < version.parse("17.9.4")) or
        (ver.major == 16 and ver.minor == 12 and ver < version.parse("16.12.10"))
    )

    assert not vulnerable, f"Device is running vulnerable IOS XE version: {ver_str}"

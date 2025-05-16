from comfy import high


@high(
    name="rule_cve_2023_20273",
    platform=["cisco_xe"],
    commands=dict(
        chk_cmd="show version | include RELEASE SOFTWARE"
    )
)
def rule_cve_2023_20273(commands, ref):
    output = str(commands.chk_cmd)

    # Example logic: treat version 17.3.x and 17.6.x as vulnerable
    is_vulnerable = "17.3." in output or "17.6." in output

    assert not is_vulnerable, ref

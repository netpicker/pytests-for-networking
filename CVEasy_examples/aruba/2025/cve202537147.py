from comfy import high


@high(
    name="rule_cve202537147",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_config="show configuration | include serial",
    ),
)
def rule_cve202537147(configuration, commands, device, devices):
    """
    CVE-2025-37147: Secure Boot Bypass allows for Compromise of Hardware Root of Trust

    Advisory: HPESBNW04958 rev.1
    Affected: Aruba APs running AOS-8 Instant and AOS-10 AP in specific vulnerable versions.
    Workaround: Restrict physical access to the device’s serial port.
    """
    advisory_url = "https://networkingsupport.hpe.com/home"

    version_output = (commands.show_version or "").strip()
    mgmt_cfg = (commands.show_mgmt_config or "").lower()

    def parse_aos_version(text: str):
        """
        Extracts the first AOS-like version token from 'show version' output.
        Returns tuple(int,int,int,int) or None.
        """
        import re

        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)\.(\d+)\b", text)
        if not m:
            return None
        return tuple(int(x) for x in m.groups())

    def version_in_branch_leq(v, branch_prefix, max_v):
        """
        v: tuple(major,minor,patch,build)
        branch_prefix: tuple(major,minor) to match
        max_v: tuple(major,minor,patch,build) inclusive upper bound
        """
        if v is None:
            return False
        if (v[0], v[1]) != branch_prefix:
            return False
        return v <= max_v

    v = parse_aos_version(version_output)

    # Vulnerable versions per advisory:
    # AOS-10.7.x.x: 10.7.2.0 and below
    # AOS-10.4.x.x: 10.4.1.7 and below
    # AOS-8.13.x.x: 8.13.0.1 and below
    # AOS-8.12.x.x: 8.12.0.5 and below
    # AOS-8.10.x.x: 8.10.0.16 and below
    version_vulnerable = any(
        [
            version_in_branch_leq(v, (10, 7), (10, 7, 2, 0)),
            version_in_branch_leq(v, (10, 4), (10, 4, 1, 7)),
            version_in_branch_leq(v, (8, 13), (8, 13, 0, 1)),
            version_in_branch_leq(v, (8, 12), (8, 12, 0, 5)),
            version_in_branch_leq(v, (8, 10), (8, 10, 0, 16)),
        ]
    )

    # If we cannot parse a version, do not fail the device (avoid false positives).
    if v is None:
        return

    if not version_vulnerable:
        # Not affected by the advisory's impacted version ranges.
        return

    # Configuration/workaround check:
    # Advisory workaround: restrict physical access to the device’s serial port.
    # We treat "serial console enabled/accessible" as a vulnerable configuration signal.
    # Since Aruba configs vary, we look for common indicators that serial access is enabled.
    serial_indicators = [
        "serial",
        "console",
        "uart",
        "tty",
    ]

    # Heuristic: if config explicitly indicates serial/console is enabled/allowed, treat as vulnerable.
    # If config indicates disabled/restricted, treat as safe.
    serial_explicitly_disabled = any(
        token in mgmt_cfg
        for token in [
            "serial disable",
            "serial disabled",
            "console disable",
            "console disabled",
            "no serial",
            "no console",
        ]
    )

    serial_explicitly_enabled = any(
        token in mgmt_cfg
        for token in [
            "serial enable",
            "serial enabled",
            "console enable",
            "console enabled",
            "uart enable",
            "tty enable",
        ]
    )

    # If we see any serial-related lines but not explicit disable, assume serial is accessible.
    serial_mentioned = any(ind in mgmt_cfg for ind in serial_indicators)

    config_vulnerable = (serial_explicitly_enabled or (serial_mentioned and not serial_explicitly_disabled))

    assert not config_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-37147 (Secure Boot Bypass) and appears to have "
        f"serial/console access enabled or not explicitly restricted while running an affected ArubaOS version "
        f"({v[0]}.{v[1]}.{v[2]}.{v[3]}). An adversary with physical access may bypass hardware root of trust "
        f"verification and run modified/custom firmware. Apply vendor fixes (upgrade to a non-affected version) "
        f"and restrict physical access to the device’s serial port. Advisory: {advisory_url}"
    )
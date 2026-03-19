from comfy import high


@high(
    name="rule_cve202547890",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_webfilter_profile="show webfilter profile",
        show_system_settings="show system settings",
    ),
)
def rule_cve202547890(configuration, commands, device, devices):
    """
    CVE-2025-47890 (Fortinet FortiOS / FortiProxy / FortiSASE) - Open Redirect in Web Filter warning page (CWE-601).

    Advisory summary (Fortinet PSIRT, 2025-10-14):
      - URL Redirection to Untrusted Site (open redirect) in the Web Filter warning page
        may allow an unauthenticated attacker to perform an open redirect via crafted HTTP requests.

    Affected versions (per advisory):
      - FortiOS 7.6.0 through 7.6.3  -> fixed in 7.6.4+
      - FortiOS 7.4.0 through 7.4.8  -> fixed in 7.4.9+
      - FortiOS 7.2 all versions     -> migrate to a fixed release (no fixed version specified in advisory)
      - FortiOS 7.0 all versions     -> migrate to a fixed release (no fixed version specified in advisory)
      - FortiOS 6.4 all versions     -> migrate to a fixed release (no fixed version specified in advisory)
      - FortiProxy 7.6.0 through 7.6.3 -> fixed in 7.6.4+
      - FortiProxy 7.4 all versions    -> migrate to a fixed release (no fixed version specified)
      - FortiProxy 7.2 all versions    -> migrate to a fixed release (no fixed version specified)
      - FortiProxy 7.0 all versions    -> migrate to a fixed release (no fixed version specified)
      - FortiSASE 25.2.a -> remediated in 25.3.b (cloud service; not directly testable via FortiOS CLI)

    Vulnerable configuration (exposure heuristic):
      - Device is running an affected FortiOS/FortiProxy version, AND
      - Web filtering is in use such that the device can present a block/warning page to users.
        (Heuristic: at least one webfilter profile exists, and the global webfilter feature is enabled.)

    Non-vulnerable scenarios:
      - Version is not affected (>= fixed version for the train), OR
      - Version cannot be parsed (rule returns safe), OR
      - Web filter feature is not enabled / no webfilter profiles configured (warning page not in use).
    """
    version_text = commands.show_version or ""
    webfilter_profile_text = (commands.show_webfilter_profile or "").lower()
    system_settings_text = (commands.show_system_settings or "").lower()

    def _parse_version(text: str):
        """
        Fortinet version formats commonly seen:
          - 'FortiOS v7.6.3,buildxxxx,...' or 'Version: 7.6.3'
          - 'FortiProxy v7.6.3,...' or 'Version: 7.6.3'
        Return (major, minor, patch) as ints, or None if not parseable.
        """
        import re

        # Prefer explicit "Version: x.y.z"
        m = re.search(r"\bversion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        # Common "vX.Y.Z" token
        m = re.search(r"\bv([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        return None

    def _is_version_vulnerable(text: str):
        """
        Release-train-based matching.

        For trains with a known fixed version, vulnerable if parsed_version < fixed_version.
        For trains marked "all versions" in the advisory (no fixed version specified),
        treat any version in that train as vulnerable.
        If version cannot be parsed, return False (safe/unknown).
        """
        v = _parse_version(text)
        if not v:
            return False

        train = (v[0], v[1])

        # Only include trains explicitly listed as affected in the advisory.
        fixed_by_train = {
            (7, 6): (7, 6, 4),  # 7.6.0-7.6.3 affected
            (7, 4): (7, 4, 9),  # 7.4.0-7.4.8 affected
            # Trains with "all versions" affected (no fixed version specified in advisory)
            (7, 2): None,
            (7, 0): None,
            (6, 4): None,
        }

        if train not in fixed_by_train:
            return False

        fixed = fixed_by_train[train]
        if fixed is None:
            return True

        return v < fixed

    parsed_version = _parse_version(version_text)
    version_vulnerable = _is_version_vulnerable(version_text)

    # Configuration / exposure heuristic:
    # - Webfilter profiles exist (common indicator that web filtering is configured)
    # - Webfilter feature enabled globally (FortiOS often has "set webfilter enable" under system settings)
    #
    # Notes:
    # - CLI output varies by model/branch; keep checks tolerant.
    has_webfilter_profile = ("config webfilter profile" in webfilter_profile_text) or (
        "\nedit " in webfilter_profile_text and "webfilter" in webfilter_profile_text
    )

    webfilter_globally_enabled = ("set webfilter enable" in system_settings_text) or (
        "webfilter enable" in system_settings_text
    )
    webfilter_globally_disabled = ("set webfilter disable" in system_settings_text) or (
        "webfilter disable" in system_settings_text
    )

    # If the global knob is absent, fall back to presence of profiles as a weak indicator.
    webfilter_effectively_enabled = (webfilter_globally_enabled and not webfilter_globally_disabled) or (
        ("webfilter" not in system_settings_text) and has_webfilter_profile
    )

    config_vulnerable = webfilter_effectively_enabled and has_webfilter_profile
    is_vulnerable = version_vulnerable and config_vulnerable

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-47890 (Fortinet): open redirect (CWE-601) in the Web Filter "
        "warning page may allow an unauthenticated attacker to redirect users to an untrusted site via crafted HTTP "
        "requests. Detected an affected FortiOS/FortiProxy release train/version "
        f"({'.'.join(map(str, parsed_version)) if parsed_version else 'unparsed'}) and Web Filter appears enabled/in use "
        "(webfilter profiles present and webfilter enabled). Remediation: upgrade FortiOS 7.6 to 7.6.4+ or FortiOS 7.4 "
        "to 7.4.9+; for FortiOS 7.2/7.0/6.4 and FortiProxy 7.4/7.2/7.0 migrate to a fixed release per Fortinet guidance. "
        "Advisory: https://www.fortiguard.com/psirt"
    )
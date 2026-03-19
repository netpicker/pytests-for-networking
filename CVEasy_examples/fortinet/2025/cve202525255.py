from comfy import high


@high(
    name="rule_cve202525255",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_profile_protocol_options="show firewall profile-protocol-options",
        show_system_settings="show system settings",
    ),
)
def rule_cve202525255(configuration, commands, device, devices):
    """
    CVE-2025-25255 (Fortinet FortiOS / FortiProxy) - Domain fronting protection bypass in explicit web proxy.

    Advisory summary:
      - Improperly implemented security check (CWE-358) in explicit web proxy domain-fronting protection.
      - May allow an unauthenticated proxy user to bypass domain fronting protection via crafted HTTP requests.

    Affected versions (per Fortinet PSIRT advisory):
      - FortiOS 7.6.0 through 7.6.3  -> fixed in 7.6.4+
      - FortiProxy 7.6.0 through 7.6.3 -> fixed in 7.6.4+
      - FortiProxy 7.4.0 through 7.4.11 -> fixed in 7.4.12+
      - FortiProxy 7.2 all versions -> migrate to a fixed release (no fixed version in-train stated)
      - FortiProxy 7.0.1 through 7.0.22 -> migrate to a fixed release (no fixed version in-train stated)

    Configuration exposure heuristic:
      - Device is running an affected version, AND
      - Explicit web proxy is enabled (system settings), AND
      - Domain-fronting protection is configured but NOT set to the new "strict" option
        (advisory: set domain-fronting strict to block Host header and SNI mismatch).

    Non-vulnerable scenarios:
      - Version is not in an affected train/range, OR
      - Explicit web proxy is not enabled, OR
      - Domain-fronting is set to "strict" (mitigation per advisory), OR
      - Version cannot be parsed (rule returns safe by default).

    Advisory:
      - https://www.fortiguard.com/psirt
    """
    version_text = commands.show_version or ""
    ppo_text = (commands.show_profile_protocol_options or "")
    settings_text = (commands.show_system_settings or "")

    def _parse_version(text: str):
        """
        Fortinet version formats commonly seen:
          - 'FortiOS v7.6.3,buildxxxx,...'
          - 'Version: 7.6.3'
          - 'FortiProxy v7.4.11,build...'
        Return (major, minor, patch) as ints, or None if not found.
        """
        import re

        patterns = [
            r"\bVersion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b",
            r"\bFortiOS\s+v([0-9]+)\.([0-9]+)\.([0-9]+)\b",
            r"\bFortiProxy\s+v([0-9]+)\.([0-9]+)\.([0-9]+)\b",
            r"\bv([0-9]+)\.([0-9]+)\.([0-9]+)\b",
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    def _detect_product(text: str):
        lt = (text or "").lower()
        if "fortiproxy" in lt:
            return "fortiproxy"
        if "fortios" in lt or "fortigate" in lt:
            return "fortios"
        return None

    def _is_version_vulnerable(version_output: str):
        """
        Train-based matching only for trains explicitly listed as affected.

        Returns:
          (is_vuln: bool, parsed_version: tuple|None, product: str|None, reason: str)
        """
        v = _parse_version(version_output)
        if not v:
            return (False, None, _detect_product(version_output), "unparsed_version_treated_safe")

        product = _detect_product(version_output)

        # Per-train fixed versions (exclusive upper bound: v < fix).
        # Only include trains explicitly listed as affected in the advisory.
        fixed_by_train = {}
        if product == "fortios":
            fixed_by_train[(7, 6)] = (7, 6, 4)
        elif product == "fortiproxy":
            fixed_by_train[(7, 6)] = (7, 6, 4)
            fixed_by_train[(7, 4)] = (7, 4, 12)
            # FortiProxy 7.2 all versions affected; no fixed version in-train stated.
            fixed_by_train[(7, 2)] = None
            # FortiProxy 7.0.1 through 7.0.22 affected; no fixed version in-train stated.
            fixed_by_train[(7, 0)] = None
        else:
            # Unknown product; do not guess.
            return (False, v, product, "unknown_product_treated_safe")

        train = (v[0], v[1])
        if train not in fixed_by_train:
            return (False, v, product, "train_not_listed_as_affected")

        fix = fixed_by_train[train]
        if fix is not None:
            return (v < fix, v, product, f"fixed_in_{fix[0]}.{fix[1]}.{fix[2]}")
        else:
            # Special cases where advisory does not provide an in-train fix.
            if product == "fortiproxy" and train == (7, 2):
                return (True, v, product, "all_versions_in_train_affected")
            if product == "fortiproxy" and train == (7, 0):
                # Affected: 7.0.1 through 7.0.22 (inclusive)
                lower = (7, 0, 1)
                upper = (7, 0, 22)
                return (lower <= v <= upper, v, product, "bounded_range_7.0.1_to_7.0.22")
            return (False, v, product, "no_fix_info_treated_safe")

    def _explicit_proxy_enabled(settings: str):
        s = (settings or "").lower()
        # Typical FortiOS/FortiProxy:
        #   config system settings
        #       set explicit-web-proxy enable
        #   end
        return "set explicit-web-proxy enable" in s

    def _domain_fronting_strict_present(ppo: str):
        p = (ppo or "").lower()
        # Advisory mitigation:
        #   config firewall profile-protocol-options
        #     edit "..."
        #       config http
        #         set domain-fronting strict
        #       end
        #     next
        #   end
        return "set domain-fronting strict" in p

    def _domain_fronting_configured_non_strict(ppo: str):
        p = (ppo or "").lower()
        # Consider vulnerable if domain-fronting is configured but not strict.
        # We treat these as non-strict:
        #   set domain-fronting enable
        #   set domain-fronting disable
        #   set domain-fronting <anything not strict>
        import re

        if "domain-fronting" not in p:
            return False

        if _domain_fronting_strict_present(ppo):
            return False

        # If we can find an explicit set line and it's not strict, mark as non-strict.
        m = re.search(r"set\s+domain-fronting\s+([^\s]+)", p)
        if m:
            val = m.group(1).strip()
            return val != "strict"

        # If domain-fronting appears but no clear value, be conservative and treat as configured non-strict.
        return True

    version_vuln, parsed_v, product, version_reason = _is_version_vulnerable(version_text)

    explicit_proxy = _explicit_proxy_enabled(settings_text)
    domain_fronting_non_strict = _domain_fronting_configured_non_strict(ppo_text)

    config_vuln = explicit_proxy and domain_fronting_non_strict
    is_vulnerable = version_vuln and config_vuln

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-25255 (Fortinet {product or 'FortiOS/FortiProxy'}): "
        "an unauthenticated explicit web proxy user may bypass the domain fronting protection feature via crafted "
        "HTTP requests (CWE-358). "
        f"Detected affected version {parsed_v[0]}.{parsed_v[1]}.{parsed_v[2]} ({version_reason}), explicit web proxy "
        f"appears enabled, and domain-fronting is not set to the advisory mitigation 'strict'. "
        "Remediation: upgrade to a fixed release (FortiOS/FortiProxy 7.6.4+, FortiProxy 7.4.12+; migrate off affected "
        "FortiProxy 7.2 and 7.0 ranges) and set 'domain-fronting strict' under the relevant "
        "firewall profile-protocol-options. "
        "Advisory: https://www.fortiguard.com/psirt"
    )
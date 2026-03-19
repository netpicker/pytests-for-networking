from comfy import high


@high(
    name="rule_cve202522252",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_tacacs="show user tacacs+",
        show_admins="show system admin",
    ),
)
def rule_cve202522252(configuration, commands, device, devices):
    """
    CVE-2025-22252 (Fortinet FortiOS / FortiProxy / FortiSwitchManager) - TACACS+ ASCII authentication bypass (CWE-306).

    Advisory summary (Fortinet PSIRT, FG-IR-24-472):
      - Missing authentication for critical function in GUI when TACACS+ is configured to use a remote TACACS+ server
        that is itself configured to use ASCII authentication.
      - May allow an attacker with knowledge of an existing admin account to access the device as a valid admin via an
        authentication bypass.
      - Limited to configurations where TACACS+ authen-type is explicitly set to ASCII.
        PAP/MSCHAP/CHAP and default "auto" are not impacted.

    Affected / fixed versions (per advisory):
      - FortiOS 7.6.0 fixed in 7.6.1+
      - FortiOS 7.4.4 - 7.4.6 fixed in 7.4.7+
      - FortiProxy 7.6.0 - 7.6.1 fixed in 7.6.2+
      - FortiSwitchManager 7.2.5 fixed in 7.2.6+

    Detection approach:
      - Parse product + version from "get system status"
      - Determine if version is in an affected train and below the first fixed version
      - Determine if TACACS+ is configured with "set authen-type ascii"
      - (Optional hardening signal) Ensure at least one admin exists (advisory requires knowledge of an existing admin account)
    """
    import re

    version_text = commands.show_version or ""
    tacacs_text = (commands.show_tacacs or "").lower()
    admins_text = (commands.show_admins or "").lower()

    def _parse_product_and_version(text: str):
        """
        Returns (product_key, version_tuple, version_str) or (None, None, None) on failure.

        product_key in: {"fortios", "fortiproxy", "fortiswitchmanager"}
        version_tuple: (major, minor, patch)
        """
        t = text or ""

        # Product detection
        tl = t.lower()
        product = None
        if "fortios" in tl:
            product = "fortios"
        elif "fortiproxy" in tl:
            product = "fortiproxy"
        elif "fortiswitchmanager" in tl or "fortiswitch manager" in tl:
            product = "fortiswitchmanager"
        else:
            return None, None, None

        # Version extraction (Fortinet commonly shows "FortiOS v7.4.6" and/or "Version: 7.4.6")
        m = re.search(r"\bversion:\s*([0-9]+(?:\.[0-9]+){1,3})\b", t, re.IGNORECASE)
        if not m:
            m = re.search(r"\bv([0-9]+(?:\.[0-9]+){1,3})\b", t, re.IGNORECASE)
        if not m:
            return product, None, None

        vstr = m.group(1)
        parts = vstr.split(".")
        # Fortinet: major.minor.patch[.build] -> we only compare major.minor.patch
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
        except ValueError:
            return product, None, None

        return product, (major, minor, patch), vstr

    def _is_version_vulnerable(product_key: str, v: tuple | None):
        """
        Release-train-based matching. Only trains explicitly listed as affected in the advisory are included.
        Returns (bool_vulnerable, fix_tuple_or_none).
        If version cannot be parsed, return (False, None) (safe/unknown).
        """
        if not product_key or not v:
            return False, None

        # Per-product affected trains -> first fixed version (exclusive upper bound: v < fix)
        fixed_by_train = {
            "fortios": {
                (7, 6): (7, 6, 1),  # 7.6.0 fixed in 7.6.1+
                (7, 4): (7, 4, 7),  # 7.4.4-7.4.6 fixed in 7.4.7+
            },
            "fortiproxy": {
                (7, 6): (7, 6, 2),  # 7.6.0-7.6.1 fixed in 7.6.2+
            },
            "fortiswitchmanager": {
                (7, 2): (7, 2, 6),  # 7.2.5 fixed in 7.2.6+
            },
        }

        train = (v[0], v[1])
        fix = fixed_by_train.get(product_key, {}).get(train)
        if not fix:
            return False, None

        # Some trains have a lower bound in the advisory; enforce it to avoid false positives.
        lower_bounds = {
            ("fortios", (7, 6)): (7, 6, 0),
            ("fortios", (7, 4)): (7, 4, 4),
            ("fortiproxy", (7, 6)): (7, 6, 0),
            ("fortiswitchmanager", (7, 2)): (7, 2, 5),
        }
        lb = lower_bounds.get((product_key, train))
        if lb and v < lb:
            return False, fix

        return v < fix, fix

    product, vtuple, vstr = _parse_product_and_version(version_text)
    version_vulnerable, fix_tuple = _is_version_vulnerable(product, vtuple)

    # Vulnerable configuration: TACACS+ explicitly configured to use ASCII authentication.
    # Advisory: "This vulnerability is limited to configurations where ASCII authentication is used.
    # PAP, MSCHAP, and CHAP configurations are not impacted. By default (authen-type auto), ASCII is not used."
    tacacs_config_present = ("config user tacacs+" in tacacs_text) or ("edit " in tacacs_text)
    tacacs_ascii = "set authen-type ascii" in tacacs_text
    tacacs_safe_non_ascii = any(
        s in tacacs_text
        for s in (
            "set authen-type pap",
            "set authen-type mschap",
            "set authen-type chap",
            "set authen-type auto",
            "unset authen-type",
        )
    )

    # If we can't see TACACS+ config, do not flag (avoid false positives).
    config_vulnerable = tacacs_config_present and tacacs_ascii

    # Advisory requires knowledge of an existing admin account; check that at least one admin is configured.
    # Typical output includes: "config system admin" and "edit \"admin\""
    admin_present = ("config system admin" in admins_text) and ("edit " in admins_text)

    is_vulnerable = bool(version_vulnerable and config_vulnerable and admin_present)

    advisory_url = "https://www.fortiguard.com/psirt"
    fix_str = ".".join(str(x) for x in fix_tuple) if fix_tuple else "a fixed release"

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-22252 (Fortinet {product or 'device'}): "
        "TACACS+ ASCII authentication bypass due to missing authentication for a critical function (CWE-306). "
        f"Detected affected version ({vstr or 'unparsed'}) in an affected train and below the first fixed version "
        f"({fix_str}+), and TACACS+ appears configured with 'set authen-type ascii'. "
        "An attacker with knowledge of an existing admin account may access the device as a valid admin via an "
        "authentication bypass. Remediation: upgrade to the fixed version for your train and/or change TACACS+ "
        "authen-type to PAP/MSCHAP/CHAP or leave it at default 'auto' (ASCII not used). "
        f"Advisory: {advisory_url}"
    )
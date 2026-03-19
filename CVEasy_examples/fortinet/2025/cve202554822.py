from comfy import high


@high(
    name="rule_cve202554822",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_vdom="show system vdom",
        show_admins="show system admin",
        show_global="show system global",
    ),
)
def rule_cve202554822(configuration, commands, device, devices):
    """
    CVE-2025-54822 (Fortinet FortiOS / FortiProxy) - Improper authorization over static files across VDOMs (CWE-285).

    Summary (Fortinet PSIRT, 2025-10-14):
      - An improper authorization vulnerability in the GUI may allow an authenticated attacker to access static files
        of other VDOMs via crafted HTTP/HTTPS requests.

    Affected versions (per advisory):
      - FortiOS 7.4.0 through 7.4.1  -> fixed in 7.4.2+
      - FortiOS 7.2.0 through 7.2.8  -> fixed in 7.2.9+
      - FortiOS 7.0.0 through 7.0.11 -> "migrate to a fixed release" (treat as fixed in 7.0.12+ for train logic)
      - FortiProxy 7.4.0 through 7.4.8 -> fixed in 7.4.9+
      - FortiProxy 7.2 all versions -> migrate to a fixed release (no fixed version specified)
      - FortiProxy 7.0 all versions -> migrate to a fixed release (no fixed version specified)
      - FortiProxy 2.0 all versions -> migrate to a fixed release (no fixed version specified)

    Vulnerable configuration (exposure heuristic):
      - Device is running an affected version, AND
      - VDOMs are enabled and more than one VDOM exists (cross-VDOM access is meaningful), AND
      - GUI management is enabled (HTTPS/HTTP admin access), AND
      - At least one admin account exists (authenticated attacker prerequisite).

    Non-vulnerable scenarios:
      - Version is not in an affected train/range, OR
      - Version cannot be parsed (rule returns safe), OR
      - VDOMs are not enabled / only one VDOM, OR
      - GUI management not enabled (no HTTP/HTTPS admin access), OR
      - No admin accounts (practically not manageable; treat as safe for this heuristic).

    Advisory:
      - https://www.fortiguard.com/psirt/FG-IR-25-684
    """
    version_text = commands.show_version or ""
    vdom_text = (commands.show_vdom or "").lower()
    admins_text = (commands.show_admins or "").lower()
    global_text = (commands.show_global or "").lower()

    def _parse_version(text: str):
        """
        Fortinet version format: major.minor.patch[.build]
        Extracts first occurrence of X.Y.Z (optionally followed by .build) and returns (X,Y,Z).
        """
        import re

        m = re.search(r"\b(?:fortios|fortiproxy)?\s*v?(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if not m:
            m = re.search(r"\bversion:\s*(\d+)\.(\d+)\.(\d+)\b", text, re.IGNORECASE)
        if not m:
            return None
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

    def _is_version_vulnerable(text: str):
        """
        Release-train-based matching only for trains explicitly listed as affected.
        Returns (is_vuln: bool, parsed_version: tuple|None, product_hint: str|None)
        """
        import re

        v = _parse_version(text)
        if not v:
            return (False, None, None)

        # Identify product hint (best-effort) to avoid applying FortiOS-only trains to FortiProxy and vice versa.
        # If unknown, we still evaluate by train keys present in the advisory; this is conservative but bounded.
        product_hint = None
        if re.search(r"\bfortiproxy\b", text, re.IGNORECASE):
            product_hint = "fortiproxy"
        elif re.search(r"\bfortios\b", text, re.IGNORECASE) or re.search(r"\bfortigate\b", text, re.IGNORECASE):
            product_hint = "fortios"

        # Per-train first fixed versions (exclusive upper bound: v < fix is vulnerable).
        # Only include trains explicitly listed as affected in the advisory.
        fixed_by_train = {
            # FortiOS
            ("fortios", (7, 4)): (7, 4, 2),
            ("fortios", (7, 2)): (7, 2, 9),
            ("fortios", (7, 0)): (7, 0, 12),  # advisory says through 7.0.11; treat 7.0.12 as first fixed in-train
            # FortiProxy
            ("fortiproxy", (7, 4)): (7, 4, 9),
            # FortiProxy trains with "all versions" affected: no fixed version specified -> always vulnerable within train.
            ("fortiproxy", (7, 2)): None,
            ("fortiproxy", (7, 0)): None,
            ("fortiproxy", (2, 0)): None,
        }

        train = (v[0], v[1])

        # If we can identify product, use product-specific mapping; otherwise, check both products for this train.
        candidates = []
        if product_hint:
            candidates.append((product_hint, train))
        else:
            candidates.append(("fortios", train))
            candidates.append(("fortiproxy", train))

        for prod, tr in candidates:
            key = (prod, tr)
            if key not in fixed_by_train:
                continue
            fix = fixed_by_train[key]
            if fix is None:
                # "all versions" affected for that train
                return (True, v, prod)
            # Vulnerable if version is within the affected train and below first fixed version.
            if v < fix:
                return (True, v, prod)
            return (False, v, prod)

        # Train not listed as affected => not vulnerable
        return (False, v, product_hint)

    def _vdoms_enabled_and_multiple(vdom_cfg: str):
        # Typical output includes:
        #   config system global
        #       set vdom-mode multi-vdom
        #   end
        # and/or:
        #   config system vdom
        #       edit "root"
        #       next
        #       edit "VDOM2"
        #       next
        #   end
        multi_vdom_mode = ("vdom-mode" in global_text and "multi-vdom" in global_text) or ("multi-vdom" in global_text)
        # Count VDOM edits in show system vdom
        import re as _re
        vdom_count = len(_re.findall(r'edit\s+"', vdom_cfg))
        return multi_vdom_mode and vdom_count >= 2

    def _gui_mgmt_enabled():
        # Heuristic: if admin GUI is enabled, config system global often has admin-https/https settings,
        # or admin ports. We look for common knobs.
        # Examples:
        #   set admin-https enable
        #   set admin-http enable
        #   set admin-sport 443
        #   set admin-port 80
        return (
            "set admin-https enable" in global_text
            or "set admin-http enable" in global_text
            or "set admin-sport" in global_text
            or "set admin-port" in global_text
        )

    def _has_admin_accounts():
        # show system admin typically contains "edit" stanzas.
        import re as _re
        return "config system admin" in admins_text and bool(_re.search(r'edit\s+"', admins_text))

    version_vulnerable, parsed_v, product = _is_version_vulnerable(version_text)

    # If version isn't vulnerable, we're done.
    if not version_vulnerable:
        assert True
        return

    # Configuration exposure heuristic
    vdoms_risky = _vdoms_enabled_and_multiple(vdom_text)
    gui_enabled = _gui_mgmt_enabled()
    admins_present = _has_admin_accounts()

    config_vulnerable = vdoms_risky and gui_enabled and admins_present
    is_vulnerable = version_vulnerable and config_vulnerable

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-54822 (Fortinet {product or 'FortiOS/FortiProxy'} GUI): "
        "an authenticated attacker may access static files of other VDOMs via crafted HTTP/HTTPS requests due to "
        "improper authorization (CWE-285). "
        f"Detected affected version {'.'.join(map(str, parsed_v or (0, 0, 0)))} in an affected train, and the device "
        "appears configured in a way that makes cross-VDOM static-file access meaningful: multi-VDOM enabled with "
        "multiple VDOMs present, GUI management (HTTP/HTTPS) appears enabled, and admin accounts exist. "
        "Remediation: upgrade to a fixed release (FortiOS 7.4.2+/7.2.9+; FortiProxy 7.4.9+; migrate off affected "
        "FortiOS 7.0.x and FortiProxy 7.2/7.0/2.0 trains) and restrict/segment GUI access. "
        "Advisory: https://www.fortiguard.com/psirt/FG-IR-25-684"
    )
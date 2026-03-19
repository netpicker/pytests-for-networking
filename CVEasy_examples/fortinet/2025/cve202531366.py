from comfy import high

import re
from urllib.parse import urlparse, parse_qs


@high(
    name="rule_cve202531366",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_webfilter_profile="show webfilter profile",
        show_system_settings="show system settings",
    ),
)
def rule_cve202531366(configuration, commands, device, devices):
    """
    CVE-2025-31366 (Fortinet FortiOS / FortiProxy / FortiSASE) - Reflected XSS in Web Filter warning page (CWE-79).

    Advisory summary:
      - Improper neutralization of input during web page generation in the Web Filter warning page.
      - May allow an unauthenticated attacker to perform reflected XSS via crafted HTTP requests.
      - (Advisory also mentions open redirect as a separate CVE.)

    Affected / fixed versions (per Fortinet PSIRT advisory):
      - FortiOS 7.6.0 through 7.6.3  -> fixed in 7.6.4+
      - FortiOS 7.4.0 through 7.4.8  -> fixed in 7.4.9+
      - FortiOS 7.2 all versions     -> migrate to a fixed release (no fixed patch in-train stated)
      - FortiOS 7.0 all versions     -> migrate to a fixed release
      - FortiOS 6.4 all versions     -> migrate to a fixed release
      - FortiProxy 7.6.0 through 7.6.3 -> fixed in 7.6.4+
      - FortiProxy 7.4/7.2/7.0 all versions -> migrate to a fixed release
      - FortiSASE 25.2.a -> remediated in 25.3.b (cloud service)

    Configuration exposure heuristic (FortiOS/FortiProxy):
      - Reflected XSS is reachable when the device serves the Web Filter warning/block page.
      - This typically requires Web Filter to be enabled in at least one firewall policy/profile.
      - We approximate this by checking for presence of webfilter profiles and that webfilter is enabled
        in system settings (where applicable). If we cannot confirm, we do not assert.

    Non-vulnerable scenarios:
      - Device is on a fixed version (e.g., FortiOS 7.6.4+, 7.4.9+), OR
      - Device is on an unaffected train (not listed), OR
      - Web Filter warning page is not in use / webfilter not enabled (heuristic), OR
      - Version cannot be parsed (return safe by requirement).
    """

    version_text = commands.show_version or ""
    webfilter_text = (commands.show_webfilter_profile or "").lower()
    settings_text = (commands.show_system_settings or "").lower()

    def _parse_version(text: str):
        """
        Fortinet version formats commonly seen:
          - 'FortiOS v7.6.3,buildxxxx,...'
          - 'Version: 7.6.3'
          - 'FortiProxy v7.6.3,...'
        Return (major, minor, patch) as ints, or None if not found.
        """
        patterns = [
            r"\bfortios\s+v(\d+)\.(\d+)\.(\d+)\b",
            r"\bfortiproxy\s+v(\d+)\.(\d+)\.(\d+)\b",
            r"\bversion:\s*(\d+)\.(\d+)\.(\d+)\b",
            r"\bv(\d+)\.(\d+)\.(\d+)\b",
        ]
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
        return None

    def _detect_product(text: str):
        lt = text.lower()
        if "fortiproxy" in lt:
            return "fortiproxy"
        if "fortios" in lt or "fortigate" in lt:
            return "fortios"
        # Unknown/other Fortinet platform (e.g., FortiSASE not typically queried via these commands)
        return "unknown"

    def _is_version_vulnerable(text: str):
        """
        Release-train-based matching only.
        Return True if version is in an affected train and below the first fixed version,
        or if advisory states "all versions" for that train.
        If version cannot be parsed, return False (safe).
        """
        v = _parse_version(text)
        if not v:
            return False

        major, minor, patch = v
        train = (major, minor)

        # Trains explicitly listed as affected in the advisory for FortiOS/FortiProxy.
        # For trains with a fixed version: vulnerable if v < fixed.
        # For trains marked "all versions": treat as vulnerable for any patch in that train.
        fixed_by_train = {
            (7, 6): (7, 6, 4),  # 7.6.0-7.6.3 affected; fixed in 7.6.4
            (7, 4): (7, 4, 9),  # 7.4.0-7.4.8 affected; fixed in 7.4.9
        }
        all_versions_trains = {
            (7, 2),
            (7, 0),
            (6, 4),
        }

        if train in fixed_by_train:
            return v < fixed_by_train[train]
        if train in all_versions_trains:
            return True
        return False

    def _webfilter_warning_page_likely_enabled(webfilter_cfg: str, settings_cfg: str):
        """
        Heuristic only:
          - If there is at least one webfilter profile stanza, and
          - Webfilter feature is enabled (if such a knob is present), or we see typical webfilter options.
        """
        has_profile = ("config webfilter profile" in webfilter_cfg) or ("\nedit " in webfilter_cfg)
        if not has_profile:
            return False

        # Some platforms expose feature toggles; if explicitly disabled, treat as not exposed.
        if re.search(r"\bset\s+webfilter\s+disable\b", settings_cfg):
            return False

        # If explicitly enabled, or if we see common webfilter profile settings, assume in use.
        if re.search(r"\bset\s+webfilter\s+enable\b", settings_cfg):
            return True

        common_profile_markers = (
            "config web",
            "set options",
            "set web-content-log",
            "set ftgd-wf",
            "set block-action",
            "set warning-duration",
            "set override",
        )
        return any(m in webfilter_cfg for m in common_profile_markers)

    product = _detect_product(version_text)
    version_vulnerable = _is_version_vulnerable(version_text)

    # This rule targets FortiOS/FortiProxy CLI outputs. If product is unknown, do not assert.
    if product not in ("fortios", "fortiproxy"):
        return

    if not version_vulnerable:
        return

    webfilter_exposed = _webfilter_warning_page_likely_enabled(webfilter_text, settings_text)
    if not webfilter_exposed:
        return

    advisory_url = "https://www.fortiguard.com/psirt/FG-IR-24-542"

    assert not (version_vulnerable and webfilter_exposed), (
        f"Device {device.name} is vulnerable to CVE-2025-31366 (Fortinet {product}): reflected XSS (CWE-79) "
        "in the Web Filter warning page may be triggered by unauthenticated crafted HTTP requests. "
        "Detected an affected release train/version and Web Filter appears configured/enabled (warning page likely reachable). "
        "Remediation: upgrade to FortiOS 7.6.4+ or 7.4.9+ (as applicable), or migrate off affected trains (7.2/7.0/6.4); "
        "for FortiProxy upgrade to 7.6.4+ or migrate off affected trains. "
        f"Advisory: {advisory_url}"
    )
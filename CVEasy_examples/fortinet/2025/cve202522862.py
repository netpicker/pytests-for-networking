from comfy import high


@high(
    name="rule_cve202522862",
    platform=["fortinet_fortinet"],
    commands=dict(
        show_version="get system status",
        show_automation_stitch="show system automation-stitch",
        show_automation_action="show system automation-action",
    ),
)
def rule_cve202522862(configuration, commands, device, devices):
    """
    CVE-2025-22862 (Fortinet FortiOS / FortiProxy) - Privilege escalation via malicious Webhook action in Automation Stitch.

    Advisory (Fortinet PSIRT, FG-IR-24-385):
      - Authentication Bypass Using an Alternate Path or Channel (CWE-288)
      - May allow an authenticated attacker to elevate privileges by triggering a malicious Webhook action
        in the Automation Stitch component.

    Affected versions (per advisory):
      FortiOS:
        - 7.4.0 through 7.4.7  (fixed in 7.4.8+)
        - 7.2.0 through 7.2.11 (fixed in 7.2.12+)
        - 7.0.6 and above      (migrate to a fixed release; fix version not specified in advisory)
      FortiProxy:
        - 7.6.0 through 7.6.2  (fixed in 7.6.3+)
        - 7.4.0 through 7.4.8  (fixed in 7.4.9+)
        - 7.2 all versions     (migrate to a fixed release; fix version not specified in advisory)
        - 7.0.5 and above      (migrate to a fixed release; fix version not specified in advisory)

    Vulnerable configuration (exposure heuristic):
      - Device is running an affected version, AND
      - Automation Stitch is configured with an action of type "webhook" (or a webhook action exists),
        which could be triggered maliciously by an authenticated attacker.

    Non-vulnerable scenarios:
      - Device version is not in an affected train/range, OR
      - Automation Stitch / webhook actions are not configured (feature not used), OR
      - Version cannot be parsed (rule returns safe to avoid false positives).

    Advisory URL:
      - https://www.fortiguard.com/psirt/FG-IR-24-385
    """
    version_text = commands.show_version or ""
    stitch_text = (commands.show_automation_stitch or "").lower()
    action_text = (commands.show_automation_action or "").lower()

    def _parse_version(text: str):
        """
        Fortinet version formats commonly seen:
          - 'FortiOS v7.4.7,build....' / 'Version: 7.4.7'
          - 'FortiProxy v7.4.8,build....' / 'Version: 7.4.8'
        Return (major, minor, patch) as ints, or None if not found.
        """
        import re

        # Prefer explicit "Version: x.y.z"
        m = re.search(r"\bversion:\s*([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        # Then try "FortiOS vX.Y.Z" / "FortiProxy vX.Y.Z"
        m = re.search(r"\bv([0-9]+)\.([0-9]+)\.([0-9]+)\b", text, re.IGNORECASE)
        if m:
            return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

        return None

    def _detect_product(text: str):
        lt = (text or "").lower()
        if "fortiproxy" in lt:
            return "fortiproxy"
        if "fortios" in lt or "fortigate" in lt:
            return "fortios"
        # Unknown product; treat as safe to avoid false positives.
        return None

    def _is_version_vulnerable(product: str, v: tuple[int, int, int] | None):
        """
        Release-train-based matching only for trains explicitly listed as affected in the advisory.
        Returns (is_vuln: bool, reason: str).
        If fix version is unknown (advisory says "migrate to a fixed release"), treat as vulnerable
        for the specified lower-bound-and-above range.
        """
        if not product or not v:
            return (False, "unparsed_or_unknown_product")

        major, minor, patch = v
        train = (major, minor)

        if product == "fortios":
            # Trains explicitly listed as affected: 7.4, 7.2, 7.0
            fixed_by_train = {
                (7, 4): (7, 4, 8),   # vulnerable if v < 7.4.8 (and >= 7.4.0 implied by train)
                (7, 2): (7, 2, 12),  # vulnerable if v < 7.2.12
                # 7.0: affected from 7.0.6 and above; fixed version not specified
            }
            if train in fixed_by_train:
                fix = fixed_by_train[train]
                return (v < fix, f"train_{train[0]}.{train[1]}_fixed_in_{fix[0]}.{fix[1]}.{fix[2]}")
            if train == (7, 0):
                return (v >= (7, 0, 6), "train_7.0_affected_from_7.0.6_and_above_fix_unspecified")
            return (False, "train_not_listed_as_affected")

        if product == "fortiproxy":
            # Trains explicitly listed as affected: 7.6, 7.4, 7.2, 7.0
            fixed_by_train = {
                (7, 6): (7, 6, 3),  # vulnerable if v < 7.6.3
                (7, 4): (7, 4, 9),  # vulnerable if v < 7.4.9
                # 7.2: all versions affected; fix unspecified
                # 7.0: affected from 7.0.5 and above; fix unspecified
            }
            if train in fixed_by_train:
                fix = fixed_by_train[train]
                return (v < fix, f"train_{train[0]}.{train[1]}_fixed_in_{fix[0]}.{fix[1]}.{fix[2]}")
            if train == (7, 2):
                return (True, "train_7.2_all_versions_affected_fix_unspecified")
            if train == (7, 0):
                return (v >= (7, 0, 5), "train_7.0_affected_from_7.0.5_and_above_fix_unspecified")
            return (False, "train_not_listed_as_affected")

        return (False, "unknown_product")

    product = _detect_product(version_text)
    v = _parse_version(version_text)
    version_vulnerable, version_reason = _is_version_vulnerable(product, v)

    # Configuration heuristic: presence of webhook action in automation.
    # Typical snippets:
    #   config system automation-action
    #       edit "myhook"
    #           set action-type webhook
    #           set uri "https://..."
    #       next
    #   end
    #
    #   config system automation-stitch
    #       edit "st1"
    #           config actions
    #               edit 1
    #                   set action "myhook"
    #               next
    #           end
    #       next
    #   end
    has_automation_stitch = "config system automation-stitch" in stitch_text or "\nedit " in stitch_text
    has_webhook_action = ("set action-type webhook" in action_text) or ("action-type webhook" in action_text)
    # Some outputs may show "webhook" without the exact token; keep conservative but useful.
    has_webhook_keyword = "webhook" in action_text

    config_vulnerable = has_automation_stitch and (has_webhook_action or has_webhook_keyword)

    is_vulnerable = version_vulnerable and config_vulnerable

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-22862 (Fortinet {product or 'unknown product'}): "
        "an authenticated attacker may be able to elevate privileges by triggering a malicious Webhook action "
        "in the Automation Stitch component (CWE-288). "
        f"Detected affected version ({'.'.join(map(str, v)) if v else 'unparsed'}; {version_reason}) and "
        "Automation Stitch appears configured with a webhook action. "
        "Remediation: upgrade/migrate to a fixed release per Fortinet guidance (FortiOS 7.4.8+, 7.2.12+; "
        "FortiProxy 7.6.3+, 7.4.9+; other affected trains require migration to a fixed release) and review/limit "
        "use of webhook automation actions. "
        "Advisory: https://www.fortiguard.com/psirt/FG-IR-24-385"
    )
from comfy import high
import re


@high(
    name="rule_cve20253456",
    platform=["arista_eos"],
    commands=dict(
        show_version="show version",
        show_running_config="show running-config",
        show_logging="show logging",
    ),
)
def rule_cve20253456(configuration, commands, device, devices):
    """
    CVE-2025-3456 (Arista EOS)

    Description:
      On affected platforms running Arista EOS, the global common encryption key configuration may be logged
      in clear text, in local or remote accounting logs. Knowledge of both the encryption key and protocol
      specific encrypted secrets from the device running-config could then be used to obtain protocol specific
      passwords in cases where symmetric passwords are required between devices with neighbor protocol
      relationships.

    Advisory access note:
      The Arista advisory content is not machine-retrievable here (CAPTCHA). This rule uses a conservative
      heuristic for versioning:
        - Treat EOS 4.x as potentially affected.
        - Treat EOS 5.x+ as not vulnerable for this rule.

    Vulnerable configuration (heuristics):
      - A global/common encryption key is configured (e.g., "key <...>" / "encryption key <...>" / "common key <...>").
      - AND at least one neighbor protocol that commonly uses symmetric shared secrets is configured with an
        encrypted/hidden secret in running-config (e.g., BGP neighbor password, OSPF authentication key,
        IS-IS authentication key, RIP authentication key, etc.).
      - AND there is evidence that the key may be logged in clear text (best-effort):
          * local logging enabled (buffered/console/monitor), OR
          * remote syslog configured, OR
          * AAA accounting configured,
        and/or the current "show logging" output contains a line that appears to include the key in clear text.

    Non-vulnerable scenarios (for this rule):
      - EOS 5.x+ (heuristic).
      - No global/common encryption key configured.
      - No neighbor protocol encrypted secrets present (no symmetric neighbor relationships indicated).
      - No logging/accounting indications and no evidence of key in "show logging" output.
    """
    version_output = commands.show_version or ""
    config_output = commands.show_running_config or ""
    logging_output = commands.show_logging or ""

    # --- Version parsing (best-effort) ---
    m = re.search(
        r"Software image version:\s*([0-9]+)\.([0-9]+)\.([0-9]+)",
        version_output,
        re.I,
    )
    if not m:
        # Cannot determine version => do not assert vulnerability based on version alone.
        return

    major, minor, patch = map(int, m.groups())

    # --- Vulnerable versions (heuristic due to advisory CAPTCHA) ---
    version_vulnerable = (major == 4)
    if not version_vulnerable:
        assert True
        return

    # --- Configuration heuristics: global/common encryption key present ---
    # We intentionally keep this broad because the exact EOS syntax may vary by feature.
    # Examples we try to catch:
    #   "encryption key <...>"
    #   "common encryption key <...>"
    #   "key <...>" (when used in a global context)
    global_key_present = bool(
        re.search(r"^\s*(common\s+)?encryption\s+key\s+\S+", config_output, re.M | re.I)
        or re.search(r"^\s*key\s+\S+", config_output, re.M | re.I)
    )

    if not global_key_present:
        assert True
        return

    # --- Neighbor protocol encrypted secrets present (best-effort) ---
    # Look for common patterns where secrets are stored encrypted/obfuscated in running-config.
    # Examples:
    #   "neighbor <ip> password 7 <...>" (BGP)
    #   "ip ospf authentication-key 7 <...>" / "message-digest-key <id> md5 7 <...>"
    #   "isis authentication key 7 <...>"
    #   "ip rip authentication key 7 <...>"
    neighbor_secret_present = bool(
        re.search(r"^\s*neighbor\s+\S+\s+password\s+\d+\s+\S+", config_output, re.M | re.I)
        or re.search(r"^\s*ip\s+ospf\s+authentication-?key\s+\d+\s+\S+", config_output, re.M | re.I)
        or re.search(r"^\s*message-digest-key\s+\d+\s+\S+\s+\d+\s+\S+", config_output, re.M | re.I)
        or re.search(r"^\s*isis\s+authentication\s+key\s+\d+\s+\S+", config_output, re.M | re.I)
        or re.search(r"^\s*ip\s+rip\s+authentication\s+key\s+\d+\s+\S+", config_output, re.M | re.I)
    )

    if not neighbor_secret_present:
        assert True
        return

    # --- Logging / accounting indications (best-effort) ---
    # If the key can be logged in clear text, risk increases when logging/accounting is enabled.
    logging_or_accounting_configured = bool(
        re.search(r"^\s*logging\s+host\s+\S+", config_output, re.M | re.I)  # remote syslog
        or re.search(r"^\s*logging\s+buffered\b", config_output, re.M | re.I)
        or re.search(r"^\s*logging\s+console\b", config_output, re.M | re.I)
        or re.search(r"^\s*logging\s+monitor\b", config_output, re.M | re.I)
        or re.search(r"^\s*aaa\s+accounting\b", config_output, re.M | re.I)
    )

    # Evidence in current logs that a key may have been logged in clear text.
    # We look for lines that include "encryption key" or "common encryption key" followed by a non-redacted value.
    key_logged_in_cleartext = bool(
        re.search(
            r"(common\s+)?encryption\s+key\s+(\S+)",
            logging_output,
            re.I,
        )
    )

    if not (logging_or_accounting_configured or key_logged_in_cleartext):
        assert True
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-3456. "
        f"Detected Arista EOS {major}.{minor}.{patch} (heuristic: EOS 4.x treated as potentially affected). "
        "A global/common encryption key appears to be configured, and neighbor protocol configuration indicates "
        "encrypted/obfuscated symmetric secrets are present (e.g., neighbor passwords/authentication keys). "
        "Logging/AAA accounting is enabled and/or current logs suggest the encryption key may be logged in clear text. "
        "An attacker with access to local/remote accounting logs could learn the global encryption key and, combined "
        "with protocol-specific encrypted secrets from running-config, potentially recover protocol passwords used for "
        "symmetric neighbor relationships. "
        "Mitigation: upgrade to a fixed EOS release per Arista advisory and review/secure accounting and syslog "
        "destinations; consider rotating shared secrets after remediation. "
        "Advisory: https://www.arista.com/en/support/advisories-notices/security-advisory"
    )
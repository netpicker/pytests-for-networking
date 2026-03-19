from comfy import high
import re


@high(
    name="rule_cve20258870",
    platform=["arista_eos"],
    commands=dict(
        show_version="show version",
        show_running_config="show running-config",
    ),
)
def rule_cve20258870(configuration, commands, device, devices):
    """
    CVE-2025-8870 (Arista EOS)

    Description:
      On affected platforms running Arista EOS, certain serial console input might result in an unexpected
      reload of the device.

    Advisory access note:
      The Arista advisory content is not machine-retrievable here (CAPTCHA). This rule uses a conservative
      heuristic for versioning and exposure:
        - Treat EOS 4.x as potentially affected.
        - Treat EOS 5.x+ as not vulnerable for this rule.

    Vulnerable configuration / exposure (heuristic):
      - Device has serial console enabled/available (typical default), AND
      - Console access is possible (e.g., no explicit console login hardening / no "no aaa authorization console"),
        OR configuration indicates console is in use (console line configured, logging/exec-timeout, etc.).

      Note: This CVE is triggered by serial console input; it is primarily a physical/adjacent access issue.
      Because most devices have a serial console, this rule flags risk when EOS version is potentially affected
      and there is no clear indication that console access is administratively restricted.

    Non-vulnerable scenarios (for this rule):
      - EOS 5.x+ (heuristic).
      - Unable to determine EOS version (rule will not assert vulnerable).
      - Console access appears explicitly restricted/disabled by configuration (best-effort heuristic).

    Advisory:
      https://www.arista.com/en/support/advisories-notices/security-advisory
    """
    version_output = commands.show_version or ""
    config_output = commands.show_running_config or ""

    # --- Version parsing (best-effort) ---
    # Common EOS output includes:
    #   "Software image version: 4.30.2F"
    #   "Software image version: 4.31.1M"
    #   "Software image version: 4.29.3.1F"
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

    # --- Console exposure heuristics (best-effort) ---
    # We consider the device "console-exposed" if:
    #  - there is explicit console configuration (line console / console settings), OR
    #  - there is no explicit hardening that would restrict console authorization.
    #
    # Indicators that console is configured/used:
    console_config_present = bool(
        re.search(r"^\s*line\s+console\b", config_output, re.M | re.I)
        or re.search(r"^\s*console\s+(?:exec-timeout|log(?:ging)?|timeout)\b", config_output, re.M | re.I)
        or re.search(r"^\s*logging\s+console\b", config_output, re.M | re.I)
    )

    # Indicators that console access is explicitly restricted/hardened:
    # (These are heuristic; EOS syntax can vary by release/features.)
    console_hardened = bool(
        re.search(r"^\s*no\s+aaa\s+authorization\s+console\b", config_output, re.M | re.I)
        or re.search(r"^\s*aaa\s+authorization\s+console\s+default\s+local\b", config_output, re.M | re.I)
        or re.search(r"^\s*aaa\s+authentication\s+login\s+console\b", config_output, re.M | re.I)
        or re.search(r"^\s*no\s+console\b", config_output, re.M | re.I)
    )

    # If we see explicit hardening, treat as not vulnerable for this rule (risk reduced).
    if console_hardened:
        assert True
        return

    # If console is configured/used OR we cannot find hardening, treat as exposed.
    console_exposed = console_config_present or True

    if not console_exposed:
        assert True
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-8870. "
        f"Detected Arista EOS {major}.{minor}.{patch} (heuristic: EOS 4.x treated as potentially affected). "
        "This issue can be triggered by certain serial console input resulting in an unexpected reload. "
        "Configuration review did not find clear indications of console access being explicitly restricted "
        "(best-effort heuristic). "
        "Mitigation: upgrade to a fixed EOS release per Arista advisory and restrict physical/console access "
        "and console authentication/authorization until upgraded. "
        "Advisory: https://www.arista.com/en/support/advisories-notices/security-advisory"
    )
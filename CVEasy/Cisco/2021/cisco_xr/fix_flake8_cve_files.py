import os
import re
import shutil

# === CONFIGURATION ===
BASE_DIR = "/home/sanps/gits/cveasy/rules/cisco/2021/ios-xr"  # ✅ Set to ios-xr folder
FILENAME_PATTERN = "cve"  # Match files like cve2021xxxx.py

def fix_file(filepath):
    with open(filepath, "r") as f:
        lines = f.readlines()

    original_lines = list(lines)
    modified = False
    new_lines = []

    # === 1. Remove placeholder comment if present at top ===
    if lines and lines[0].strip() == "# Placeholder for CVE script":
        lines.pop(0)
        modified = True

    # === 2. Trim trailing whitespace ===
    lines = [line.rstrip() + '\n' for line in lines]

    # === 3. Ensure 2 blank lines before @high ===
    for i, line in enumerate(lines):
        if line.strip().startswith("@high"):
            j = i - 1
            blank_lines = 0
            while j >= 0 and lines[j].strip() == "":
                blank_lines += 1
                j -= 1
            if blank_lines < 2:
                lines = lines[:j + 1] + ["\n", "\n"] + lines[i:]
                modified = True
            break

    # === 4. Fix 'For more information, see https://...' lines ===
    for line in lines:
        # Match lines like: "... For more information, see https://...."
        match = re.search(r'^(.*?)(For more information, see )https://([^"\n]+)(.*)', line)
        if match:
            indent = re.match(r'^\s*', line).group(0)
            before = match.group(1).rstrip()
            lead = match.group(2).strip()
            url = match.group(3).strip()
            after = match.group(4).rstrip()

            # Quote each part correctly
            if before:
                new_lines.append(f'{before}"{lead}"\n')
            else:
                new_lines.append(f'{indent}"{lead}"\n')

            new_lines.append(f'{indent}"https://{url}{after}"\n')
            modified = True
        else:
            new_lines.append(line)

    # === 5. Backup and write changes ===
    if modified or new_lines != original_lines:
        backup_path = filepath + ".bak"
        shutil.copy2(filepath, backup_path)
        print(f"✅ Fixed: {filepath} (backup saved as {backup_path})")
        with open(filepath, "w") as f:
            f.writelines(new_lines)
    else:
        print(f"➖ No changes needed: {filepath}")


def walk_and_fix(base_dir):
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.startswith(FILENAME_PATTERN) and file.endswith(".py"):
                filepath = os.path.join(root, file)
                fix_file(filepath)


if __name__ == "__main__":
    walk_and_fix(BASE_DIR)

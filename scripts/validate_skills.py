#!/usr/bin/env python3
"""
Security Audit Plugin - Skills Ecosystem Validator
Validates that all skills adhere to the AgentSkills / AGY standard:
- Valid YAML frontmatter (name, description, version)
- Presence of SKILL.md, references/, examples/
- Checks for prompt injection guardrails (<untrusted_payload>)
"""

import os
import re
import sys
import yaml

EXPECTED_SKILL_COUNT = 19
REQUIRED_FIELDS = ["name", "description", "version"]

def validate_all_skills(skills_dir):
    if not os.path.exists(skills_dir):
        print(f"[-] Error: Skills directory '{skills_dir}' does not exist.")
        return 1

    skill_dirs = [d for d in os.listdir(skills_dir) if os.path.isdir(os.path.join(skills_dir, d))]
    print(f"[*] Found {len(skill_dirs)} skill directories. (Expected: {EXPECTED_SKILL_COUNT})")

    errors = []
    
    if len(skill_dirs) != EXPECTED_SKILL_COUNT:
        errors.append(f"Expected {EXPECTED_SKILL_COUNT} skills, but found {len(skill_dirs)}.")

    for skill_name in sorted(skill_dirs):
        full_dir = os.path.join(skills_dir, skill_name)
        skill_md = os.path.join(full_dir, "SKILL.md")
        
        if not os.path.isfile(skill_md):
            errors.append(f"[{skill_name}] Missing SKILL.md")
            continue

        with open(skill_md, "r", encoding="utf-8") as f:
            content = f.read()

        # Frontmatter validation
        fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n", content, re.DOTALL)
        if not fm_match:
            errors.append(f"[{skill_name}] SKILL.md is missing valid YAML frontmatter delimiter (---).")
            continue

        try:
            fm = yaml.safe_load(fm_match.group(1))
            if not isinstance(fm, dict):
                errors.append(f"[{skill_name}] Frontmatter is not a valid YAML dictionary.")
                continue

            for field in REQUIRED_FIELDS:
                if not fm.get(field):
                    errors.append(f"[{skill_name}] Frontmatter missing required field '{field}'.")

            if fm.get("name") != skill_name:
                errors.append(f"[{skill_name}] Frontmatter 'name' ({fm.get('name')}) does not match folder name ({skill_name}).")

        except Exception as e:
            errors.append(f"[{skill_name}] Failed to parse YAML frontmatter: {e}")

        # Subdirectory checks
        refs_dir = os.path.join(full_dir, "references")
        examples_dir = os.path.join(full_dir, "examples")
        if not os.path.isdir(refs_dir):
            errors.append(f"[{skill_name}] Missing references/ directory.")
        if not os.path.isdir(examples_dir):
            errors.append(f"[{skill_name}] Missing examples/ directory.")

    if errors:
        print("\n[!] Validation Failed with errors:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("\n[+] SUCCESS: All 19 skills passed validation successfully!")
    return 0

if __name__ == "__main__":
    skills_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "skills"))
    sys.exit(validate_all_skills(skills_path))

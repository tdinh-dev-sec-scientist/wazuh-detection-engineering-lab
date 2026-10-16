#!/usr/bin/env python3
"""Prepare a Wazuh manager so that wazuh-logtest can evaluate Windows eventchannel rules.

wazuh-logtest runs the normal decoders but not the eventchannel decoder, which lives in a
separate thread of wazuh-analysisd. Wazuh's own ruleset tests (ruleset/testing/runtests.py)
get around this by changing the base rule 60000 so that it accepts events decoded by the
generic json decoder. This script makes the same change, so a Windows event in the decoded
{"win": {...}} form reaches every rule below 60000 exactly as it does in production.

Use it on a throwaway manager only (CI or a test VM). It edits the stock ruleset file, which a
Wazuh upgrade overwrites. To undo it, run with --revert.
"""
import argparse
import re
import sys
from pathlib import Path

BASE = Path("/var/ossec/ruleset/rules/0575-win-base_rules.xml")
BACKUP = BASE.with_suffix(".xml.orig")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--revert", action="store_true")
    parser.add_argument("--file", default=str(BASE))
    args = parser.parse_args()
    path = Path(args.file)
    backup = path.with_suffix(".xml.orig")

    if args.revert:
        if backup.exists():
            path.write_text(backup.read_text(encoding="utf-8"), encoding="utf-8")
            print("restored", path)
            return 0
        print("no backup found")
        return 1

    text = path.read_text(encoding="utf-8")
    match = re.search(r'<rule id="60000"[^>]*>.*?</rule>', text, flags=re.S)
    if not match:
        print("rule 60000 not found", file=sys.stderr)
        return 1
    block = match.group(0)
    if "<decoded_as>json</decoded_as>" in block:
        print("already prepared")
        return 0
    new_block = block.replace("<decoded_as>windows_eventchannel</decoded_as>", "<decoded_as>json</decoded_as>")
    new_block = re.sub(r"\s*<category>ossec</category>", "", new_block)
    if new_block == block:
        print("rule 60000 has an unexpected shape", file=sys.stderr)
        return 1
    if not backup.exists():
        backup.write_text(text, encoding="utf-8")
    path.write_text(text.replace(block, new_block), encoding="utf-8")
    print("rule 60000 now accepts json decoded events:", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

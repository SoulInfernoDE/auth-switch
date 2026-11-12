#!/usr/bin/env python3
"""Fill untranslated entries of a .po file from a JSON object.

Singular texts map to a string, plural texts (msgid_plural) to a list of
forms: {"msgid": "msgstr", "singular msgid": ["form 0", "form 1"]}.

Usage: fill-translations.py <catalog.po> <translations.json>
"""

import json
import re
import sys
from pathlib import Path


def unquote(block: str) -> str:
    return "".join(json.loads(line) for line in block.splitlines() if line.startswith('"'))


def quote(text: str) -> str:
    return json.dumps(text, ensure_ascii=False)


def main() -> int:
    catalog, translations = Path(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    entry = re.compile(
        r'msgid ((?:"[^\n]*"\n)+)(?:msgid_plural ((?:"[^\n]*"\n)+))?'
        r'(?:msgstr ""\n|msgstr\[0\] ""\n(?:msgstr\[\d+\] ""\n)+)(?=\n|\Z)'
    )

    def fill(match: re.Match) -> str:
        msgid = unquote(match.group(1))
        if msgid not in translations:
            return match.group(0)
        value = translations.pop(msgid)
        if match.group(2) is None:
            return f"msgid {quote(msgid)}\nmsgstr {quote(value)}\n"
        forms = "".join(f"msgstr[{index}] {quote(form)}\n" for index, form in enumerate(value))
        return f"msgid {quote(msgid)}\nmsgid_plural {quote(unquote(match.group(2)))}\n{forms}"

    catalog.write_text(entry.sub(fill, catalog.read_text(encoding="utf-8")), encoding="utf-8")
    for unused in translations:
        print(f"not found or already translated: {unused}", file=sys.stderr)
    return 1 if translations else 0


if __name__ == "__main__":
    sys.exit(main())

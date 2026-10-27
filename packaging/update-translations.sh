#!/bin/sh
# Extract the program texts, merge them into every catalog and compile them.
set -eu
cd "$(dirname "$0")/.."

pot=authswitch/locale/auth-switch.pot
xgettext --language=Python --keyword=_ --from-code=UTF-8 --sort-by-file \
    --package-name=auth-switch --msgid-bugs-address=https://github.com/SoulInfernoDE/auth-switch/issues \
    --output="$pot" authswitch/*.py
# Keep the template stable between runs.
sed -i '/^"POT-Creation-Date:/d' "$pot"

for po in authswitch/locale/*/LC_MESSAGES/auth-switch.po; do
    msgmerge --quiet --update --backup=none --no-fuzzy-matching "$po" "$pot"
    msgattrib --no-obsolete --output-file="$po" "$po"
    msgfmt --check --statistics --output-file="${po%.po}.mo" "$po"
done

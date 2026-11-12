"""Translations come from gettext catalogs in ``locale/``; English is the fallback."""

import gettext
from pathlib import Path

_translation = gettext.translation("auth-switch", Path(__file__).parent / "locale", fallback=True)
_ = _translation.gettext
ngettext = _translation.ngettext

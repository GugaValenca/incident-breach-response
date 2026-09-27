"""WSGI entrypoint for Vercel's Python runtime.

Vercel's `@vercel/python` builder auto-detects a WSGI app by looking for
a module-level `app` callable in this file — everything else (routing
every request here, running the Django app itself) is regular Django via
`config.wsgi`. Not used for local development; `python manage.py
runserver` bypasses this entirely.
"""

import os
import sys
from pathlib import Path

# The project root (one level up from this api/ directory) needs to be
# importable as `config.wsgi`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

from config.wsgi import application as app

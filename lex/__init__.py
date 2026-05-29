"""LEX EUROPE — extracted pure-logic modules.

This package holds side-effect-free logic carved out of the historical
``main.py`` monolith so it can be unit-tested in isolation. ``main.py``
imports from here; behaviour is intentionally identical to the inlined
originals. See the project plan for the modularization milestone (M1).

Guardrail modules first: :mod:`lex.privacy` carries the PII / doxxing /
defamation safeguards. These are mandatory pipeline stages — they must only
ever get stricter, never looser.
"""

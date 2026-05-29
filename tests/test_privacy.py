"""Regression tests for the privacy / defamation guardrails (lex.privacy).

These tests encode the project's hard safety invariants. They must stay green:
a failure here means the tool could leak PII, propagate a doxxing source, or
publish an actionable defamatory label. The guardrails may only ever get
stricter — never looser — so these assertions are deliberately strict.
"""
import re

from lex.privacy import (
    redact_pii,
    is_doxxing_text,
    classify_doxxing_target,
    sanitize_doxxing_event,
    neutralize_political_labels,
)


# ── redact_pii: every PII class must be stripped ──────────────────────────
class TestRedactPII:
    def test_email_removed(self):
        out = redact_pii("Kontakt: max.mustermann@example.org schreibt")
        assert "@example.org" not in out
        assert "[E-Mail entfernt]" in out

    def test_phone_removed(self):
        out = redact_pii("Erreichbar unter 030 12345678 tagsüber")
        assert "12345678" not in out
        assert "[Telefon entfernt]" in out

    def test_license_plate_removed(self):
        out = redact_pii("Fahrzeug B-XY 1234 gesehen")
        assert "[Kennzeichen entfernt]" in out

    def test_birthdate_removed(self):
        out = redact_pii("Person geboren am 12.03.1985 in Berlin")
        assert "12.03.1985" not in out
        assert "[Geburtsdatum entfernt]" in out

    def test_address_removed(self):
        out = redact_pii("Wohnhaft Bahnhofstraße 12 im Erdgeschoss")
        assert "Bahnhofstraße 12" not in out
        assert "[Adresse entfernt]" in out

    def test_doxxing_name_list_removed(self):
        out = redact_pii("Geoutet: Max Mustermann, Erika Beispiel und Klaus Test")
        assert "Max Mustermann" not in out
        assert "[Namen entfernt]" in out

    def test_public_figure_name_preserved(self):
        # Public figures in press context are intentionally NOT masked.
        out = redact_pii("Wir haben Olaf Scholz geoutet")
        assert "Olaf Scholz" in out

    def test_empty_input_safe(self):
        assert redact_pii("") == ""
        assert redact_pii(None) == ""


# ── is_doxxing_text: detection trigger ────────────────────────────────────
class TestIsDoxxingText:
    def test_outing_with_address_detected(self):
        assert is_doxxing_text(
            "Wir haben Max Mustermann geoutet, er wohnt in der Bahnhofstraße 5"
        ) is True

    def test_outing_with_wohnumfeld_detected(self):
        assert is_doxxing_text(
            "Der Nazi wurde enttarnt, das Wohnumfeld wurde informiert"
        ) is True

    def test_plain_violence_report_not_doxxing(self):
        # A normal incident report without PII signals must NOT trigger.
        assert is_doxxing_text(
            "In Leipzig brannten drei Fahrzeuge, ein Bekennerschreiben tauchte auf"
        ) is False

    def test_empty_safe(self):
        assert is_doxxing_text("") is False
        assert is_doxxing_text(None) is False


# ── classify_doxxing_target: role only, never the person ──────────────────
class TestClassifyDoxxingTarget:
    def test_politician(self):
        assert classify_doxxing_target("ein AfD-Politiker und Abgeordneter") == "Politiker:in"

    def test_police(self):
        assert classify_doxxing_target("der leitende Polizeibeamte") == "Polizeibeamte:r"

    def test_default_private(self):
        assert classify_doxxing_target("irgendjemand ohne Rolle") == "Privatperson"


# ── sanitize_doxxing_event: NO PII and NO source URL may survive ──────────
class TestSanitizeDoxxingEvent:
    def test_source_url_dropped(self):
        summ, desc, url = sanitize_doxxing_event(
            {"ort": "Leipzig"},
            "Wir haben Max Mustermann (Bahnhofstraße 5, max@x.de) geoutet",
            "barrikade.info",
        )
        # The returned URL must be empty — the source itself carries the PII.
        assert url == ""

    def test_no_pii_in_output(self):
        raw = "Wir haben Max Mustermann, Bahnhofstraße 5, Tel 030 1234567, max@x.de geoutet"
        summ, desc, url = sanitize_doxxing_event({"ort": "Berlin"}, raw, "indymedia")
        blob = f"{summ} {desc}"
        assert "Max Mustermann" not in blob
        assert "Bahnhofstraße" not in blob
        assert "@x.de" not in blob
        assert "1234567" not in blob

    def test_role_present(self):
        summ, desc, url = sanitize_doxxing_event(
            {"ort": "Wien"}, "ein FPÖ-Politiker wurde geoutet", "nazifrei"
        )
        assert "Politiker:in" in summ or "Politiker:in" in desc


# ── neutralize_political_labels: defamatory labels removed ─────────────────
class TestNeutralizeLabels:
    def test_nazi_kader_neutralized(self):
        out = neutralize_political_labels(
            "Bei dem Angriff wurde ein bekannter Nazi-Kader getroffen"
        )
        assert not re.search(r"nazi", out, re.IGNORECASE)
        assert "Privatperson" in out

    def test_party_functionary_neutralized(self):
        out = neutralize_political_labels("Das Auto eines AfD-Funktionärs brannte")
        assert "Funktionär" not in out
        assert "politischer Funktion" in out

    def test_slur_removed(self):
        out = neutralize_political_labels("Tod dem Nazi-Schwein stand an der Wand")
        assert "Schwein" not in out

    def test_organization_not_neutralized(self):
        # "Identitäre Bewegung" is a formal org label, must be preserved.
        out = neutralize_political_labels("Die Identitäre Bewegung demonstrierte")
        assert "Identitäre Bewegung" in out

    def test_empty_safe(self):
        assert neutralize_political_labels("") == ""
        assert neutralize_political_labels(None) == ""

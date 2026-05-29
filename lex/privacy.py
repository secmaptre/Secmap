"""Privacy & defamation guardrails — PII redaction, doxxing sanitization,
political-label neutralization.

Extracted verbatim from ``main.py`` (M1 modularization). These functions are
the project's hard privacy safeguards and are mandatory pipeline stages in
``save_incident``:

  * :func:`is_doxxing_text`            — trigger for doxxing sanitization
  * :func:`classify_doxxing_target`   — role-only classification (never the person)
  * :func:`sanitize_doxxing_event`    — document the *event*, drop source URL + all PII
  * :func:`redact_pii`                — strip email/phone/plate/birthdate/address/names
  * :func:`neutralize_political_labels` — remove defamatory person-labels (StGB §§185-187)

Design principle: these safeguards must only ever get **stricter**. Doxxing-victim
data is never stored or published. The functions depend only on the stdlib ``re``
module so they are trivially unit-testable (see ``tests/test_privacy.py``).
"""
import re

# ════════════════════════════════════════════════════════════════════
# PII / DOXXING REDACTION
# ════════════════════════════════════════════════════════════════════
# Doxxing-Texte aus der autonomen Szene (insbesondere Indymedia-Outings
# gegen vermeintliche Rechte) enthalten Klarnamen + Wohnadressen. Diese
# Daten dürfen NIE in unsere öffentliche DB oder UI gelangen — sonst
# verlängern wir die Reichweite der Doxxing-Aktion. Vor jeder Speicherung
# laufen Beschreibungen UND Zusammenfassungen durch redact_pii().
#
# Strategie:
#   1. Adressen (Straße + Hausnummer, Plätze, Gassen, Alleen, Wege) → entfernt
#   2. Doxxing-Marker ("wurden X, Y und Z geoutet") triggern Heavy-Redaction:
#      die gesamte Namensliste in solchen Sätzen wird durch "[Namen entfernt]"
#      ersetzt, NICHT nur einzelne Namen.
#   3. Telefon-, Mail-, Geburtsdaten-Muster → entfernt.
#   4. Auto-Kennzeichen → entfernt.
# Bewusst NICHT entfernt: Namen bekannter Politiker, öffentliche Personen
# in Pressekontext (Olaf Scholz, Donald Trump etc.) — diese werden über
# Whitelist verschont.

_PII_ADDRESS_RE = re.compile(
    r'\b([A-ZÄÖÜ][a-zäöüß\-]{2,}(?:[\- ][A-ZÄÖÜ][a-zäöüß\-]+)*'
    r'(?:straße|str\.|platz|gasse|allee|weg|ufer|damm|ring|chaussee|landstraße|hof))'
    r'\s+\d{1,4}[a-z]?',
    re.IGNORECASE
)
# Name unit: First+Last OR First+Middle+Last (up to 3 capitalised tokens)
_NAME_UNIT = r'[A-ZÄÖÜ][a-zäöüß\-]+(?:\s+[A-ZÄÖÜ][a-zäöüß\-]+){1,2}'
# Trigger words allow upper/lower variants explicitly. We do NOT use
# re.IGNORECASE here because that would make _NAME_UNIT also match
# lowercase tokens like "und"/"als"/"die", causing the regex to gobble
# past name boundaries and leave later names un-redacted.
_PII_DOXXING_LIST_RE = re.compile(
    # "wurden X, Y und Z [geoutet|outet|enttarnt|veröffentlicht]"
    r'\b[Ww]urden?\b\s+'
    r'(' + _NAME_UNIT +
    r'(?:\s*,\s*' + _NAME_UNIT + r'){0,5}'
    r'(?:\s+und\s+' + _NAME_UNIT + r')?)'
    r'\s+(?:durch|von|als|in\s+ihrem|in\s+ihrer|[Gg]eoutet|[Ee]nttarnt|[Oo]utet|veröffentlicht|bekannt)'
)
_PII_DOXXING_OPENER_RE = re.compile(
    # Headline-Muster: "Wir haben X, Y und Z [in ihrem Wohnumfeld] geoutet."
    r'\b(?:[Ww]ir\s+haben|[Aa]ntifa\s+outet|[Gg]eoutet:)\s+'
    r'(' + _NAME_UNIT +
    r'(?:\s*,\s*' + _NAME_UNIT + r'){0,5}'
    r'(?:\s+und\s+' + _NAME_UNIT + r')?)'
)
_PII_EMAIL_RE  = re.compile(r'\b[\w\.\-]+@[\w\.\-]+\.[a-z]{2,}\b', re.IGNORECASE)
_PII_PHONE_RE  = re.compile(r'\b(?:\+?\d{1,3}[\s\-/]?)?(?:0\d{2,4}[\s\-/]?\d{4,10})\b')
_PII_LICENSE_RE = re.compile(r'\b[A-ZÄÖÜ]{1,3}[\s\-][A-Z]{1,2}\s?\d{1,4}\b')
_PII_BIRTHDATE_RE = re.compile(r'\bgeb(?:oren|\.)?\s*(?:am)?\s*\d{1,2}[./]\d{1,2}[./]\d{2,4}\b', re.IGNORECASE)

# Doxxing-Kontext-Detektor: triggert is_pii_heavy() = True
_DOXXING_CONTEXT_RE = re.compile(
    # Verb-Stämme ohne trailing \b, weil deutsche Flexionen
    # ("veröffentlicht/veröffentlichte/veröffentlichten") sonst nicht matchen.
    r'\b(geoutet|geout|enttarnt|outing|outet|outed|'
    r'wohnumfeld|nachbarn\s+infor|'
    r'klarnamen?\s+ver[öo]ffentlich|'
    r'persönliche\s+daten\s+ver[öo]ffentlich|'
    r'arbeitgeber\s+ver[öo]ffentlich|'
    r'privat(?:adresse|anschrift)|'
    r'wohn(?:adresse|anschrift|ort)\s+ver[öo]ffentlich)',
    re.IGNORECASE
)

# Politisch öffentliche Personen — bewusst nicht maskiert. Liste minimal halten.
_PII_PUBLIC_FIGURES = {
    "olaf scholz","friedrich merz","alice weidel","tino chrupalla","markus söder",
    "robert habeck","annalena baerbock","christian lindner","sahra wagenknecht",
    "donald trump","joe biden","kamala harris","emmanuel macron","giorgia meloni",
    "ursula von der leyen","viktor orban","lina e.","horst seehofer",
    "thomas haldenwang","sandro brotz","alain berset","viola amherd",
    "karl nehammer","wolfgang sobotka",
}

def is_doxxing_text(text: str) -> bool:
    """True if the text reads like a Klarnamen-Outing.
    Sicherheits-Politik v3 (User-Hinweis): Doxxing-Vorfälle werden NICHT
    mehr komplett verworfen; sie werden als anonymisierter Kontext-Eintrag
    aufgenommen — siehe sanitize_doxxing_event() unten. is_doxxing_text()
    bleibt der Trigger, der in save_incident() die Sanitisierung aktiviert.
    Erweiterte Erkennung: Doxxing-Kontext PLUS *irgendein* PII-Signal
    reicht — Adresse, E-Mail, Telefon, Geburtsdatum, Auto-Kennzeichen,
    Opener-Muster ('Wir haben X geoutet'). Damit sind auch Outings
    erfasst, die nur Klarname+E-Mail oder Wohnumfeld-Hinweis ohne
    konkrete Adresse enthalten."""
    if not text: return False
    t = text.lower()
    if not _DOXXING_CONTEXT_RE.search(t):
        return False
    return bool(
        _PII_ADDRESS_RE.search(text)        or
        _PII_DOXXING_OPENER_RE.search(text) or
        _PII_DOXXING_LIST_RE.search(text)   or
        _PII_EMAIL_RE.search(text)          or
        _PII_PHONE_RE.search(text)          or
        _PII_BIRTHDATE_RE.search(text)      or
        re.search(r"\bwohnumfeld\b|\bnachbarn\s+infor", t)
    )

def classify_doxxing_target(text: str) -> str:
    """Bestimmt die Rolle der gedoxxten Person aus Textsignalen.
    Bleibt absichtlich grob — wir wollen die Rolle benennen, nicht die Person."""
    t = (text or "").lower()
    if re.search(r"\b(afd|cdu|csu|spd|fdp|grüne|linke|bsw|fpö|svp|övp|spö)\b.*"
                 r"\b(politiker|abgeordnet|kandidat|stadtrat|landtag|bundestag|"
                 r"gemeinderat|nationalrat|kreisvorstand|parteivorstand)", t):
        return "Politiker:in"
    if re.search(r"\b(politiker|abgeordnet|nationalrat|landtag|bundestag)\b", t):
        return "Politiker:in"
    if re.search(r"\b(polizist|polizeibeamt|polizeif[üu]hr|kommissar|polizeichef|"
                 r"leitend.{0,15}polizei)", t):
        return "Polizeibeamte:r"
    if re.search(r"\b(richter|staatsanwalt|justiz|amtsrichter)\b", t):
        return "Justiz-Person"
    if re.search(r"\b(unternehmer|gesch[äa]ftsf[üu]hr|investor|immobilien(?:firm|invest)|"
                 r"hausverwalt|vermieter|bauherr)", t):
        return "Unternehmer:in"
    if re.search(r"\b(journalist|redakteur|medien|chefredakteur|herausgeber)\b", t):
        return "Journalist:in"
    if re.search(r"\b(junge\s+tat|\bjt\b|identit[äa]r|neonazi|kameradschaft|"
                 r"rechtsextrem|nationalsozialist|rechte\s+szene)", t):
        return "rechtsextrem aktive Person"
    return "Privatperson"

def sanitize_doxxing_event(ai: dict, text: str, source: str):
    """
    Sicherheits-Politik (User-Hinweis): wenn ein Doxxing/Outing-Bericht
    erkannt wird, wird der EVENT dokumentiert, aber:
      - Quelle (source_url) wird gelöscht — sie selbst trägt die PII weiter.
      - Description wird durch einen Rollen-Hinweis ersetzt — keine Namen,
        keine Adressen, keine Identifikatoren bleiben in der DB.
      - Tier wird auf 'context' gesetzt (T3) — wir dokumentieren, dass das
        Ereignis stattfand, ohne es als T1-Akt selbst zu zertifizieren.
      - Kategorie wird 'Doxxing' — eigene Kategorie damit User-seitig
        sichtbar/filterbar als eigene Bedrohungsklasse.
      - Source-String wird auf 'censored:datenschutz' normalisiert,
        die ursprüngliche Plattform-Domain (barrikade.info / indymedia /
        nazifrei) wird als Plattform-Hinweis vorangestellt.
    Returns: (sanitized_summary, sanitized_description, sanitized_url_norm)
    """
    role = classify_doxxing_target(text)
    ort  = (ai.get("ort") or "unbekanntem Ort").strip() or "unbekanntem Ort"
    summ = f"{role} in {ort} wurde gedoxxt — Quelle zurückgehalten (Datenschutz)."
    desc = (
        f"Doxxing/Outing-Bericht. Zielrolle: {role}. Ort: {ort}. "
        f"Inhalt und Originalquelle werden zum Schutz der betroffenen "
        f"Person nicht angezeigt (Plattform-Politik §C3 #1: keine "
        f"Klarnamen, Adressen, Arbeitgeber oder Familiendaten in der DB)."
    )
    return summ, desc, ""

def redact_pii(text: str) -> str:
    """
    Replace personally identifying details with neutral placeholders.
    Conservative: errs on the side of redacting more, because the cost
    of a false-negative (publishing a private address) is much higher
    than the cost of a false-positive (slightly less specific summary).
    """
    if not text:
        return ""
    # 1. Email + phone + license plate + birthdate
    out = _PII_EMAIL_RE.sub("[E-Mail entfernt]", text)
    out = _PII_PHONE_RE.sub("[Telefon entfernt]", out)
    out = _PII_LICENSE_RE.sub("[Kennzeichen entfernt]", out)
    out = _PII_BIRTHDATE_RE.sub("[Geburtsdatum entfernt]", out)
    # 2. Address: street + number
    out = _PII_ADDRESS_RE.sub("[Adresse entfernt]", out)
    # 3. Doxxing-Namenslisten (zwei Muster)
    def _strip_names_keep_publics(m):
        names_block = m.group(1)
        # Wenn alle genannten Namen öffentliche Figuren sind, lass sie stehen.
        candidates = [n.strip().lower() for n in re.split(r',|\s+und\s+', names_block) if n.strip()]
        if candidates and all(c in _PII_PUBLIC_FIGURES for c in candidates):
            return m.group(0)
        # Sonst maskieren.
        return m.group(0).replace(names_block, "[Namen entfernt]")
    out = _PII_DOXXING_LIST_RE.sub(_strip_names_keep_publics, out)
    out = _PII_DOXXING_OPENER_RE.sub(_strip_names_keep_publics, out)
    # 4. Cleanup: doppelte Platzhalter zusammenfassen
    out = re.sub(r'(\[(?:Namen|Adresse|Telefon|E-Mail|Kennzeichen|Geburtsdatum) entfernt\])'
                 r'(\s+\1){1,}', r'\1', out)
    return out

# ──────────────────────────────────────────────────────────────────────
# Defamation-Sanitisation (§C3 #4: keine Vorverurteilung)
# ──────────────────────────────────────────────────────────────────────
# Rechtsschutz: ein Bekennerschreiben einer antifaschistischen Gruppe
# bedeutet NICHT, dass die Zielperson tatsächlich "rechtsextrem" oder
# "Nazi" ist. Solche Labels sind in DE/AT/CH justiziabel als Beleidigung/
# üble Nachrede/Verleumdung (StGB §§ 185-187, § 111 öStGB, Art. 173/174
# StGB CH). Wir entfernen sie aus jeder von uns gespeicherten Beschreibung
# und aus jeder Zusammenfassung — auch wenn die Originalquelle sie führt.
# Was bleibt: die Tat (Brand, Sabotage, Sachbeschädigung), das politische
# Motiv-Signal der TÄTER-Seite (Bekennerschreiben antifaschistischer
# Gruppe), und neutrale Rollenbeschreibungen ohne Bewertung der Zielperson.
_NEUTRALIZE_PATTERNS = [
    # 1. "als <Ideologie> [bekannt/eingestuft/geltend/geoutet]" inkl. nach-
    #    folgendem Substantiv (Kader/Funktionär/Organisation/Person).
    #    Output: gleicher Artikel, dann "politisch zugeordneten <Noun>".
    (re.compile(
        r"\b(eines?|einer?|einem|einen|den?|der|die|das)\s+"
        r"als\s+"
        r"(?:rechtsextrem(?:istisch)?\w*|rechtsradikal\w*|neonazistisch\w*|"
        r"neonazi\w*|nazi(?!onal)\w*|faschistisch\w*|faschist\w*)\s+"
        r"(?:bekannten?|eingestuften?|geltenden?|verd[äa]chtigen?|"
        r"geouteten?|enttarnt(?:en)?)\s+"
        r"(\w+)",
        re.IGNORECASE,
    ), r"\1 politisch zugeordneten \2"),
    # 2. "wurde als <Ideologie>(...) [geoutet|bezeichnet|enttarnt|...]"
    (re.compile(
        r"\b(wurde|wird|gilt|outet[e]?\s+sich|enttarnt|enttarnte)\s+"
        r"(?:als\s+|zum\s+)?"
        r"(?:rechtsextrem(?:istisch)?\w*|neonazi\w*|nazi(?!onal)\w*|"
        r"faschist\w*|rechtsradikal\w*)"
        r"(?:\s+(?:geoutet|bezeichnet|beschimpft|enttarnt|abgestempelt|"
        r"verurteilt|tituliert|dargestellt))?",
        re.IGNORECASE,
    ), r"\1 politisch eingeordnet"),
    # 2b. "als <Ideologie> beschimpft/bezeichnet/tituliert" ohne Verb davor
    (re.compile(
        r"\bals\s+"
        r"(?:rechtsextrem(?:istisch)?\w*|neonazi\w*|nazi(?!onal)\w*|"
        r"faschist\w*|rechtsradikal\w*)\s+"
        r"(beschimpft|bezeichnet|tituliert|verleumdet|dargestellt|"
        r"abgestempelt|verurteilt)",
        re.IGNORECASE,
    ), r"politisch eingeordnet \1"),
    # 3. "Nazi-Schwein/Sau/Pack" und Hetzphrasen
    (re.compile(
        r"\b(?:nazi|fascho)[\-–\s]?"
        r"(?:schwein|sau|pack|gesindel|abschaum|bande)\w*",
        re.IGNORECASE,
    ), "[politische Beleidigung entfernt]"),
    # 4. "<Artikel> [bekannten/mutmasslichen] <Partei>-<Rolle>" → neutralisieren
    (re.compile(
        r"\b(eines?|einer?|den?|der|die|das|einem|einen)\s+"
        r"(?:bekannten?\s+|mutma[ßs]lichen?\s+|f[üu]hrenden?\s+|"
        r"hochrangigen?\s+|langj[äa]hrigen?\s+)?"
        r"(?:afd|svp|fp[öo]|cdu|csu|spd|fdp|gr[üu]ne[rn]?|linke[rn]?|"
        r"bsw|[öo]vp|sp[öo]|npd|junge\s+alternative|ja-|jl-|jvp)"
        r"[\-–\s]+"
        r"(?:funktion[äa]r(?:in|s|en)?|kader[ns]?|politiker(?:in|s|en)?|"
        r"abgeordnete[rmn]?|mitglied(?:s|er)?|kandidat(?:in|en)?|"
        r"aktivist(?:in|en)?|vorstand(?:s|es)?|chef(?:in|s)?|"
        r"sprecher(?:in|s)?)\b",
        re.IGNORECASE,
    ), lambda m: f"{m.group(1)} Person mit politischer Funktion"),
    # 5. "<Artikel> [bekannten] <Ideologie>-<Rolle>" oder
    #    zusammengeschrieben "Identitärer-Aktivist". → Privatperson.
    #    Wichtig: NICHT für "Identitäre Bewegung" (formelle Organisation).
    (re.compile(
        r"\b(eines?|einer?|den?|der|die|das|einem|einen)\s+"
        r"(?:bekannten?\s+|mutma[ßs]lichen?\s+|f[üu]hrenden?\s+|"
        r"hochrangigen?\s+|sogenannten?\s+|angeblichen?\s+)?"
        r"(?:rechtsextrem(?:istisch)?\w*|rechtsradikal\w*|neonazistisch\w*|"
        r"neonazi\w*|nazi(?!onal)\w*|faschistisch\w*|faschist\w*|"
        r"identit[äa]r\w*|junge[\-\s]tat)"
        r"(?:[\-–\s]+)?"
        r"(?:aktivist(?:in|en)?|kader[ns]?|funktion[äa]r(?:in|s|en)?|"
        r"politiker(?:in|s|en)?|mitglied(?:s|er)?|anh[äa]nger(?:in|s)?|"
        r"k[äa]mpfer(?:in|s)?|person|sympathisant(?:in|en)?|"
        r"szene[\-\s](?:angeh[öo]riger?|mitglied))\b",
        re.IGNORECASE,
    ), lambda m: f"{m.group(1)} Privatperson"),
    # 6. Solitäres Personen-Substantiv "ein Rechtsextremer" / "der Nazi"
    #    Negative Lookahead: nicht für Bewegung/Partei/Szene/Aufmarsch
    #    (das sind Organisations-/Event-Begriffe, keine Personen-Etiketten).
    (re.compile(
        r"\b(eines?|einer?|den?|der|die|das|einem|einen)\s+"
        r"(?:bekannten?\s+|mutma[ßs]lichen?\s+)?"
        r"(?:rechtsextreme[rmns]?|neonazis?|nazis?(?!onal)|"
        r"faschist(?:en|in)?|rechtsradikale[rmns]?)"
        r"\b(?!\s+(?:bewegung|partei|szene|aufmarsch|demonstration))",
        re.IGNORECASE,
    ), lambda m: f"{m.group(1)} Privatperson"),
    # 7. "<Ideologie>-<Rolle>" ohne Artikel ("AfD-Politiker", "Nazi-Kader")
    #    als Satzfragment-Subjekt. Hier ersetzen wir nur das Etikett.
    (re.compile(
        r"\b(?:afd|svp|fp[öo]|cdu|csu|spd|fdp|[öo]vp|sp[öo]|npd|junge\s+"
        r"alternative)[\-–\s]+(funktion[äa]r(?:in|s|en)?|kader[ns]?|"
        r"politiker(?:in|s|en)?|abgeordnete[rmn]?|mitglied(?:s|er)?|"
        r"aktivist(?:in|en)?|sprecher(?:in|s)?)",
        re.IGNORECASE,
    ), "Person mit politischer Funktion"),
    (re.compile(
        r"\b(?:rechtsextrem(?:istisch)?|rechtsradikal|neonazistisch|"
        r"neonazi|nazi(?!onal)|faschistisch|faschist|identit[äa]r|"
        r"junge[\-\s]tat)\w*"
        r"[\-–\s]+(aktivist(?:in|en)?|kader[ns]?|funktion[äa]r(?:in|s|en)?|"
        r"politiker(?:in|s|en)?|mitglied(?:s|er)?|anh[äa]nger(?:in|s)?)",
        re.IGNORECASE,
    ), "Privatperson"),
    # 8. Solo-Substantive in der Ziel-Rolle, z.B. "Ein Nazi verhaftet"
    (re.compile(
        r"\b(ein|der|die|das|den)\s+"
        r"(?:rechtsextremer?|neonazi|nazi(?!onal)|faschist)\b"
        r"(?!\s+(?:bewegung|partei|szene|aufmarsch))",
        re.IGNORECASE,
    ), lambda m: f"{'eine' if m.group(1).lower() == 'ein' else 'die'} Privatperson"),
]

# Genitiv-/Akkusativ-Korrekturen nach Geschlechtswechsel: ein maskulines
# "eines/einen <Subjekt>" wird in der Neutralisierung zu femininem
# "einer <Person>" — der Artikel muss mitwandern.
_NEUTRALIZE_GENDER_FIXUPS = [
    (re.compile(r"\beines\s+(Privatperson|Person\s+mit\s+politischer\s+Funktion)\b"),
     r"einer \1"),
    (re.compile(r"\beinen\s+(Privatperson|Person\s+mit\s+politischer\s+Funktion)\b"),
     r"eine \1"),
    (re.compile(r"\bein\s+(Privatperson|Person\s+mit\s+politischer\s+Funktion)\b"),
     r"eine \1"),
    (re.compile(r"\beinem\s+(Privatperson|Person\s+mit\s+politischer\s+Funktion)\b"),
     r"einer \1"),
    (re.compile(r"\bden\s+(Privatperson|Person\s+mit\s+politischer\s+Funktion)\b"),
     r"die \1"),
    (re.compile(r"\bdes\s+(Privatperson|Person\s+mit\s+politischer\s+Funktion)\b"),
     r"der \1"),
    (re.compile(r"\bdem\s+(Privatperson|Person\s+mit\s+politischer\s+Funktion)\b"),
     r"der \1"),
]

def neutralize_political_labels(text: str) -> str:
    """
    Entferne diffamierende Personen-Etiketten ("rechtsextrem", "Nazi",
    "AfD-Funktionär" etc.) aus einem Text.

    Wichtige Abgrenzung:
      - Bekenner- und Akteurs-Bezeichnungen auf der TÄTER-Seite bleiben
        erhalten ("antifaschistische Gruppe", "Bekennerschreiben") —
        das ist die Selbst-Beschreibung der Täter, kein Vorwurf an einen
        Dritten.
      - Politisch-Motiv-Signale für die Tat-Klassifikation bleiben
        erhalten (`_POLITICAL_MOTIVE_RE` greift weiter).
      - Verbleibende Lücken werden im sauberen `clean_description()`-
        Pass nach diesem Helper kompaktiert.
    """
    if not text:
        return ""
    out = text
    for rx, repl in _NEUTRALIZE_PATTERNS:
        out = rx.sub(repl, out)
    # Grammatik-Pass: Geschlechts-Übergänge korrigieren
    for rx, repl in _NEUTRALIZE_GENDER_FIXUPS:
        out = rx.sub(repl, out)
    # Cleanup: doppelte Leerzeichen + ", ," → ","
    out = re.sub(r"\s{2,}", " ", out)
    out = re.sub(r",\s*[\.,]", ".", out)
    return out.strip(" ,;")

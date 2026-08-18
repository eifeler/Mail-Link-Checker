# Mail-Link-Checker

PHP-Tool zur Überprüfung von Links in E-Mails: Text einfügen, Links werden
extrahiert und automatisch mit lokalen Heuristiken sowie (optional) gegen
VirusTotal und Google Safe Browsing geprüft. Läuft **ohne Datenbank**,
State lebt nur in der PHP-Session.

**Hosting:** All-Inkl (PHP 8.3), Deployment via FTP.

## Setup

1. `config/config.example.php` nach `config/config.php` kopieren.
2. `VT_API_KEY` eintragen (VirusTotal, kostenloser Account reicht).
3. Optional: `SAFE_BROWSING_API_KEY` eintragen (Google Cloud Console →
   Safe Browsing API aktivieren → API-Key erstellen). Ohne Key wird
   Safe Browsing einfach übersprungen, kein Fehler.
4. Komplettes Verzeichnis per FTP hochladen.
5. Voraussetzung: PHP-Extension `dom` muss aktiv sein (für die
   Link-Text-vs-Ziel-Prüfung). Auf gängigem Hosting Standard, aber nicht
   garantiert - fehlt sie, wird diese eine Zusatzprüfung automatisch
   übersprungen statt die Seite abstürzen zu lassen.

## Prüf-Ebenen

1. **Lokale Heuristiken** (`includes/heuristics.php`, kein API-Call, sofort):
   - Link-Text-vs-Ziel-Abgleich: sichtbarer Text sieht wie eine Domain aus
     (z.B. "www.paypal.com"), href zeigt aber woanders hin
   - IP-Adresse statt Domain, `@`-Trick, Punycode-Domains, auffällig lange
     Subdomain-Ketten, bekannte URL-Verkürzer, unverschlüsseltes http
2. **Google Safe Browsing** (`includes/safe_browsing.php`, optional):
   läuft automatisch beim Laden der Ergebnisse, EIN Request für alle
   Links (Batch-Endpoint), synchron, kein Polling. Großzügiges
   Free-Tier-Limit (10.000/Tag).
3. **VirusTotal** (`includes/vt_api.php`): auf Klick, gründlichste Prüfung
   über viele Engines, aber langsam (Free-Tier: 4 Requests/Minute) - siehe
   Architektur-Hinweise unten.

## Architektur-Hinweise

- **Kein blockierendes Polling im Server-Prozess.** VirusTotal-Analysen
  dauern teils >30s. Statt dass PHP darauf wartet (Timeout-Risiko auf
  Shared Hosting), reicht `submit_url` die URL nur ein und gibt die
  Analyse-ID zurück. Der Client pollt anschließend selbst per
  `check_status` in kurzen Abständen – jeder einzelne Request bleibt kurz.
- **Rate-Limit transparent statt hart:** Client hält sich per
  rollierendem 60s-Fenster proaktiv an VirusTotals 4/Min.-Limit (5s
  Mindestabstand zwischen Anfragen, danach sichtbarer Countdown statt
  Fehlermeldung).
- **Redirect-Ketten werden aufgelöst.** Mail-Provider (Gmail) und
  Newsletter-Tools wrappen Links oft mehrfach ineinander
  (`google.com/url?q=...` → Klick-Tracker → echtes Ziel).
  `unwrap_redirect()` löst das rekursiv bis zur tatsächlichen
  Zieladresse auf - verhindert doppelte Einträge für denselben Link.
- **Bild-URLs werden gefiltert** (z.B. Gmails eigene Emoji-Icons) - kein
  Klick-Ziel, für den Anwendungsfall irrelevant.
- **CSRF-Token** auf Formular und allen AJAX-Endpunkten (`includes/csrf.php`).
- **Session-basiertes Rate-Limiting** serverseitig zusätzlich zum
  Client-Throttle (Defense in Depth).
- **API-Keys** liegen in `config/config.php` (nicht `getenv()`, da
  Umgebungsvariablen unter PHP-FPM auf All-Inkl nicht zuverlässig
  funktionieren). Datei ist per `.gitignore` und `.htaccess` geschützt.
- Max. 25 Links pro Extraktion (Schutz vor versehentlichem
  Quota-Verbrauch bei sehr langen Texten).

## Offene Ideen (noch nicht umgesetzt)

- SPF/DKIM/DMARC-Check anhand roher E-Mail-Header (braucht Workflow-
  Änderung: rohe Header statt nur HTML-Body einfügen)
- Anhänge/Dateien gegen VirusTotal prüfen (anderer API-Endpoint, Upload nötig)
- Text-Heuristiken für Social-Engineering-Formulierungen (niedrige
  Priorität, anfällig für Fehlalarme)

# Mail-Link-Checker

PHP-Tool zur Überprüfung von Links in E-Mails: Text einfügen, Links werden
extrahiert und können einzeln oder gesammelt gegen VirusTotal geprüft werden.
Läuft **ohne Datenbank**, State lebt nur in der PHP-Session.

**Hosting:** All-Inkl (PHP 8.3), Deployment via FTP.

## Setup

1. `config/config.example.php` nach `config/config.php` kopieren und den
   VirusTotal-API-Key eintragen.
2. Komplettes Verzeichnis per FTP hochladen.
3. Fertig – kein DB-Setup nötig.

## Architektur-Hinweise

- **Kein blockierendes Polling im Server-Prozess.** VirusTotal-Analysen
  dauern teils >30s. Statt dass PHP darauf wartet (Timeout-Risiko auf
  Shared Hosting), reicht `submit_url` die URL nur ein und gibt die
  Analyse-ID zurück. Der Client pollt anschließend selbst per
  `check_status` in kurzen Abständen – jeder einzelne Request bleibt kurz.
- **CSRF-Token** auf Formular und AJAX-Endpunkten (`includes/csrf.php`).
- **Session-basiertes Rate-Limiting** (`includes/rate_limit.php`), da der
  VirusTotal-Free-Tier auf 4 Requests/Minute begrenzt ist – gilt für
  Submit und Status-Abfrage gemeinsam.
- **API-Key** liegt in `config/config.php` (nicht `getenv()`, da
  Umgebungsvariablen unter PHP-FPM auf All-Inkl nicht zuverlässig
  funktionieren). Datei ist per `.gitignore` und `.htaccess` geschützt.
- Max. 25 Links pro Extraktion (Schutz vor versehentlichem
  Quota-Verbrauch bei sehr langen Texten).

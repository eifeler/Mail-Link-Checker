<?php
declare(strict_types=1);

// Diese Datei nach config/config.php kopieren und die echten Keys eintragen.
// config/config.php wird per .gitignore NICHT ins Repo übernommen.

define('VT_API_KEY', 'DEIN_VIRUSTOTAL_API_KEY');

// Optional. Ohne Key wird Safe Browsing einfach übersprungen (kein Fehler).
// Key erstellen: Google Cloud Console -> Safe Browsing API aktivieren -> API-Key anlegen.
define('SAFE_BROWSING_API_KEY', '');

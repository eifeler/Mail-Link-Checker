<?php
declare(strict_types=1);

/**
 * Einfaches session-basiertes Rate-Limiting für VT-API-Aufrufe.
 * Der VirusTotal Free-Tier erlaubt 4 Requests/Minute – dieses Limit
 * gilt für ALLE API-Calls (Submit + Status-Abfrage), daher hier zentral
 * geprüft. Kein DB nötig, State lebt nur in der PHP-Session.
 */
function vt_rate_limit_ok(int $maxPerMinute = 4): bool
{
    $now = time();
    $recent = array_values(array_filter(
        $_SESSION['vt_request_log'] ?? [],
        static fn($t) => $t > $now - 60
    ));

    if (count($recent) >= $maxPerMinute) {
        $_SESSION['vt_request_log'] = $recent;
        return false;
    }

    $recent[] = $now;
    $_SESSION['vt_request_log'] = $recent;
    return true;
}

<?php
declare(strict_types=1);

/**
 * Prüft mehrere URLs in EINEM Request gegen Google Safe Browsing (Lookup
 * API v4). Anders als VirusTotal synchron und ohne Polling - und mit
 * deutlich großzügigerem Free-Tier-Limit (10.000 Anfragen/Tag), da hier
 * pro Aufruf viele URLs auf einmal geprüft werden können (bis zu 500).
 *
 * @param string[] $urls
 * @return array{ok: bool, error?: string, results?: array<string, array{threat: bool, types: string[]}>}
 */
function safe_browsing_check(array $urls, string $apiKey): array
{
    $urls = array_values(array_unique($urls));
    if (empty($urls)) {
        return ['ok' => true, 'results' => []];
    }

    $payload = json_encode([
        'client' => ['clientId' => 'mail-link-checker', 'clientVersion' => '1.0.0'],
        'threatInfo' => [
            'threatTypes' => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes' => ['ANY_PLATFORM'],
            'threatEntryTypes' => ['URL'],
            'threatEntries' => array_map(static fn($u) => ['url' => $u], $urls),
        ],
    ]);

    $ch = curl_init('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . urlencode($apiKey));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    $body = curl_exec($ch);

    if ($body === false) {
        $error = curl_error($ch);
        curl_close($ch);
        return ['ok' => false, 'error' => "Verbindungsfehler: $error"];
    }
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $json = json_decode($body, true);

    if ($status !== 200) {
        $msg = $json['error']['message'] ?? "HTTP $status";
        return ['ok' => false, 'error' => "Safe-Browsing-Abfrage fehlgeschlagen: $msg"];
    }

    $results = [];
    foreach ($urls as $u) {
        $results[$u] = ['threat' => false, 'types' => []];
    }
    foreach (($json['matches'] ?? []) as $match) {
        $matchedUrl = $match['threat']['url'] ?? null;
        $type = $match['threatType'] ?? 'UNBEKANNT';
        if ($matchedUrl !== null && isset($results[$matchedUrl])) {
            $results[$matchedUrl]['threat'] = true;
            $results[$matchedUrl]['types'][] = $type;
        }
    }

    return ['ok' => true, 'results' => $results];
}

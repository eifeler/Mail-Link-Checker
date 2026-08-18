<?php
declare(strict_types=1);

/**
 * Extrahiert alle eindeutigen, validen http(s)-Links aus dem rohen,
 * eingefügten HTML (nicht nur aus sichtbarem Text!).
 *
 * Wichtig: Bei eingefügten HTML-Mails steckt der eigentliche Link oft nur
 * im href-Attribut ("Hier klicken" -> http://evil.example), nicht im
 * sichtbaren Text. Deshalb wird hier bewusst über den rohen HTML-String
 * gescannt (Tags/Attribute inklusive) statt nur über den sichtbaren Text -
 * die URL in href="..." landet dabei ganz einfach als Teilstring im Fund.
 *
 * @return string[]
 */
function extract_links(string $html): array
{
    $text = html_entity_decode($html, ENT_QUOTES | ENT_HTML5);

    preg_match_all('/https?:\/\/[^\s"<>()]+/i', $text, $matches);
    $candidates = $matches[0] ?? [];

    $finalLinks = [];
    foreach ($candidates as $link) {
        $link = rtrim($link, ".,;:!?\"'<>");
        if (!filter_var($link, FILTER_VALIDATE_URL)) {
            continue;
        }
        $finalLinks[] = $link;

        // Redirect-/Tracking-Links (?url=..., ?u=...) enthalten oft das
        // eigentliche Ziel als Parameter - das ebenfalls mit aufnehmen.
        $parts = parse_url($link);
        if (!empty($parts['query'])) {
            parse_str($parts['query'], $queryVars);
            foreach ($queryVars as $value) {
                if (is_string($value)
                    && preg_match('/^https?:\/\//i', $value)
                    && filter_var($value, FILTER_VALIDATE_URL)
                ) {
                    $finalLinks[] = $value;
                }
            }
        }
    }

    return array_values(array_unique($finalLinks));
}

/**
 * Reine Text-Vorschau des eingefügten Inhalts fürs Redisplay im Editor.
 * Absichtlich NIE das rohe HTML zurückgeben/anzeigen (XSS-Schutz) - hier
 * wird nur der lesbare Text gebraucht, die Link-Extraktion selbst läuft
 * unabhängig davon auf dem rohen HTML in extract_links().
 */
function plain_text_preview(string $html): string
{
    $text = html_entity_decode($html, ENT_QUOTES | ENT_HTML5);
    $text = strip_tags($text);
    return trim($text);
}

function vt_url_id(string $url): string
{
    return rtrim(strtr(base64_encode($url), '+/', '-_'), '=');
}

/**
 * Führt einen VirusTotal-API-Request aus. Zentrale Stelle für
 * Timeout/Header-Handling statt Duplikation pro Aufruf.
 */
function vt_request(string $method, string $endpoint, string $apiKey, ?array $postFields = null): array
{
    $ch = curl_init('https://www.virustotal.com/api/v3/' . $endpoint);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15); // kurz halten: nie mehr blockierend als nötig

    $headers = ['x-apikey: ' . $apiKey];
    if ($method === 'POST') {
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($postFields ?? []));
        $headers[] = 'Content-Type: application/x-www-form-urlencoded';
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $body = curl_exec($ch);
    if ($body === false) {
        $error = curl_error($ch);
        curl_close($ch);
        return ['ok' => false, 'error' => "Verbindungsfehler: $error"];
    }
    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return ['ok' => true, 'status' => $status, 'json' => json_decode($body, true)];
}

/**
 * Prüft, ob für die URL bereits ein (aktueller) Report existiert.
 * Gibt null zurück, wenn keiner existiert (dann muss neu eingereicht werden).
 */
function vt_existing_report(string $url, string $apiKey): ?array
{
    $res = vt_request('GET', 'urls/' . vt_url_id($url), $apiKey);
    if (!$res['ok']) {
        return ['status' => 'error', 'error' => $res['error']];
    }
    if ($res['status'] === 200 && isset($res['json']['data']['attributes'])) {
        $attr = $res['json']['data']['attributes'];
        return [
            'status' => 'completed',
            'stats' => $attr['last_analysis_stats'] ?? [],
            'results' => $attr['last_analysis_results'] ?? [],
        ];
    }
    return null;
}

/**
 * Reicht eine URL zur Analyse ein. Blockiert NICHT auf das Ergebnis -
 * gibt nur die Analyse-ID zurück, mit der der Client anschließend pollt.
 */
function vt_submit_url(string $url, string $apiKey): array
{
    $res = vt_request('POST', 'urls', $apiKey, ['url' => $url]);
    if (!$res['ok']) {
        return ['status' => 'error', 'error' => $res['error']];
    }
    if ($res['status'] !== 200 || empty($res['json']['data']['id'])) {
        $msg = $res['json']['error']['message'] ?? "HTTP {$res['status']}";
        return ['status' => 'error', 'error' => "Einreichung fehlgeschlagen: $msg"];
    }
    return ['status' => 'pending', 'analysis_id' => $res['json']['data']['id']];
}

/**
 * Fragt den Status einer laufenden Analyse EINMAL ab (kein Sleep-Loop
 * im Server-Prozess - das übernimmt der Client per Intervall-Polling).
 */
function vt_check_analysis(string $analysisId, string $apiKey): array
{
    $res = vt_request('GET', 'analyses/' . $analysisId, $apiKey);
    if (!$res['ok']) {
        return ['status' => 'error', 'error' => $res['error']];
    }
    if ($res['status'] !== 200) {
        $msg = $res['json']['error']['message'] ?? "HTTP {$res['status']}";
        return ['status' => 'error', 'error' => "Status-Abfrage fehlgeschlagen: $msg"];
    }

    $attr = $res['json']['data']['attributes'] ?? [];
    if (($attr['status'] ?? '') === 'completed') {
        return [
            'status' => 'completed',
            'stats' => $attr['stats'] ?? [],
            'results' => $attr['results'] ?? [],
        ];
    }
    return ['status' => 'pending'];
}

<?php
declare(strict_types=1);

/**
 * Löst verschachtelte Redirect-/Tracking-Wrapper rekursiv auf und gibt
 * die GESAMTE Kette zurück (nicht nur das Endziel) - jede Stufe (Wrapper,
 * Tracker, Endziel) soll einzeln prüfbar bleiben, weil auch ein
 * Zwischen-Hop (z.B. ein kompromittierter Tracking-Dienst) bösartig sein
 * kann, selbst wenn das finale Ziel unauffällig ist.
 *
 * Deckt zwei verbreitete Muster ab:
 *  - Ziel als Query-Parameter (z.B. Gmail: google.com/url?q=<ziel>&...)
 *  - Ziel urlencodiert im Pfad (typischer Klick-Tracker: /CL0/<ziel>/...)
 * Tiefenbegrenzung verhindert Endlosschleifen bei kaputten/zirkulären Links.
 *
 * @return string[] Kette von der äußeren URL bis zum aufgelösten Ziel
 */
function unwrap_redirect_chain(string $url, int $depth = 0): array
{
    if ($depth >= 5) {
        return [$url];
    }

    $parts = parse_url($url);

    if (!empty($parts['query'])) {
        parse_str($parts['query'], $vars);
        foreach ($vars as $value) {
            if (is_string($value)
                && preg_match('/^https?:\/\//i', $value)
                && filter_var($value, FILTER_VALIDATE_URL)
                && $value !== $url
            ) {
                return array_merge([$url], unwrap_redirect_chain($value, $depth + 1));
            }
        }
    }

    if (!empty($parts['path'])) {
        $decodedPath = rawurldecode($parts['path']);
        if (preg_match('/https?:\/\/[^\s"\'<>]+/i', $decodedPath, $m)) {
            $inner = rtrim($m[0], ".,;:!?\"'<>");
            if ($inner !== $url && filter_var($inner, FILTER_VALIDATE_URL)) {
                return array_merge([$url], unwrap_redirect_chain($inner, $depth + 1));
            }
        }
    }

    return [$url];
}

/**
 * Bild-URLs (z.B. Gmails eigene Emoji-Icons, Tracking-Pixel) sind für
 * einen Link-Checker irrelevant - niemand "klickt" darauf.
 */
function is_image_url(string $url): bool
{
    $path = parse_url($url, PHP_URL_PATH) ?? '';
    return (bool)preg_match('/\.(png|jpe?g|gif|webp|svg|ico|bmp)$/i', $path);
}

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
 * Verschachtelte Redirect-/Tracking-Wrapper werden über
 * unwrap_redirect_chain() aufgelöst - JEDE Stufe der Kette (Wrapper bis
 * Endziel) landet als eigener, einzeln prüfbarer Link in der Liste
 * (dedupliziert). Bild-URLs werden herausgefiltert (siehe is_image_url()).
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

        foreach (unwrap_redirect_chain($link) as $hop) {
            if (!is_image_url($hop)) {
                $finalLinks[] = $hop;
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
    if ($res['status'] === 404) {
        return null; // eindeutig: kein bestehender Report -> vt_submit_url() übernimmt
    }
    // Alles andere (400/401/403/414/429/5xx/...) ist ein ECHTER Fehler,
    // kein "einfach noch nicht gescannt" - sonst wird ein echtes Problem
    // (z.B. abgelehnte Anfrage) fälschlich als "Eingereicht" angezeigt.
    $msg = $res['json']['error']['message'] ?? "HTTP {$res['status']}";
    return ['status' => 'error', 'error' => "Report-Abfrage fehlgeschlagen: $msg"];
}

/**
 * Reicht eine URL zur Analyse ein. Kein Warten auf das Ergebnis - der
 * Nutzer klickt später einfach nochmal, dann greift vt_existing_report().
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

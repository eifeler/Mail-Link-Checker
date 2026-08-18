<?php
declare(strict_types=1);

/**
 * Findet Links, deren SICHTBARER Text selbst wie eine URL/Domain aussieht
 * (z.B. "www.paypal.com"), deren href aber auf eine andere Domain zeigt.
 * Klassischer Phishing-Trick. Läuft komplett lokal, kein API-Call.
 *
 * Prüft bewusst den ROHEN href (vor unwrap_redirect()) - genau das sieht
 * ein Nutzer beim Hovern über den Link im Mail-Programm.
 *
 * @return array<int, array{visible_text: string, href: string}>
 */
function detect_link_mismatches(string $html): array
{
    if (trim($html) === '' || !class_exists('DOMDocument')) {
        // ext-dom sollte auf jedem gängigen Hosting aktiv sein, aber ohne
        // sie soll die Seite trotzdem funktionieren - nur ohne diese
        // eine Zusatzprüfung, statt komplett abzustürzen.
        return [];
    }

    libxml_use_internal_errors(true);
    $doc = new DOMDocument();
    $doc->loadHTML('<?xml encoding="utf-8" ?><div>' . $html . '</div>', LIBXML_NOERROR | LIBXML_NOWARNING);
    libxml_clear_errors();

    $mismatches = [];
    foreach ($doc->getElementsByTagName('a') as $a) {
        $href = trim($a->getAttribute('href'));
        if ($href === '' || !preg_match('/^https?:\/\//i', $href)) {
            continue;
        }

        $visibleText = trim(preg_replace('/\s+/', ' ', $a->textContent) ?? '');
        if ($visibleText === '') {
            continue;
        }

        $visibleUrl = $visibleText;
        if (!preg_match('#^https?://#i', $visibleUrl)) {
            // z.B. "www.paypal.com/login" ohne Schema - für den Host-Vergleich ergänzen
            if (!preg_match('/^(www\.)?[a-z0-9-]+(\.[a-z0-9-]+)+(\/\S*)?$/i', $visibleUrl)) {
                continue; // sichtbarer Text ist keine Domain -> kein Vergleich möglich/nötig
            }
            $visibleUrl = 'http://' . $visibleUrl;
        }

        $visibleHost = strtolower((string)(parse_url($visibleUrl, PHP_URL_HOST) ?? ''));
        $hrefHost = strtolower((string)(parse_url($href, PHP_URL_HOST) ?? ''));
        $visibleHost = preg_replace('/^www\./', '', $visibleHost);
        $hrefHost = preg_replace('/^www\./', '', $hrefHost);

        if ($visibleHost !== '' && $hrefHost !== '' && $visibleHost !== $hrefHost) {
            $mismatches[] = ['visible_text' => $visibleText, 'href' => $href];
        }
    }

    return $mismatches;
}

/**
 * Bekannte URL-Verkürzer. Nicht automatisch bösartig, aber verschleiern
 * das eigentliche Ziel - sollte transparent gemacht werden.
 */
const URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'lnkd.in',
];

/**
 * Lokale Risiko-Heuristiken für eine einzelne URL. Kein API-Call, kein
 * Rate-Limit-Verbrauch - läuft sofort bei der Anzeige der Ergebnisliste.
 *
 * @return string[] Liste kurzer, verständlicher Warnhinweise (leer = unauffällig)
 */
function url_risk_flags(string $url): array
{
    $flags = [];
    $parts = parse_url($url);
    $host = strtolower($parts['host'] ?? '');

    if ($host === '') {
        return $flags;
    }

    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $flags[] = 'IP-Adresse statt Domain';
    }

    if (!empty($parts['user'])) {
        // http://echte-domain.de@evil.tld/... - der Teil vor dem @ täuscht die echte Domain nur vor
        $flags[] = '@-Trick (angezeigter Domain-Teil vor "@" ist nicht das echte Ziel)';
    }

    if (str_contains($host, 'xn--')) {
        $flags[] = 'Punycode-Domain (evtl. Homoglyph-Fälschung bekannter Marke)';
    }

    $labels = explode('.', $host);
    $longestLabel = 0;
    foreach ($labels as $label) {
        $longestLabel = max($longestLabel, strlen($label));
    }
    if (count($labels) >= 5 || $longestLabel >= 25) {
        $flags[] = 'ungewöhnlich lange/verschachtelte Subdomain-Struktur';
    }

    $hostNoWww = preg_replace('/^www\./', '', $host);
    if (in_array($hostNoWww, URL_SHORTENERS, true)) {
        $flags[] = 'Kurz-URL-Dienst (verschleiert das eigentliche Ziel)';
    }

    if (($parts['scheme'] ?? '') === 'http') {
        $flags[] = 'unverschlüsselt (http statt https)';
    }

    return $flags;
}

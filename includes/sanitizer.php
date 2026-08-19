<?php
declare(strict_types=1);

/**
 * Sanitizer für die WYSIWYG-Wiederanzeige des eingefügten E-Mail-HTMLs.
 *
 * Grundprinzip: ALLOWLIST statt Blocklist. Nur explizit erlaubte Tags und
 * Attribute bleiben erhalten, alles andere wird entfernt (Tags werden
 * "entpackt" - Inhalt bleibt, Tag verschwindet - außer bei aktiv
 * gefährlichen Tags wie <script>, die komplett samt Inhalt rausfliegen).
 *
 * Bewusste Einschränkungen (Sicherheit vor Formatierungstreue):
 *  - <img> wird komplett entfernt: ein Sicherheits-Tool soll keine
 *    Remote-Bilder aus einer verdächtigen Mail nachladen (Tracking-Pixel).
 *  - url(...) in style-Attributen wird entfernt (gleicher Grund, nur über
 *    CSS background-image statt <img>).
 *  - href nur mit http(s):/mailto: Schema, alles andere (javascript:,
 *    data:, ...) wird entfernt.
 */

const SANITIZE_ALLOWED_TAGS = [
    'a', 'b', 'strong', 'i', 'em', 'u', 'p', 'div', 'span', 'br', 'hr',
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'td', 'th',
    'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'blockquote', 'font', 'center', 'small', 'sub', 'sup',
];

// Diese Tags fliegen SAMT Inhalt raus (Inhalt ist keine sichere Text-
// Darstellung, sondern Code/Markup, z.B. CSS oder JS).
const SANITIZE_STRIP_ENTIRELY = [
    'script', 'style', 'iframe', 'object', 'embed', 'applet', 'form',
    'noscript', 'svg', 'math', 'link', 'meta', 'base', 'img',
];

const SANITIZE_ALLOWED_ATTRS = [
    'href', 'style', 'align', 'valign', 'width', 'height',
    'colspan', 'rowspan', 'border', 'cellpadding', 'cellspacing',
    'color', 'face', 'size', 'bgcolor',
];

function sanitize_html_for_display(string $html): string
{
    if (trim($html) === '' || !class_exists('DOMDocument')) {
        return '';
    }

    libxml_use_internal_errors(true);
    $doc = new DOMDocument();
    $doc->loadHTML('<?xml encoding="utf-8" ?><div>' . $html . '</div>', LIBXML_NOERROR | LIBXML_NOWARNING);
    libxml_clear_errors();

    $body = $doc->getElementsByTagName('body')->item(0);
    $wrapper = $body ? $body->firstChild : null;
    if (!$wrapper) {
        return '';
    }

    sanitize_node_recursive($doc, $wrapper);

    $result = '';
    foreach (iterator_to_array($wrapper->childNodes) as $child) {
        $result .= $doc->saveHTML($child);
    }
    return $result;
}

function sanitize_node_recursive(DOMDocument $doc, DOMNode $node): void
{
    foreach (iterator_to_array($node->childNodes) as $child) {
        if ($child->nodeType === XML_COMMENT_NODE) {
            // Outlook-Conditional-Comments/VML-Müll etc. raus
            $node->removeChild($child);
            continue;
        }

        if ($child->nodeType !== XML_ELEMENT_NODE) {
            continue; // Text-Knoten unangetastet lassen
        }

        /** @var DOMElement $child */
        $tag = strtolower($child->tagName);

        if (in_array($tag, SANITIZE_STRIP_ENTIRELY, true)) {
            $node->removeChild($child);
            continue;
        }

        if (!in_array($tag, SANITIZE_ALLOWED_TAGS, true)) {
            // Tag nicht auf der Liste (z.B. <section>, <button>) - Kinder
            // behalten (erst bereinigen), Tag selbst entfernen ("entpacken").
            sanitize_node_recursive($doc, $child);
            while ($child->firstChild) {
                $node->insertBefore($child->firstChild, $child);
            }
            $node->removeChild($child);
            continue;
        }

        if ($child->hasAttributes()) {
            foreach (iterator_to_array($child->attributes) as $attr) {
                $attrName = strtolower($attr->nodeName);

                if (!in_array($attrName, SANITIZE_ALLOWED_ATTRS, true)) {
                    $child->removeAttribute($attr->nodeName);
                    continue;
                }

                if ($attrName === 'href') {
                    $href = trim($attr->nodeValue);
                    if (!preg_match('/^(https?:|mailto:)/i', $href)) {
                        $child->removeAttribute('href');
                    }
                }

                if ($attrName === 'style') {
                    $value = $attr->nodeValue;
                    if (preg_match('/expression\s*\(/i', $value)) {
                        // Uralte IE-only-Angriffstechnik, längst tot - trotzdem
                        // sauber: ganzes style-Attribut verwerfen statt Teilstrings
                        // zu entfernen und Reste stehen zu lassen.
                        $child->removeAttribute('style');
                    } else {
                        $clean = preg_replace('/url\s*\([^)]*\)/i', '', $value) ?? $value;
                        $child->setAttribute('style', $clean);
                    }
                }
            }
        }

        sanitize_node_recursive($doc, $child);
    }
}

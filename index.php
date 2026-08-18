<?php
declare(strict_types=1);
session_start();

require __DIR__ . '/includes/csrf.php';
require __DIR__ . '/includes/rate_limit.php';
require __DIR__ . '/includes/vt_api.php';
require __DIR__ . '/includes/heuristics.php';
require __DIR__ . '/includes/safe_browsing.php';

const MAX_LINKS = 25;

$apiKey = '';
$safeBrowsingKey = '';
$configFile = __DIR__ . '/config/config.php';
if (is_file($configFile)) {
    require $configFile;
    $apiKey = defined('VT_API_KEY') ? VT_API_KEY : '';
    $safeBrowsingKey = defined('SAFE_BROWSING_API_KEY') ? SAFE_BROWSING_API_KEY : '';
}

// ---------------------------------------------------------------------
// AJAX-Endpunkte (submit_url / check_status). Jeder Aufruf ist kurz und
// blockiert nie länger als ein einzelner cURL-Timeout (15s).
// ---------------------------------------------------------------------
if (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest') {
    header('Content-Type: application/json; charset=utf-8');

    if (!csrf_verify($_POST['csrf_token'] ?? null)) {
        http_response_code(403);
        echo json_encode(['status' => 'error', 'error' => 'Ungültiges Sicherheits-Token. Seite bitte neu laden.']);
        exit;
    }

    $action = $_POST['action'] ?? '';

    // Safe Browsing braucht keinen VT-Key und keinen VT-Rate-Limit-Slot -
    // eigene, viel großzügigere Quota (siehe includes/safe_browsing.php).
    if ($action === 'check_safe_browsing') {
        if (empty($safeBrowsingKey)) {
            echo json_encode(['status' => 'error', 'error' => 'Kein Safe-Browsing-API-Schlüssel konfiguriert.']);
            exit;
        }
        $sessionLinks = $_SESSION['links'] ?? [];
        $sb = safe_browsing_check($sessionLinks, $safeBrowsingKey);
        if (!$sb['ok']) {
            echo json_encode(['status' => 'error', 'error' => $sb['error']]);
            exit;
        }
        echo json_encode(['status' => 'completed', 'results' => $sb['results']]);
        exit;
    }

    if (empty($apiKey)) {
        echo json_encode(['status' => 'error', 'error' => 'Kein VirusTotal API-Schlüssel konfiguriert (config/config.php).']);
        exit;
    }

    if ($action === 'submit_url') {
        $url = (string)($_POST['url'] ?? '');
        if (!filter_var($url, FILTER_VALIDATE_URL) || !preg_match('/^https?:\/\//i', $url)) {
            echo json_encode(['status' => 'error', 'error' => 'Ungültige URL.']);
            exit;
        }
        if (!vt_rate_limit_ok()) {
            echo json_encode(['status' => 'error', 'error' => 'VirusTotal-Limit erreicht (4/Min.). Bitte kurz warten.']);
            exit;
        }
        $existing = vt_existing_report($url, $apiKey);
        echo json_encode($existing ?? vt_submit_url($url, $apiKey));
        exit;
    }

    if ($action === 'check_status') {
        $analysisId = (string)($_POST['analysis_id'] ?? '');
        if ($analysisId === '') {
            echo json_encode(['status' => 'error', 'error' => 'Keine Analyse-ID übergeben.']);
            exit;
        }
        if (!vt_rate_limit_ok()) {
            echo json_encode(['status' => 'error', 'error' => 'VirusTotal-Limit erreicht (4/Min.). Bitte kurz warten.']);
            exit;
        }
        echo json_encode(vt_check_analysis($analysisId, $apiKey));
        exit;
    }

    echo json_encode(['status' => 'error', 'error' => 'Unbekannte Aktion.']);
    exit;
}

// ---------------------------------------------------------------------
// Normale Formulare (Extrahieren / Zurücksetzen)
// ---------------------------------------------------------------------
$links = $_SESSION['links'] ?? [];
$mismatches = $_SESSION['mismatches'] ?? [];
$emailContent = '';
$noLinks = false;
$linksCapped = false;
$formError = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['reset_all'])) {
        session_unset();
        session_destroy();
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }

    if (isset($_POST['extract'])) {
        if (!csrf_verify($_POST['csrf_token'] ?? null)) {
            $formError = 'Ungültiges Sicherheits-Token. Bitte Text erneut absenden.';
        } else {
            $emailContentRaw = (string)($_POST['email_content'] ?? '');
            $emailContent = plain_text_preview($emailContentRaw); // nur fürs Redisplay
            $found = extract_links($emailContentRaw);
            $mismatches = detect_link_mismatches($emailContentRaw);
            $_SESSION['mismatches'] = $mismatches;

            if (count($found) > MAX_LINKS) {
                $linksCapped = true;
                $found = array_slice($found, 0, MAX_LINKS);
            }

            if (empty($found)) {
                $noLinks = true;
                $links = [];
                unset($_SESSION['links']);
            } else {
                $links = $found;
                $_SESSION['links'] = $found;
            }
        }
    }
}

$token = csrf_token();
?>
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mail-Link-Checker</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = {
    theme: {
      extend: {
        colors: {
          paper: '#F3F4F1',
          ink: '#1C2321',
          accent: '#1D4E45',
          warn: '#B45309',
          danger: '#B42318',
          hairline: '#D8DBD6',
        },
        fontFamily: {
          sans: ['"IBM Plex Sans"', 'system-ui', 'sans-serif'],
          mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'],
        },
      },
    },
  };
</script>
<style>
    body { background-color: #F3F4F1; }
    .step { position: relative; }
    .step-done .step-dot { background-color: #1D4E45; border-color: #1D4E45; }
    .step-done .step-label { color: #1C2321; }
    .placeholder-text:empty::before {
        content: attr(data-placeholder);
        color: rgba(28,35,33,0.35);
        pointer-events: none;
        display: block;
    }
    .verdict-badge {
        display: inline-block;
        padding: 0.15rem 0.6rem;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-family: "IBM Plex Mono", monospace;
        border-width: 1px;
        white-space: nowrap;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .spinner {
        display: inline-block; width: 12px; height: 12px;
        border: 2px solid rgba(0,0,0,0.15); border-top-color: #1D4E45;
        border-radius: 50%; animation: spin 0.8s linear infinite;
    }
</style>
</head>
<body class="font-sans text-ink min-h-screen flex flex-col items-center px-4 py-8 sm:py-12">

<main class="w-full max-w-3xl">

    <!-- Instrument-Strip -->
    <header class="mb-6">
        <div class="flex items-baseline justify-between flex-wrap gap-2">
            <h1 class="text-xl font-semibold tracking-tight">Mail·Link·Checker</h1>
            <nav class="flex items-center gap-4 text-xs font-mono text-ink/50" aria-label="Ablauf">
                <span class="step <?php echo $emailContent !== '' || !empty($links) ? 'step-done' : ''; ?>">
                    <span class="step-dot inline-block w-2 h-2 rounded-full border border-ink/30 align-middle mr-1"></span>
                    <span class="step-label">Einfügen</span>
                </span>
                <span class="step <?php echo !empty($links) ? 'step-done' : ''; ?>">
                    <span class="step-dot inline-block w-2 h-2 rounded-full border border-ink/30 align-middle mr-1"></span>
                    <span class="step-label">Extrahieren</span>
                </span>
                <span class="step" id="step-checked">
                    <span class="step-dot inline-block w-2 h-2 rounded-full border border-ink/30 align-middle mr-1"></span>
                    <span class="step-label">Prüfen</span>
                </span>
            </nav>
        </div>
        <p class="text-sm text-ink/60 mt-2">
            Verdächtigen E-Mail-Inhalt einfügen, Links extrahieren, gegen VirusTotal &amp; Google Safe Browsing prüfen. Alle Angaben ohne Gewähr.
        </p>
    </header>

    <?php if (empty($apiKey)): ?>
        <div class="mb-6 border border-warn/30 bg-warn/5 text-warn text-sm rounded-md px-4 py-3">
            Kein VirusTotal API-Schlüssel konfiguriert. <code class="font-mono">config/config.example.php</code> nach
            <code class="font-mono">config/config.php</code> kopieren und Key eintragen.
        </div>
    <?php endif; ?>

    <?php if ($formError): ?>
        <div class="mb-6 border border-danger/30 bg-danger/5 text-danger text-sm rounded-md px-4 py-3">
            <?php echo htmlspecialchars($formError); ?>
        </div>
    <?php endif; ?>

    <?php if (!empty($mismatches)): ?>
        <div class="mb-6 border border-danger/40 bg-danger/5 rounded-md px-4 py-3">
            <p class="text-sm font-semibold text-danger mb-2">⚠ Link-Text stimmt nicht mit dem Ziel überein (<?php echo count($mismatches); ?>)</p>
            <ul class="text-sm text-ink/80 space-y-1.5">
                <?php foreach ($mismatches as $m): ?>
                <li class="font-mono text-xs break-all">
                    Text zeigt <strong>„<?php echo htmlspecialchars($m['visible_text']); ?>“</strong>,
                    Link führt aber zu <strong class="text-danger"><?php echo htmlspecialchars($m['href']); ?></strong>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <!-- Eingabe -->
    <section class="bg-white border border-hairline rounded-lg p-5 sm:p-6 shadow-sm">
        <form method="post" action="" onsubmit="prepareContent()">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($token); ?>">
            <input type="hidden" name="email_content" id="email_content_input">
            <label for="editor" class="block text-sm font-medium mb-2 text-ink/80">E-Mail-Inhalt</label>
            <div
                id="editor"
                contenteditable="true"
                data-placeholder="Hier E-Mail-Inhalt einfügen (Strg+V) – HTML-Formatierung bleibt erhalten, damit auch versteckte Links in Buttons/Texten gefunden werden …"
                class="placeholder-text w-full h-72 border border-hairline rounded-md p-4 font-mono text-sm leading-relaxed overflow-y-auto focus:outline-none focus:ring-2 focus:ring-accent/40 focus:border-accent transition"
            ><?php echo htmlspecialchars($emailContent); ?></div>
            <div class="mt-4 flex items-center gap-3">
                <button type="submit" name="extract"
                    class="px-5 py-2.5 bg-accent text-white text-sm font-medium rounded-md hover:bg-accent/90 focus:outline-none focus:ring-2 focus:ring-accent/40 transition">
                    Links extrahieren
                </button>
                <?php if (!empty($links)): ?>
                <span class="text-xs text-ink/40">bereits <?php echo count($links); ?> Link(s) extrahiert</span>
                <?php endif; ?>
            </div>
        </form>
    </section>

    <?php if ($noLinks): ?>
        <p class="mt-4 text-sm text-warn">Keine Links im eingefügten Text gefunden.</p>
    <?php endif; ?>

    <?php if ($linksCapped): ?>
        <p class="mt-4 text-sm text-warn">Nur die ersten <?php echo MAX_LINKS; ?> Links werden angezeigt (VirusTotal-Limit).</p>
    <?php endif; ?>

    <?php if (!empty($links)): ?>
    <!-- Ergebnisse -->
    <section class="mt-6">
        <div class="flex items-center justify-between flex-wrap gap-3 mb-3">
            <h2 class="text-sm font-semibold text-ink/70 uppercase tracking-wide">Gefundene Links (<?php echo count($links); ?>)</h2>
            <div class="flex gap-2">
                <button type="button" id="copyAllBtn"
                    class="px-3 py-1.5 border border-hairline text-xs font-medium rounded-md hover:bg-paper transition">
                    Alle kopieren
                </button>
                <button type="button" id="checkAllBtn" <?php echo empty($apiKey) ? 'disabled' : ''; ?>
                    class="px-3 py-1.5 bg-accent text-white text-xs font-medium rounded-md hover:bg-accent/90 disabled:opacity-40 disabled:cursor-not-allowed transition">
                    Alle Links mit VirusTotal prüfen
                </button>
            </div>
        </div>

        <div id="progressBar" class="hidden w-full bg-hairline rounded-full h-2 mb-1 relative overflow-hidden">
            <div id="progressFill" class="bg-accent h-2 rounded-full transition-all duration-300" style="width:0%"></div>
        </div>
        <p id="progressText" class="text-xs text-ink/50 mb-1"></p>
        <p id="rateLimitStatus" class="text-xs text-ink/40 mb-3"></p>

        <ul class="space-y-2">
            <?php foreach ($links as $i => $l):
                $encoded = rtrim(strtr(base64_encode($l), '+/', '-_'), '=');
                $vtGui = "https://www.virustotal.com/gui/url/$encoded/detection";
                $host = preg_replace('/^www\./i', '', parse_url($l, PHP_URL_HOST) ?? '');
                $urlvoidUrl = "https://www.urlvoid.com/scan/{$host}/";
                $urlEnc = urlencode($l);
                $kasperskyUrl = "https://opentip.kaspersky.com/$urlEnc/";
                $googleSbUrl = "https://transparencyreport.google.com/safe-browsing/search?url=$urlEnc";
                $riskFlags = url_risk_flags($l);
            ?>
            <li class="bg-white border border-hairline rounded-md p-3">
                <div class="flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-3">
                    <span class="font-mono text-sm break-all flex-1"><?php echo htmlspecialchars($l); ?></span>
                    <div class="flex items-center gap-1.5 flex-wrap">
                        <?php if (!empty($safeBrowsingKey)): ?>
                        <span class="verdict-badge bg-hairline text-ink/50 border-hairline" data-sb-badge="<?php echo $i; ?>">SB: Prüfe …</span>
                        <?php endif; ?>
                        <span class="verdict-badge bg-hairline text-ink/50 border-hairline" data-badge="<?php echo $i; ?>">VT: Ungeprüft</span>
                    </div>
                </div>
                <?php if (!empty($riskFlags)): ?>
                <div class="flex flex-wrap gap-1.5 mt-2">
                    <?php foreach ($riskFlags as $flag): ?>
                    <span class="text-xs text-warn border border-warn/30 bg-warn/5 rounded px-2 py-0.5">⚠ <?php echo htmlspecialchars($flag); ?></span>
                    <?php endforeach; ?>
                </div>
                <?php endif; ?>
                <div class="flex flex-wrap gap-2 mt-2 text-xs">
                    <button type="button" class="copy-btn px-2.5 py-1 border border-hairline rounded hover:bg-paper transition" data-url="<?php echo htmlspecialchars($l); ?>">Kopieren</button>
                    <button type="button" class="check-btn px-2.5 py-1 bg-accent/10 text-accent border border-accent/30 rounded hover:bg-accent/20 transition" data-index="<?php echo $i; ?>" data-url="<?php echo htmlspecialchars($l); ?>" <?php echo empty($apiKey) ? 'disabled' : ''; ?>>VT prüfen</button>
                    <a href="<?php echo htmlspecialchars($vtGui); ?>" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 border border-hairline rounded hover:bg-paper transition">VT-Web</a>
                    <a href="<?php echo htmlspecialchars($urlvoidUrl); ?>" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 border border-hairline rounded hover:bg-paper transition">URLvoid</a>
                    <a href="<?php echo htmlspecialchars($kasperskyUrl); ?>" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 border border-hairline rounded hover:bg-paper transition">Kaspersky</a>
                    <a href="<?php echo htmlspecialchars($googleSbUrl); ?>" target="_blank" rel="noopener noreferrer" class="px-2.5 py-1 border border-hairline rounded hover:bg-paper transition">Google</a>
                </div>
                <div class="hidden" data-detail="<?php echo $i; ?>"></div>
            </li>
            <?php endforeach; ?>
        </ul>

        <input type="hidden" id="linksData" value="<?php echo htmlspecialchars(json_encode(array_values($links))); ?>">
    </section>
    <?php endif; ?>

    <form method="post" action="" class="mt-8">
        <button type="submit" name="reset_all"
            class="px-4 py-2 text-sm border border-hairline rounded-md text-ink/60 hover:bg-white transition">
            Alles zurücksetzen
        </button>
    </form>

    <!-- Weitere Checker (demoted, kein Wettbewerb zum Hauptfluss) -->
    <footer class="mt-10 pt-6 border-t border-hairline text-xs text-ink/40 flex flex-wrap gap-x-4 gap-y-1">
        <span>Weitere Checker:</span>
        <a class="hover:text-ink/70 underline" href="https://www.virustotal.com/gui/home/url" target="_blank" rel="noopener noreferrer">VirusTotal</a>
        <a class="hover:text-ink/70 underline" href="https://www.urlvoid.com/" target="_blank" rel="noopener noreferrer">URLvoid</a>
        <a class="hover:text-ink/70 underline" href="https://opentip.kaspersky.com/" target="_blank" rel="noopener noreferrer">Kaspersky</a>
        <a class="hover:text-ink/70 underline" href="https://transparencyreport.google.com/safe-browsing/search" target="_blank" rel="noopener noreferrer">Google Safe Browsing</a>
        <span class="ml-auto">&copy; <?php echo date('Y'); ?> Michael Theis</span>
    </footer>

</main>

<script>
    window.CSRF_TOKEN = <?php echo json_encode($token); ?>;
    window.API_KEY_MISSING = <?php echo empty($apiKey) ? 'true' : 'false'; ?>;
    window.SAFE_BROWSING_ENABLED = <?php echo empty($safeBrowsingKey) ? 'false' : 'true'; ?>;
</script>
<script src="assets/app.js"></script>
</body>
</html>

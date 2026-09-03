document.addEventListener('DOMContentLoaded', () => {
    const CSRF_TOKEN = window.CSRF_TOKEN || '';
    const API_KEY_MISSING = window.API_KEY_MISSING === true;
    const SAFE_BROWSING_ENABLED = window.SAFE_BROWSING_ENABLED === true;

    const linksDataEl = document.getElementById('linksData');
    const links = linksDataEl ? JSON.parse(linksDataEl.value || '[]') : [];

    const checkAllBtn = document.getElementById('checkAllBtn');
    const copyAllBtn = document.getElementById('copyAllBtn');
    const progressBar = document.getElementById('progressBar');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const stepChecked = document.getElementById('step-checked');

    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

    // Überträgt das rohe HTML des contenteditable-Editors ins Formularfeld.
    // Wichtig: innerHTML (nicht innerText!) - sonst gehen Links verloren,
    // die nur als href hinter einem Text wie "Hier klicken" stecken.
    window.prepareContent = function () {
        const editor = document.getElementById('editor');
        const input = document.getElementById('email_content_input');
        if (editor && input) input.value = editor.innerHTML;
    };

    function escapeHtml(text) {
        const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
        return String(text).replace(/[&<>"']/g, (m) => map[m]);
    }

    async function callApi(action, params) {
        const fd = new FormData();
        fd.append('action', action);
        fd.append('csrf_token', CSRF_TOKEN);
        for (const [k, v] of Object.entries(params)) fd.append(k, v);

        const res = await fetch(window.location.href, {
            method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest' },
            body: fd,
        });
        if (!res.ok) {
            return { status: 'error', error: `HTTP-Fehler ${res.status}` };
        }
        return res.json();
    }

    function verdictFromStats(stats) {
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        if (malicious > 0) return { label: `Bösartig (${malicious})`, cls: 'bg-danger/10 text-danger border-danger/30' };
        if (suspicious > 0) return { label: `Verdächtig (${suspicious})`, cls: 'bg-warn/10 text-warn border-warn/30' };
        return { label: 'Unauffällig', cls: 'bg-accent/10 text-accent border-accent/30' };
    }

    function renderResult(index, report) {
        const badge = document.querySelector(`[data-badge="${index}"]`);
        const detail = document.querySelector(`[data-detail="${index}"]`);
        if (!badge) return;

        if (report.status === 'error') {
            badge.textContent = 'Fehler';
            badge.className = 'verdict-badge bg-danger/10 text-danger border-danger/30';
            if (detail) {
                detail.innerHTML = `<p class="text-danger text-sm">${escapeHtml(report.error || 'Unbekannter Fehler')}</p>`;
                detail.classList.remove('hidden');
            }
            return;
        }

        if (report.status === 'submitted') {
            badge.textContent = 'VT: Neu bei VirusTotal …';
            badge.className = 'verdict-badge bg-blue-500/10 text-blue-700 border-blue-500/30';
            return;
        }

        const stats = report.stats || {};
        const v = verdictFromStats(stats);
        badge.textContent = v.label;
        badge.className = `verdict-badge ${v.cls}`;

        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        if ((malicious > 0 || suspicious > 0) && detail) {
            const results = report.results || {};
            let items = '';
            for (const engine in results) {
                const r = results[engine];
                if (r.category === 'malicious' || r.category === 'suspicious') {
                    const cls = r.category === 'malicious' ? 'text-danger font-semibold' : 'text-warn';
                    items += `<li class="${cls}">${escapeHtml(engine)}: ${escapeHtml(r.result || r.category)}</li>`;
                }
            }
            detail.innerHTML = `<ul class="list-disc pl-5 text-sm mt-2 space-y-0.5">${items}</ul>`;
            detail.classList.remove('hidden');
        }
    }

    function setBadgePending(index) {
        const badge = document.querySelector(`[data-badge="${index}"]`);
        if (badge) {
            badge.textContent = 'VT: Prüfe …';
            badge.className = 'verdict-badge bg-hairline text-ink/60 border-hairline';
        }
    }

    /**
     * Safe Browsing: EIN Request für ALLE Links (Batch-Endpoint), läuft
     * automatisch beim Laden - synchron, eigenes Kontingent.
     */
    async function runSafeBrowsingCheck() {
        if (!SAFE_BROWSING_ENABLED || links.length === 0) return;

        const res = await callApi('check_safe_browsing', {});
        if (res.status === 'error') {
            document.querySelectorAll('[data-sb-badge]').forEach((el) => {
                el.textContent = 'SB: Fehler';
                el.className = 'verdict-badge bg-danger/10 text-danger border-danger/30';
                el.title = res.error || '';
            });
            return;
        }

        links.forEach((url, i) => {
            const badge = document.querySelector(`[data-sb-badge="${i}"]`);
            if (!badge) return;
            const entry = (res.results || {})[url];
            if (!entry) {
                badge.textContent = 'SB: n/a';
                badge.className = 'verdict-badge bg-hairline text-ink/40 border-hairline';
                return;
            }
            if (entry.threat) {
                badge.textContent = `SB: Bedrohung (${entry.types.join(', ')})`;
                badge.className = 'verdict-badge bg-danger/10 text-danger border-danger/30';
            } else {
                badge.textContent = 'SB: Sicher';
                badge.className = 'verdict-badge bg-accent/10 text-accent border-accent/30';
            }
        });
    }

    let anyCheckRunning = false;
    /**
     * Geteiltes VT-Zeitfenster (5s Mindestabstand, max. 4 Anfragen pro
     * rollierender Minute) - EINE Quelle der Wahrheit auf Basis echter
     * Zeitstempel, gemeinsam genutzt von Einzel-Klick, Sammel-Prüfung UND
     * automatischem 60s-Rückruf. Zählt nie "neu los", egal welcher der
     * drei Wege gerade einen Aufruf macht - alle lesen/schreiben dasselbe
     * Array.
     */
    const VT_MIN_GAP_MS = 5000;
    const VT_WINDOW_MS = 60000;
    const VT_MAX_PER_WINDOW = 4;
    let vtCallLog = []; // Zeitstempel der letzten VT-Aufrufe

    async function waitForVtSlot(index) {
        const badge = document.querySelector(`[data-badge="${index}"]`);

        while (true) {
            const now = Date.now();
            vtCallLog = vtCallLog.filter((t) => now - t < VT_WINDOW_MS);

            let waitMs = 0;
            if (vtCallLog.length > 0) {
                const sinceLast = now - vtCallLog[vtCallLog.length - 1];
                if (sinceLast < VT_MIN_GAP_MS) waitMs = Math.max(waitMs, VT_MIN_GAP_MS - sinceLast);
            }
            if (vtCallLog.length >= VT_MAX_PER_WINDOW) {
                waitMs = Math.max(waitMs, VT_WINDOW_MS - (now - vtCallLog[0]));
            }

            if (waitMs <= 0) break;
            if (badge) badge.textContent = `VT: Warte ${Math.ceil(waitMs / 1000)}s (Limit) …`;
            await sleep(Math.min(waitMs, 1000));
        }

        vtCallLog.push(Date.now());
    }

    const pendingRetries = {}; // index -> {timeoutId, intervalId}

    function clearPendingRetry(index) {
        const p = pendingRetries[index];
        if (p) {
            clearTimeout(p.timeoutId);
            clearInterval(p.intervalId);
            delete pendingRetries[index];
        }
    }

    /**
     * Automatischer Rückruf - EINE Nachfrage nach 12s, technisch identisch
     * zu "Nutzer klickt manuell nochmal". Bewusst nur ein Versuch (nicht
     * mehrfach), da jeder Rückruf echtes VT-Kontingent verbraucht (4/Min.
     * geteilt über alle Links) - mehr automatische Versuche würden bei
     * mehreren gleichzeitig wartenden Links unnötig Slots blockieren.
     */
    const AUTO_RETRY_INTERVAL_MS = 12000;
    const MAX_AUTO_RETRIES = 1;

    function scheduleAutoRetry(index, url, attempt) {
        clearPendingRetry(index);
        const badge = document.querySelector(`[data-badge="${index}"]`);

        if (attempt > MAX_AUTO_RETRIES) {
            if (badge) badge.textContent = 'VT: Neu bei VirusTotal – Analyse läuft noch, bitte später erneut klicken';
            return;
        }

        const startedAt = Date.now();
        const tick = () => {
            if (!badge) return;
            const remaining = Math.max(0, Math.ceil((AUTO_RETRY_INTERVAL_MS - (Date.now() - startedAt)) / 1000));
            badge.textContent = `VT: Neu bei VirusTotal – Rückmeldung folgt (erneut in ${remaining}s)`;
        };
        tick();
        const intervalId = setInterval(tick, 1000);

        const timeoutId = setTimeout(async () => {
            clearPendingRetry(index);
            if (anyCheckRunning) {
                // Andere Prüfung blockiert gerade - gleich nochmal versuchen,
                // statt den Versuch stillschweigend verfallen zu lassen.
                scheduleAutoRetry(index, url, attempt);
                return;
            }
            anyCheckRunning = true;
            setAllCheckButtonsDisabled(true);
            await checkOne(index, url, attempt);
            anyCheckRunning = false;
            setAllCheckButtonsDisabled(false);
        }, AUTO_RETRY_INTERVAL_MS);

        pendingRetries[index] = { timeoutId, intervalId };
    }

    function setAllCheckButtonsDisabled(disabled) {
        if (checkAllBtn) checkAllBtn.disabled = disabled || API_KEY_MISSING || links.length === 0;
        document.querySelectorAll('.check-btn').forEach((el) => {
            el.disabled = disabled || API_KEY_MISSING;
        });
    }

    // Ein Klick = ein VT-Aufruf (nach Einhalten des geteilten Zeitfensters,
    // Ein Klick = ein VT-Aufruf (nach Einhalten des geteilten Zeitfensters,
    // siehe waitForVtSlot). Kommt ein neuer Link als "Eingereicht" zurück,
    // übernimmt scheduleAutoRetry() das automatische, begrenzte Nachfragen.
    async function checkOne(index, url, retryAttempt = 0) {
        clearPendingRetry(index);
        await waitForVtSlot(index);
        setBadgePending(index);
        const report = await callApi('check_url', { url });
        renderResult(index, report);
        if (stepChecked) stepChecked.classList.add('step-done');
        if (report.status === 'submitted') {
            scheduleAutoRetry(index, url, retryAttempt + 1);
        }
        return report;
    }

    // Einzelner "Prüfen"-Button pro Link
    document.body.addEventListener('click', async (event) => {
        const btn = event.target.closest('.check-btn');
        if (btn && !anyCheckRunning) {
            anyCheckRunning = true;
            setAllCheckButtonsDisabled(true);
            await checkOne(Number(btn.dataset.index), btn.dataset.url);
            anyCheckRunning = false;
            setAllCheckButtonsDisabled(false);
        }

        const copyBtn = event.target.closest('.copy-btn');
        if (copyBtn) {
            const original = copyBtn.textContent;
            try {
                await navigator.clipboard.writeText(copyBtn.dataset.url);
                copyBtn.textContent = 'Kopiert!';
            } catch {
                copyBtn.textContent = 'Fehler';
            }
            setTimeout(() => { copyBtn.textContent = original; }, 1500);
        }
    });

    // "Alle Links kopieren"
    if (copyAllBtn) {
        copyAllBtn.addEventListener('click', async () => {
            const original = copyAllBtn.textContent;
            try {
                await navigator.clipboard.writeText(links.join('\n'));
                copyAllBtn.textContent = 'Kopiert!';
            } catch {
                copyAllBtn.textContent = 'Fehler';
            }
            setTimeout(() => { copyAllBtn.textContent = original; }, 1500);
        });
    }

    // "Alle Links mit VT prüfen" - Pausen/Wartezeit übernimmt zentral
    // waitForVtSlot() innerhalb von checkOne(), hier nur noch die Schleife.
    if (checkAllBtn) {
        checkAllBtn.addEventListener('click', async () => {
            if (API_KEY_MISSING || links.length === 0 || anyCheckRunning) return;

            anyCheckRunning = true;
            setAllCheckButtonsDisabled(true);
            checkAllBtn.textContent = 'Prüfung läuft …';
            if (progressBar) progressBar.classList.remove('hidden');

            let done = 0;
            for (let i = 0; i < links.length; i++) {
                await checkOne(i, links[i]);
                done++;
                const pct = Math.round((done / links.length) * 100);
                if (progressFill) progressFill.style.width = `${pct}%`;
                if (progressText) progressText.textContent = `${pct}% (${done}/${links.length})`;
            }

            anyCheckRunning = false;
            setAllCheckButtonsDisabled(false);
            checkAllBtn.textContent = 'Alle Links mit VirusTotal prüfen';
            setTimeout(() => { if (progressBar) progressBar.classList.add('hidden'); }, 2000);
        });
    }

    runSafeBrowsingCheck();
});

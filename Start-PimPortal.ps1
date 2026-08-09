<#
.SYNOPSIS
    Local web app for daily PIM role activation - browse eligible Azure resource
    roles across any tenant/subscription you belong to and bulk activate or
    deactivate them, instead of the Azure Portal's one-at-a-time "Activate" flow.

.DESCRIPTION
    Runs a tiny local web server (System.Net.HttpListener - no Node/npm needed,
    no Az module dependency either).

    Sign-in uses a plain OAuth2 Authorization Code + PKCE flow run from the
    page's own JavaScript, reusing "Microsoft Azure PowerShell" - the same
    well-known, already-consented public client ID Az PowerShell itself uses -
    so no app registration or new consent is needed. Because the page opens the
    sign-in tab itself (window.open), the tab can close itself once sign-in
    completes (a system-browser tab opened by an external process, like Az
    PowerShell's own sign-in, can never do this - browsers refuse to let a
    script close a tab it didn't open via window.open).

    All PIM/ARM calls go straight to the Azure Resource Manager REST API with
    this script's own token (Invoke-RestMethod), not through Az cmdlets -
    Az.Accounts' -AccessToken login mode turned out not to support the silent
    token refresh several Az.Resources cmdlets need internally, failing with
    "the access token is invalid" even for a freshly-minted, valid token.

.PARAMETER Port
    Local port to serve on. Default 8787.

.EXAMPLE
    .\Start-PimPortal.ps1
    # then browse to http://localhost:8787/
#>

[CmdletBinding()]
param(
    [int] $Port = 8787
)

Add-Type -AssemblyName System.Web

# Well-known, Microsoft-owned public client ID that Az PowerShell itself uses -
# already trusted/consented in every tenant Az PowerShell works in. Reusing it
# means no app registration or new consent is needed for this custom flow.
$script:ClientId = "1950a258-227b-4e31-a9cf-717495945fc2"
$script:ArmScope = "https://management.azure.com/user_impersonation openid profile offline_access"
$script:ArmApiVersion = "2020-10-01"

$script:Connected = $false
$script:AccountLabel = $null
$script:CurrentTenantId = $null
$script:MyPrincipalId = $null
$script:RefreshToken = $null

function Get-ArmToken {
    # Redeem our stored refresh_token (from the offline_access scope) for a
    # fresh access token right before every ARM call - cheap, always valid, and
    # also how tenant switching works with no popup: a multi-tenant app's
    # refresh token can be redeemed against any tenant the user has access to.
    param([string]$TenantId)
    $resp = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body @{
        client_id     = $script:ClientId
        grant_type    = "refresh_token"
        refresh_token = $script:RefreshToken
        scope         = $script:ArmScope
    } -ErrorAction Stop
    $script:RefreshToken = $resp.refresh_token
    $claims = Get-JwtClaims -Jwt $resp.access_token
    $script:CurrentTenantId = $TenantId
    $script:MyPrincipalId = $claims.oid
    $script:AccountLabel = @($claims.upn, $claims.preferred_username, $claims.unique_name, $claims.email, $claims.name, $claims.oid) |
        Where-Object { $_ } | Select-Object -First 1
    return $resp.access_token
}

function Invoke-Arm {
    # Talks to Azure Resource Manager directly - what Az.Resources cmdlets do
    # internally anyway - so this script never depends on the Az module at all.
    param([string]$Method = "GET", [string]$Path, $Body, [string]$TenantId = $script:CurrentTenantId)
    $token = Get-ArmToken -TenantId $TenantId
    $uri = "https://management.azure.com$Path"
    $headers = @{ Authorization = "Bearer $token" }
    if ($Body) {
        return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 10) -ErrorAction Stop
    }
    return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -ErrorAction Stop
}

function Get-ArmErrorMessage {
    param($ErrorRecord)
    if ($ErrorRecord.ErrorDetails.Message) { return $ErrorRecord.ErrorDetails.Message }
    return $ErrorRecord.Exception.Message
}

function Get-JwtClaims {
    param([string]$Jwt)
    $payload = $Jwt.Split('.')[1]
    $payload += "=" * ((4 - $payload.Length % 4) % 4)
    $json = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload.Replace('-','+').Replace('_','/')))
    return $json | ConvertFrom-Json
}

function Write-JsonResponse {
    param($Context, $Object, [int]$StatusCode = 200)
    $json = $Object | ConvertTo-Json -Depth 6
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $Context.Response.StatusCode = $StatusCode
    $Context.Response.ContentType = "application/json"
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.OutputStream.Close()
}

function Write-HtmlResponse {
    param($Context, [string]$Html)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Html)
    $Context.Response.ContentType = "text/html"
    $Context.Response.ContentLength64 = $bytes.Length
    $Context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
    $Context.Response.OutputStream.Close()
}

function Get-RequestBody {
    param($Context)
    $reader = New-Object System.IO.StreamReader($Context.Request.InputStream)
    $body = $reader.ReadToEnd()
    $reader.Close()
    if ([string]::IsNullOrWhiteSpace($body)) { return $null }
    return $body | ConvertFrom-Json
}

# ---------- HTML shell ----------
$IndexHtml = @'
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Bulk PIM Activator (Resources Only)</title>
<style>
  :root {
    --accent: #2563eb;
    --accent-dark: #1d4ed8;
    --bg: #f4f5f7;
    --panel: #ffffff;
    --border: #e5e7eb;
    --text: #1f2328;
    --text-secondary: #6b7280;
    --success-bg: #dcfce7;
    --success-fg: #15803d;
    --danger-bg: #fee2e2;
    --danger-fg: #b91c1c;
    --info-bg: #dbeafe;
    --info-fg: #1d4ed8;
    --warn-bg: #fef3c7;
    --warn-fg: #92400e;
  }
  * { box-sizing: border-box; }
  body {
    font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, Arial, sans-serif;
    margin: 0; min-height: 100vh; color: var(--text); font-size: 14px; background: var(--bg);
  }
  .topbar {
    background: var(--panel); border-bottom: 1px solid var(--border);
    color: var(--text); height: 56px; display: flex; align-items: center;
    padding: 0 22px; gap: 10px;
  }
  .topbar .brand-icon { font-size: 20px; }
  .topbar .brand { font-weight: 700; font-size: 16px; letter-spacing: .2px; color: var(--text); }
  .topbar .spacer { flex: 1; }
  .topbar .account {
    font-size: 12.5px; background: var(--bg); padding: 5px 12px; border-radius: 999px;
    display: none; align-items: center; gap: 7px; border: 1px solid var(--border);
  }
  .topbar .account .dot { width: 8px; height: 8px; border-radius: 50%; background: #16a34a; }
  main { max-width: 1160px; margin: 0 auto; padding: 28px 20px 60px; }
  .page-title { font-size: 22px; font-weight: 700; margin: 4px 0 20px; display: flex; align-items: baseline; gap: 12px; }
  .page-title .subtitle { font-size: 13px; font-weight: 400; color: var(--text-secondary); }
  .panel {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    box-shadow: 0 1px 2px rgba(0,0,0,.04);
    padding: 20px 22px; margin-bottom: 18px;
  }
  .panel h2 {
    font-size: 12.5px; font-weight: 700; text-transform: uppercase; letter-spacing: .6px;
    color: var(--text-secondary); margin: 0 0 14px;
  }
  .status-banner {
    padding: 10px 14px; border-radius: 8px; background: var(--warn-bg); color: var(--warn-fg);
    font-size: 13px; margin-bottom: 12px;
  }
  .status-banner.ok { background: var(--success-bg); color: var(--success-fg); }
  .btn {
    cursor: pointer; border: 1px solid var(--border); border-radius: 8px; padding: 0 18px; height: 36px;
    font-size: 13.5px; font-family: inherit; font-weight: 600; display: inline-flex; align-items: center; gap: 6px;
  }
  .btn:disabled { opacity: .5; cursor: not-allowed; }
  .btn-primary { background: var(--accent); color: #fff; border-color: var(--accent); }
  .btn-primary:hover:not(:disabled) { background: var(--accent-dark); border-color: var(--accent-dark); }
  .btn-secondary { background: var(--panel); color: var(--text); }
  .btn-secondary:hover:not(:disabled) { background: var(--bg); }
  .field-row { display: none; align-items: center; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
  .field-row:last-child { margin-bottom: 0; }
  .field-row label { font-size: 13px; color: var(--text-secondary); min-width: 90px; }
  select, input[type=text], input[type=number] {
    padding: 7px 12px; border: 1px solid var(--border); border-radius: 8px; font-size: 13.5px;
    font-family: inherit; background: var(--panel); color: var(--text); height: 34px;
  }
  select:focus, input:focus { outline: 2px solid rgba(37,99,235,.4); outline-offset: 1px; }
  select { min-width: 340px; }
  input[type=number] { width: 76px; }
  .command-bar {
    display: flex; align-items: center; gap: 4px; border-top: 1px solid var(--border);
    margin-top: 16px; padding-top: 12px; flex-wrap: wrap;
  }
  .cmd {
    cursor: pointer; background: transparent; border: none; color: var(--text); font-size: 13px;
    font-family: inherit; font-weight: 600; display: flex; align-items: center; gap: 6px;
    padding: 7px 12px; border-radius: 8px;
  }
  .cmd:hover:not(:disabled) { background: var(--bg); }
  .cmd:disabled { opacity: .4; cursor: not-allowed; }
  .cmd svg { width: 16px; height: 16px; flex-shrink: 0; }
  .cmd-activate svg { color: var(--success-fg); }
  .cmd-deactivate svg { color: var(--danger-fg); }
  .cmd-sep { width: 1px; align-self: stretch; background: var(--border); margin: 4px 6px; }
  table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
  thead th {
    text-align: left; padding: 12px 16px; font-weight: 700; color: var(--text-secondary);
    border-bottom: 1px solid var(--border); font-size: 12px; white-space: nowrap;
    text-transform: uppercase; letter-spacing: .4px;
  }
  tbody td { padding: 12px 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }
  tbody tr:hover { background: var(--bg); }
  tbody tr:has(input:checked) { background: #eff6ff; }
  tbody tr:last-child td { border-bottom: none; }
  .scope-cell { font-size: 11.5px; color: var(--text-secondary); font-family: Consolas, monospace; }
  input[type=checkbox] {
    width: 17px; height: 17px; cursor: pointer; accent-color: var(--accent); border-radius: 4px;
  }
  .badge {
    padding: 4px 12px; border-radius: 999px; font-size: 12px; display: inline-flex; align-items: center; gap: 5px;
    font-weight: 600;
  }
  .badge.done { background: var(--success-bg); color: var(--success-fg); }
  .badge.fail { background: var(--danger-bg); color: var(--danger-fg); cursor: help; }
  .badge.active { background: var(--info-bg); color: var(--info-fg); }
  .badge.busy { background: var(--warn-bg); color: var(--warn-fg); }
  .spinner {
    width: 11px; height: 11px; border: 2px solid rgba(146,64,14,.25); border-top-color: var(--warn-fg);
    border-radius: 50%; display: inline-block; animation: spin .7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  .statusbar { padding: 12px 22px; font-size: 12.5px; color: var(--text-secondary); border-top: 1px solid var(--border); }
  .empty-state { padding: 30px 20px; text-align: center; color: var(--text-secondary); font-size: 13.5px; }
</style>
</head>
<body>

<div class="topbar">
  <span class="brand-icon">&#9889;</span>
  <span class="brand">Bulk PIM Activator <span style="opacity:.6; font-weight:400; font-size:12.5px;">(Resources Only)</span></span>
  <span class="spacer"></span>
  <span class="account" id="topAccount"><span class="dot"></span><span id="topAccountLabel"></span></span>
</div>

<main>
  <div class="page-title">My eligible roles <span class="subtitle">Azure resources &middot; bulk activate/deactivate</span></div>

  <section class="panel">
    <div id="status" class="status-banner">Checking sign-in status...</div>
    <button class="btn btn-primary" id="loginBtn">Sign in</button>
  </section>

  <section class="panel">
    <h2>Scope</h2>
    <div class="field-row" id="tenantBar">
      <label>Directory</label>
      <select id="tenantSelect"></select>
      <button class="btn btn-secondary" id="useTenantBtn">Switch directory</button>
    </div>
    <div class="field-row" id="subBar">
      <label>Subscription</label>
      <select id="subscriptionSelect"></select>
      <button class="btn btn-secondary" id="useSubBtn">Load eligible roles</button>
    </div>
  </section>

  <section class="panel" id="controls" style="display:none">
    <h2>Activation settings</h2>
    <div class="field-row" style="display:flex">
      <label>Reason</label>
      <input type="text" id="justification" value="Routine daily access activation" style="min-width:340px">
      <label style="min-width:auto">Duration (hrs)</label>
      <input type="number" id="duration" value="8" min="1" max="24">
    </div>
    <div class="command-bar">
      <button class="cmd" id="refreshBtn">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9M13.5 2v3.2h-3.2"/></svg>
        Refresh
      </button>
      <span class="cmd-sep"></span>
      <button class="cmd" id="selectAllBtn">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="2.5" y="2.5" width="11" height="11" rx="1.5"/><path d="M5 8l2 2 4-4.5"/></svg>
        Select all
      </button>
      <button class="cmd" id="deselectAllBtn">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"><rect x="2.5" y="2.5" width="11" height="11" rx="1.5"/></svg>
        Deselect all
      </button>
      <span class="cmd-sep"></span>
      <button class="cmd cmd-activate" id="activateBtn">
        <svg viewBox="0 0 16 16" fill="currentColor"><path d="M4 2.5v11l10-5.5-10-5.5z"/></svg>
        Activate selected
      </button>
      <button class="cmd cmd-deactivate" id="deactivateBtn">
        <svg viewBox="0 0 16 16" fill="currentColor"><rect x="3.5" y="3.5" width="9" height="9" rx="1"/></svg>
        Deactivate selected
      </button>
    </div>
  </section>

  <section class="panel" style="padding:0; overflow-x:auto">
    <table id="roleTable" style="display:none">
      <thead><tr><th></th><th>Role</th><th>Resource</th><th>Scope</th><th>End time</th><th>Status</th></tr></thead>
      <tbody></tbody>
    </table>
    <div id="log" class="statusbar"></div>
  </section>
</main>

<script>
let roles = [];
const busy = () => document.querySelectorAll('.badge.busy').length > 0;

function setRowStatus(i, html) {
  const el = document.getElementById('st-' + i);
  if (el) el.innerHTML = html;
}
function badgeFor(role) {
  return role.alreadyActive ? '<span class="badge active">Already active</span>' : '';
}

// ---- PKCE OAuth helpers (runs in-page so the sign-in tab we open can close itself) ----
function b64url(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function randomString(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return b64url(arr.buffer);
}
async function sha256(str) {
  return await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
}

async function signInFlow(tenantId, statusMsg) {
  document.getElementById('status').textContent = statusMsg;
  // Open the tab synchronously in the click handler (blank first, redirected once
  // the URL is ready) so it's recognized as script-opened and can close itself later.
  const popup = window.open('about:blank', '_blank');
  const verifier = randomString(64);
  const challenge = b64url(await sha256(verifier));
  const state = randomString(16);
  const redirectUri = window.location.origin + '/';
  const authority = tenantId ? `https://login.microsoftonline.com/${tenantId}` : 'https://login.microsoftonline.com/organizations';
  const params = new URLSearchParams({
    client_id: '1950a258-227b-4e31-a9cf-717495945fc2',
    response_type: 'code',
    redirect_uri: redirectUri,
    response_mode: 'query',
    scope: 'https://management.azure.com/user_impersonation openid profile offline_access',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state
  });
  if (!popup) {
    document.getElementById('log').textContent = 'Popup blocked - please allow popups for this page and try again.';
    return false;
  }
  popup.location.href = authority + '/oauth2/v2.0/authorize?' + params;

  const result = await new Promise(resolve => {
    const timer = setTimeout(() => { cleanup(); resolve({ ok: false, error: 'Timed out waiting for sign-in.' }); }, 5 * 60 * 1000);
    function handler(ev) {
      if (ev.origin !== window.location.origin) return;
      if (!ev.data || ev.data.type !== 'oauth-callback' || ev.data.state !== state) return;
      cleanup();
      if (ev.data.error) resolve({ ok: false, error: ev.data.error_description || ev.data.error });
      else resolve({ ok: true, code: ev.data.code });
    }
    function cleanup() { clearTimeout(timer); window.removeEventListener('message', handler); }
    window.addEventListener('message', handler);
  });

  if (!result.ok) {
    document.getElementById('log').textContent = 'Sign-in failed: ' + result.error;
    return false;
  }

  document.getElementById('status').textContent = 'Finishing sign-in...';
  const r = await fetch('/api/oauth/exchange', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code: result.code, codeVerifier: verifier, redirectUri, tenantId })
  }).then(r => r.json());
  if (!r.ok) {
    document.getElementById('log').textContent = 'Sign-in failed: ' + r.error;
    return false;
  }
  return true;
}

async function refreshStatus() {
  const r = await fetch('/api/status').then(r => r.json());
  const el = document.getElementById('status');
  const topAccount = document.getElementById('topAccount');
  if (r.connected) {
    el.textContent = 'Signed in as ' + r.account;
    el.classList.add('ok');
    document.getElementById('loginBtn').textContent = 'Re-sign in';
    document.getElementById('tenantBar').style.display = 'flex';
    topAccount.style.display = 'inline-flex';
    document.getElementById('topAccountLabel').textContent = r.account;
    await loadTenants(r.tenantId);
  } else {
    el.textContent = 'Not signed in';
    el.classList.remove('ok');
    document.getElementById('tenantBar').style.display = 'none';
    document.getElementById('subBar').style.display = 'none';
    document.getElementById('controls').style.display = 'none';
    topAccount.style.display = 'none';
  }
}

async function loadTenants(currentTenantId) {
  const r = await fetch('/api/tenants').then(r => r.json());
  const sel = document.getElementById('tenantSelect');
  sel.innerHTML = '';
  (r.tenants || []).forEach(t => {
    const opt = document.createElement('option');
    opt.value = t.id;
    opt.textContent = (t.name || t.id) + ' (' + t.id + ')';
    if (t.id === currentTenantId) opt.selected = true;
    sel.appendChild(opt);
  });
  if (currentTenantId) await loadSubscriptions();
}

async function loadSubscriptions() {
  const r = await fetch('/api/subscriptions').then(r => r.json());
  const sel = document.getElementById('subscriptionSelect');
  sel.innerHTML = '';
  (r.subscriptions || []).forEach(s => {
    const opt = document.createElement('option');
    opt.value = s.id;
    opt.textContent = s.name + ' (' + s.id + ')';
    sel.appendChild(opt);
  });
  document.getElementById('subBar').style.display = 'flex';
  if (r.subscriptions && r.subscriptions.length) {
    document.getElementById('controls').style.display = 'flex';
    loadRoles();
  }
}

async function loadRoles() {
  document.getElementById('log').textContent = 'Loading eligible roles...';
  const subId = document.getElementById('subscriptionSelect').value;
  const r = await fetch('/api/roles?subscriptionId=' + subId).then(r => r.json());
  roles = r.roles || [];
  const tbody = document.querySelector('#roleTable tbody');
  tbody.innerHTML = '';
  roles.forEach((role, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td><input type="checkbox" class="rowchk" data-i="${i}" ${role.alreadyActive ? '' : 'checked'}></td>
      <td>${role.role}</td><td>${role.resourceName}</td><td class="scope-cell">${role.scope}</td>
      <td>${role.endTime || ''}</td><td id="st-${i}">${badgeFor(role)}</td>`;
    tbody.appendChild(tr);
  });
  document.getElementById('roleTable').style.display = roles.length ? 'table' : 'none';
  document.getElementById('log').textContent = roles.length ? `${roles.length} eligible role(s) found.` : 'No eligible roles found.';
}

document.getElementById('loginBtn').onclick = async () => {
  if (await signInFlow(null, 'Opening a sign-in tab...')) refreshStatus();
};
document.getElementById('useTenantBtn').onclick = async () => {
  const tenantId = document.getElementById('tenantSelect').value;
  if (!tenantId) return;
  document.getElementById('status').textContent = 'Switching to tenant ' + tenantId + '...';
  const r = await fetch('/api/tenant/select', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ tenantId })
  }).then(r => r.json());
  if (!r.ok) {
    document.getElementById('log').textContent = 'Tenant switch failed: ' + r.error;
  }
  refreshStatus();
};
document.getElementById('useSubBtn').onclick = loadRoles;

document.getElementById('refreshBtn').onclick = loadRoles;
document.getElementById('selectAllBtn').onclick = () => {
  document.querySelectorAll('.rowchk').forEach(c => c.checked = true);
};
document.getElementById('deselectAllBtn').onclick = () => {
  document.querySelectorAll('.rowchk').forEach(c => c.checked = false);
};

async function runBulkAction(endpoint, filterFn, verb) {
  if (busy()) return;
  const targets = [...document.querySelectorAll('.rowchk:checked')]
    .map(c => ({ i: Number(c.dataset.i), role: roles[c.dataset.i] }))
    .filter(x => filterFn(x.role));
  if (!targets.length) { alert('Nothing to ' + verb + ' in the current selection.'); return; }
  const justification = document.getElementById('justification').value;
  const duration = document.getElementById('duration').value;
  document.getElementById('log').textContent = verb.charAt(0).toUpperCase() + verb.slice(1) + 'ing ' + targets.length + ' role(s)...';

  let doneCount = 0;
  for (const t of targets) {
    setRowStatus(t.i, '<span class="badge busy"><span class="spinner"></span>' + verb.charAt(0).toUpperCase() + verb.slice(1) + 'ing...</span>');
    try {
      const r = await fetch(endpoint, {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ items: [t.role], justification, durationHours: duration })
      }).then(r => r.json());
      const res = (r.results || [])[0] || { ok: false, error: 'No response' };
      if (res.alreadyActive) {
        setRowStatus(t.i, '<span class="badge active">Already active</span>');
        t.role.alreadyActive = true;
      } else if (res.deactivated) {
        setRowStatus(t.i, '<span class="badge done">Deactivated</span>');
        t.role.alreadyActive = false;
      } else if (res.ok) {
        setRowStatus(t.i, '<span class="badge done">Activated</span>');
        t.role.alreadyActive = true;
      } else {
        setRowStatus(t.i, '<span class="badge fail" title="'+res.error+'">Failed</span>');
      }
    } catch (e) {
      setRowStatus(t.i, '<span class="badge fail" title="'+e+'">Failed</span>');
    }
    doneCount++;
    document.getElementById('log').textContent = `${doneCount}/${targets.length} ${verb}d.`;
  }
}

document.getElementById('activateBtn').onclick = () =>
  runBulkAction('/api/activate', role => !role.alreadyActive, 'activate');
document.getElementById('deactivateBtn').onclick = () =>
  runBulkAction('/api/deactivate', role => role.alreadyActive, 'deactivate');

refreshStatus();
</script>
</body>
</html>
'@

# Minimal page the OAuth redirect lands on. Since the sign-in tab was opened via
# window.open() by the main page's own script, it - unlike a system-browser tab -
# is allowed to close itself once it hands the code back via postMessage.
$CallbackHtmlTemplate = @'
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Signing in...</title></head>
<body style="font-family:Segoe UI,Arial,sans-serif;padding:2rem;">
<p id="msg">Completing sign-in...</p>
<script>
  const data = __DATA__;
  if (window.opener) {
    window.opener.postMessage(Object.assign({ type: 'oauth-callback' }, data), window.location.origin);
    window.close();
  }
  document.getElementById('msg').textContent = data.error
    ? 'Sign-in failed: ' + (data.error_description || data.error) + '. You can close this window.'
    : 'Sign-in complete. You can close this window.';
</script>
</body></html>
'@

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
$listener.Start()
Write-Host "PIM Role Activator running at http://localhost:$Port/ (Ctrl+C to stop)" -ForegroundColor Cyan
Start-Process "http://localhost:$Port/"

try {
    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $req = $context.Request
        $path = $req.Url.AbsolutePath
        $query = [System.Web.HttpUtility]::ParseQueryString($req.Url.Query)

        try {
            if ($path -eq "/" -and $req.HttpMethod -eq "GET" -and ($query["code"] -or $query["error"])) {
                # OAuth redirect landed here (redirect_uri is the site root) - serve the
                # self-closing callback page instead of the main app.
                $data = @{
                    code             = $query["code"]
                    state            = $query["state"]
                    error            = $query["error"]
                    error_description = $query["error_description"]
                }
                $html = $CallbackHtmlTemplate.Replace("__DATA__", ($data | ConvertTo-Json -Compress))
                Write-HtmlResponse -Context $context -Html $html
            }
            elseif ($path -eq "/" -and $req.HttpMethod -eq "GET") {
                Write-HtmlResponse -Context $context -Html $IndexHtml
            }
            elseif ($path -eq "/api/status" -and $req.HttpMethod -eq "GET") {
                Write-JsonResponse -Context $context -Object @{ connected = $script:Connected; account = $script:AccountLabel; tenantId = $script:CurrentTenantId }
            }
            elseif ($path -eq "/api/oauth/exchange" -and $req.HttpMethod -eq "POST") {
                $body = Get-RequestBody -Context $context
                $authority = if ($body.tenantId) { "https://login.microsoftonline.com/$($body.tenantId)" } else { "https://login.microsoftonline.com/organizations" }
                try {
                    $tokenResp = Invoke-RestMethod -Method Post -Uri "$authority/oauth2/v2.0/token" -ContentType "application/x-www-form-urlencoded" -Body @{
                        client_id     = $script:ClientId
                        grant_type    = "authorization_code"
                        code          = $body.code
                        redirect_uri  = $body.redirectUri
                        code_verifier = $body.codeVerifier
                        scope         = $script:ArmScope
                    } -ErrorAction Stop

                    $claims = Get-JwtClaims -Jwt $tokenResp.access_token
                    $accountId = @($claims.upn, $claims.preferred_username, $claims.unique_name, $claims.email, $claims.name, $claims.oid) |
                        Where-Object { $_ } | Select-Object -First 1

                    $script:Connected = $true
                    $script:AccountLabel = $accountId
                    $script:CurrentTenantId = $claims.tid
                    $script:MyPrincipalId = $claims.oid
                    $script:RefreshToken = $tokenResp.refresh_token
                    Write-JsonResponse -Context $context -Object @{ ok = $true; account = $accountId; tenantId = $claims.tid }
                } catch {
                    $msg = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
                    Write-JsonResponse -Context $context -Object @{ ok = $false; error = $msg }
                }
            }
            elseif ($path -eq "/api/tenant/select" -and $req.HttpMethod -eq "POST") {
                # Silent tenant switch - no popup needed. A multi-tenant app's refresh
                # token can be redeemed against any tenant the user has access to.
                $body = Get-RequestBody -Context $context
                try {
                    Get-ArmToken -TenantId $body.tenantId | Out-Null
                    Write-JsonResponse -Context $context -Object @{ ok = $true; tenantId = $script:CurrentTenantId }
                } catch {
                    Write-JsonResponse -Context $context -Object @{ ok = $false; error = (Get-ArmErrorMessage $_) }
                }
            }
            elseif ($path -eq "/api/tenants" -and $req.HttpMethod -eq "GET") {
                if (-not $script:Connected) {
                    Write-JsonResponse -Context $context -Object @{ tenants = @() }
                } else {
                    $resp = Invoke-Arm -Path "/tenants?api-version=2020-01-01"
                    $tenants = $resp.value | ForEach-Object { @{ id = $_.tenantId; name = $_.displayName } }
                    Write-JsonResponse -Context $context -Object @{ tenants = @($tenants) }
                }
            }
            elseif ($path -eq "/api/subscriptions" -and $req.HttpMethod -eq "GET") {
                if (-not $script:Connected) {
                    Write-JsonResponse -Context $context -Object @{ subscriptions = @() }
                } else {
                    $resp = Invoke-Arm -Path "/subscriptions?api-version=2020-01-01"
                    $subs = $resp.value | ForEach-Object { @{ id = $_.subscriptionId; name = $_.displayName } }
                    Write-JsonResponse -Context $context -Object @{ subscriptions = @($subs) }
                }
            }
            elseif ($path -eq "/api/roles" -and $req.HttpMethod -eq "GET" -and -not $script:Connected) {
                Write-JsonResponse -Context $context -Object @{ roles = @() }
            }
            elseif ($path -eq "/api/roles" -and $req.HttpMethod -eq "GET") {
                $subscriptionId = $query["subscriptionId"]
                # Querying scoped to a subscription ("/subscriptions/{id}/providers/...")
                # returns nothing even for eligibility at resource groups underneath it -
                # asTarget() only traverses properly from the tenant root. So always query
                # at root and filter by subscription client-side instead.
                $eligibleResp = Invoke-Arm -Path "/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=$script:ArmApiVersion&`$filter=asTarget()"
                $eligible = $eligibleResp.value | Where-Object { $_.properties.status -eq "Provisioned" }
                if ($subscriptionId) {
                    $eligible = $eligible | Where-Object { $_.properties.scope -like "/subscriptions/$subscriptionId*" }
                }

                $activeResp = Invoke-Arm -Path "/providers/Microsoft.Authorization/roleAssignmentScheduleInstances?api-version=$script:ArmApiVersion&`$filter=asTarget()"
                $active = @{}
                $activeResp.value | Where-Object { $_.properties.status -eq "Provisioned" } |
                    ForEach-Object { $active["$($_.properties.scope)|$($_.properties.roleDefinitionId)"] = $true }

                $roles = @($eligible | ForEach-Object {
                    $p = $_.properties
                    @{
                        role             = $p.expandedProperties.roleDefinition.displayName
                        resourceName     = ($p.scope -split "/")[-1]
                        scope            = $p.scope
                        endTime          = $p.endDateTime
                        roleDefinitionId = $p.roleDefinitionId
                        eligibilityName  = $p.roleEligibilityScheduleId
                        alreadyActive    = [bool]$active.ContainsKey("$($p.scope)|$($p.roleDefinitionId)")
                    }
                })
                Write-JsonResponse -Context $context -Object @{ roles = $roles }
            }
            elseif ($path -eq "/api/activate" -and $req.HttpMethod -eq "POST") {
                $body = Get-RequestBody -Context $context
                $results = @()
                foreach ($item in $body.items) {
                    $requestName = [guid]::NewGuid().ToString()
                    try {
                        Invoke-Arm -Method PUT -Path "$($item.scope)/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/$requestName`?api-version=$script:ArmApiVersion" -Body @{
                            properties = @{
                                principalId      = $script:MyPrincipalId
                                roleDefinitionId = $item.roleDefinitionId
                                requestType      = "SelfActivate"
                                linkedRoleEligibilityScheduleId = $item.eligibilityName
                                justification    = $body.justification
                                scheduleInfo = @{
                                    startDateTime = (Get-Date).ToUniversalTime().ToString("o")
                                    expiration    = @{ type = "AfterDuration"; duration = "PT$($body.durationHours)H" }
                                }
                            }
                        } | Out-Null
                        $results += @{ ok = $true; scope = $item.scope; role = $item.role }
                    } catch {
                        $msg = Get-ArmErrorMessage $_
                        if ($msg -like "*RoleAssignmentExists*" -or $msg -like "*already exists*") {
                            $results += @{ ok = $true; alreadyActive = $true; scope = $item.scope; role = $item.role }
                        } else {
                            $results += @{ ok = $false; scope = $item.scope; role = $item.role; error = $msg }
                        }
                    }
                }
                Write-JsonResponse -Context $context -Object @{ results = @($results) }
            }
            elseif ($path -eq "/api/deactivate" -and $req.HttpMethod -eq "POST") {
                $body = Get-RequestBody -Context $context
                $results = @()
                foreach ($item in $body.items) {
                    $requestName = [guid]::NewGuid().ToString()
                    try {
                        Invoke-Arm -Method PUT -Path "$($item.scope)/providers/Microsoft.Authorization/roleAssignmentScheduleRequests/$requestName`?api-version=$script:ArmApiVersion" -Body @{
                            properties = @{
                                principalId      = $script:MyPrincipalId
                                roleDefinitionId = $item.roleDefinitionId
                                requestType      = "SelfDeactivate"
                                justification    = $body.justification
                            }
                        } | Out-Null
                        $results += @{ ok = $true; deactivated = $true; scope = $item.scope; role = $item.role }
                    } catch {
                        $results += @{ ok = $false; scope = $item.scope; role = $item.role; error = (Get-ArmErrorMessage $_) }
                    }
                }
                Write-JsonResponse -Context $context -Object @{ results = @($results) }
            }
            else {
                $context.Response.StatusCode = 404
                $context.Response.OutputStream.Close()
            }
        } catch {
            Write-JsonResponse -Context $context -Object @{ error = $_.Exception.Message } -StatusCode 500
        }
    }
} finally {
    $listener.Stop()
    $listener.Close()
}

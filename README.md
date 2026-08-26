# Bulk PIM Activator (Resources Only)

A tiny local web app for activating (or deactivating) multiple Azure PIM
(Privileged Identity Management) **resource role** assignments at once,
instead of clicking "Activate" one row at a time in the Azure Portal.

## What it does

- You sign in with your **own** Azure AD account — no shared credentials, no
  service principal, no app registration.
- Pick your directory (tenant) and subscription.
- See every Azure resource role you're currently eligible to activate via
  PIM (Contributor, Owner, etc. on management groups / subscriptions /
  resource groups / resources).
- Select some or all of them and **activate or deactivate in bulk**, with
  live per-row progress.
- Runs entirely on your own machine as a local web server — nothing is
  hosted centrally, and no data leaves your laptop besides normal calls to
  Microsoft's own sign-in and Azure Resource Manager endpoints.

## Requirements

- Windows with PowerShell 5.1+ (built into Windows 10/11 — nothing to
  install)
- Your own Azure AD account with PIM-eligible resource role assignments

## How to run

1. Clone this repo (or download it as a ZIP and extract it):
   ```bash
   git clone https://github.com/aatef14/azure-pim-bulk-activation.git
   ```
2. Open PowerShell in the folder:
   ```powershell
   cd azure-pim-bulk-activation
   ```
3. Run:
   ```powershell
   .\Start-PimPortal.ps1
   ```
4. Your browser opens automatically at `http://localhost:8787` (if not,
   open it manually).
5. Click **Sign in** and complete the Microsoft login in the tab that
   opens — it closes itself automatically once you're done.
6. Pick your **Directory** (tenant) → click **Switch directory**.
7. Pick your **Subscription** → click **Load eligible roles**.
8. Check the roles you want, adjust **Reason** / **Duration** if needed,
   then click **Activate selected** (or **Deactivate selected**).

Running on a different port (if 8787 is already in use):
```powershell
.\Start-PimPortal.ps1 -Port 9000
```

## How sign-in works (security notes)

- Uses a standard OAuth2 Authorization Code + PKCE flow against Microsoft's
  own login page, reusing the same well-known, already-trusted
  **"Microsoft Azure PowerShell"** client ID that the official Az
  PowerShell module itself uses. No app registration and no new admin
  consent are required.
- Every teammate signs in with **their own** account — the tool never
  stores, shares, or transmits credentials anywhere, and every activation
  request uses the signed-in user's own identity, exactly like clicking
  Activate in the Portal would.
- The web server binds to `localhost` only — it's not reachable from the
  network, and there's nothing to deploy or host.
- Scoped to **Azure resource roles only**. PIM for Groups and Microsoft
  Entra directory roles are intentionally not supported, since those
  require a separate, high-privilege Microsoft Graph permission that most
  tenants restrict to admin consent.

## Troubleshooting

- **Popup blocked**: allow popups for `localhost` in your browser and
  click Sign in again.
- **Sign-in tab doesn't close / nothing happens after signing in**: close
  the tab manually and click Sign in again.
- **"No eligible roles found"**: double check you picked the right
  Directory and Subscription — PIM eligibility is scoped per
  subscription/resource group.
- Stop the app any time with `Ctrl+C` in the PowerShell window, or just
  close the window.

## Optional: using it via Claude Code (MCP)

If your team uses Claude Code, `pim_mcp_server.py` wraps this app as an MCP
server so you can just ask Claude to activate your roles instead of clicking
through the browser.

Requirements: Python 3.10+, with `mcp` and `requests` installed
(`pip install mcp requests`).

1. Add a `.mcp.json` in the project you're working from (already included in
   this repo if you're running Claude Code from here):
   ```json
   {
     "mcpServers": {
       "bulk-pim-activator": {
         "command": "python",
         "args": ["pim_mcp_server.py"],
         "cwd": "."
       }
     }
   }
   ```
2. Restart Claude Code and approve the `bulk-pim-activator` server when
   prompted.
3. Ask Claude something like "activate my PIM roles" — it will sign you in,
   list your tenants/subscriptions, ask which to target, and activate
   whichever roles you pick.

The MCP server just calls the same local web app under the hood
(`Start-PimPortal.ps1`, auto-started if not already running), so the same
security notes above apply.

## Sharing this with your team

Anyone with access to this repo can clone it and run
`.\Start-PimPortal.ps1` — no setup, install, or configuration needed.
Each person signs in with their own account and only ever sees and
activates their **own** eligible roles.

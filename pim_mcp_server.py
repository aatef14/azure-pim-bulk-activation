"""
MCP server wrapping the Bulk PIM Activator (Start-PimPortal.ps1) local web app.

Exposes tenant/subscription/role listing and bulk activate/deactivate as MCP
tools so an agent can drive PIM activation directly - listing tenants and
subscriptions, asking the user which to target, then activating roles there -
instead of the user doing it by hand in the browser.

Sign-in itself still has to happen in a real browser (it's a genuine Azure AD
login), so `sign_in` just makes sure the local portal is running and opens it;
the tools that need an authenticated session will say so if you're not signed
in yet.
"""

import json
import os
import socket
import subprocess
import time
import webbrowser

import requests
from mcp.server.mcpserver import MCPServer

PORT = 8787
BASE_URL = f"http://localhost:{PORT}"
SCRIPT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Start-PimPortal.ps1")

server = MCPServer(name="bulk-pim-activator")

# Cache of the last role listing per subscription, so activate/deactivate can
# look up the full role record (scope, roleDefinitionId, eligibilityName) from
# just a scope string without the caller having to pass everything back.
_role_cache: dict[str, list[dict]] = {}


def _port_open() -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", PORT)) == 0


def _ensure_portal_running() -> None:
    if _port_open():
        return
    subprocess.Popen(
        [
            "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", SCRIPT_PATH,
        ],
        creationflags=subprocess.CREATE_NO_WINDOW,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(20):
        if _port_open():
            return
        time.sleep(0.5)
    raise RuntimeError("Portal did not start listening on port " + str(PORT))


@server.tool()
def sign_in() -> str:
    """Make sure the local PIM portal is running and open it in the browser
    so the user can sign in. Sign-in is a real Azure AD login and has to
    happen in a browser - this tool cannot complete it on its own. After the
    user confirms they've signed in, call get_status to verify."""
    _ensure_portal_running()
    webbrowser.open(BASE_URL)
    return (
        f"Opened {BASE_URL} in your browser. Click Sign in there and complete "
        "the Microsoft login (the tab closes itself when done). Once you "
        "confirm you're signed in, call get_status to verify."
    )


@server.tool()
def get_status() -> dict:
    """Check whether the user is currently signed in, and if so, as whom and
    in which tenant (directory)."""
    _ensure_portal_running()
    return requests.get(f"{BASE_URL}/api/status", timeout=10).json()


@server.tool()
def list_tenants() -> list[dict]:
    """List every Azure AD tenant (directory) the signed-in user can access.
    Each entry has 'id' and 'name'. Requires the user to already be signed in
    (call sign_in first if get_status shows connected=false)."""
    _ensure_portal_running()
    return requests.get(f"{BASE_URL}/api/tenants", timeout=15).json().get("tenants", [])


@server.tool()
def select_tenant(tenant_id: str) -> dict:
    """Switch the active directory (tenant) to the given tenant ID. This is
    silent (no browser popup) - it reuses the existing sign-in. Call this
    before list_subscriptions/list_roles for a tenant other than the one the
    user first signed into."""
    _ensure_portal_running()
    resp = requests.post(
        f"{BASE_URL}/api/tenant/select",
        json={"tenantId": tenant_id},
        timeout=15,
    )
    return resp.json()


@server.tool()
def list_subscriptions() -> list[dict]:
    """List every subscription in the currently-selected tenant. Each entry
    has 'id' and 'name'. Call select_tenant first if you need a different
    tenant than the one currently active (check with get_status)."""
    _ensure_portal_running()
    return requests.get(f"{BASE_URL}/api/subscriptions", timeout=15).json().get("subscriptions", [])


@server.tool()
def list_roles(subscription_id: str) -> list[dict]:
    """List every Azure resource role the user is currently PIM-eligible for
    within the given subscription (across all its resource groups/resources).
    Each entry has: role, resourceName, scope, endTime, alreadyActive. Use the
    'scope' values with activate_roles/deactivate_roles."""
    _ensure_portal_running()
    roles = requests.get(
        f"{BASE_URL}/api/roles", params={"subscriptionId": subscription_id}, timeout=30
    ).json().get("roles", [])
    _role_cache[subscription_id] = roles
    return roles


def _resolve_roles(subscription_id: str, scopes: list[str] | None) -> list[dict]:
    if subscription_id not in _role_cache:
        list_roles(subscription_id)
    cached = _role_cache.get(subscription_id, [])
    if not scopes:
        return cached
    wanted = set(scopes)
    return [r for r in cached if r["scope"] in wanted]


@server.tool()
def activate_roles(
    subscription_id: str,
    scopes: list[str] | None = None,
    justification: str = "Routine daily access activation",
    duration_hours: int = 8,
) -> dict:
    """Activate PIM-eligible roles in the given subscription. Pass 'scopes'
    as a list of the 'scope' values from list_roles to activate specific
    ones, or omit/pass null to activate ALL currently-eligible, not-yet-active
    roles in that subscription. Returns per-role results (ok/alreadyActive/
    error)."""
    _ensure_portal_running()
    items = [r for r in _resolve_roles(subscription_id, scopes) if not r.get("alreadyActive")]
    if not items:
        return {"results": [], "message": "Nothing to activate - all matching roles are already active."}
    resp = requests.post(
        f"{BASE_URL}/api/activate",
        json={"items": items, "justification": justification, "durationHours": duration_hours},
        timeout=60,
    )
    return resp.json()


@server.tool()
def deactivate_roles(
    subscription_id: str,
    scopes: list[str] | None = None,
    justification: str = "Routine deactivation",
) -> dict:
    """Deactivate active PIM role assignments in the given subscription. Pass
    'scopes' as a list of the 'scope' values from list_roles to deactivate
    specific ones, or omit/pass null to deactivate ALL currently-active roles
    in that subscription. Returns per-role results (ok/error)."""
    _ensure_portal_running()
    items = [r for r in _resolve_roles(subscription_id, scopes) if r.get("alreadyActive")]
    if not items:
        return {"results": [], "message": "Nothing to deactivate - no matching roles are currently active."}
    resp = requests.post(
        f"{BASE_URL}/api/deactivate",
        json={"items": items, "justification": justification},
        timeout=60,
    )
    return resp.json()


@server.tool()
def list_presets() -> list[dict]:
    """List saved presets (name, tenantId, subscriptionId, filter). A preset
    bundles a tenant + subscription + optional resource-name filter so you
    don't have to re-specify scope every time."""
    _ensure_portal_running()
    return requests.get(f"{BASE_URL}/api/presets", timeout=10).json().get("presets", [])


@server.tool()
def save_preset(name: str, tenant_id: str, subscription_id: str, filter: str = "") -> dict:
    """Save (or overwrite) a preset with the given name, tenant, subscription,
    and an optional case-insensitive substring filter on resource group name
    (e.g. 'api-portal' to only match resource groups containing that text;
    leave blank to match every eligible role in that subscription)."""
    _ensure_portal_running()
    resp = requests.post(
        f"{BASE_URL}/api/presets",
        json={"name": name, "tenantId": tenant_id, "subscriptionId": subscription_id, "filter": filter},
        timeout=10,
    )
    return resp.json()


@server.tool()
def run_preset(
    name: str,
    justification: str = "Routine daily access activation",
    duration_hours: int = 8,
) -> dict:
    """Activate every not-yet-active eligible role matching a saved preset in
    one call (resolves tenant/subscription/filter itself - no need to call
    select_tenant/list_roles first). Returns per-role results."""
    _ensure_portal_running()
    resp = requests.post(
        f"{BASE_URL}/api/presets/run",
        json={"name": name, "justification": justification, "durationHours": duration_hours},
        timeout=60,
    )
    return resp.json()


@server.tool()
def schedule_preset(name: str, time: str = "08:00") -> dict:
    """Register a Windows scheduled task that runs the named preset
    automatically every day at the given time (HH:mm, 24h), with no browser
    or user interaction - requires save_session_for_scheduling to have been
    called at least once so a saved sign-in exists for it to use."""
    _ensure_portal_running()
    resp = requests.post(
        f"{BASE_URL}/api/schedule/install",
        json={"name": name, "time": time},
        timeout=15,
    )
    return resp.json()


@server.tool()
def save_session_for_scheduling() -> dict:
    """Encrypt and save the current sign-in (Windows DPAPI - only this
    Windows account on this machine can decrypt it) so scheduled/headless
    preset runs can authenticate without a browser. Requires being signed in
    already (check get_status first)."""
    _ensure_portal_running()
    resp = requests.post(f"{BASE_URL}/api/session/save", timeout=10)
    return resp.json()


if __name__ == "__main__":
    server.run()

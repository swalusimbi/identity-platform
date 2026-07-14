const state = {
  clients: [],
  users: [],
  roles: [],
  permissions: [],
  apiKeys: [],
  serviceAccounts: [],
  audit: [],
  settings: {
    apiBase: window.location.origin,
    adminKey: "",
    tenantAuth: "",
    authScheme: "Bearer",
  },
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));
const settingsKey = "identityAdminSettings";

function readStoredSettings(storage) {
  try {
    return JSON.parse(storage.getItem(settingsKey) || "{}");
  } catch {
    return {};
  }
}

function loadSettings() {
  const legacy = readStoredSettings(localStorage);
  const saved = readStoredSettings(sessionStorage);
  localStorage.removeItem(settingsKey);

  state.settings = {
    ...state.settings,
    apiBase: saved.apiBase || legacy.apiBase || state.settings.apiBase,
    adminKey: saved.adminKey || "",
    tenantAuth: saved.tenantAuth || "",
    authScheme: saved.authScheme || legacy.authScheme || state.settings.authScheme,
  };
  $("#apiBase").value = state.settings.apiBase;
  $("#adminKey").value = state.settings.adminKey;
  $("#tenantAuth").value = state.settings.tenantAuth;
  $("#authScheme").value = state.settings.authScheme;
  updateStatus();
}

function saveSettings() {
  state.settings = {
    apiBase: $("#apiBase").value.replace(/\/$/, "") || window.location.origin,
    adminKey: $("#adminKey").value,
    tenantAuth: $("#tenantAuth").value,
    authScheme: $("#authScheme").value,
  };
  sessionStorage.setItem(settingsKey, JSON.stringify(state.settings));
  updateStatus();
  showNotice("Settings saved", "ok");
}

function clearCredentials() {
  state.settings.adminKey = "";
  state.settings.tenantAuth = "";
  $("#adminKey").value = "";
  $("#tenantAuth").value = "";
  sessionStorage.setItem(settingsKey, JSON.stringify(state.settings));
  clearSecret();
  updateStatus();
  showNotice("Credentials cleared", "ok");
}

function updateStatus() {
  const hasTenant = Boolean(state.settings.tenantAuth);
  const hasOperator = Boolean(state.settings.adminKey);
  $("#statusText").textContent = hasTenant || hasOperator ? "Connected" : "Disconnected";
}

function showNotice(message, tone = "ok") {
  const notice = $("#notice");
  notice.textContent = message;
  notice.className = `notice ${tone}`;
  notice.hidden = false;
  window.clearTimeout(showNotice.timer);
  showNotice.timer = window.setTimeout(() => {
    notice.hidden = true;
  }, 5000);
}

function showSecret(label, payload) {
  const box = $("#secretOutput");
  box.hidden = false;
  box.innerHTML = `<strong>${escapeHtml(label)}</strong><pre>${escapeHtml(
    JSON.stringify(payload, null, 2)
  )}</pre>`;
}

function clearSecret() {
  $("#secretOutput").hidden = true;
  $("#secretOutput").innerHTML = "";
}

async function request(path, options = {}) {
  const headers = {
    Accept: "application/json",
    ...(options.body ? { "Content-Type": "application/json" } : {}),
    ...(options.headers || {}),
  };

  const response = await fetch(`${state.settings.apiBase}${path}`, {
    ...options,
    headers,
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;

  if (!response.ok) {
    const message = data?.error || data?.message || `HTTP ${response.status}`;
    throw new Error(message);
  }

  return data;
}

function adminHeaders() {
  return { "X-Admin-Key": state.settings.adminKey };
}

function tenantHeaders() {
  return {
    Authorization: `${state.settings.authScheme} ${state.settings.tenantAuth}`,
  };
}

function jsonBody(value) {
  return JSON.stringify(value);
}

function csv(value) {
  return String(value || "")
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function selectedValues(containerSelector) {
  return $$(`${containerSelector} input[type="checkbox"]:checked`).map(
    (input) => input.value
  );
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function fmtDate(value) {
  if (!value) return "";
  return new Date(value).toLocaleString();
}

function pill(value, tone = "") {
  return `<span class="pill ${tone}">${escapeHtml(value)}</span>`;
}

function permissionLabel(permission) {
  return `${permission.resource}:${permission.action}`;
}

function roleName(roleId) {
  return state.roles.find((role) => role.id === roleId)?.name || roleId;
}

function setView(view) {
  $$(".nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === view);
  });
  $$(".view").forEach((section) => {
    section.classList.toggle("active", section.id === `view-${view}`);
  });
}

async function loadClients() {
  state.clients = await request("/clients", { headers: adminHeaders() });
  renderClients();
  showNotice("Clients loaded", "ok");
}

function renderClients() {
  $("#clientsBody").innerHTML = state.clients
    .map(
      (client) => `
        <tr>
          <td>${escapeHtml(client.name)}</td>
          <td><code>${escapeHtml(client.clientId)}</code></td>
          <td>${client.isActive ? pill("active", "ok") : pill("inactive", "warn")}</td>
          <td class="actions">
            <button data-action="toggleClient" data-id="${client.id}" data-active="${client.isActive}">
              ${client.isActive ? "Deactivate" : "Reactivate"}
            </button>
            <button data-action="rotateClient" data-id="${client.id}">Rotate</button>
            <button data-action="bootstrapClient" data-id="${client.id}">Bootstrap</button>
          </td>
        </tr>
      `
    )
    .join("");
}

async function loadRolesAndPermissions() {
  const [roles, permissions] = await Promise.all([
    request("/roles", { headers: tenantHeaders() }),
    request("/roles/permissions", { headers: tenantHeaders() }),
  ]);
  state.roles = roles;
  state.permissions = permissions;
  renderRoles();
  renderRoleChoices();
}

function renderRoles() {
  $("#rolesBody").innerHTML = state.roles
    .map((role) => {
      const permissions = (role.permissions || [])
        .map((permission) => pill(permissionLabel(permission)))
        .join("");
      return `
        <tr>
          <td>${escapeHtml(role.name)}</td>
          <td>${role.isDefault ? pill("default", "ok") : ""}</td>
          <td>${permissions}</td>
        </tr>
      `;
    })
    .join("");
  $("#metricRoles").textContent = state.roles.length;
}

function renderRoleChoices() {
  const permissionChoices = state.permissions
    .map(
      (permission) => `
        <label>
          <input type="checkbox" value="${permission.id}" />
          ${escapeHtml(permissionLabel(permission))}
        </label>
      `
    )
    .join("");

  const roleChoices = state.roles
    .map(
      (role) => `
        <label>
          <input type="checkbox" value="${role.id}" />
          ${escapeHtml(role.name)}
        </label>
      `
    )
    .join("");

  $("#rolePermissionChoices").innerHTML = permissionChoices;
  $("#userRoleChoices").innerHTML = roleChoices;
  $("#serviceAccountRoleChoices").innerHTML = roleChoices;
}

async function loadUsers() {
  state.users = await request("/users", { headers: tenantHeaders() });
  renderUsers();
}

function renderUsers() {
  $("#usersBody").innerHTML = state.users
    .map(
      (user) => `
        <tr>
          <td>${escapeHtml(user.email)}</td>
          <td>${user.emailVerified ? pill("yes", "ok") : pill("no", "warn")}</td>
          <td>${user.isActive ? pill("active", "ok") : pill("inactive", "warn")}</td>
          <td class="actions">
            <button data-action="toggleUser" data-id="${user.id}" data-active="${user.isActive}">
              ${user.isActive ? "Deactivate" : "Reactivate"}
            </button>
          </td>
        </tr>
      `
    )
    .join("");
  $("#metricUsers").textContent = state.users.length;
}

async function loadApiKeys() {
  state.apiKeys = await request("/api-keys", { headers: tenantHeaders() });
  renderApiKeys();
}

function renderApiKeys() {
  $("#apiKeysBody").innerHTML = state.apiKeys
    .map(
      (key) => `
        <tr>
          <td>${escapeHtml(key.name)}</td>
          <td><code>${escapeHtml(key.keyPrefix)}</code></td>
          <td>${(key.scopes || []).map((scope) => pill(scope)).join("")}</td>
          <td>${key.revoked ? pill("yes", "warn") : pill("no", "ok")}</td>
          <td class="actions">
            ${
              key.revoked
                ? ""
                : `<button data-action="revokeApiKey" data-id="${key.id}" class="danger">Revoke</button>`
            }
          </td>
        </tr>
      `
    )
    .join("");
  $("#metricKeys").textContent = state.apiKeys.length;
}

async function loadServiceAccounts() {
  state.serviceAccounts = await request("/service-accounts", {
    headers: tenantHeaders(),
  });
  renderServiceAccounts();
}

function renderServiceAccounts() {
  $("#serviceAccountsBody").innerHTML = state.serviceAccounts
    .map(
      (account) => `
        <tr>
          <td>${escapeHtml(account.name)}</td>
          <td>${account.isActive ? pill("active", "ok") : pill("inactive", "warn")}</td>
          <td>${(account.roleIds || []).map((roleId) => pill(roleName(roleId))).join("")}</td>
          <td class="actions">
            <button data-action="toggleServiceAccount" data-id="${account.id}" data-active="${account.isActive}">
              ${account.isActive ? "Deactivate" : "Reactivate"}
            </button>
            <button data-action="createServiceAccountKey" data-id="${account.id}">Create key</button>
          </td>
        </tr>
      `
    )
    .join("");
  $("#metricServiceAccounts").textContent = state.serviceAccounts.length;
}

async function loadAudit(params = {}) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value) query.set(key, value);
  });
  const suffix = query.toString() ? `?${query.toString()}` : "";
  const page = await request(`/audit${suffix}`, { headers: tenantHeaders() });
  state.audit = page.entries || [];
  renderAudit();
}

function renderAudit() {
  $("#auditBody").innerHTML = state.audit
    .map(
      (event) => `
        <tr>
          <td>${escapeHtml(fmtDate(event.createdAt))}</td>
          <td>${escapeHtml(event.action)}</td>
          <td>${escapeHtml(event.actorType)} ${event.actorId ? `<code>${escapeHtml(event.actorId)}</code>` : ""}</td>
          <td>${escapeHtml(event.targetType || "")} ${event.targetId ? `<code>${escapeHtml(event.targetId)}</code>` : ""}</td>
          <td><code>${escapeHtml(JSON.stringify(event.details || {}))}</code></td>
        </tr>
      `
    )
    .join("");
}

async function loadTenantOverview() {
  await Promise.allSettled([
    loadRolesAndPermissions(),
    loadUsers(),
    loadApiKeys(),
    loadServiceAccounts(),
  ]);
}

async function handleSubmit(event, handler) {
  event.preventDefault();
  clearSecret();
  try {
    await handler(new FormData(event.currentTarget), event.currentTarget);
    event.currentTarget.reset();
    showNotice("Saved", "ok");
  } catch (error) {
    showNotice(error.message, "error");
  }
}

function bindForms() {
  $("#createClientForm").addEventListener("submit", (event) =>
    handleSubmit(event, async (form) => {
      const body = {
        name: form.get("name"),
        redirectUris: csv(form.get("redirectUris")),
        isPublic: form.has("isPublic"),
        allowUserRegistration: form.has("allowUserRegistration"),
        passwordResetUrl: form.get("passwordResetUrl") || undefined,
        emailVerifyUrl: form.get("emailVerifyUrl") || undefined,
      };
      const created = await request("/clients", {
        method: "POST",
        headers: adminHeaders(),
        body: jsonBody(body),
      });
      showSecret("Client secret", created);
      await loadClients();
    })
  );

  $("#createPermissionForm").addEventListener("submit", (event) =>
    handleSubmit(event, async (form) => {
      await request("/roles/permissions", {
        method: "POST",
        headers: tenantHeaders(),
        body: jsonBody({
          resource: form.get("resource"),
          action: form.get("action"),
          description: form.get("description") || undefined,
        }),
      });
      await loadRolesAndPermissions();
    })
  );

  $("#createRoleForm").addEventListener("submit", (event) =>
    handleSubmit(event, async (form) => {
      await request("/roles", {
        method: "POST",
        headers: tenantHeaders(),
        body: jsonBody({
          name: form.get("name"),
          description: form.get("description") || undefined,
          isDefault: form.has("isDefault"),
          permissionIds: selectedValues("#rolePermissionChoices"),
        }),
      });
      await loadRolesAndPermissions();
    })
  );

  $("#createUserForm").addEventListener("submit", (event) =>
    handleSubmit(event, async (form) => {
      await request("/users", {
        method: "POST",
        headers: tenantHeaders(),
        body: jsonBody({
          email: form.get("email"),
          roleIds: selectedValues("#userRoleChoices"),
          sendInvite: form.has("sendInvite"),
        }),
      });
      await loadUsers();
    })
  );

  $("#createApiKeyForm").addEventListener("submit", (event) =>
    handleSubmit(event, async (form) => {
      const expires = form.get("expiresInDays");
      const created = await request("/api-keys", {
        method: "POST",
        headers: tenantHeaders(),
        body: jsonBody({
          name: form.get("name"),
          scopes: csv(form.get("scopes")),
          expiresInDays: expires ? Number(expires) : undefined,
        }),
      });
      showSecret("API key", created);
      await loadApiKeys();
    })
  );

  $("#createServiceAccountForm").addEventListener("submit", (event) =>
    handleSubmit(event, async (form) => {
      await request("/service-accounts", {
        method: "POST",
        headers: tenantHeaders(),
        body: jsonBody({
          name: form.get("name"),
          description: form.get("description") || undefined,
          roleIds: selectedValues("#serviceAccountRoleChoices"),
        }),
      });
      await loadServiceAccounts();
    })
  );

  $("#auditFilterForm").addEventListener("submit", (event) =>
    handleSubmit(event, async (form) => {
      await loadAudit({
        action: form.get("action"),
        actorId: form.get("actorId"),
        targetId: form.get("targetId"),
      });
    })
  );
}

function bindButtons() {
  $("#saveSettings").addEventListener("click", saveSettings);
  $("#clearCredentials").addEventListener("click", clearCredentials);
  $("#refreshClients").addEventListener("click", () => safe(loadClients));
  $("#refreshAll").addEventListener("click", () => safe(loadTenantOverview));
  $("#refreshRoles").addEventListener("click", () => safe(loadRolesAndPermissions));
  $("#refreshUsers").addEventListener("click", () => safe(loadUsers));
  $("#refreshApiKeys").addEventListener("click", () => safe(loadApiKeys));
  $("#refreshServiceAccounts").addEventListener("click", () =>
    safe(loadServiceAccounts)
  );
  $("#refreshAudit").addEventListener("click", () => safe(loadAudit));

  $(".nav").addEventListener("click", (event) => {
    const button = event.target.closest("button[data-view]");
    if (button) setView(button.dataset.view);
  });

  document.body.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;
    safe(() => handleAction(button));
  });
}

async function safe(fn) {
  clearSecret();
  try {
    await fn();
  } catch (error) {
    showNotice(error.message, "error");
  }
}

async function handleAction(button) {
  const { action, id } = button.dataset;

  if (action === "toggleClient") {
    await request(`/clients/${id}`, {
      method: "PATCH",
      headers: adminHeaders(),
      body: jsonBody({ isActive: button.dataset.active !== "true" }),
    });
    await loadClients();
    return;
  }

  if (action === "rotateClient") {
    const rotated = await request(`/clients/${id}/rotate-secret`, {
      method: "POST",
      headers: adminHeaders(),
    });
    showSecret("Client secret", rotated);
    return;
  }

  if (action === "bootstrapClient") {
    const adminEmail = window.prompt("Admin email");
    if (!adminEmail) return;
    const bootstrapped = await request(`/clients/${id}/bootstrap`, {
      method: "POST",
      headers: adminHeaders(),
      body: jsonBody({ adminEmail }),
    });
    showSecret("Bootstrap result", bootstrapped);
    return;
  }

  if (action === "toggleUser") {
    await request(`/users/${id}`, {
      method: "PATCH",
      headers: tenantHeaders(),
      body: jsonBody({ isActive: button.dataset.active !== "true" }),
    });
    await loadUsers();
    return;
  }

  if (action === "revokeApiKey") {
    await request(`/api-keys/${id}`, {
      method: "DELETE",
      headers: tenantHeaders(),
    });
    await loadApiKeys();
    return;
  }

  if (action === "toggleServiceAccount") {
    await request(`/service-accounts/${id}`, {
      method: "PATCH",
      headers: tenantHeaders(),
      body: jsonBody({ isActive: button.dataset.active !== "true" }),
    });
    await loadServiceAccounts();
    return;
  }

  if (action === "createServiceAccountKey") {
    const name = window.prompt("Key name");
    if (!name) return;
    const created = await request(`/service-accounts/${id}/api-keys`, {
      method: "POST",
      headers: tenantHeaders(),
      body: jsonBody({ name }),
    });
    showSecret("Service account key", created);
    await loadApiKeys();
  }
}

loadSettings();
bindForms();
bindButtons();

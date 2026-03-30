const API_BASE = "http://localhost:4000/api";
let token = "";
let alertsInterval;

const loginStatusEl = document.getElementById("loginStatus");
const policiesTableEl = document.getElementById("policiesTable");
const alertsTableEl = document.getElementById("alertsTable");

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

document.getElementById("loginBtn").addEventListener("click", async () => {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  try {
    const response = await api("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });

    token = response.token;
    loginStatusEl.textContent = `Logged in as ${response.user.username} (${response.user.role})`;
    await Promise.all([loadPolicies(), loadAlerts(), loadMetrics()]);

    clearInterval(alertsInterval);
    alertsInterval = setInterval(loadAlerts, 15000);
  } catch (error) {
    loginStatusEl.textContent = `Login failed: ${error.message}`;
  }
});

document.getElementById("refreshPoliciesBtn").addEventListener("click", loadPolicies);
document.getElementById("refreshAlertsBtn").addEventListener("click", loadAlerts);
document.getElementById("refreshMetricsBtn").addEventListener("click", loadMetrics);

document.getElementById("policyForm").addEventListener("submit", async (event) => {
  event.preventDefault();

  const policy = {
    name: document.getElementById("policyName").value,
    mode: document.getElementById("policyMode").value,
    targets: ["upload", "paste", "input"],
    appliesTo: { groups: ["grp-finance"], users: [] },
    conditions: {
      data_type: document.getElementById("policyDataType").value,
      target_domains: parseCSV(document.getElementById("policyDomains").value, ["*"]),
      keywords: parseCSV(document.getElementById("policyKeywords").value, []),
    },
  };

  try {
    await api("/policies", { method: "POST", body: JSON.stringify(policy) });
    event.target.reset();
    await loadPolicies();
  } catch (error) {
    alert(`Policy creation failed: ${error.message}`);
  }
});

async function loadPolicies() {
  if (!token) return;

  const data = await api("/policies");
  policiesTableEl.innerHTML = "";

  data.items.forEach((policy) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${policy.name}</td>
      <td>${policy.mode}</td>
      <td>${policy.conditions.data_type}</td>
      <td>${(policy.conditions.target_domains || []).join(", ")}</td>
      <td><button data-id="${policy.id}" class="delete-btn">Delete</button></td>
    `;
    policiesTableEl.appendChild(row);
  });

  document.querySelectorAll(".delete-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await api(`/policies/${btn.dataset.id}`, { method: "DELETE" });
      await loadPolicies();
    });
  });
}

async function loadAlerts() {
  if (!token) return;

  const data = await api("/alerts");
  alertsTableEl.innerHTML = "";

  data.items.forEach((alert) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${new Date(alert.ts).toLocaleString()}</td>
      <td>${alert.user_id}</td>
      <td>${alert.device_id}</td>
      <td>${alert.action}</td>
      <td>${alert.matched_policy?.name || "-"}</td>
      <td>${alert.decision}</td>
      <td class="sev-${alert.severity}">${alert.severity}</td>
    `;
    alertsTableEl.appendChild(row);
  });
}

async function loadMetrics() {
  if (!token) return;
  const metrics = await api("/metrics");

  document.getElementById("mTotal").textContent = metrics.total_events;
  document.getElementById("mRate").textContent = `${Math.round(metrics.enforcement_success_rate * 100)}%`;
  document.getElementById("mUsers").textContent = metrics.active_users;
  document.getElementById("mDevices").textContent = metrics.active_devices;
}

function parseCSV(raw, fallback) {
  const items = raw
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);

  return items.length ? items : fallback;
}

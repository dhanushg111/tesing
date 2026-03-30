const browserApi = globalThis.browser ?? globalThis.chrome;
const API_BASE_DEFAULT = "http://localhost:4000/api";

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function getSettings() {
  const { settings } = await browserApi.storage.local.get(["settings"]);
  return settings || { apiBase: API_BASE_DEFAULT, pollIntervalMs: 45_000 };
}

async function getSession() {
  const { session } = await browserApi.storage.local.get(["session"]);
  return session;
}

async function apiFetch(path, options = {}) {
  const settings = await getSettings();
  const base = settings.apiBase || API_BASE_DEFAULT;
  return fetch(`${base}${path}`, options);
}

async function registerDevice() {
  const session = await getSession();
  if (!session?.token || !session?.device_id) return;

  await apiFetch("/devices/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${session.token}`,
    },
    body: JSON.stringify({
      device_id: session.device_id,
      browser: navigator.userAgent,
      extension_version: "1.0.1",
    }),
  });
}

async function fetchPoliciesForHost(host) {
  const session = await getSession();
  if (!session?.token) return [];

  const response = await apiFetch(`/extension/policies?host=${encodeURIComponent(host)}`, {
    headers: { Authorization: `Bearer ${session.token}` },
  });

  if (!response.ok) {
    if (response.status === 401) {
      const current = await getSession();
      await browserApi.storage.local.set({ session: { ...current, token: "" }, policies: [] });
    }
    return [];
  }

  const json = await response.json();
  const settings = await getSettings();
  await browserApi.storage.local.set({
    policies: json.policies,
    settings: { ...settings, pollIntervalMs: (json.polling_interval_seconds || 45) * 1000 },
    lastPolicySyncAt: json.fetched_at,
  });
  return json.policies;
}

async function postEvent(eventPayload) {
  const session = await getSession();
  if (!session?.token) return;

  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const response = await apiFetch("/events", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session.token}`,
        },
        body: JSON.stringify(eventPayload),
      });

      if (response.ok) return;
    } catch {
      // retry on network failure
    }

    await wait(300 * (attempt + 1));
  }
}

browserApi.runtime.onInstalled.addListener(async () => {
  const session = {
    token: "",
    user_id: "",
    device_id: `browser-${crypto.randomUUID()}`,
  };

  await browserApi.storage.local.set({
    session,
    policies: [],
    settings: { apiBase: API_BASE_DEFAULT, pollIntervalMs: 45_000 },
  });
});

browserApi.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    if (message.type === "DLP_EVENT") {
      const { session } = await browserApi.storage.local.get(["session"]);
      await postEvent({
        device_id: session?.device_id,
        action: message.action,
        page_url: message.page_url,
        payload: message.payload,
      });
      sendResponse({ ok: true });
      return;
    }

    if (message.type === "FETCH_POLICIES") {
      const host = new URL(message.page_url).hostname;
      const policies = await fetchPoliciesForHost(host);
      sendResponse({ policies });
      return;
    }

    if (message.type === "LOGIN") {
      const response = await apiFetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: message.username, password: message.password }),
      });

      if (!response.ok) {
        sendResponse({ ok: false, error: "Invalid login" });
        return;
      }

      const json = await response.json();
      const { session } = await browserApi.storage.local.get(["session"]);
      await browserApi.storage.local.set({
        session: { ...session, token: json.token, user_id: json.user.id },
      });
      await registerDevice();
      sendResponse({ ok: true, user: json.user });
      return;
    }

    if (message.type === "UPDATE_API_BASE") {
      const settings = await getSettings();
      await browserApi.storage.local.set({ settings: { ...settings, apiBase: message.apiBase || API_BASE_DEFAULT } });
      sendResponse({ ok: true });
    }
  })();

  return true;
});

async function pollingLoop() {
  while (true) {
    try {
      const [tab] = await browserApi.tabs.query({ active: true, currentWindow: true });
      if (tab?.url) {
        const host = new URL(tab.url).hostname;
        await fetchPoliciesForHost(host);
      }
    } catch {
      // noop
    }

    const settings = await getSettings();
    await wait(settings.pollIntervalMs || 45_000);
  }
}

pollingLoop();

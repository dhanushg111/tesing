const browserApi = globalThis.browser ?? globalThis.chrome;

const statusEl = document.getElementById("status");

document.getElementById("saveBtn").addEventListener("click", async () => {
  const apiBase = document.getElementById("apiBase").value.trim();
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;

  await browserApi.runtime.sendMessage({ type: "UPDATE_API_BASE", apiBase });

  const response = await browserApi.runtime.sendMessage({
    type: "LOGIN",
    username,
    password,
  });

  if (!response?.ok) {
    statusEl.textContent = "Login failed. Check credentials/API base.";
    return;
  }

  statusEl.textContent = `Connected as ${response.user.username}`;
});

import express from "express";
import cors from "cors";
import crypto from "crypto";
import { scanTextForSensitiveData } from "../shared/detection.js";

const app = express();
app.use(cors({ origin: process.env.CORS_ORIGIN || true }));
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 4000;
const HOST = process.env.HOST || "127.0.0.1";
const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-production";
const TOKEN_TTL_MS = Number(process.env.TOKEN_TTL_MS || 1000 * 60 * 60 * 8);

const users = [
  { id: "u-admin", username: "admin", password: "admin123", role: "security_admin", groupIds: ["grp-finance"] },
  { id: "u-analyst", username: "analyst", password: "analyst123", role: "compliance", groupIds: ["grp-finance"] },
];

const devices = [];
const events = [];

const policies = [
  {
    id: "pol-001",
    name: "Block CC Upload",
    mode: "block",
    enabled: true,
    targets: ["upload", "paste", "input"],
    appliesTo: { groups: ["grp-finance"], users: [] },
    conditions: {
      data_type: "credit_card",
      target_domains: ["gmail.com", "drive.google.com"],
      keywords: [],
    },
  },
  {
    id: "pol-002",
    name: "Warn on SSN to external forms",
    mode: "warn",
    enabled: true,
    targets: ["input", "paste"],
    appliesTo: { groups: ["grp-finance"], users: [] },
    conditions: {
      data_type: "ssn",
      target_domains: ["*"],
      keywords: [],
    },
  },
];

const POLICY_MODES = new Set(["block", "warn", "allow"]);
const TARGET_ACTIONS = new Set(["upload", "paste", "input"]);

function signToken(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", JWT_SECRET).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function verifyToken(token) {
  const [encoded, signature] = (token || "").split(".");
  if (!encoded || !signature) return null;

  const expected = crypto.createHmac("sha256", JWT_SECRET).update(encoded).digest("base64url");
  if (expected !== signature) return null;

  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

function authMiddleware(req, res, next) {
  const raw = req.headers.authorization || "";
  const token = raw.startsWith("Bearer ") ? raw.slice(7) : "";
  const payload = verifyToken(token);

  if (!payload) {
    return res.status(401).json({ error: "Unauthorized or expired token" });
  }

  req.user = payload;
  next();
}

function domainMatch(currentHost, allowedDomains) {
  if (!allowedDomains || allowedDomains.length === 0 || allowedDomains.includes("*")) return true;
  return allowedDomains.some((allowed) => currentHost === allowed || currentHost.endsWith(`.${allowed}`));
}

function policyAppliesToActor(policy, user) {
  if (policy.appliesTo.users.includes(user.id)) return true;
  return user.groupIds.some((groupId) => policy.appliesTo.groups.includes(groupId));
}

function validatePolicyInput(input) {
  if (!input || typeof input !== "object") return "Body must be a JSON object";
  if (!input.name || typeof input.name !== "string") return "Policy name is required";
  if (!POLICY_MODES.has(input.mode)) return "Policy mode must be one of block|warn|allow";
  if (!input.conditions?.data_type) return "conditions.data_type is required";

  const targets = input.targets ?? ["input"];
  if (!Array.isArray(targets) || targets.some((t) => !TARGET_ACTIONS.has(t))) {
    return "targets must contain only upload|paste|input";
  }

  return null;
}

app.get("/api/health", (_, res) => {
  res.json({ status: "ok", service: "browser-dlp-platform", version: "1.0.1" });
});

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body || {};
  const user = users.find((u) => u.username === username && u.password === password);
  if (!user) return res.status(401).json({ error: "Invalid credentials" });

  const now = Date.now();
  const token = signToken({
    id: user.id,
    role: user.role,
    groupIds: user.groupIds,
    iat: now,
    exp: now + TOKEN_TTL_MS,
  });

  res.json({
    token,
    expires_in_seconds: Math.floor(TOKEN_TTL_MS / 1000),
    user: { id: user.id, username: user.username, role: user.role, groupIds: user.groupIds },
  });
});

app.post("/api/devices/register", authMiddleware, (req, res) => {
  const { device_id, browser, extension_version } = req.body || {};
  if (!device_id || !browser) return res.status(400).json({ error: "device_id and browser are required" });

  const existing = devices.find((d) => d.device_id === device_id && d.user_id === req.user.id);
  if (existing) {
    existing.last_seen = new Date().toISOString();
    existing.browser = browser;
    existing.extension_version = extension_version;
    return res.json(existing);
  }

  const record = {
    id: `dev-${devices.length + 1}`,
    user_id: req.user.id,
    device_id,
    browser,
    extension_version: extension_version || "unknown",
    registered_at: new Date().toISOString(),
    last_seen: new Date().toISOString(),
  };

  devices.push(record);
  res.status(201).json(record);
});

app.get("/api/extension/policies", authMiddleware, (req, res) => {
  const host = (req.query.host || "").toString().toLowerCase();

  const effectivePolicies = policies
    .filter((policy) => policy.enabled)
    .filter((policy) => policyAppliesToActor(policy, req.user))
    .filter((policy) => domainMatch(host, policy.conditions.target_domains));

  res.json({
    fetched_at: new Date().toISOString(),
    polling_interval_seconds: 45,
    policies: effectivePolicies,
  });
});

app.get("/api/policies", authMiddleware, (_, res) => {
  res.json({ items: policies });
});

app.post("/api/policies", authMiddleware, (req, res) => {
  const input = req.body;
  const validationError = validatePolicyInput(input);
  if (validationError) return res.status(400).json({ error: validationError });

  const newPolicy = {
    id: `pol-${String(policies.length + 1).padStart(3, "0")}`,
    name: input.name.trim(),
    mode: input.mode,
    enabled: input.enabled ?? true,
    targets: Array.isArray(input.targets) ? input.targets : ["input"],
    appliesTo: input.appliesTo ?? { groups: [], users: [] },
    conditions: {
      data_type: input.conditions.data_type,
      target_domains: Array.isArray(input.conditions.target_domains) ? input.conditions.target_domains : ["*"],
      keywords: Array.isArray(input.conditions.keywords) ? input.conditions.keywords : [],
    },
  };

  policies.push(newPolicy);
  res.status(201).json(newPolicy);
});

app.put("/api/policies/:id", authMiddleware, (req, res) => {
  const policy = policies.find((p) => p.id === req.params.id);
  if (!policy) return res.status(404).json({ error: "Policy not found" });

  const candidate = {
    ...policy,
    ...req.body,
    conditions: { ...policy.conditions, ...(req.body?.conditions || {}) },
  };

  const validationError = validatePolicyInput(candidate);
  if (validationError) return res.status(400).json({ error: validationError });

  Object.assign(policy, candidate);
  res.json(policy);
});

app.delete("/api/policies/:id", authMiddleware, (req, res) => {
  const idx = policies.findIndex((p) => p.id === req.params.id);
  if (idx < 0) return res.status(404).json({ error: "Policy not found" });

  const [removed] = policies.splice(idx, 1);
  res.json(removed);
});

app.post("/api/events", authMiddleware, (req, res) => {
  const { device_id, action, page_url, payload } = req.body || {};
  if (!action || !page_url) return res.status(400).json({ error: "action and page_url are required" });
  if (!TARGET_ACTIONS.has(action)) return res.status(400).json({ error: "Unsupported action" });

  let host;
  try {
    host = new URL(page_url).hostname;
  } catch {
    return res.status(400).json({ error: "Invalid page_url" });
  }

  const text = String(payload?.text || "");
  const lowered = text.toLowerCase();
  const findings = scanTextForSensitiveData(text, payload?.keywords ?? []);

  const matchedPolicy = policies.find((policy) => {
    if (!policy.enabled || !policyAppliesToActor(policy, req.user)) return false;
    if (!policy.targets.includes(action)) return false;
    if (!domainMatch(host, policy.conditions.target_domains)) return false;

    const keywords = Array.isArray(policy.conditions.keywords) ? policy.conditions.keywords : [];
    const keywordHit = keywords.some((kw) => lowered.includes(String(kw).toLowerCase()));

    if (policy.conditions.data_type === "keyword") return keywordHit;

    const typeHit = findings.some((f) => f.data_type === policy.conditions.data_type);
    if (!typeHit) return false;

    if (keywords.length > 0 && !keywordHit) return false;
    return true;
  });

  const event = {
    id: `evt-${events.length + 1}`,
    ts: new Date().toISOString(),
    severity: matchedPolicy?.mode === "block" ? "high" : matchedPolicy?.mode === "warn" ? "medium" : "low",
    user_id: req.user.id,
    device_id: device_id || "unknown",
    action,
    page_url,
    findings,
    matched_policy: matchedPolicy ? { id: matchedPolicy.id, name: matchedPolicy.name, mode: matchedPolicy.mode } : null,
    decision: matchedPolicy?.mode || "allow",
  };

  events.push(event);
  res.status(201).json(event);
});

app.get("/api/alerts", authMiddleware, (_, res) => {
  const alerts = [...events].filter((e) => e.decision !== "allow").slice(-200).reverse();
  res.json({ items: alerts });
});

app.get("/api/metrics", authMiddleware, (_, res) => {
  const totalEvents = events.length;
  const blocked = events.filter((e) => e.decision === "block").length;
  const warned = events.filter((e) => e.decision === "warn").length;

  res.json({
    total_events: totalEvents,
    enforcement_success_rate: totalEvents ? (blocked + warned) / totalEvents : 0,
    active_users: new Set(events.map((e) => e.user_id)).size,
    active_devices: new Set(devices.map((d) => d.device_id)).size,
    blocked,
    warned,
  });
});

app.listen(PORT, HOST, () => {
  console.log(`DLP backend running on http://${HOST}:${PORT}`);
});

function parseHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function domainMatches(host, targets) {
  if (!targets || targets.length === 0 || targets.includes("*")) return true;
  return targets.some((d) => host === d || host.endsWith(`.${d}`));
}

function matchesDetection(dataType, text) {
  const map = {
    email: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
    credit_card: /\b(?:\d[ -]*?){13,16}\b/,
    phone: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/,
    keyword: /.*/,
  };

  if (dataType === "keyword") return true;
  return map[dataType]?.test(text) || false;
}

function evaluatePolicies(action, text, policies) {
  const host = parseHost(window.location.href);

  for (const policy of policies) {
    if (!policy.targets.includes(action)) continue;
    if (!domainMatches(host, policy.conditions.target_domains)) continue;

    const keywordHit = (policy.conditions.keywords || []).some((kw) => text.toLowerCase().includes(kw.toLowerCase()));
    const typeHit = matchesDetection(policy.conditions.data_type, text);
    if (!keywordHit && !typeHit) continue;

    return policy;
  }

  return null;
}

function handleEnforcement(policy) {
  if (!policy) return "allow";

  if (policy.mode === "warn") {
    alert(`DLP Warning: Policy '${policy.name}' matched. Please verify before sending data.`);
    return "warn";
  }

  if (policy.mode === "block") {
    alert(`DLP Blocked: '${policy.name}' prevented this action.`);
    return "block";
  }

  return "allow";
}

async function emitEvent(action, text) {
  const response = await chrome.runtime.sendMessage({
    type: "FETCH_POLICIES",
    page_url: window.location.href,
  });
  const policies = response?.policies || [];

  const matched = evaluatePolicies(action, text, policies);
  const decision = handleEnforcement(matched);

  await chrome.runtime.sendMessage({
    type: "DLP_EVENT",
    action,
    page_url: window.location.href,
    payload: {
      text: text.slice(0, 2000),
      keywords: matched?.conditions?.keywords || [],
      matched_policy_id: matched?.id || null,
      decision,
    },
  });

  return decision;
}

const debounceTimers = new WeakMap();

document.addEventListener(
  "paste",
  async (event) => {
    const text = event.clipboardData?.getData("text") || "";
    const decision = await emitEvent("paste", text);
    if (decision === "block") {
      event.preventDefault();
      event.stopPropagation();
    }
  },
  true
);

document.addEventListener(
  "input",
  async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement)) return;

    clearTimeout(debounceTimers.get(target));
    const timer = setTimeout(async () => {
      await emitEvent("input", target.value || "");
    }, 300);
    debounceTimers.set(target, timer);
  },
  true
);

document.addEventListener(
  "change",
  async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement) || target.type !== "file") return;

    const fileNames = [...(target.files || [])].map((f) => f.name).join(", ");
    const decision = await emitEvent("upload", fileNames);
    if (decision === "block") {
      target.value = "";
      event.preventDefault();
      event.stopPropagation();
    }
  },
  true
);

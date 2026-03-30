export const DETECTORS = [
  {
    dataType: "email",
    severity: "medium",
    regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  },
  {
    dataType: "credit_card",
    severity: "high",
    regex: /\b(?:\d[ -]*?){13,16}\b/g,
  },
  {
    dataType: "phone",
    severity: "medium",
    regex: /\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
  },
  {
    dataType: "ssn",
    severity: "high",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
];

export function scanTextForSensitiveData(text, keywords = []) {
  const findings = [];

  DETECTORS.forEach((detector) => {
    const matches = [...text.matchAll(detector.regex)].map((x) => x[0]);
    if (!matches.length) return;

    findings.push({
      data_type: detector.dataType,
      severity: detector.severity,
      count: new Set(matches).size,
      samples: [...new Set(matches)].slice(0, 3),
    });
  });

  if (keywords.length > 0) {
    const lowered = text.toLowerCase();
    const hitKeywords = keywords.filter((kw) => lowered.includes(kw.toLowerCase()));
    if (hitKeywords.length > 0) {
      findings.push({
        data_type: "keyword",
        severity: "medium",
        count: hitKeywords.length,
        samples: hitKeywords.slice(0, 3),
      });
    }
  }

  return findings;
}

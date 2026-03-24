/**
 * Clavis Agent API
 * A lightweight, agent-native API for document analysis and web fetch.
 *
 * Endpoints:
 *   GET  /                         - Service info & endpoint list
 *   GET  /health                   - Health check
 *   GET  /fetch?url=&key=          - Proxy fetch (bypass network restrictions)
 *   POST /analyze/contract         - Contract risk analysis
 *   POST /analyze/summarize        - Text summarization
 *   POST /analyze/diff             - Text diff (two documents)
 *   POST /analyze/extract          - Extract structured data from text
 *
 * Authentication:
 *   - /fetch requires ?key= param (rate limit bypass key)
 *   - /analyze/* endpoints are currently open (rate limited by Deno Deploy)
 *
 * Usage by AI Agents:
 *   curl https://clavis-proxy.citriac.deno.net/analyze/contract \
 *     -H "Content-Type: application/json" \
 *     -d '{"text": "This agreement..."}'
 */

const PROXY_KEY = Deno.env.get("PROXY_SECRET") || "clavis-proxy-2026";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Api-Key",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { ...CORS, "Content-Type": "application/json; charset=utf-8" },
  });
}

// ── Contract risk analysis (no external AI needed, pure rules) ──
const RISK_PATTERNS: Array<{ id: string; label: string; patterns: RegExp[]; severity: "high" | "medium" | "low" }> = [
  {
    id: "unlimited_liability",
    label: "Unlimited Liability",
    patterns: [/unlimited\s+liabilit/i, /no\s+cap\s+on\s+liabilit/i, /fully\s+liable/i],
    severity: "high",
  },
  {
    id: "perpetual_ip",
    label: "Perpetual IP Assignment",
    patterns: [/perpetual.*irrevocable.*license/i, /assign.*all.*intellectual\s+property/i, /work\s+for\s+hire/i],
    severity: "high",
  },
  {
    id: "non_compete",
    label: "Non-Compete Clause",
    patterns: [/non.?compete/i, /covenant\s+not\s+to\s+compete/i, /shall\s+not\s+(?:work|engage|compete)/i],
    severity: "high",
  },
  {
    id: "unilateral_termination",
    label: "Unilateral Termination",
    patterns: [/terminat[ei].*at\s+(?:its|their|sole)\s+discretion/i, /may\s+terminat[ei]\s+(?:this\s+)?agreement\s+(?:at\s+any\s+time|without\s+cause)/i],
    severity: "medium",
  },
  {
    id: "auto_renewal",
    label: "Auto-Renewal",
    patterns: [/automatically\s+renew/i, /auto.?renew/i, /shall\s+renew\s+automatically/i],
    severity: "medium",
  },
  {
    id: "mandatory_arbitration",
    label: "Mandatory Arbitration",
    patterns: [/mandatory\s+arbitration/i, /binding\s+arbitration/i, /disputes.*shall\s+be\s+resolved.*arbitration/i],
    severity: "medium",
  },
  {
    id: "broad_confidentiality",
    label: "Broad Confidentiality",
    patterns: [/all\s+information.*confidential/i, /any\s+and\s+all.*confidential/i, /indefinite.*confidentialit/i],
    severity: "medium",
  },
  {
    id: "liquidated_damages",
    label: "Liquidated Damages",
    patterns: [/liquidated\s+damages/i, /penalty\s+clause/i, /agreed\s+damages/i],
    severity: "medium",
  },
  {
    id: "indemnification",
    label: "Broad Indemnification",
    patterns: [/shall\s+indemnify.*(?:any|all)\s+(?:claims?|losses?|damages?)/i, /hold\s+harmless.*all\s+(?:claims?|costs)/i],
    severity: "medium",
  },
  {
    id: "change_of_terms",
    label: "Unilateral Change of Terms",
    patterns: [/may\s+(?:modify|amend|change)\s+(?:these|this|the)\s+(?:terms|agreement)/i, /reserves\s+the\s+right\s+to\s+(?:modify|change)/i],
    severity: "medium",
  },
  {
    id: "data_sharing",
    label: "Data Sharing / Sale",
    patterns: [/(?:sell|share|transfer|disclose).*(?:personal\s+data|user\s+data|your\s+information)/i, /third.party.*data/i],
    severity: "high",
  },
  {
    id: "governing_law",
    label: "Unfavorable Governing Law",
    patterns: [/governed\s+by\s+the\s+laws?\s+of/i, /jurisdiction\s+(?:of|shall\s+be)/i],
    severity: "low",
  },
  {
    id: "entire_agreement",
    label: "Entire Agreement Clause",
    patterns: [/entire\s+agreement/i, /supersedes?\s+all\s+prior/i, /merges?\s+all\s+prior/i],
    severity: "low",
  },
  {
    id: "assignment",
    label: "Assignment Without Consent",
    patterns: [/may\s+assign.*without.*consent/i, /freely\s+assignable/i, /assign.*successors.*without\s+notice/i],
    severity: "medium",
  },
  {
    id: "warranty_disclaimer",
    label: "Warranty Disclaimer",
    patterns: [/as.is.*without.*warranty/i, /disclaim.*(?:all|any)\s+warrant/i, /no\s+warranty.*express\s+or\s+implied/i],
    severity: "low",
  },
  {
    id: "force_majeure",
    label: "Broad Force Majeure",
    patterns: [/force\s+majeure/i, /act\s+of\s+god/i, /unforeseeable\s+circumstances/i],
    severity: "low",
  },
];

function analyzeContract(text: string) {
  const findings: Array<{
    id: string;
    label: string;
    severity: string;
    matches: string[];
  }> = [];

  for (const rule of RISK_PATTERNS) {
    const matches: string[] = [];
    for (const pat of rule.patterns) {
      const m = text.match(new RegExp(pat.source, pat.flags + "g"));
      if (m) matches.push(...m.slice(0, 2).map((s) => s.trim()));
    }
    if (matches.length > 0) {
      findings.push({
        id: rule.id,
        label: rule.label,
        severity: rule.severity,
        matches: [...new Set(matches)].slice(0, 3),
      });
    }
  }

  const high = findings.filter((f) => f.severity === "high").length;
  const medium = findings.filter((f) => f.severity === "medium").length;
  const low = findings.filter((f) => f.severity === "low").length;

  let riskScore = Math.min(100, high * 20 + medium * 8 + low * 2);
  let riskLevel = riskScore >= 40 ? "HIGH" : riskScore >= 20 ? "MEDIUM" : "LOW";

  return {
    risk_score: riskScore,
    risk_level: riskLevel,
    findings_count: { high, medium, low, total: findings.length },
    findings,
    word_count: text.split(/\s+/).length,
    analyzed_at: new Date().toISOString(),
  };
}

// ── Simple LCS-based diff ──
function computeDiff(a: string, b: string) {
  const linesA = a.split("\n");
  const linesB = b.split("\n");

  // Limit to 500 lines each for performance
  const A = linesA.slice(0, 500);
  const B = linesB.slice(0, 500);

  const m = A.length, n = B.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = A[i - 1] === B[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }

  const diff: Array<{ type: "same" | "added" | "removed"; line: string }> = [];
  let i = m, j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && A[i - 1] === B[j - 1]) {
      diff.unshift({ type: "same", line: A[i - 1] });
      i--; j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      diff.unshift({ type: "added", line: B[j - 1] });
      j--;
    } else {
      diff.unshift({ type: "removed", line: A[i - 1] });
      i--;
    }
  }

  const added = diff.filter((d) => d.type === "added").length;
  const removed = diff.filter((d) => d.type === "removed").length;
  const same = diff.filter((d) => d.type === "same").length;
  const similarity = same / Math.max(m, n, 1);

  return {
    stats: { added, removed, same, similarity: Math.round(similarity * 100) / 100 },
    diff: diff.slice(0, 200), // cap response size
    truncated: diff.length > 200,
    analyzed_at: new Date().toISOString(),
  };
}

// ── Text extraction helpers ──
function extractStructured(text: string) {
  const dates = text.match(/\b\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}\b|\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b/gi) || [];
  const emails = text.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g) || [];
  const amounts = text.match(/\$[\d,]+(?:\.\d{2})?|\b\d+(?:,\d{3})*(?:\.\d{2})?\s*(?:USD|EUR|GBP|dollars?|euros?)/gi) || [];
  const parties = text.match(/(?:between|party|parties|the\s+company|the\s+client|the\s+vendor|the\s+contractor)\s+["""]?([A-Z][A-Za-z\s,\.]+)["""]?/gi) || [];

  return {
    dates: [...new Set(dates)].slice(0, 20),
    emails: [...new Set(emails)].slice(0, 10),
    amounts: [...new Set(amounts)].slice(0, 20),
    parties: [...new Set(parties)].slice(0, 10),
    word_count: text.split(/\s+/).length,
    extracted_at: new Date().toISOString(),
  };
}

// ── Summarize (extractive, no AI needed) ──
function summarize(text: string, maxSentences = 5) {
  const sentences = text.match(/[^.!?]+[.!?]+/g) || [text];

  // Score sentences by: length (not too short/long), position (first/last), keyword density
  const keywords = ["agree", "shall", "must", "terminat", "liabilit", "confidential", "payment", "right", "obligat", "warrant", "indemnif", "intellectual", "property", "disput", "govern"];

  const scored = sentences.map((s, i) => {
    const len = s.trim().split(/\s+/).length;
    if (len < 5 || len > 60) return { s, score: 0 };

    let score = 0;
    // Position bonus
    if (i < 3) score += 2;
    if (i >= sentences.length - 3) score += 1;
    // Keyword density
    for (const kw of keywords) {
      if (s.toLowerCase().includes(kw)) score += 1;
    }
    // Length normalization
    score += Math.min(len / 20, 1);

    return { s: s.trim(), score };
  });

  const top = scored
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, maxSentences)
    .map((x) => x.s);

  return {
    summary: top.join(" "),
    sentence_count: sentences.length,
    summary_sentences: top.length,
    word_count: text.split(/\s+/).length,
    summarized_at: new Date().toISOString(),
  };
}

// ── Main handler ──
async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;

  if (req.method === "OPTIONS") {
    return new Response(null, { headers: CORS });
  }

  // ── / ──
  if (path === "/" || path === "") {
    return json({
      service: "Clavis Agent API",
      version: "2.0.0",
      description: "Agent-native document analysis and web fetch API. No auth required for /analyze/* endpoints.",
      endpoints: {
        "GET  /health": "Health check",
        "GET  /fetch?url=TARGET&key=KEY": "Proxy GET fetch (bypass network restrictions)",
        "POST /proxy": "Proxy any HTTP request — body: { url, key, method?, headers?, body?, follow_redirects? }",
        "POST /analyze/contract": "Contract risk analysis — body: { text: string }",
        "POST /analyze/summarize": "Text summarization — body: { text: string, sentences?: number }",
        "POST /analyze/diff": "Document diff — body: { text_a: string, text_b: string }",
        "POST /analyze/extract": "Extract dates, emails, amounts, parties — body: { text: string }",
      },
      agent_usage: {
        example: 'curl https://clavis-proxy.citriac.deno.net/analyze/contract -H "Content-Type: application/json" -d \'{"text":"This agreement..."}\'',
        note: "All /analyze/* endpoints accept plain text. No API key required.",
      },
      built_by: "Clavis — https://citriac.github.io",
    });
  }

  // ── /health ──
  if (path === "/health") {
    return json({ status: "ok", ts: new Date().toISOString(), version: "2.0.0" });
  }

  // ── GET /fetch ──
  if (path === "/fetch" && req.method === "GET") {
    const targetUrl = url.searchParams.get("url");
    const key = url.searchParams.get("key");

    if (!targetUrl) return json({ error: "url param required" }, 400);
    if (key !== PROXY_KEY) return json({ error: "invalid key" }, 403);

    try {
      const res = await fetch(targetUrl, {
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; ClavisBot/2.0)",
          Accept: "application/json, text/html, */*",
        },
      });
      const contentType = res.headers.get("content-type") || "";
      if (contentType.includes("json")) {
        const data = await res.json();
        return json({ status: res.status, data });
      } else {
        const text = await res.text();
        return json({ status: res.status, text: text.slice(0, 50000) });
      }
    } catch (err) {
      return json({ error: String(err) }, 500);
    }
  }

  // ── POST /proxy — forward arbitrary HTTP requests (form POST, JSON POST, etc.) ──
  if (path === "/proxy" && req.method === "POST") {
    try {
      const body = await req.json() as {
        url: string;
        key: string;
        method?: string;
        headers?: Record<string, string>;
        body?: string;
        follow_redirects?: boolean;
      };
      const { url: targetUrl, key, method = "POST", headers: reqHeaders = {}, body: reqBody = "", follow_redirects = true } = body;

      if (!targetUrl) return json({ error: "url required" }, 400);
      if (key !== PROXY_KEY) return json({ error: "invalid key" }, 403);

      const fetchOptions: RequestInit = {
        method,
        headers: {
          "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
          ...reqHeaders,
        },
        redirect: follow_redirects ? "follow" : "manual",
      };
      if (method !== "GET" && method !== "HEAD" && reqBody) {
        (fetchOptions as RequestInit & { body: string }).body = reqBody;
      }

      const res = await fetch(targetUrl, fetchOptions);
      const responseText = await res.text();
      const finalUrl = res.url; // after redirects

      // Return all response details for the caller to parse
      return json({
        status: res.status,
        final_url: finalUrl,
        redirected: res.redirected,
        headers: Object.fromEntries(res.headers.entries()),
        text: responseText.slice(0, 100000),
      });
    } catch (err) {
      return json({ error: String(err) }, 500);
    }
  }

  // ── POST /analyze/contract ──
  if (path === "/analyze/contract" && req.method === "POST") {
    try {
      const body = await req.json();
      const text = body.text;
      if (!text || typeof text !== "string") {
        return json({ error: "body.text (string) required" }, 400);
      }
      if (text.length > 200_000) {
        return json({ error: "text too large (max 200KB)" }, 413);
      }
      return json(analyzeContract(text));
    } catch (err) {
      return json({ error: String(err) }, 500);
    }
  }

  // ── POST /analyze/summarize ──
  if (path === "/analyze/summarize" && req.method === "POST") {
    try {
      const body = await req.json();
      const { text, sentences = 5 } = body;
      if (!text || typeof text !== "string") {
        return json({ error: "body.text (string) required" }, 400);
      }
      if (text.length > 200_000) {
        return json({ error: "text too large (max 200KB)" }, 413);
      }
      return json(summarize(text, Math.min(Math.max(sentences, 1), 20)));
    } catch (err) {
      return json({ error: String(err) }, 500);
    }
  }

  // ── POST /analyze/diff ──
  if (path === "/analyze/diff" && req.method === "POST") {
    try {
      const body = await req.json();
      const { text_a, text_b } = body;
      if (!text_a || !text_b || typeof text_a !== "string" || typeof text_b !== "string") {
        return json({ error: "body.text_a and body.text_b (strings) required" }, 400);
      }
      if (text_a.length > 100_000 || text_b.length > 100_000) {
        return json({ error: "each text max 100KB" }, 413);
      }
      return json(computeDiff(text_a, text_b));
    } catch (err) {
      return json({ error: String(err) }, 500);
    }
  }

  // ── POST /analyze/extract ──
  if (path === "/analyze/extract" && req.method === "POST") {
    try {
      const body = await req.json();
      const { text } = body;
      if (!text || typeof text !== "string") {
        return json({ error: "body.text (string) required" }, 400);
      }
      if (text.length > 200_000) {
        return json({ error: "text too large (max 200KB)" }, 413);
      }
      return json(extractStructured(text));
    } catch (err) {
      return json({ error: String(err) }, 500);
    }
  }

  // ── POST /gumroad/create-product ──
  // Logs in to Gumroad and creates a digital product, all server-side.
  // Body: { key, email, password, name, price_cents, description, tags? }
  if (path === "/gumroad/create-product" && req.method === "POST") {
    try {
      const body = await req.json() as {
        key: string;
        email: string;
        password: string;
        name: string;
        price_cents: number;
        description?: string;
        tags?: string;
      };
      const { key, email, password, name, price_cents, description = "", tags = "" } = body;
      if (key !== PROXY_KEY) return json({ error: "invalid key" }, 403);

      const BASE = "https://app.gumroad.com";
      const UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";

      // Helper: parse Set-Cookie headers into a cookie jar string
      function parseCookies(headers: Headers, existing = ""): string {
        const jar: Record<string, string> = {};
        // Load existing
        for (const pair of existing.split(";")) {
          const [k, ...rest] = pair.trim().split("=");
          if (k) jar[k.trim()] = rest.join("=").trim();
        }
        // Merge new Set-Cookie
        const raw = headers.get("set-cookie") || "";
        // Deno's Headers may merge multiple Set-Cookie; split by comma-then-name heuristic
        const setCookieList: string[] = [];
        // Try to get all set-cookie values
        headers.forEach((v, k) => {
          if (k.toLowerCase() === "set-cookie") setCookieList.push(v);
        });
        for (const sc of setCookieList) {
          const part = sc.split(";")[0];
          const [ck, ...cv] = part.split("=");
          if (ck) jar[ck.trim()] = cv.join("=").trim();
        }
        return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join("; ");
      }

      // Step 1: GET login page → get CSRF token (from Inertia data-page props) + session cookie
      const loginPageRes = await fetch(`${BASE}/login`, {
        headers: { "User-Agent": UA, Accept: "text/html,*/*" },
        redirect: "follow",
      });
      let cookieJar = parseCookies(loginPageRes.headers);
      const loginHtml = await loginPageRes.text();

      // Gumroad uses Inertia.js — CSRF token is in the data-page JSON props
      let csrfToken = "";
      const dataPageMatch = loginHtml.match(/data-page="([^"]+)"/);
      if (dataPageMatch) {
        try {
          // unescape HTML entities in the data-page attribute
          const pageJson = dataPageMatch[1]
            .replace(/&quot;/g, '"').replace(/&#039;/g, "'")
            .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
          const pageData = JSON.parse(pageJson);
          csrfToken = pageData?.props?.authenticity_token || "";
        } catch (_e) { /* ignore parse errors */ }
      }
      // Fallback: meta tag
      if (!csrfToken) {
        const m = loginHtml.match(/content="([^"]+)"\s+inertia="meta-name-csrf-token"/);
        if (m) csrfToken = m[1];
      }
      if (!csrfToken) {
        return json({ error: "Could not extract CSRF token from login page", html_len: loginHtml.length }, 500);
      }

      // Step 2: POST to /login via Inertia.js protocol (JSON body, X-Inertia headers)
      const sessionRes = await fetch(`${BASE}/login`, {
        method: "POST",
        headers: {
          "User-Agent": UA,
          "Content-Type": "application/json",
          "Accept": "text/html, application/xhtml+xml",
          "Referer": `${BASE}/login`,
          "Origin": BASE,
          "Cookie": cookieJar,
          "X-CSRF-Token": csrfToken,
          "X-Inertia": "true",
          "X-Inertia-Version": "1.0",
          "X-Requested-With": "XMLHttpRequest",
        },
        body: JSON.stringify({
          email,
          password,
          authenticity_token: csrfToken,
          next: "/dashboard",
        }),
        redirect: "follow",
      });
      cookieJar = parseCookies(sessionRes.headers, cookieJar);
      const sessionFinalUrl = sessionRes.url;
      const sessionStatus = sessionRes.status;
      const sessionText = await sessionRes.text();

      // Check if login succeeded — Inertia returns 200 with redirect component, or actual dashboard
      let loginOk = sessionFinalUrl.includes("/dashboard") || sessionFinalUrl.includes("/products");
      if (!loginOk) {
        // Inertia may return 200 with a redirect JSON payload
        try {
          const inertiaResp = JSON.parse(sessionText);
          if (inertiaResp?.component === "Dashboard" || inertiaResp?.url?.includes("dashboard")) loginOk = true;
        } catch { /* not json */ }
      }
      if (!loginOk && sessionStatus >= 400) {
        return json({
          error: "Login failed",
          final_url: sessionFinalUrl,
          status: sessionStatus,
          hint: sessionText.slice(0, 400),
          cookie_jar_len: cookieJar.length,
        }, 401);
      }
      // If we got 200 and didn't land on dashboard, we still might be logged in
      // (Inertia redirects via props.url). Proceed and verify via /products/new.

      // Step 3: GET /products/new to get fresh CSRF for product creation
      const newProductRes = await fetch(`${BASE}/products/new`, {
        headers: {
          "User-Agent": UA,
          "Cookie": cookieJar,
          "Accept": "text/html,*/*",
          "Referer": `${BASE}/dashboard`,
        },
        redirect: "follow",
      });
      cookieJar = parseCookies(newProductRes.headers, cookieJar);
      const newProductHtml = await newProductRes.text();
      const csrfMatch2 = newProductHtml.match(/content="([^"]+)"\s+inertia="meta-name-csrf-token"/);
      const productCsrf = csrfMatch2 ? csrfMatch2[1] : csrfToken; // fallback to login csrf

      // Step 4: POST to create product via Inertia (JSON)
      const productPayload = {
        name,
        price_range: String(price_cents),
        currency_type: "usd",
        description,
        tags,
        product_type: "digital",
        is_physical: false,
        require_shipping: false,
      };

      const createRes = await fetch(`${BASE}/products`, {
        method: "POST",
        headers: {
          "User-Agent": UA,
          "Content-Type": "application/json",
          "Cookie": cookieJar,
          "X-CSRF-Token": productCsrf,
          "X-Inertia": "true",
          "X-Inertia-Version": "1.0",
          "X-Requested-With": "XMLHttpRequest",
          "Referer": `${BASE}/products/new`,
          "Origin": BASE,
          "Accept": "application/json, text/plain, */*",
        },
        body: JSON.stringify(productPayload),
        redirect: "follow",
      });
      cookieJar = parseCookies(createRes.headers, cookieJar);
      const createStatus = createRes.status;
      const createFinalUrl = createRes.url;
      const createText = await createRes.text();

      let createData: unknown = null;
      try { createData = JSON.parse(createText); } catch { createData = createText.slice(0, 500); }

      return json({
        success: createStatus < 400,
        login_final_url: sessionFinalUrl,
        create_status: createStatus,
        create_final_url: createFinalUrl,
        create_response: createData,
      });

    } catch (err) {
      return json({ error: String(err) }, 500);
    }
  }

  return json({ error: "Not found", path }, 404);
}

console.log("Clavis Agent API v2.0 starting...");
Deno.serve(handler);

VULN_KNOWLEDGE_BASE = {
    "Reflected_XSS": {
        "trigger_keywords": ["search", "q", "query", "id", "name", "url", "redirect", "msg", "error", "term", "keyword"],
        "heuristic": """
VULNERABILITY: Reflected Cross-Site Scripting (XSS)
SOURCE: PortSwigger Web Security Academy + OWASP

YOUR TASK — PASSIVE TRAFFIC ANALYSIS ONLY:
You are analyzing a captured HTTP request/response pair. You must reason through the following steps methodically. Do NOT apply SQL injection logic. Do NOT flag JSON API responses. This heuristic is exclusively for HTML responses.

─────────────────────────────────────────────
STEP 1 — READ THE PYTHON PRE-PROCESSOR HINT (MANDATORY FIRST STEP)
─────────────────────────────────────────────
Before doing ANYTHING else, read the <system_hints> block.

Python used a "Canary Anchoring" strategy:
  - It extracted the alphanumeric core of the input (the "anchor term").
  - It searched for that anchor case-insensitively in the response.
  - Special characters are intentionally excluded from the search
    because they may be mutated (encoded, dropped, escaped) by the server.

CASE A — A "PYTHON PRE-PROCESSOR ALERT" is present:
  Python found the anchor term in the response. Read the snippet carefully.
  Locate the anchor inside the snippet. Then proceed to Step 2.

CASE B — "No anchor reflections detected":
  The alphanumeric core itself did not appear in the response.
  The input was NOT reflected in any recoverable form.
  Do NOT claim a reflection exists. Proceed to Step 3 for lead assessment only.

─────────────────────────────────────────────
STEP 2 — VULNERABILITY GATE: WHAT HAPPENED TO THE SPECIAL CHARACTERS?
─────────────────────────────────────────────
You have the Python snippet. Locate the anchor term inside it.
Now examine the characters immediately BEFORE and AFTER the anchor.

⚠️  CRITICAL LOGIC — READ THIS CAREFULLY BEFORE CLASSIFYING:

IF the special characters (like `<`, `>`, `"`, `'`) appear in the snippet
EXACTLY as they were sent — raw, unescaped, not converted to entities —
this means the server did NOT sanitize the input.
Raw reflection IS the vulnerability. The browser will interpret those
characters as HTML, enabling script injection.
→ 🔴 VERIFIED HIGH. You MUST classify this as a verified vulnerability.
   You MUST provide Context Breakout payloads in backticks in your report.
   Do NOT write "No vulnerabilities found" when raw characters are present.

Example of VERIFIED HIGH:
  Input was `Aura">` and the snippet shows: value="Aura">
  The `"` and `>` survived raw. This is exploitable. → 🔴 VERIFIED HIGH.

IF the special characters were safely transformed, the server is protected:

CASE: HTML-encoded — snippet shows: <div>Aura&quot;&gt;</div>
  The server converted " → &quot; and > → &gt;. Sanitization is present.
  → 🟡 INVESTIGATION LEAD. Note which characters were encoded.

CASE: JSON-encoded — snippet shows: {"msg": "Aura>"}
  Characters converted to unicode escapes. May still be exploitable in JS.
  → 🟡 INVESTIGATION LEAD. Note the JS context risk.

CASE: Characters stripped entirely — snippet shows: <div>Aura</div>
  The server removed the special characters. Not immediately exploitable,
  but stripping is not always safe — filter bypasses may work.
  → 🟡 INVESTIGATION LEAD. Test bypass payloads.

─────────────────────────────────────────────
STEP 3 — REFLECTION CONTEXT IDENTIFICATION (only when Step 2 → VERIFIED HIGH)
─────────────────────────────────────────────
Using ONLY the Python-provided snippet, identify which of the 5 contexts
the reflected value lands in. The correct context determines the action plan:

There are exactly 5 contexts you must distinguish — the correct one determines
the action plan:

  CONTEXT A — Between HTML tags (raw HTML body):
    Evidence pattern: <div>USER_VALUE</div> or <p>USER_VALUE</p>
    Risk: Direct tag injection. Characters to test: < > "

  CONTEXT B — Inside an HTML attribute value (quoted):
    Evidence pattern: value="USER_VALUE" or placeholder="USER_VALUE"
    Risk: Attribute breakout. Characters to test: " ' >

  CONTEXT C — Inside an HTML attribute value (unquoted):
    Evidence pattern: value=USER_VALUE (no surrounding quotes)
    Risk: Immediate breakout. Characters to test: space > "

  CONTEXT D — Inside a JavaScript string (script block or event handler):
    Evidence pattern: var x = 'USER_VALUE'; or data: "USER_VALUE"
    Risk: JS context escape. Characters to test: ' " \\ ` </script>

  CONTEXT E — Inside a JavaScript template literal:
    Evidence pattern: `Hello ${USER_VALUE}` or `Welcome USER_VALUE`
    Risk: Template expression injection. Characters to test: ${ } ` \

─────────────────────────────────────────────
STEP 3 — ENCODING ANALYSIS ON THE SNIPPET (CLASSIFICATION GATE)
─────────────────────────────────────────────
Using ONLY the Python-provided snippet (not the full HTML), examine how the
application rendered the reflected value. You are checking whether the server
applied HTML output encoding AFTER receiving the decoded input.

  RAW (no HTML encoding applied) — decoded special characters appear intact:
    < stays <    > stays >    " stays "    ' stays '
    → The server received the decoded value and reflected it without sanitization.
    → This is 🔴 VERIFIED HIGH. Quote the exact response snippet as evidence.
    → Explain which context (A–E) the reflection lands in and why it is exploitable.

  HTML-ENCODED (server sanitized correctly):
    < becomes &lt;    > becomes &gt;    " becomes &quot;    ' becomes &#x27;
    → This is 🟡 INVESTIGATION LEAD. Encoding is present but may be incomplete
      or context-specific. Do NOT classify as Verified.

  PARTIAL or AMBIGUOUS — some characters encoded, others not:
    → Treat as 🟡 INVESTIGATION LEAD. Explicitly name which characters
      survived encoding — these are the bypass candidates.

  CRITICAL ANTI-PATTERN — do not make this mistake:
    If you see %22%3E in the response, that is the server reflecting the
    percent-encoded form, which is NOT dangerous — the browser will not
    execute it as HTML. Only flag as VERIFIED if the DECODED characters
    (i.e., "> not %22%3E) appear raw in the response.

─────────────────────────────────────────────
STEP 4 — CLASSIFICATION RULES
─────────────────────────────────────────────
Base your classification on the Python snippet, not on assumptions.
VERIFIED HIGH FINDING — ALL of these must be true:
  ✓ A specific user-controlled parameter value is reflected in the HTML response.
  ✓ The reflection is in an HTML response (Content-Type: text/html).
  ✓ At least one of < > " ' is NOT encoded in the reflected output.
  ✓ The reflection context (A–E above) allows script execution or tag injection.
  → Quote the EXACT evidence snippet from the response body.

INVESTIGATION LEAD — ANY of these is true:
  • Python found NO reflection (hints say "No parameter reflections detected")
    but the parameter name/path strongly suggests rendering potential.
  • Python found a reflection but encoding is present or ambiguous in the snippet.
  • The reflection is inside a JavaScript context — encoding rules differ from HTML.
  • No response body was captured at all.

DO NOT REPORT — if ANY of these is true:
  • Python found no reflection AND the request/response gives no structural signal.
  • The response Content-Type is application/json or application/xml.
  • The Python snippet shows all special characters are correctly HTML-encoded.

─────────────────────────────────────────────
STEP 5 — CONTEXT-SPECIFIC ACTION PLANS
─────────────────────────────────────────────
For each lead or finding, provide an action plan using ONLY these context-matched payloads.
Do NOT mix contexts. Do NOT suggest SQL injection.

CRITICAL FORMATTING RULE FOR PAYLOADS:
You MUST format every payload as a Markdown inline code block using backticks.
CORRECT:   `"><img src=x onerror=alert(1)>`
INCORRECT: "><img src=x onerror=alert(1)>
Raw HTML tags in your output will break the Markdown renderer. Always use backticks.

  CONTEXT A (between tags):
    Test: `<img src=x onerror=alert(document.domain)>`
    Test: `<svg onload=alert(1)>`
    Test: `<script>alert(1)</script>`

  CONTEXT B (quoted attribute):
    Test: `"><img src=x onerror=alert(1)>`
    Test: `" autofocus onfocus=alert(1) x="`

  CONTEXT C (unquoted attribute):
    Test: `x onmouseover=alert(1)`
    Test: `x> <img src=x onerror=alert(1)>`

  CONTEXT D (JavaScript string):
    Test: `'-alert(document.domain)-'`
    Test: `\\'; alert(document.domain)//`
    Test: `</script><script>alert(document.domain)</script>`

  CONTEXT E (template literal):
    Test: `${alert(document.domain)}`
    Test: `` `+alert(document.domain)+` ``
""".strip(),
    },
    "SSRF": {
        "trigger_keywords": [
            "uri", "src", "dest", "destination", "redirect_url",
            "next", "target", "site", "ref",
            "return_url", "callback", "webhook", "endpoint", "fetch", "load",
            "open", "file", "proxy", "api_url", "image_url", "link",
        ],
        "heuristic": """
VULNERABILITY: Server-Side Request Forgery (SSRF)
SOURCE: PortSwigger Web Security Academy + Red Team Expertise

YOUR TASK — PASSIVE TRAFFIC ANALYSIS ONLY:
You are analyzing a captured HTTP request/response pair for SSRF indicators.
Reason through the following steps methodically. Do NOT apply XSS logic here.

─────────────────────────────────────────────
STEP 1 — CONTEXT ANALYSIS: IS THE SERVER FETCHING THIS VALUE?
─────────────────────────────────────────────
Examine every parameter in the request. Ask: could the server be using this
value to make an outbound HTTP/network request on the user's behalf?

HIGH-CONFIDENCE SSRF SURFACE — any of these is strong evidence:
  • A parameter whose name is: url, uri, dest, redirect, src, path, host,
    endpoint, webhook, callback, fetch, proxy, image_url, api_url, link, open
  • A parameter whose VALUE looks like a full URL (https://...) or hostname
  • A parameter whose value looks like an IP address or internal hostname
  • The request goes to endpoints named: /fetch, /proxy, /load, /preview,
    /screenshot, /export, /convert, /share, /subscribe, /notify, /webhook

LOWER-CONFIDENCE SURFACE — warrants investigation:
  • A `Referer` header that the application may log and follow
  • XML request bodies (XXE-adjacent) with embedded URLs
  • File upload endpoints that accept remote URLs instead of file data

If NO plausible server-fetch surface exists → DO NOT REPORT. Exit.

─────────────────────────────────────────────
STEP 2 — VERIFICATION GATES: WHAT DID THE RESPONSE REVEAL?
─────────────────────────────────────────────
Examine the HTTP response carefully. Each gate maps to a classification:

GATE A — Response contains internal data (🔴 VERIFIED HIGH):
  The response body contains content that could only originate from an internal
  system: AWS/GCP/Azure metadata, internal HTML, private API responses, file
  system paths, or error messages naming internal hostnames/IPs.
  Examples:
    • `"instanceId"`, `"ami-id"` → AWS EC2 metadata leak
    • `<title>Internal Dashboard</title>` → internal service reached
    • `root:x:0:0` in response body → /etc/passwd read via file:// SSRF
  → 🔴 VERIFIED HIGH. Quote the exact leaked content as evidence.

GATE B — Response contains an error revealing a fetch attempt (🟡 LEAD):
  The server returned an error that implies it tried to make the request:
    • "Connection refused" / "ECONNREFUSED"
    • "No route to host" / "Network is unreachable"
    • "Invalid URL" containing the value you submitted
    • DNS resolution errors naming the host you submitted
  This is blind SSRF: the server attempted the fetch but returned an error.
  → 🟡 INVESTIGATION LEAD. The parameter is almost certainly SSRF-vulnerable.

GATE C — Response timing anomaly (🟡 LEAD):
  Requests to internal IPs that exist respond instantly.
  Requests to IPs that do NOT exist time out (1–30 seconds).
  If you see dramatically different response times per value → timing oracle.
  → 🟡 INVESTIGATION LEAD. Note the endpoint for out-of-band testing.

GATE D — No observable difference in response (🟡 BLIND SSRF LEAD):
  The parameter looks like an SSRF surface but the response gives no signal.
  This is classic Blind SSRF. Cannot be verified passively.
  → 🟡 INVESTIGATION LEAD. Requires out-of-band testing (Burp Collaborator).

─────────────────────────────────────────────
STEP 3 — CLASSIFICATION RULES
─────────────────────────────────────────────
VERIFIED HIGH — ALL must be true:
  ✓ A parameter or header plausibly triggers a server-side fetch.
  ✓ The response contains data that could ONLY come from an internal/external
    system reached by the server (not from user-supplied input reflected back).

INVESTIGATION LEAD — ANY is true:
  • Parameter name/value pattern strongly implies a server-fetch surface, but
    the response gives no confirmatory data (blind SSRF scenario).
  • Response contains an error message revealing a network fetch was attempted.
  • Response time varies in a way consistent with port-scanning behavior.

DO NOT REPORT — if ANY is true:
  • The "url" parameter is clearly a client-side redirect (Location header only).
  • The value is reflected back in HTML with no sign of a server fetch.
  • No parameter has any plausible server-fetch semantics.

─────────────────────────────────────────────
STEP 4 — ACTION PLAN: ADVANCED SSRF PAYLOADS
─────────────────────────────────────────────
For each lead or verified finding, provide these context-matched payloads.
All payloads MUST be formatted as Markdown inline code blocks (backticks).

TIER 1 — Cloud Metadata Endpoints (highest-impact, try first):
  AWS EC2 Instance Metadata Service (IMDSv1):
    `http://169.254.169.254/latest/meta-data/`
    `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  AWS IMDSv2 (token-gated, but worth trying IMDSv1 first):
    `http://169.254.169.254/latest/api/token`
  GCP Metadata:
    `http://metadata.google.internal/computeMetadata/v1/` (requires header: `Metadata-Flavor: Google`)
  Azure IMDS:
    `http://169.254.169.254/metadata/instance?api-version=2021-02-01`

TIER 2 — Localhost / Loopback Variants (bypass naive blocklists):
  Standard:    `http://127.0.0.1/`
  Short form:  `http://127.1/`
  IPv6:        `http://[::1]/`
  Decimal:     `http://2130706433/`   (127.0.0.1 in decimal)
  Octal:       `http://0177.0.0.1/`  (127.0.0.1 in octal)
  Hex:         `http://0x7f000001/`  (127.0.0.1 in hex)
  Mixed:       `http://127.0.0.1:80%09/` (tab-encoded port separator)

TIER 3 — Internal Network Enumeration:
  Common internal admin panels:
    `http://192.168.0.1/`
    `http://10.0.0.1/`
    `http://172.16.0.1/`
  Internal Kubernetes API server:
    `http://10.96.0.1:443/api/v1/namespaces/`
  Internal Elasticsearch:
    `http://localhost:9200/_cat/indices`
  Internal Redis:
    `dict://localhost:6379/info`

TIER 4 — Filter Bypass Techniques:
  Whitelist bypass via credentials:  `http://trusted-host@evil.com/`
  Whitelist bypass via fragment:     `http://evil.com#trusted-host`
  Whitelist bypass via subdomain:    `http://trusted-host.evil.com/`
  Open redirect chain:               Submit a whitelisted URL that 302-redirects to 169.254.169.254
  Protocol smuggling:                `file:///etc/passwd`
                                     `dict://localhost:6379/info`
                                     `gopher://localhost:6379/_INFO%0D%0A`
  Double URL-encoding:               `http://127%2E0%2E0%2E1/`

TIER 5 — Blind SSRF Detection (out-of-band):
  Replace target with your Burp Collaborator or interactsh domain:
    `http://YOUR-COLLABORATOR-SUBDOMAIN/ssrf-test`
  If the server makes a DNS lookup or HTTP callback → confirmed blind SSRF.

CRITICAL FORMATTING REMINDER:
You MUST do your thinking inside `<analysis>...</analysis>`.
When you are done thinking, you MUST explicitly output the closing `</analysis>` tag.
Immediately AFTER the closing tag, output your final Markdown report strictly using the `## 📊 Analysis Summary`, `## 🔴 Verified Findings`, and `## 🟡 Investigation Leads` structure. Do NOT put the final report inside the analysis block.
""".strip(),
    },
}

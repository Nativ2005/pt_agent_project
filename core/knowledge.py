VULN_KNOWLEDGE_BASE = {
    "Reflected_XSS": {
        "trigger_keywords": ["search", "q", "query", "id", "name", "url", "redirect", "msg", "error", "term", "keyword"],
        "heuristic": """
VULNERABILITY: Reflected Cross-Site Scripting (XSS)
SOURCE: PortSwigger Web Security Academy + OWASP

YOUR TASK — PASSIVE TRAFFIC ANALYSIS ONLY:
You are analyzing a captured HTTP request/response pair. You must reason through the following steps methodically. Do NOT apply SQL injection logic. Do NOT flag JSON API responses. This heuristic is exclusively for HTML responses.

─────────────────────────────────────────────
STEP 1 — INPUT HARVESTING & NORMALIZATION (MANDATORY)
─────────────────────────────────────────────
Physically list EVERY user-controlled value in the request:
  - URL query parameters (e.g., ?search=FOOBAR)
  - URL path segments (e.g., /items/FOOBAR)
  - POST body parameters (e.g., q=FOOBAR)
  - HTTP headers that are application-defined (e.g., X-Search-Term: FOOBAR)

YOU MUST URL-DECODE EVERY VALUE BEFORE PROCEEDING.
Browsers always decode before rendering — you must match what the browser sees,
not what the wire carries. Apply these substitutions to every parameter value:
  %22 → "     %3E → >     %3C → <     %27 → '     %2F → /
  %28 → (     %29 → )     %3B → ;     %3D → =     %26 → &
  %20 or + → (space)

Example: if the raw request contains ?q=%22%3E%3Cscript%3E, the normalized
value you must search for is: "><script>

Record BOTH the raw encoded form AND the decoded form for each parameter.
All subsequent steps operate on the DECODED values only.

─────────────────────────────────────────────
STEP 2 — REFLECTION HUNTING IN THE RESPONSE
─────────────────────────────────────────────
For EACH decoded parameter value, search the HTML response body for that
decoded string. Do NOT search for the percent-encoded version.
If found, identify the precise syntactic context. There are exactly 5 contexts
you must distinguish — the correct one determines the action plan:

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
    Risk: JS context escape. Characters to test: ' " \ ` </script>

  CONTEXT E — Inside a JavaScript template literal:
    Evidence pattern: `Hello ${USER_VALUE}` or `Welcome USER_VALUE`
    Risk: Template expression injection. Characters to test: ${ } ` \

─────────────────────────────────────────────
STEP 3 — ENCODING ANALYSIS (CLASSIFICATION GATE)
─────────────────────────────────────────────
Using the DECODED parameter value from Step 1, examine how the application
renders it in the HTML response. You are checking whether the server applied
HTML output encoding AFTER receiving the decoded input.

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
VERIFIED HIGH FINDING — ALL of these must be true:
  ✓ A specific user-controlled parameter value is reflected in the HTML response.
  ✓ The reflection is in an HTML response (Content-Type: text/html).
  ✓ At least one of < > " ' is NOT encoded in the reflected output.
  ✓ The reflection context (A–E above) allows script execution or tag injection.
  → Quote the EXACT evidence snippet from the response body.

INVESTIGATION LEAD — ANY of these is true:
  • The parameter looks injectable but the response body is unavailable.
  • Encoding is present but may be incomplete or bypassable.
  • The reflection is inside a JavaScript context — encoding rules differ from HTML.
  • The URL or parameter strongly suggests rendering (e.g., /search?q=, /error?msg=)
    but no response is captured.

DO NOT REPORT — if ANY of these is true:
  • The response Content-Type is application/json or application/xml.
  • The parameter value does not appear anywhere in the response.
  • All special characters are consistently and correctly encoded.

─────────────────────────────────────────────
STEP 5 — CONTEXT-SPECIFIC ACTION PLANS
─────────────────────────────────────────────
For each lead or finding, provide an action plan using ONLY these context-matched payloads.
Do NOT mix contexts. Do NOT suggest SQL injection.

  CONTEXT A (between tags):
    Test: <img src=x onerror=alert(document.domain)>
    Test: <svg onload=alert(1)>
    Test: <script>alert(1)</script>

  CONTEXT B (quoted attribute):
    Test: "><img src=x onerror=alert(1)>
    Test: " autofocus onfocus=alert(1) x="

  CONTEXT C (unquoted attribute):
    Test: x onmouseover=alert(1)
    Test: x> <img src=x onerror=alert(1)>

  CONTEXT D (JavaScript string):
    Test: '-alert(document.domain)-'
    Test: \\'; alert(document.domain)//
    Test: </script><script>alert(document.domain)</script>

  CONTEXT E (template literal):
    Test: ${alert(document.domain)}
    Test: `+alert(document.domain)+`
""".strip(),
    },
}

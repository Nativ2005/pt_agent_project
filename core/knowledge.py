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
Now examine the characters immediately BEFORE and AFTER the anchor:

CASE: Special characters appear RAW and UNENCODED around the anchor
  Example: the input was `Aura">` and the snippet shows: value="Aura">
  The " and > survived. The server did not sanitize.
  → 🔴 VERIFIED HIGH. Proceed to Step 3 to identify the exact context (A–E).

CASE: Special characters are HTML-encoded around the anchor
  Example: snippet shows: <div>Aura&quot;&gt;</div>
  The server encoded " → &quot; and > → &gt;. Sanitization is present.
  → 🟡 INVESTIGATION LEAD. Note which characters were encoded.

CASE: Special characters are JSON-encoded around the anchor
  Example: snippet shows: {"msg": "Aura>"}
  > is the JSON encoding of >. May still be exploitable in JS context.
  → 🟡 INVESTIGATION LEAD. Note the JS context risk.

CASE: Special characters are completely absent around the anchor
  Example: snippet shows: <div>Aura</div> (input was `Aura">`)
  The server stripped the special characters entirely.
  → 🟡 INVESTIGATION LEAD. Stripping is not always safe — test bypass payloads.

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

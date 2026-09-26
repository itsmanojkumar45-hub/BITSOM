"""Finding catalogue: every detection maps to an OWASP Top 10 for LLM Applications
(2025) category, a business-impact statement for a BFSI context, and a
developer-ready fix."""

CATALOG = {
    "instruction_override": {
        "title": "Prompt injection - instruction override",
        "owasp": "LLM01:2025 Prompt Injection",
        "impact": "Attacker rewrites the agent's operating rules; any downstream tool (refund, KYC, transfer) becomes attacker-controlled.",
        "fix": "Keep system rules outside user-controllable context; route all user/RAG text through the Sentinel input gate; never let natural language grant permissions.",
        "snippet": "resp = sentinel.inspect_input(user_msg, channel='user')\nif resp.blocked: return safe_refusal(resp.lang)",
    },
    "role_play": {
        "title": "Jailbreak - persona / privileged-mode request",
        "owasp": "LLM01:2025 Prompt Injection",
        "impact": "Agent is coaxed into an 'admin' or 'manager' persona and skips customer-level restrictions.",
        "fix": "Bind role to the authenticated session token, not to conversation text. Reject persona switches at the gateway.",
        "snippet": "role = session.claims['role']  # never from prompt\npolicy.check(tool, args, role=role)",
    },
    "prompt_leak": {
        "title": "System prompt extraction attempt",
        "owasp": "LLM07:2025 System Prompt Leakage",
        "impact": "Leaked prompts expose internal limits, tool names and escalation paths, making follow-up attacks precise.",
        "fix": "Plant a canary token in the system prompt and block any response containing it; keep no secrets in prompts.",
        "snippet": "if CANARY in response: response = redact_and_alert(response)",
    },
    "bulk_exfiltration": {
        "title": "Bulk customer-data exfiltration request",
        "owasp": "LLM02:2025 Sensitive Information Disclosure",
        "impact": "Mass exposure of Aadhaar/PAN/account data - reportable personal-data breach under the DPDP Act, 2023.",
        "fix": "Agents get record-scoped tools only (own customer id). No list/search-all tools exposed to customer-facing agents.",
        "snippet": "@tool(scope='self')\ndef get_kyc(customer_id=session.customer_id): ...",
    },
    "authority_claim": {
        "title": "Social engineering - authority claim / verification bypass",
        "owasp": "LLM06:2025 Excessive Agency",
        "impact": "Agent is talked out of OTP / step-up verification, enabling account takeover (mobile or email change).",
        "fix": "Step-up auth (OTP) is enforced by the policy engine and cannot be waived by the model or the user's text.",
        "snippet": "policy.require_step_up('update_contact')  # deterministic, not prompt-based",
    },
    "indirect_injection": {
        "title": "Indirect prompt injection in attached document / RAG context",
        "owasp": "LLM01:2025 Prompt Injection",
        "impact": "Instructions hidden in a statement, complaint PDF or knowledge-base page execute with the agent's privileges.",
        "fix": "Treat retrieved/attached content as data: scan it at ingestion, strip instruction-like markup, and never execute tool calls sourced from documents.",
        "snippet": "ctx = sentinel.inspect_input(doc_text, channel='document')\nagent.run(user_msg, context=ctx.sanitised)",
    },
    "obfuscation": {
        "title": "Evasion - script switching / invisible characters / homoglyphs",
        "owasp": "LLM01:2025 Prompt Injection",
        "impact": "Payload is disguised to slip past English keyword filters.",
        "fix": "Normalise (NFKC, strip zero-width, fold homoglyphs, transliterate Indic scripts) before any detection.",
        "snippet": "text = sentinel.normalize(raw).canonical",
    },
    "ml_classifier": {
        "title": "Malicious intent predicted by multilingual classifier",
        "owasp": "LLM01:2025 Prompt Injection",
        "impact": "Message resembles known manipulation patterns even without exact trigger words.",
        "fix": "Keep the on-prem classifier in the loop and retrain it on red-team findings from your own traffic.",
        "snippet": "risk = max(rule_score, clf.predict_proba(text))",
    },
    "policy_bola": {
        "title": "Cross-account access (broken object-level authorisation)",
        "owasp": "LLM06:2025 Excessive Agency",
        "impact": "Agent reads or acts on another customer's account.",
        "fix": "Tool arguments that identify an object are checked against the session owner before execution.",
        "snippet": "assert args['account_id'] in session.owned_accounts",
    },
    "policy_limit": {
        "title": "High-value action above autonomous limit",
        "owasp": "LLM06:2025 Excessive Agency",
        "impact": "Direct financial loss from refunds/transfers approved by the model alone.",
        "fix": "Hard monetary limits per tool; above-limit actions go to a maker-checker human queue.",
        "snippet": "if amount > LIMITS[tool]: return queue_for_approval(call)",
    },
    "policy_stepup": {
        "title": "Sensitive change without step-up authentication",
        "owasp": "LLM06:2025 Excessive Agency",
        "impact": "Mobile/email change is the first step of most account-takeover frauds.",
        "fix": "Contact changes require fresh OTP on the registered device, enforced outside the model.",
        "snippet": "if not session.step_up_ok: deny('update_contact')",
    },
    "policy_beneficiary": {
        "title": "Transfer to unregistered beneficiary",
        "owasp": "LLM06:2025 Excessive Agency",
        "impact": "Funds moved to a mule account.",
        "fix": "Transfers only to pre-registered beneficiaries past their cooling period.",
        "snippet": "assert to in session.beneficiaries",
    },
    "policy_privileged_tool": {
        "title": "Privileged tool requested by customer-facing agent",
        "owasp": "LLM06:2025 Excessive Agency",
        "impact": "Admin-only capability reachable through conversation.",
        "fix": "Do not register admin tools with customer-facing agents at all (least privilege).",
        "snippet": "agent = Agent(tools=CUSTOMER_TOOLS)  # no admin tools",
    },
    "pii_output": {
        "title": "Sensitive identifiers in agent output",
        "owasp": "LLM02:2025 Sensitive Information Disclosure",
        "impact": "Full Aadhaar / PAN / card numbers shown in chat logs and screenshots.",
        "fix": "Mask identifiers at the output gate (Aadhaar last-4 per UIDAI practice, PAN, cards via Luhn).",
        "snippet": "response = sentinel.redact(response)",
    },
    "canary_leak": {
        "title": "System prompt leaked in response",
        "owasp": "LLM07:2025 System Prompt Leakage",
        "impact": "Internal instructions disclosed to the user.",
        "fix": "Canary detection at the output gate; replace response with a safe refusal.",
        "snippet": "if CANARY in response: block()",
    },
}


def make_finding(key: str, layer: str, evidence: str, severity: str = "high") -> dict:
    meta = CATALOG[key]
    return {"id": key, "layer": layer, "severity": severity, "evidence": evidence, **meta}

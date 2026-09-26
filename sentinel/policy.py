"""Deterministic tool-call policy engine.

This is the enforcement boundary. It never looks at the prompt; it only sees
(tool, arguments, authenticated session). So even if a manipulated prompt gets
past every detector, the unsafe action is still blocked before execution.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .findings import make_finding

CUSTOMER_TOOLS = {"get_account_summary", "get_kyc", "issue_refund", "transfer_funds", "update_contact", "faq"}

LIMITS = {"issue_refund": 5000, "transfer_funds": 10000}  # INR, autonomous limit


@dataclass
class Session:
    customer_id: str = "C1001"
    owned_accounts: tuple = ("ACC-1001",)
    beneficiaries: tuple = ("ACC-1002",)
    role: str = "customer"
    step_up_ok: bool = False  # fresh OTP verified in this session?


@dataclass
class Decision:
    allowed: bool
    action: str  # allow | deny | require_approval | require_step_up
    reason: str
    finding: dict | None = None


def check(tool: str, args: dict, s: Session) -> Decision:
    if tool not in CUSTOMER_TOOLS:
        return Decision(False, "deny", f"'{tool}' is not registered for customer-facing agents",
                        make_finding("policy_privileged_tool", "policy-engine", f"tool={tool} role={s.role}", "critical"))

    acct = args.get("account_id")
    if acct and tool in {"get_account_summary", "issue_refund", "transfer_funds"} and acct not in s.owned_accounts:
        return Decision(False, "deny", f"{acct} is not owned by {s.customer_id}",
                        make_finding("policy_bola", "policy-engine", f"{tool}(account_id={acct}) by {s.customer_id}", "critical"))

    cust = args.get("customer_id")
    if tool == "get_kyc" and cust and cust != s.customer_id:
        return Decision(False, "deny", f"KYC of {cust} requested by {s.customer_id}",
                        make_finding("policy_bola", "policy-engine", f"get_kyc(customer_id={cust}) by {s.customer_id}", "critical"))

    if tool == "update_contact" and not s.step_up_ok:
        return Decision(False, "require_step_up", "Contact change needs fresh OTP on registered device",
                        make_finding("policy_stepup", "policy-engine", f"update_contact({args})", "high"))

    if tool == "transfer_funds":
        to = args.get("to_account")
        if to not in s.beneficiaries:
            return Decision(False, "deny", f"{to} is not a registered beneficiary",
                            make_finding("policy_beneficiary", "policy-engine", f"transfer to {to}", "critical"))

    if tool in LIMITS:
        amt = float(args.get("amount") or 0)
        if amt > LIMITS[tool]:
            return Decision(False, "require_approval", f"INR {amt:,.0f} exceeds autonomous limit INR {LIMITS[tool]:,}",
                            make_finding("policy_limit", "policy-engine", f"{tool} amount={amt:,.0f} limit={LIMITS[tool]:,}", "high"))

    return Decision(True, "allow", "within policy")

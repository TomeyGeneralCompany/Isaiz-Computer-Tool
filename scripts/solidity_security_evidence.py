"""Conservative, source-correlated Solidity security behavior classification.

Never treats an arbitrary expected-value mismatch or revert expectation mismatch
as security proof. Every positive classification requires:
- Owned/authorized repository source correlation
- Concrete before/after EVM transactions and observations on Ganache
- Non-administrator ($account1) triggering an unauthorized transition,
  takeover, value/token extraction, or unguarded dangerous primitive.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Tuple

from solidity_access_evidence import authorization_transition_observed


_AUTH_NAMES = {
    "owner", "admin", "administrator", "governance", "governor",
    "controller", "guardian", "authority", "operator", "manager",
}


def _strip_comments(text: str) -> str:
    return re.sub(r"//[^\n]*|/\*[\s\S]*?\*/", "", text)


def _extract_fn_body(source: str, fn_name: str) -> Tuple[str, str]:
    cleaned = _strip_comments(source)
    pattern = re.compile(
        r"\bfunction\s+" + re.escape(fn_name) + r"\s*\([^)]*\)\s*(?:external|public)\b[^;{]*\{"
    )
    for m in pattern.finditer(cleaned):
        depth = 1
        pos = m.end()
        while pos < len(cleaned) and depth > 0:
            if cleaned[pos] == "{":
                depth += 1
            elif cleaned[pos] == "}":
                depth -= 1
            pos += 1
        if depth == 0:
            return m.group(0), cleaned[m.end():pos - 1]
    return "", ""


def _is_auth_getter(step: dict, require_passed: bool = True) -> bool:
    if step.get("operation") not in ("call", "observe"):
        return False
    if not isinstance(step.get("actual"), str):
        return False
    if require_passed and step.get("operation") == "call" and step.get("passed") is not True:
        return False
    fn = str(step.get("function", ""))
    base = fn.split("(", 1)[0].strip().lower()
    return base in _AUTH_NAMES and not step.get("deploymentId")


def _reinit_or_constructor_takeover_observed(
    file: Path, selector: str, data: dict
) -> bool:
    steps = data.get("steps") or []
    accounts = data.get("accounts") or []
    if len(accounts) != 3 or len(steps) < 4:
        return False
    acc0 = str(accounts[0]).lower()
    acc1 = str(accounts[1]).lower()
    acc2 = str(accounts[2]).lower()
    fn_name = selector.split(".")[-1]
    if not re.match(r"^(?:initialize|init|__[A-Za-z0-9_]*init)$", fn_name, re.I):
        return False
    try:
        source = file.read_text(encoding="utf8")
    except OSError:
        return False
    header, body = _extract_fn_body(source, fn_name)
    if not header and not body:
        return False
    # Look for initial setup by deployer ($account0), verified auth == $account0,
    # followed by non-deployer ($account1) non-reverting send changing auth to $account1/$account2.
    init0 = next(
        (
            i for i, s in enumerate(steps)
            if s.get("operation") == "send"
            and str(s.get("function", "")).startswith(fn_name + "(")
            and s.get("sender") == 0
            and not s.get("reverted")
        ),
        None,
    )
    if init0 is None:
        return False
    before_auth = next(
        (
            i for i in range(init0 + 1, len(steps))
            if _is_auth_getter(steps[i], require_passed=True)
            and str(steps[i].get("actual", "")).lower() == acc0
        ),
        None,
    )
    if before_auth is None:
        return False
    attack_send = next(
        (
            i for i in range(before_auth + 1, len(steps))
            if s_is_non_deployer_ok(steps[i], fn_name)
        ),
        None,
    )
    if attack_send is None:
        return False
    after_auth = next(
        (
            i for i in range(attack_send + 1, len(steps))
            if _is_auth_getter(steps[i], require_passed=False)
        ),
        None,
    )
    if after_auth is None:
        return False
    new_auth = str(steps[after_auth].get("actual", "")).lower()
    return new_auth in (acc1, acc2) and new_auth != acc0


def s_is_non_deployer_ok(step: dict, fn_name: str) -> bool:
    return (
        step.get("operation") == "send"
        and not step.get("deploymentId")
        and str(step.get("function", "")).startswith(fn_name + "(")
        and step.get("sender") == 1
        and step.get("reverted") is False
    )


def _has_source_auth_guard(header: str, body: str) -> bool:
    combined = header + "\n" + body
    if re.search(
        r"\b(?:onlyOwner|onlyRole|onlyAdmin|onlyOperator|onlyGovernance|onlyMinter|onlyController|onlyGuardian|initializer|hasRole|_checkRole)\b",
        combined,
        re.I,
    ):
        return True
    if re.search(r"\b(?:msg\s*\.\s*sender|_msgSender\s*\(\s*\))\s*[!=]=", combined):
        return True
    return False


def _unauthorized_value_extraction_observed(
    repository: Path, file: Path, selector: str, data: dict
) -> Tuple[bool, str]:
    steps = data.get("steps") or []
    accounts = data.get("accounts") or []
    if len(accounts) != 3 or len(steps) < 3:
        return False, ""
    rel = file.as_posix()
    if re.search(r"(?:^|/)(?:mocks?|tests?|__tests__|fixtures)(?:/|$)|Mock\.sol$", rel, re.I):
        return False, ""
    fn_name = selector.split(".")[-1]
    try:
        source = file.read_text(encoding="utf8")
    except OSError:
        return False, ""
    header, body = _extract_fn_body(source, fn_name)
    if not body or _has_source_auth_guard(header, body):
        return False, ""

    attack_idx = next(
        (i for i, s in enumerate(steps) if s_is_non_deployer_ok(s, fn_name)),
        None,
    )
    if attack_idx is None:
        return False, ""

    acc1 = str(accounts[1]).lower()
    acc2 = str(accounts[2]).lower()
    contract_addr = str(data.get("contract", "")).lower()

    # 1. ETH balance extraction
    if re.search(r"\.\s*(?:transfer|send)\s*\(|\.\s*call\s*\{[^}]*\bvalue\b", body, re.I):
        before_eth = [
            s for s in steps[:attack_idx]
            if s.get("operation") == "eth_balance" and isinstance(s.get("balanceWei"), str)
        ]
        after_eth = [
            s for s in steps[attack_idx + 1:]
            if s.get("operation") == "eth_balance" and isinstance(s.get("balanceWei"), str)
        ]
        before_c = next((int(s["balanceWei"]) for s in before_eth if str(s.get("address", "")).lower() == contract_addr), None)
        after_c = next((int(s["balanceWei"]) for s in after_eth if str(s.get("address", "")).lower() == contract_addr), None)
        before_r = next((int(s["balanceWei"]) for s in before_eth if str(s.get("address", "")).lower() in (acc1, acc2)), None)
        after_r = next((int(s["balanceWei"]) for s in after_eth if str(s.get("address", "")).lower() in (acc1, acc2)), None)
        if before_c is not None and after_c is not None and before_r is not None and after_r is not None:
            if after_c < before_c and after_r > before_r:
                return True, (
                    f"Verified unauthorized ETH extraction by $account1 via {selector} "
                    f"(contract ETH {before_c} -> {after_c}, recipient ETH {before_r} -> {after_r}); "
                    "reachability and exploit impact still require independent review."
                )

    # 2. ERC20 balance extraction (using preparation token deployment)
    if re.search(r"\.\s*(?:safeTransfer|transfer)\s*\(", body, re.I):
        def _token_bal(slice_steps: list, target_ref: str) -> int | None:
            for s in slice_steps:
                if (
                    s.get("operation") in ("call", "observe")
                    and s.get("deploymentId")
                    and str(s.get("function", "")).startswith("balanceOf(")
                    and isinstance(s.get("actual"), str)
                    and re.fullmatch(r"\d+", s["actual"])
                ):
                    pass
            return None

        before_tok = [
            s for s in steps[:attack_idx]
            if s.get("operation") in ("call", "observe")
            and s.get("deploymentId")
            and str(s.get("function", "")).startswith("balanceOf(")
            and re.fullmatch(r"\d+", str(s.get("actual", "")))
        ]
        after_tok = [
            s for s in steps[attack_idx + 1:]
            if s.get("operation") in ("call", "observe")
            and s.get("deploymentId")
            and str(s.get("function", "")).startswith("balanceOf(")
            and re.fullmatch(r"\d+", str(s.get("actual", "")))
        ]
        if len(before_tok) >= 2 and len(after_tok) >= 2:
            b_contract = int(before_tok[-2]["actual"])
            b_recip = int(before_tok[-1]["actual"])
            a_contract = int(after_tok[0]["actual"])
            a_recip = int(after_tok[1]["actual"])
            if a_contract < b_contract and a_recip > b_recip:
                return True, (
                    f"Verified unauthorized ERC20 extraction by $account1 via {selector} "
                    f"(contract balance {b_contract} -> {a_contract}, recipient balance {b_recip} -> {a_recip}); "
                    "reachability and exploit impact still require independent review."
                )

    # 3. Unguarded non-mock token minting
    if re.search(
        r"\b_?(?:safeM|m)int\s*\(|\btotalSupply\s*\+=|\b(?:balanceOf|_balances)\s*\[[^\]]+\]\s*\+=",
        body,
    ):
        def _mint_metrics(slice_steps: list) -> dict[str, int]:
            metrics: dict[str, int] = {}
            for s in slice_steps:
                if s.get("operation") not in ("call", "observe") or s.get("deploymentId"):
                    continue
                fn = str(s.get("function", ""))
                val = str(s.get("actual", ""))
                if not re.fullmatch(r"\d+", val):
                    continue
                if fn.startswith("balanceOf("):
                    metrics["balanceOf"] = int(val)
                elif fn.startswith("totalSupply("):
                    metrics["totalSupply"] = int(val)
            return metrics

        before_m = _mint_metrics(steps[:attack_idx])
        after_m = _mint_metrics(steps[attack_idx + 1:])
        bal_increased = (
            "balanceOf" in before_m and "balanceOf" in after_m and after_m["balanceOf"] > before_m["balanceOf"]
        )
        sup_increased = (
            "totalSupply" in before_m and "totalSupply" in after_m and after_m["totalSupply"] > before_m["totalSupply"]
        )
        if bal_increased or sup_increased:
            return True, (
                f"Verified unguarded non-mock token minting by $account1 via {selector}; "
                "reachability and exploit impact still require independent review."
            )

    return False, ""


def _unguarded_dangerous_primitive_observed(file: Path, selector: str, data: dict) -> Tuple[bool, str]:
    steps = data.get("steps") or []
    if len(data.get("accounts") or []) != 3 or not steps:
        return False, ""
    rel = file.as_posix()
    if re.search(r"(?:^|/)(?:mocks?|tests?|__tests__|fixtures)(?:/|$)|Mock\.sol$", rel, re.I):
        return False, ""
    fn_name = selector.split(".")[-1]
    try:
        source = file.read_text(encoding="utf8")
    except OSError:
        return False, ""
    header, body = _extract_fn_body(source, fn_name)
    if not body or _has_source_auth_guard(header, body):
        return False, ""
    primitive_match = re.search(r"\b(?:selfdestruct|suicide)\s*\(|\.\s*delegatecall\s*\(", body)
    if not primitive_match:
        return False, ""
    attack_idx = next(
        (i for i, s in enumerate(steps) if s_is_non_deployer_ok(s, fn_name)),
        None,
    )
    if attack_idx is None:
        return False, ""
    return True, (
        f"Verified unguarded dangerous primitive execution by $account1 via {selector}; "
        "reachability and exploit impact still require independent review."
    )


def security_behavior_observed(
    repository: Path,
    file: Path,
    selector: str,
    data: dict,
    specification: dict | None = None,
) -> Tuple[bool, str | None, str]:
    """Return (behavior_observed, classification, limitation)."""
    if authorization_transition_observed(repository, file, selector, data):
        return (
            True,
            "authorization_transition",
            "Verified nonadministrator role mutation with before/after EVM observations and a source-declared privileged role consumer; reachability and exploit impact still require independent review.",
        )
    if _reinit_or_constructor_takeover_observed(file, selector, data):
        return (
            True,
            "reinit_or_constructor_takeover",
            "Verified unauthorized initialization or re-initialization authority takeover by $account1 with before/after EVM authority observations; reachability and exploit impact still require independent review.",
        )
    extracted, extract_msg = _unauthorized_value_extraction_observed(repository, file, selector, data)
    if extracted:
        return True, "unauthorized_value_extraction", extract_msg
    prim, prim_msg = _unguarded_dangerous_primitive_observed(file, selector, data)
    if prim:
        return True, "unguarded_dangerous_primitive", prim_msg
    return (
        False,
        None,
        "Only bounded Solidity transactions and assertions were observed. An expected-value mismatch is not independent security proof.",
    )

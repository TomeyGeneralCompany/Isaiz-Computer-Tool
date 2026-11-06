"""Conservative, source-correlated authorization-transition observation.

Does not treat a caller-provided expected value or arbitrary ABI assertion as proof.
Requires on-chain receipt, before/after role getter, privileged role consumer,
and a nonadministrator caller, all from owned/authorized repository files.
"""
from pathlib import Path
import re


def authorization_transition_observed(repository: Path, file: Path, selector: str, data: dict) -> bool:
    try:
        source=file.read_text(encoding="utf8")
        steps=data["steps"]
        accounts=data["accounts"]
        if len(accounts)!=3 or len(steps)<3 or len(source)>256000:
            return False
        function=selector.split(".")[-1]
        if not re.fullmatch(r"[A-Za-z_]\w*",function):
            return False
        decl=re.search(r"\bfunction\s+"+re.escape(function)+r"\s*\([^)]*\)\s*(?:external|public)\b[^;{]*\{",source)
        if not decl:
            return False
        body=source[decl.end():source.find("}",decl.end())]
        # A direct role-state assignment, with no caller authorization check
        # in this method. Do not pretend that absence of a check alone is proof.
        assignment=re.search(r"\b([A-Za-z_]\w*)\s*=\s*[A-Za-z_]\w*\s*;",body)
        if not assignment or re.search(r"msg\s*\.\s*sender|onlyOwner|onlyRole|onlyAdmin|onlyOperator|hasRole",decl.group(0)+body):
            return False
        role=assignment.group(1)
        if role.lower() not in {"operator","owner","administrator","admin","manager","guardian","controller","authority"}:
            return False
        if not re.search(r"\baddress\s+public\s+"+re.escape(role)+r"\s*;",source):
            return False
        # Source proof that this variable acts as a privileged authority.
        # Search only bounded .sol files in the same checked-out repository.
        privileged=False
        count=0
        for candidate in repository.rglob("*.sol"):
            count+=1
            if count>200:
                break
            if candidate.stat().st_size>256000:
                continue
            text=candidate.read_text(encoding="utf8")
            if re.search(r"\brequire\s*\(\s*msg\s*\.\s*sender\s*==\s*"+re.escape(role)+r"\b",text):
                privileged=True
                break
        if not privileged:
            return False
        role_getter=role+"()"
        before=next((i for i,s in enumerate(steps) if s.get("operation")=="observe"
                     and s.get("function")==role_getter),None)
        send=next((i for i,s in enumerate(steps) if s.get("operation")=="send"
                   and s.get("function","").startswith(function+"(")
                   and s.get("sender")==1 and not s.get("reverted") and s.get("passed")),None)
        if before is None or send is None or before>=send:
            return False
        after=next((i for i in range(send+1,len(steps)) if steps[i].get("operation")=="observe"
                    and steps[i].get("function")==role_getter),None)
        if after is None:
            return False
        prior=str(steps[before]["actual"]).lower()
        changed=str(steps[after]["actual"]).lower()
        return prior==str(accounts[0]).lower() and changed==str(accounts[2]).lower() and prior!=changed
    except (OSError,KeyError,TypeError,ValueError):
        return False

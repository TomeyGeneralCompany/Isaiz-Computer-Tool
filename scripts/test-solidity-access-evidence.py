#!/usr/bin/env python3
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from solidity_access_evidence import authorization_transition_observed


class TestSolidityAccessEvidence(unittest.TestCase):
    def test_source_grounded_nonadmin_role_change(self):
        with tempfile.TemporaryDirectory(prefix="lotus-solidity-evidence-") as directory:
            root=Path(directory)
            authority=root/"Authority.sol"
            authority.write_text("""pragma solidity ^0.8.20;
contract Authority {
address public administrator;address public operator;
constructor(){administrator=msg.sender;operator=msg.sender;}
function rotateOperator(address next) external {require(next!=address(0),"zero");operator=next;}
function changeAdministrator(address next) external {
require(msg.sender==administrator,"admin");administrator=next;
}
}""")
            consumer=root/"Vault.sol"
            consumer.write_text("""pragma solidity ^0.8.20;
contract Vault {address public operator;
function settle() external {require(msg.sender==operator,"operator only");}
}""")
            a=["0x"+"11"*20,"0x"+"22"*20,"0x"+"33"*20]
            steps=[
                {"operation":"observe","function":"operator()","actual":a[0]},
                {"operation":"send","function":"rotateOperator(address)","sender":1,"passed":True,"reverted":False},
                {"operation":"observe","function":"operator()","actual":a[2]}
            ]
            d={"accounts":a,"steps":steps}
            self.assertTrue(authorization_transition_observed(root,authority,"Authority.rotateOperator",d))
            external_source=authority.read_text()
            public_source=external_source.replace(
                'rotateOperator(address next) external',
                'rotateOperator(address next) public')
            authority.write_text(public_source)
            self.assertTrue(authorization_transition_observed(root,authority,"Authority.rotateOperator",d),
                "A public function is externally callable and must receive the same evidence test")
            authority.write_text(public_source.replace(
                'rotateOperator(address next) public',
                'rotateOperator(address next) public onlyOwner'))
            self.assertFalse(authorization_transition_observed(root,authority,"Authority.rotateOperator",d),
                "Role-guarded Solidity modifiers must defeat this unguarded-mutation hypothesis")
            authority.write_text(external_source)
            self.assertFalse(authorization_transition_observed(root,authority,"Authority.rotateOperator",
                {"accounts":a,"steps":[steps[0],dict(steps[1],reverted=True),steps[2]]}))
            consumer.unlink()
            self.assertFalse(authorization_transition_observed(root,authority,"Authority.rotateOperator",d),
                "a public setter without independent evidence of a protected role is not a verified security issue")
            consumer.write_text("contract Vault {function settle() external {require(msg.sender==operator);}}")
            authority.write_text(authority.read_text().replace('require(next!=address(0),"zero");operator=next;',
              'require(msg.sender==administrator,"admin");operator=next;'))
            self.assertFalse(authorization_transition_observed(root,authority,"Authority.rotateOperator",d))


    def test_privileged_consumer_in_late_source_file(self):
        with tempfile.TemporaryDirectory(prefix="lotus-solidity-index-scale-") as directory:
            root=Path(directory)
            for i in range(240):
                (root/("Unrelated%04d.sol"%i)).write_text(
                    "pragma solidity ^0.8.20; contract Unrelated%04d {}"%i)
            target=root/"Service2048.sol"
            target.write_text("""pragma solidity ^0.8.20;
contract Service2048 {
address public administrator;
address public operator;
constructor(){administrator=msg.sender;operator=msg.sender;}
function rotateOperator(address candidate) public {
require(candidate!=address(0),"zero");operator=candidate;
}
function settle(address receiver,uint256 amount) external {
require(msg.sender==operator,"operator only");
}
}""")
            accounts=["0x"+"11"*20,"0x"+"22"*20,"0x"+"33"*20]
            events=[
                {"operation":"observe","function":"operator()","actual":accounts[0]},
                {"operation":"send","function":"rotateOperator(address)","sender":1,"passed":True,"reverted":False},
                {"operation":"observe","function":"operator()","actual":accounts[2]}
            ]
            self.assertTrue(authorization_transition_observed(
                root,target,"Service2048.rotateOperator",
                {"accounts":accounts,"steps":events}),
                "The tested source must not be excluded by the first-200-file scan")


if __name__=="__main__":
    unittest.main()

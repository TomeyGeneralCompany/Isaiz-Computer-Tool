# Overnight investigation evidence — October 24–25, 2026

Source: user-provided diagnostic ZIP collected at 2026-10-25T13:34:24Z. Collection reported no errors. Associations below use a unique final model-response timestamp within two seconds of the persisted coverage outcome; they are timestamp correlations, not run IDs.

| Program | Recorded stopping outcome | Read operations / distinct paths | Probe requests |
|---|---|---|---|
| Berachain | Local audit reached its 80-turn inspection limit | 76 / 5 | 0 |
| Avail | Ollama returned empty final response | 20 / 7 | 0 |
| Marinade | Source capability preflight: No runnable Python, JavaScript, Java or Solidity sources found | No uniquely associated model log | Not established from model log |
| TermMax | Local audit reached its 80-turn inspection limit | 11 / 7 | 0 |
| 88mphV3 | Local audit reached its 80-turn inspection limit | 79 / 2 | 0 |
| Deri Protocol | Local audit reached its 80-turn inspection limit | 75 / 6 | 0 |
| Alpen Labs | Ollama returned empty final response | 20 / 2 | 0 |
| Coinbase | Ollama returned empty final response | 21 / 7 | 0 |
| TRON DAO | Partial inspection; model reported no compatible probe candidate after one Java file | 9 / 1 | 0 |

## Conclusions supported by the records

- TRON was not a completed test campaign: nine page reads covered AbstractActuator.java; no probe was requested. The model’s broad statement about other source is not independently verified. Persisted coverage correctly says partial; the old dashboard label hid that distinction.
- TermMax repeatedly requested the nonexistent `contracts/interfaces/ITermMaxMarketV2.sol`; only 11 reads succeeded. Missing-path errors were not covered by the duplicate-success guard. The repair gives corrective navigation feedback and ends incomplete after three requests for the same missing path, instead of consuming 80 turns.
- Four runs reached 80 turns; three ended with empty final responses. No completed test campaign is established for these runs.
- Configuration, deployment, fixture and library reads dominated some early source selection. Ranking source hints and using Solidity outlines targets this without excluding those files.
- Reads as small as 128–451 characters came from the conservative page estimate. The exact serialized exchange fitter already enforces the budget; the new candidate-page estimate uses available space with that same fitter, context limit and output reservation.
- 110 assessments were saved, versus 69 in the preceding diagnostic: the 41-program queue completed. The retained data does not explain the earlier fall from the prior displayed assessment count. It cannot prove a particular user action or database replacement caused it.
- Normal restart persistence is tested in a fresh process. Source review also found stale assessment writes could overwrite concurrent metadata, and explicit Reassess discarded unrelated summary fields. Both are repaired; neither is asserted as the proven cause of the earlier count drop.
- Daily dispatch paused at 8/8 according to its configured quota. This is a separate scheduling rule, not an inference stall. The existing quota is retained.

## Validation boundaries

Report generation, source evidence, independent replay and submission serialization are tested with owned fixtures and a mock destination. No live submission is made by these checks. The new blind reasoning harness includes a vulnerable and a clean case, randomized filenames/functions and grading held outside model context. Scripted harness success does not establish Qwen reasoning ability. Running it against the actual laptop model is still required.

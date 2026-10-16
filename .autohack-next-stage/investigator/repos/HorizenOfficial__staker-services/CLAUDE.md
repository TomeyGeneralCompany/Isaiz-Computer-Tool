Read the README.md for a description of the folder contents.

For the project https://github.com/HorizenOfficial/staker you must:
- base the work on the branch: dev (merges to main at the v1 mainnet go-live)
- see the file docs/frontend-integration.md for an explanation of the features that must be provided by the UX

# General hints

Use an harmonic graphic, style and positions of the commands across all sections.
Use english language everywhere.

# Architecture

**No custom backend.** The frontend reads from two sources directly:
- **Subgraph (GraphQL)** — all indexed / historical data: the live `Deposit`
  entity (id, owner, delegatee, claimer, stakedAmount, earningPower, timestamps)
  plus immutable event history. Solves the "deposit IDs are not enumerable
  on-chain" problem. Assumed already deployed (its deployment is **not** part of
  this repo); the frontend only consumes the `SUBGRAPH` endpoint. Reference
  entity shapes in `staker/subgraphs/schema.graphql`.
- **Chain (ethers v6 RPC)** — live values the subgraph can't hold:
  `unclaimedReward(depositId)` (accrues per block) and `getGlobalState()`
  (`rewardRate` / `rewardPerTokenAccumulated`), plus all write transactions.

Source split per need:
| Need | Source |
|---|---|
| Deposit IDs + per-deposit balance/delegatee/claimer/earningPower | Subgraph `deposits(where:{owner})` |
| Activity / history feed | Subgraph event entities |
| Reward distribution history (APY chart) | Subgraph `RewardNotifiedEvent` |
| Live unclaimed rewards | Chain `unclaimedReward` / `getDepositorFullSummary` |
| Global state (total staked, reward rate, end time) | Chain `getGlobalState` |
| All writes (stake, withdraw, claim, alter…) | Chain (signed) |

Anything the user is about to sign against (e.g. withdraw max) should be
confirmed with a live `getDepositInfo` read, not the subgraph snapshot.

A **subgraph health check** (`useSubgraphHealth` / `SubgraphHealthBanner`)
compares the subgraph's indexed head to the chain head and warns on stale,
desynced (ahead → chain restarted), indexing-error, or unreachable states — no
silent fallback. This catches the devnet "anvil restarted, graph-node not reset"
case.

# Dev environment

To run the system locally, the `staker/devnet/` docker-compose stack (anvil chain `31337` + graph-node +
auto-deployed contracts & subgraph) can be used. Restarting anvil yields a fresh chain with
deterministic addresses that stay the same across clean restarts. Deployed
addresses live in `staker/broadcast/DeployZenStakerTestnet.s.sol/31337/run-latest.json`.

Config (`frontend/.env.template`), points at the devnet — values the browser needs are
mirrored to `NEXT_PUBLIC_*` via `next.config.ts` (wallet/contract calls run
client-side). Copy the file to frontend/.env before first run. 

# Deployment

The frontend is a fully client-side dApp, built as a **static export**
(`output: "export"` in `next.config.ts`) → `next build` emits a static `out/`
folder, deployed as static assets on **Cloudflare Pages** (no server / edge
runtime). `next dev` ignores the export setting, so local devnet runs are
unaffected; `next start` is not used (run `npm run serve` to preview the static
build locally). Server-side `redirect()` is unavailable in export, so `/stake`
and `/deposits` redirect client-side (`/stake` also via `public/_redirects` at
the CDN edge). Env vars are inlined at build time, so they must be set in the
Cloudflare build environment and must point at **public HTTPS** endpoints (a
deployed HTTPS site cannot reach `http://localhost`). See the README for the
full Cloudflare setup.

# Design choices

**Delegation is NOT surfaced in v1.** Each deposit's delegatee (and claimer)
defaults silently to the user's own address — no delegatee input, no
"change delegatee" action.

## Single-position UX (flag `SINGLE_POSITION`, default true)

The underlying Staker contract supports multiple deposits per address, but those
only matter when deposits differ in delegatee, claimer, or earning power. In v1
delegation and claimer are not surfaced and the IdentityEarningPowerCalculator
makes earning power == balance, so multiple deposits carry no user benefit.

Therefore the frontend presents a **single aggregated position**:
- "Stake" creates a deposit if the user has none, otherwise calls `stakeMore` on
  the existing one ("Add to Stake").
- "My Deposits" shows one Position card; if more than one deposit exists (legacy
  or created elsewhere) it falls back to the multi-deposit table.
- Set `SINGLE_POSITION=false` to expose the full multi-deposit model. This will
  be needed once per-deposit delegation is surfaced.

When `SINGLE_POSITION` is true the whole UX collapses onto the **dashboard**:
there is no "Stake" tab and no "My Stake" tab. The position lives in the "Your
Position" section, where "My Staked" has **Add Stake** + **Withdraw** buttons and
"Unclaimed Rewards" has a **Claim** button, all opening dialogs. The "Stake" tab
is removed in every mode (staking is always a dashboard dialog); the multi-deposit
table at `/deposits` is only reachable when `SINGLE_POSITION=false`. `/stake` and
(in single mode) `/deposits` redirect to `/`.

"Earning power" is hidden from the UX while `SINGLE_POSITION` is true: under the
IdentityEarningPowerCalculator it always equals the staked amount, so it is
redundant. It is shown again in the multi-deposit model (flag false), where a
non-identity calculator (e.g. binary eligibility) could make it diverge.

The create-vs-increase decision must not rely on the subgraph alone (it lags
indexing). Use the session "learned deposits" store — the deposit id parsed from
each stake receipt — so a just-created deposit is known immediately.
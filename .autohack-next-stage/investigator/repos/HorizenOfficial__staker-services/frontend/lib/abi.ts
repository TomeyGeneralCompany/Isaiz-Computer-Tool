// Curated ABIs — only what the stake flow needs, plus the custom errors so
// ethers v6 can decode reverts automatically.

export const ZEN_TOKEN_ABI = [
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "function balanceOf(address) view returns (uint256)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function nonces(address owner) view returns (uint256)",
  "function approve(address spender, uint256 amount) returns (bool)",
  // public mint on the dev mock token — useful to fund a test wallet
  "function mint(address account, uint256 amount)",
] as const;

export const ZEN_STAKER_ABI = [
  // stake has two overloads — ethers needs the explicit signature to disambiguate
  "function stake(uint256 _amount, address _delegatee) returns (uint256 _depositId)",
  "function stake(uint256 _amount, address _delegatee, address _claimer) returns (uint256 _depositId)",
  "function permitAndStake(uint256 _amount, address _delegatee, address _claimer, uint256 _deadline, uint8 _v, bytes32 _r, bytes32 _s) returns (uint256 _depositId)",
  "function getGlobalState() view returns (uint256 totalStaked_, uint256 totalEarningPower_, uint256 rewardRate_, uint256 rewardEndTime_, uint256 lastCheckpointTime_, uint256 rewardPerTokenAccumulated_)",
  "function getDepositorSummary(address _depositor) view returns (uint256 totalStaked_, uint256 totalEarningPower_)",
  "function getDepositorFullSummary(address _depositor, uint256[] _depositIds) view returns (uint256 totalStaked_, uint256 totalEarningPower_, uint256 totalUnclaimedRewards_)",
  "function getDepositsInfo(uint256[] _depositIds) view returns (uint96[] balances, address[] owners, uint96[] earningPowers, uint256[] unclaimedRewards)",
  "function unclaimedReward(uint256 _depositId) view returns (uint256)",
  "function stakeMore(uint256 _depositId, uint256 _amount)",
  "function withdraw(uint256 _depositId, uint256 _amount)",
  "function claimReward(uint256 _depositId) returns (uint256)",
  "event StakeDeposited(address indexed owner, uint256 indexed depositId, uint256 amount, uint256 depositBalance, uint256 earningPower)",
  "event StakeWithdrawn(address indexed owner, uint256 indexed depositId, uint256 amount, uint256 depositBalance, uint256 earningPower)",
  "event RewardClaimed(uint256 indexed depositId, address indexed claimer, uint256 amount, uint256 earningPower)",
  // custom errors (subset relevant to staking) for auto-decode
  "error Staker__InvalidAddress()",
  "error Staker__Unauthorized(bytes32 reason, address caller)",
  "error Staker__InvalidRewardRate()",
  "error Staker__ExpiredDeadline()",
  "error Staker__InvalidSignature()",
  "error StakerPermitAndStake__UnauthorizedToken()",
] as const;

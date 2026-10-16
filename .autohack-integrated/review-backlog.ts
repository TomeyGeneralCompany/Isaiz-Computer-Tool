import 'dotenv/config';
import { processAdversarialQueue } from '@bounty/security-solver';
import { loadConfig } from '@bounty/core';
loadConfig();
await processAdversarialQueue();

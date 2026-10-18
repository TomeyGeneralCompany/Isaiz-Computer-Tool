import "dotenv/config";
import { checkHackerOneAccess } from "../packages/security-discovery/src/provider-preflight";
const result = await checkHackerOneAccess(process.env.HACKERONE_USERNAME || "", process.env.HACKERONE_API_TOKEN || "");
console.log(JSON.stringify(result));
process.exitCode = result.passed ? 0 : 1;

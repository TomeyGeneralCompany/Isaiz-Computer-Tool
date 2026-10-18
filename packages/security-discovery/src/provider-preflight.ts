/** One bounded, read-only account request. Never lists target assets or submits. */
export async function checkHackerOneAccess(username: string, token: string): Promise<{
  passed: boolean; detail: string;
}> {
  if (!username || !token) return {passed:false, detail:"Set HACKERONE_USERNAME and HACKERONE_API_TOKEN in .env"};
  try {
    const response = await fetch("https://api.hackerone.com/v1/hackers/programs?page%5Bsize%5D=1", {
      method:"GET", redirect:"error", signal:AbortSignal.timeout(15_000),
      headers:{Accept:"application/json", Authorization:"Basic " + Buffer.from(username+":"+token).toString("base64")},
    });
    if (!response.ok) {
      await response.body?.cancel();
      const advice = response.status === 401 ? "Credentials rejected; replace the username/token pair" :
        response.status === 403 ? "Account lacks permission for the Hacker API" :
        response.status === 429 ? "Provider rate limit; retry later" : "Provider unavailable; retry later";
      return {passed:false, detail:`HackerOne HTTP ${response.status}. ${advice}`};
    }
    // Successful authorization is sufficient; do not retain account/program data.
    await response.body?.cancel();
    return {passed:true, detail:"HackerOne authenticated read access succeeded; submission permission is not established"};
  } catch {
    return {passed:false, detail:"HackerOne connection failed, timed out, or redirected; check host connectivity"};
  }
}

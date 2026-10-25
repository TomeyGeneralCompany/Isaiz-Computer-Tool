/** Child-process fixture helper; parent supplies an isolated database and mock endpoint. */
import {appRouter} from '../packages/dashboard/src/server/router';
console.log('RESTART_RESULT='+JSON.stringify(await appRouter.createCaller({}).securityAnalyzePrograms()));

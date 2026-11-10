// Isolated test process: transport never contacts Telegram or exposes payload.
import { databaseSettings } from "../../src/server/config.ts";
import { openDatabase } from "../../src/server/database.ts";
import { acquireWorker } from "../../src/server/telegram/model.ts";
import { TelegramDeliveryWorker } from "../../src/server/telegram/worker.ts";
const db=openDatabase(databaseSettings());const now=Number(process.env.TELEGRAM_TEST_NOW);
setInterval(()=>{},1000); // parent must terminate this isolated fixture with SIGKILL
if(!Number.isSafeInteger(now)||!acquireWorker(db,'crash-fixture',now))throw new Error('FIXTURE_NOT_READY');
const api={getMe:async()=>({ok:true,value:{id:123456,username:'FixtureBot'}}),getUpdates:async()=>({ok:true,value:[]}),
  send:()=>new Promise(()=>{setImmediate(()=>process.stdout.write('CLAIM_COMMITTED\n'));})};
await new TelegramDeliveryWorker(db,'crash-fixture',api,()=>now).dispatch();

// Local OS-authorized operator only. No public endpoint or invitation/token stdout.
import { closeSync, constants, openSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { databaseSettings } from "../src/server/config.ts";
import { openDatabase, privateDirectory, privateFile } from "../src/server/database.ts";
import { TelegramAdministration } from "../src/server/telegram/admin.ts";
import { createInvite, telegramState, TelegramModelError } from "../src/server/telegram/model.ts";
import { loadTelegramConfiguration, telegramConfigPath } from "../src/server/telegram/config.ts";
import { manageTelegram } from "../src/server/telegram/management.ts";
import { expireTelegramJobs } from "../src/server/telegram/worker.ts";

let db;
try {
  const [command, ...args] = process.argv.slice(2); const options = {};
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (!["--local-operator", "--recipient", "--details-file", "--invite-file"].includes(key) || key in options) throw new Error();
    if (key === "--local-operator") options[key] = true;
    else { if (!args[i + 1] || args[i + 1].startsWith("--")) throw new Error(); options[key] = args[++i]; }
  }
  if (command === "manage") {
    if (options["--local-operator"] !== true) throw new Error();
    const chunks=[]; let size=0; for await (const chunk of process.stdin) { size+=chunk.length; if(size>8192)throw new Error();chunks.push(chunk); }
    const input=JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!input || typeof input!=="object" || Array.isArray(input) || !["plan","configure","bootstrap","diagnose"].includes(input.operation) || Object.keys(input).some(k=>!["operation","token","confirmation","expected"].includes(k)))throw new Error();
    const settings=databaseSettings();privateFile(settings.path);db=openDatabase(settings);
    const result=await manageTelegram(db,settings.path,input.operation,input);
    console.log(JSON.stringify({status:"OK",...result}));
  } else {
  if (!["status", "bootstrap-owner", "invite", "renew", "enable", "disable", "recipient-on", "recipient-off", "revoke", "test"].includes(command)) throw new Error();
  const settings = databaseSettings(); privateFile(settings.path); db = openDatabase(settings);
  // The local OS account owns the private DB/directory. The nologin service UID
  // is reached by an authorized operator, not by a browser/Telegram command.
  if (command !== "status" && options["--local-operator"] !== true) throw new Error();
  const admin = new TelegramAdministration(db, async () => ({ authenticated: true, subject: `local-os:${process.getuid()}`, permissions: ["telegram:manage"] }));
  if (["bootstrap-owner", "invite", "renew"].includes(command)) {
    const file = options["--invite-file"];
    if (typeof file !== "string" || !isAbsolute(file) || !relative(process.cwd(), resolve(file)).startsWith(`..${sep}`)) throw new Error();
    privateDirectory(dirname(file));
    let name = "Владелец";
    if (command === "invite") {
      const details = options["--details-file"]; if (typeof details !== "string") throw new Error();
      privateFile(details); const text = readFileSync(details); if (text.length > 4096) throw new Error();
      const value = JSON.parse(text); if (Object.keys(value).join(",") !== "displayName") throw new Error(); name = value.displayName;
    }
    const invite = command === "bootstrap-owner" ? createInvite(db, name, Date.now(), undefined, true) :
      command === "invite" ? await admin.invite(name) : await admin.renew(options["--recipient"]);
    const fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { writeFileSync(fd, invite.link + "\n"); } finally { closeSync(fd); }
    console.log(JSON.stringify({ recipientId: invite.recipientId, expiresAt: invite.expiresAt, invitationWritten: true }));
  } else if (command === "status") {
    expireTelegramJobs(db, Date.now());
    const state = telegramState(db);
    let configurationReady=false;try { loadTelegramConfiguration(telegramConfigPath(settings.path)); configurationReady=true; } catch {}
    console.log(JSON.stringify({ enabled: !!state.enabled, botReady: !!state.bot_username,
      configurationReady, runtime: await admin.status(),
      recipients: db.prepare("SELECT id,connection_status,active FROM telegram_recipients ORDER BY created_at,id").all(),
      queue: db.prepare("SELECT status,count(*) AS count FROM telegram_outbox GROUP BY status").all(),
      errors: db.prepare("SELECT last_error,count(*) AS count FROM telegram_outbox WHERE status='failed' GROUP BY last_error").all() }));
  } else if (command === "enable" || command === "disable") { await admin.enabled(command === "enable"); console.log("Telegram notification setting saved"); }
  else if (command === "recipient-on" || command === "recipient-off") { await admin.active(options["--recipient"], command === "recipient-on"); console.log("Telegram recipient setting saved"); }
  else if (command === "revoke") { await admin.revoke(options["--recipient"]); console.log("Telegram access revoked"); }
  else if (command === "test") console.log(JSON.stringify({ testJobId: await admin.test(options["--recipient"]) }));
  }
} catch (error) {
  const safe=new Set(["OWNER_ALREADY_BOOTSTRAPPED","BOT_NOT_READY","RECIPIENT_NOT_FOUND","INVITATION_REQUIRED","RECIPIENT_OR_NOTIFICATIONS_DISABLED","AUTHORIZATION_REQUIRED","INVALID_RECIPIENT_NAME","TELEGRAM_STORAGE_UNAVAILABLE","TOKEN_REQUIRED","AUTH_INVALID","CONCURRENT_POLLING","INVALID_BOT_RESPONSE","BOT_CHANGED_RELINK_REQUIRED","INSTANCE_MISMATCH","CONFIGURATION_PLAN_CHANGED","BOOTSTRAP_CONFIRMATION_INVALID","NETWORK_UNCERTAIN","TEMPORARY_FAILURE","RATE_LIMITED","WEBHOOK_CONFIGURED","WEBHOOK_STATE_UNCONFIRMED"]);
  const code=error instanceof TelegramModelError && safe.has(error.code) ? error.code : "COMMAND_REJECTED";
  if(process.argv[2]==="manage") console.log(JSON.stringify({status:"FAILED",code}));else console.error("Telegram command failed: "+code);process.exitCode=1;
}
finally { db?.close(); }

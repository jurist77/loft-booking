import "server-only";
import { appMode } from "../lib/app-mode.ts";
import { getDatabasePool } from "./database.ts";

export async function databaseHealth(): Promise<Response> {
  const headers = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };
  if (appMode(process.env.APP_MODE) !== "server") return Response.json({ status: "not_found" }, { status: 404, headers });
  try {
    await getDatabasePool().query("SELECT 1 AS ok");
    return Response.json({ status: "ok" }, { status: 200, headers });
  } catch {
    return Response.json({ status: "unavailable" }, { status: 503, headers });
  }
}

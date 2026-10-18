export type AppMode = "demo" | "server";

export function appMode(value: string | undefined): AppMode {
  if (value === undefined || value === "demo") return "demo";
  if (value === "server") return "server";
  throw new Error("APP_MODE must be demo or server");
}

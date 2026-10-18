import { randomBytes } from "node:crypto";
import { writeFile } from "node:fs/promises";

for (const [file, kind, port] of [[".env.local", "dev", 54329], [".env.test.local", "test", 54330]]) {
  const database = `studio1925_${kind}`;
  const prefix = `studio_${kind}`;
  const password = () => randomBytes(24).toString("hex");
  const bootstrap = password(); const app = password(); const migration = password();
  const appURL = `postgresql://${prefix}_app:${app}@127.0.0.1:${port}/${database}?sslmode=disable`;
  const migrationURL = `postgresql://${prefix}_migrator:${migration}@127.0.0.1:${port}/${database}?sslmode=disable`;
  const env = {
    APP_MODE: "server", POSTGRES_DB: database, POSTGRES_PORT: port,
    POSTGRES_USER: `${prefix}_bootstrap`, POSTGRES_PASSWORD: bootstrap,
    POSTGRES_APP_USER: `${prefix}_app`, POSTGRES_APP_PASSWORD: app,
    POSTGRES_MIGRATION_USER: `${prefix}_migrator`, POSTGRES_MIGRATION_PASSWORD: migration,
    DATABASE_URL: appURL, MIGRATION_DATABASE_URL: migrationURL,
    DB_POOL_MAX: 5, DB_CONNECT_TIMEOUT_MS: 2000, DB_QUERY_TIMEOUT_MS: 2000, MIGRATION_QUERY_TIMEOUT_MS: 30000,
    ...(kind === "test" ? { TEST_DATABASE_URL: appURL, TEST_MIGRATION_DATABASE_URL: migrationURL } : {}),
  };
  try {
    await writeFile(file, "# Generated for LOCAL development/testing only; never commit.\n" + Object.entries(env).map(([key, value]) => `${key}=${value}`).join("\n") + "\n", { flag: "wx", mode: 0o600 });
    console.log(`Created ${file}; local credentials are not printed`);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    console.log(`Kept existing ${file} unchanged`);
  }
}

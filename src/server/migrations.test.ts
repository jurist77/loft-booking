import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { migrationFiles } from "./migrations";

const folders: string[] = [];
afterEach(async () => { for (const folder of folders.splice(0)) await rm(folder, { recursive: true, force: true }); });
async function fixture(names: string[]) {
  const folder = await mkdtemp(join(tmpdir(), "studio-sql-manifest-")); folders.push(folder);
  for (const name of names) await writeFile(join(folder, name), "SELECT 1;\n");
  return folder;
}
describe("SQL migration manifest", () => {
  it("sorts versions and fingerprints exact SQL contents", async () => {
    const folder = await fixture(["0002_second.sql", "0001_first.sql"]);
    const files = await migrationFiles(folder);
    expect(files.map((file) => file.version)).toEqual([1, 2]);
    const checksum = files[0].checksum;
    await writeFile(join(folder, "0001_first.sql"), "SELECT 2;\n");
    expect((await migrationFiles(folder))[0].checksum).not.toBe(checksum);
  });
  it.each([{ names: [] }, { names: ["0002_gap.sql"] }, { names: ["0001_a.sql", "0001_b.sql"] }, { names: ["bad.sql"] }])("rejects invalid manifest $names", async ({ names }) => {
    await expect(migrationFiles(await fixture(names))).rejects.toThrow("INVALID_FILES");
  });
});

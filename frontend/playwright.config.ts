import { defineConfig, devices } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const venvPython = path.resolve(here, "../.venv/bin/python");
const python =
  process.env.AGENTGUARD_PYTHON ?? (fs.existsSync(venvPython) ? venvPython : "python3");

// Never attach to a developer's demo server: the harness always starts an
// isolated instance on this port and resets its own state directory.
const channel = process.env.PW_CHANNEL ?? (process.env.CI ? undefined : "chrome");
const webkit = process.env.PW_ENGINE === "webkit";

export default defineConfig({
  testDir: "./tests/e2e",
  outputDir: "./test-results",
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  timeout: 120_000,
  expect: { timeout: 15_000 },
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : [["list"]],
  use: {
    baseURL: "http://127.0.0.1:8876",
    channel: webkit ? undefined : channel,
    headless: true,
    viewport: { width: 1440, height: 1000 },
    // WebKit screencast preparation injects an inline `body {}` stylesheet.
    // Keep CSP enforced and retain DOM/action traces without that recorder.
    trace: { mode: "retain-on-failure", screenshots: !webkit, snapshots: true },
    screenshot: "only-on-failure",
    video: "off",
  },
  projects: [
    {
      name: webkit ? "webkit" : "chrome",
      use: webkit
        ? { ...devices["Desktop Safari"], browserName: "webkit", channel: undefined, viewport: { width: 1440, height: 1000 } }
        : { ...devices["Desktop Chrome"], channel, viewport: { width: 1440, height: 1000 } },
    },
  ],
  webServer: {
    command:
      "env -u PYTHONHOME -u PYTHONPATH PYTHONDONTWRITEBYTECODE=1 " +
      `"${python}" -m tests.e2e_server --port 8876 --state-dir frontend/.e2e-run`,
    cwd: "..",
    url: "http://127.0.0.1:8876/",
    reuseExistingServer: false,
    timeout: 120_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});

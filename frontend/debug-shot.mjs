import fs from "node:fs";
import { chromium } from "@playwright/test";

const code = fs.readFileSync(".e2e-debug/bootstrap-code", "utf8").trim();
const browser = await chromium.launch({ channel: "chrome", headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
await page.goto("http://127.0.0.1:8877/");
await page.getByLabel("Bootstrap code").fill(code);
await page.getByRole("button", { name: "Open local workbench" }).click();
await page.getByRole("heading", { name: "Overview", level: 1 }).waitFor();
await page.getByRole("navigation", { name: "Primary navigation" }).getByRole("link", { name: /Agent traces/ }).click();
await page.getByRole("button", { name: "Run scripted scenario" }).click();
await page.getByLabel("Scenario").selectOption("injection");
await page.getByLabel("Server policy preset").selectOption("approve-v1");
await page.getByRole("button", { name: "Start run" }).click();
await page.waitForURL(/\/traces\/run_/);
await page.getByRole("navigation", { name: "Primary navigation" }).getByRole("link", { name: /Policy & approvals/ }).click();
await page.getByRole("link", { name: "Review request" }).click();
await page.waitForURL(/\/policies\/approvals\/apr_/);
await page.getByRole("heading", { name: "Review one exact request", level: 1 }).waitFor();
await page.waitForLoadState("networkidle");
await page.screenshot({ path: ".e2e-debug/full-before.png", fullPage: true, animations: "disabled" });
await page.screenshot({ path: ".e2e-debug/viewport-before.png", fullPage: false, animations: "disabled" });
await page.addStyleTag({ content: ".sidebar { position: static !important; height: auto !important; } .app-shell { min-height: 0 !important; }" });
await page.screenshot({ path: ".e2e-debug/full-static.png", fullPage: true, animations: "disabled" });
const metrics = await page.evaluate(() => ({
  headings: [...document.querySelectorAll("h1")].map((h) => h.textContent),
  bodyText: document.body.innerText.slice(0, 500),
  sidebarPosition: getComputedStyle(document.querySelector(".sidebar")).position,
  scrollHeight: document.documentElement.scrollHeight,
  clientHeight: document.documentElement.clientHeight,
}));
console.log(metrics);
await browser.close();

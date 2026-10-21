import { expect, test, type ConsoleMessage, type Page } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const codeFile = path.resolve(here, "../../.e2e-run/bootstrap-code");
const bootstrapCode = fs.readFileSync(codeFile, "utf8").trim();
const captureDocs = process.env.AG_CAPTURE_SCREENSHOTS === "1";
const screenshotDir = path.resolve(here, "../../../docs/screenshots");

async function screenshot(page: Page, name: string): Promise<void> {
  if (!captureDocs) return;
  await page.screenshot({
    path: path.join(screenshotDir, `${name}.png`),
    fullPage: true,
    animations: "disabled",
  });
}

async function nav(page: Page, name: string): Promise<void> {
  await page
    .getByRole("navigation", { name: "Primary navigation" })
    .getByRole("link", { name: new RegExp(name) })
    .click();
  await page.waitForLoadState("networkidle");
}

function expectedConsoleNoise(message: ConsoleMessage): boolean {
  // The session probe intentionally returns 401 before the operator exchanges
  // the bootstrap code. Chrome reports that as a failed resource.
  const url = message.location().url;
  if (url.endsWith("/api/v1/session") && /401/.test(message.text())) return true;
  if (url.endsWith("/api/v1/session/exchange") && /403/.test(message.text())) return true;
  return url.endsWith("/favicon.ico") && /404/.test(message.text());
}

test("operator workflow: evidence, authorization, evaluation, audit, responsive shell", async ({
  page,
  browser,
}) => {
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const serverErrors: string[] = [];

  page.on("console", (message) => {
    if (message.type() === "error" && !expectedConsoleNoise(message) && !message.location().url.includes("fnd_unavailable")) {
      consoleErrors.push(`${message.text()} (${message.location().url})`);
    }
  });
  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("response", (response) => {
    if (response.status() >= 500 && !response.url().includes("fnd_unavailable")) {
      serverErrors.push(`${response.status()} ${response.request().method()} ${response.url()}`);
    }
  });

  await test.step("single-use bootstrap gate rejects a wrong code", async () => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Agent Security Workbench", level: 1 })).toBeVisible();
    await page.getByLabel("Bootstrap code").fill("0000-0000-0000-0000");
    await page.getByRole("button", { name: "Open local workbench" }).click();
    await expect(page.getByText("Session not established")).toBeVisible();
  });

  await test.step("overview reads the synthetic dataset scope", async () => {
    await page.getByLabel("Bootstrap code").fill(bootstrapCode);
    await page.getByRole("button", { name: "Open local workbench" }).click();
    await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
    await expect(page.locator(".scope-line__value")).toHaveText("Shared-host agent scenario");
    await expect(page.getByText("Audit chain valid")).toBeVisible();
    const review = page.locator(".signal", { hasText: "Review findings" });
    await expect(review.locator(".signal__value")).toHaveText("2");
    await expect(page.getByRole("link", { name: /Overview/ })).toHaveAttribute("aria-current", "page");
    await screenshot(page, "01-overview");
  });

  await test.step("finding and immutable evidence carry exact source line", async () => {
    await nav(page, "Investigations");
    await expect(page.getByRole("heading", { name: "Investigations", level: 1 })).toBeVisible();
    await expect(
      page.getByText("Unapproved publish attempt with correlated outbound upload"),
    ).toBeVisible();
    await screenshot(page, "02-investigations-queue");

    await page
      .getByRole("link", { name: "Unapproved publish attempt with correlated outbound upload" })
      .click();
    await expect(
      page.getByRole("heading", {
        name: "Unapproved publish attempt with correlated outbound upload",
        level: 1,
      }),
    ).toBeVisible();
    await expect(page.getByText("Evidence integrity failed")).toHaveCount(0);
    await screenshot(page, "03-finding-detail");

    await page.locator('a[href^="/investigations/evidence/"]').first().click();
    await expect(page.getByRole("table", { name: "Captured source context" })).toBeVisible();
    await expect(page.getByText("captured line").first()).toBeVisible();
    await expect(page.getByText("Record SHA-256").first()).toBeVisible();
  });

  await test.step("investigation revision records a bounded verdict", async () => {
    await nav(page, "Investigations");
    await page.getByRole("button", { name: "New investigation" }).click();
    await page.getByLabel("Title").fill("Synthetic Data publish review");
    await page
      .getByLabel("Analyst notes")
      .fill("Initial review of the synthetic Data publish finding. Evidence only; no claim of successful exfiltration.");
    await page.getByLabel(/Select data finding/).check();
    await page.getByRole("button", { name: "Create investigation" }).click();
    await page.waitForURL(/\/investigations\/inv_/, { timeout: 15_000 });
    await expect(page.getByRole("heading", { name: "Synthetic Data publish review", level: 1 })).toBeVisible();
    await screenshot(page, "04-investigation-detail");

    const citations = page.locator(".citation input");
    await citations.nth(0).check();
    if ((await citations.count()) > 1) await citations.nth(1).check();
    await page
      .getByLabel("Rationale")
      .fill(
        "The selected synthetic HTTP and IDS records support a policy-outcome review. Shared-host attribution remains unresolved, so this does not establish agent ownership or successful exfiltration.",
      );
    await page.getByRole("button", { name: /Save verdict revision/ }).click();
    await expect(page.getByText(/Verdict revision \d+ saved/)).toBeVisible();
    await screenshot(page, "05-investigation-verdict");
  });

  await test.step("scoped case revision and local export", async () => {
    await page.getByRole("link", { name: "Create case from scope" }).click();
    await page.waitForURL(/\/audit\?.*create=1/, { timeout: 15_000 });
    await expect(page.getByRole("heading", { name: "Create scoped case" })).toBeVisible();
    await page.locator("#case-title").fill("Synthetic shared-host publish review");
    await page
      .locator("#case-summary")
      .fill(
        "Synthetic records show a Data agent publish attempt with cross-source HTTP and IDS observations. The review is scoped to policy outcome, not proven compromise.",
      );
    await page
      .locator("#case-scope")
      .fill(
        "Shared-host synthetic dataset; selected Data finding and correlated HTTP/IDS evidence; unresolved Build/Data host attribution.",
      );
    await page
      .locator("#case-conclusion")
      .fill(
        "The synthetic evidence supports a policy-violation review outcome. It does not prove malicious intent or successful exfiltration.",
      );
    await page
      .locator("#case-recommendations")
      .fill(
        "Retain the scoped evidence hashes with this synthetic case.\nValidate attribution only with an independent, non-IP signal in a future scenario.",
      );
    await page.getByRole("button", { name: /Create case revision 1/ }).click();
    await page.waitForURL(/\/audit\/cases\/case_/, { timeout: 15_000 });
    await expect(
      page.getByRole("heading", { name: "Synthetic shared-host publish review", level: 1 }),
    ).toBeVisible();
    await screenshot(page, "06-case-detail");

    const [download] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: "Export Markdown" }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/-r1\.md$/);
    await expect(page.getByText(/Created .*\.md\. This is a local file download/)).toBeVisible();
    await screenshot(page, "07-case-export");

    await page.getByRole("button", { name: "New revision" }).click();
    await page.locator("#revise-title").fill("Synthetic shared-host publish review (rev 2)");
    await page.getByRole("button", { name: "Save revision 2" }).click();
    await expect(page.getByText("Case revision 2 saved. Previous revisions remain immutable.")).toBeVisible();
    await expect(page.getByText(/revision 2/).first()).toBeVisible();
  });

  await test.step("scripted proposal pauses at the exact-request approval gate", async () => {
    await nav(page, "Agent traces");
    await page.getByRole("button", { name: "Run scripted scenario" }).click();
    await page.getByLabel("Scenario").selectOption("injection");
    await page.getByLabel("Server policy preset").selectOption("approve-v1");
    await page.getByLabel("Runtime").selectOption("scripted");
    await page.getByRole("button", { name: "Start run" }).click();
    await page.waitForURL(/\/traces\/run_/, { timeout: 15_000 });
    await expect(page.getByText("Waiting for approval").first()).toBeVisible();
    await screenshot(page, "09-agent-trace-waiting");

    await nav(page, "Policy & approvals");
    await expect(page.getByRole("heading", { name: "Policy & approvals", level: 1 })).toBeVisible();
    await expect(page.getByText("Pending approval queue")).toBeVisible();
    await screenshot(page, "08-policy-approvals");

    await page.getByRole("link", { name: "Review request" }).click();
    await page.waitForURL(/\/policies\/approvals\/apr_/, { timeout: 15_000 });
    await expect(page.getByRole("heading", { name: "Review one exact request", level: 1 })).toBeVisible();
    await expect(page.getByText("Request digest").first()).toBeVisible();
    await screenshot(page, "10-approval-review");

    await page
      .getByLabel("Decision reason")
      .fill("Approve one local synthetic receipt for the scoped investigation; no external delivery.");
    await page.getByLabel(/I reviewed the exact arguments/).check();
    await page.getByRole("button", { name: "Approve once and execute" }).click();
    await expect(page.getByText(/Approved once · committed/)).toBeVisible();
    await screenshot(page, "11-approval-committed");
  });

  await test.step("consumed approval is terminal and execution is separately visible", async () => {
    await page.reload();
    await expect(page.getByText("This approval is not actionable")).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve once and execute" })).toHaveCount(0);
    await page.getByRole("link", { name: "Open the agent run and trace" }).click();
    await expect(page.getByText("SUCCEEDED").first()).toBeVisible();
    await page.getByText("Execution result and receipt").click();
    await expect(page.getByText(/Local synthetic receipt/)).toBeVisible();
  });

  await test.step("evaluation separates synthetic detection and scripted enforcement", async () => {
    await nav(page, "Evaluation");
    await page.getByRole("button", { name: "Run synthetic baseline suite" }).click();
    await page.waitForURL(/\/evaluation\/evl_/, { timeout: 60_000 });
    await expect(page.getByText("Synthetic detection metrics")).toBeVisible();
    const truePositive = page.locator(".metric-strip > div", { hasText: "True positive" }).locator("strong");
    await expect(truePositive).toHaveText("2");
    await expect(page.getByText(/conditional on emitted binary decisions/).first()).toBeVisible();
    await expect(page.getByText(/Local Ollama runs with an observed response/).first()).toBeVisible();
    await screenshot(page, "12-evaluation");

    for (const label of ["JSON", "Markdown", "CSV"]) {
      const [report] = await Promise.all([
        page.waitForEvent("download"),
        page.getByRole("link", { name: label, exact: true }).click(),
      ]);
      expect(report.suggestedFilename()).toMatch(/^evaluation-evl_.+\.(json|md|csv)$/);
      await report.cancel();
    }
  });

  await test.step("audit claims are separate and case revision history is browsable", async () => {
    await nav(page, "Audit & cases");
    await page.getByRole("button", { name: "Run verification" }).click();
    await expect(page.getByText(/ver_[0-9a-f]{16}/)).toBeVisible();
    await expect(page.locator(".claim", { hasText: "Integrity" }).getByText("VALID")).toBeVisible();
    await expect(
      page.locator(".claim", { hasText: "Completeness" }).getByText("CHECKPOINT MATCHED"),
    ).toBeVisible();
    await screenshot(page, "13-audit");

    await page.getByRole("tab", { name: /Cases/ }).click();
    await expect(page.getByText("Synthetic shared-host publish review", { exact: false })).toBeVisible();
    await screenshot(page, "14-cases");

    await page.getByRole("link", { name: /Synthetic shared-host publish review/ }).click();
    await expect(page.getByText("Revision history")).toBeVisible();
    await expect(page.getByText("Revision 2", { exact: true })).toBeVisible();
  });

  await test.step("keyboard and responsive shell remain usable", async () => {
    await nav(page, "Overview");
    await expect(page.getByRole("link", { name: /Overview/ })).toHaveAttribute("aria-current", "page");

    // Reload so sequential focus starts at the beginning of the document.
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
    const fullLinkNavigation = browser.browserType().name() === "webkit" && process.platform === "darwin";
    await page.keyboard.press(fullLinkNavigation ? "Alt+Tab" : "Tab");
    await expect(page.getByRole("link", { name: "Skip to main content" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator("#main-content")).toBeFocused();

    await page
      .getByRole("navigation", { name: "Primary navigation" })
      .getByRole("link", { name: /Investigations/ })
      .focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("heading", { name: "Investigations", level: 1 })).toBeVisible();

    await page.setViewportSize({ width: 1024, height: 800 });
    await expect(page.locator(".sidebar")).toBeVisible();
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1))
      .toBe(true);

    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByRole("navigation", { name: "Primary navigation" })).toBeVisible();
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1))
      .toBe(true);
    await page.getByRole("navigation", { name: "Primary navigation" })
      .getByRole("link", { name: /Overview/ })
      .click();
    await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
    await page.setViewportSize({ width: 1440, height: 1000 });
  });

  await test.step("the bootstrap code cannot open a second session", async () => {
    const second = await browser.newContext({ baseURL: "http://127.0.0.1:8876" });
    const secondPage = await second.newPage();
    await secondPage.goto("/");
    await secondPage.getByLabel("Bootstrap code").fill(bootstrapCode);
    await secondPage.getByRole("button", { name: "Open local workbench" }).click();
    await expect(secondPage.getByText("Session not established")).toBeVisible();
    await expect(secondPage.getByText(/already been used|expired|Too many/i)).toBeVisible();
    await second.close();
  });

  await test.step("failed navigation clears the previous finding and retry recovers", async () => {
    await nav(page, "Investigations");
    await page.getByRole("link", { name: "Unapproved publish attempt with correlated outbound upload" }).click();
    await expect(page.getByRole("heading", { name: "Unapproved publish attempt with correlated outbound upload", level: 1 })).toBeVisible();
    await page.route("**/api/v1/findings/fnd_unavailable", (route) => route.fulfill({ status: 503,
      contentType: "application/json", body: JSON.stringify({ code: "TEST_OUTAGE", message: "Test evidence service unavailable." }) }));
    // Simulate browser history navigation without reloading the React app.
    await page.evaluate(() => {
      history.pushState({ ...history.state }, "", "/investigations/findings/fnd_unavailable");
      window.dispatchEvent(new PopStateEvent("popstate", { state: history.state }));
    });
    await expect(page.getByText("Test evidence service unavailable.")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Unapproved publish attempt with correlated outbound upload", level: 1 })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Retry", exact: true })).toBeVisible();
    await page.unroute("**/api/v1/findings/fnd_unavailable");
    await nav(page, "Investigations");
    await expect(page.getByRole("heading", { name: "Investigations", level: 1 })).toBeVisible();
  });

  await test.step("untrusted analyst text is rendered as text", async () => {
    await page.getByRole("button", { name: "New investigation" }).click();
    const payload = '<img src=x onerror="window.__workbenchXss=1">';
    await page.getByLabel("Title", { exact: true }).fill(payload);
    await page.getByLabel(/Select data finding/).check();
    await page.getByRole("button", { name: "Create investigation" }).click();
    await expect(page.getByRole("heading", { name: payload, level: 1 })).toBeVisible();
    await expect(page.locator("main img")).toHaveCount(0);
    expect(await page.evaluate(() => Object.hasOwn(window, "__workbenchXss"))).toBe(false);
  });

  await test.step("a different origin cannot submit a mutation with the operator browser", async () => {
    const hostile = await page.context().newPage();
    await hostile.route("http://127.0.0.1:8877/", (route) => route.fulfill({ contentType: "text/html", body:
      '<form action="http://127.0.0.1:8876/api/v1/datasets/sample/import" method="post"><button>Cross-origin submit</button></form>' }));
    await hostile.goto("http://127.0.0.1:8877/");
    const [response] = await Promise.all([
      hostile.waitForResponse("**/api/v1/datasets/sample/import"),
      hostile.getByRole("button", { name: "Cross-origin submit" }).click(),
    ]);
    expect(response.status()).toBe(403);
    expect((await response.json()).code).toBe("UNTRUSTED_ORIGIN");
    await hostile.close();
  });

  await test.step("CSP still blocks arbitrary inline styles and scripts", async () => {
    const policy = (await page.request.get("/health")).headers()["content-security-policy"];
    const probe = await page.context().newPage();
    await probe.route("**/csp-boundary-probe", (route) => route.fulfill({
      contentType: "text/html", headers: { "Content-Security-Policy": policy },
      body: '<select aria-label="Native control"><option>A</option><option>B</option></select>' +
        '<div id="untrusted-style" style="color:rgb(255,0,0)">Untrusted style</div>' +
        '<script>window.__cspBypass=1</script>',
    }));
    await probe.goto("/csp-boundary-probe");
    expect(await probe.evaluate(() => Object.hasOwn(window, "__cspBypass"))).toBe(false);
    expect(await probe.locator("#untrusted-style").evaluate((element) => getComputedStyle(element).color))
      .not.toBe("rgb(255, 0, 0)");
    await probe.getByLabel("Native control").selectOption({ label: "B" });
    await expect(probe.getByLabel("Native control")).toHaveValue("B");
    await probe.close();
  });

  expect(pageErrors, `uncaught page errors: ${pageErrors.join(" | ")}`).toEqual([]);
  expect(serverErrors, `5xx responses: ${serverErrors.join(" | ")}`).toEqual([]);
  expect(consoleErrors, `unexpected console errors: ${consoleErrors.join(" | ")}`).toEqual([]);
});

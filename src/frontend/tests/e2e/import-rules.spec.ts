import { expect, test } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";

test.describe("Import Rules Dialog", () => {
  let groupsPage: GroupsPage;

  test.beforeEach(async ({ page }) => {
    groupsPage = new GroupsPage(page);

    // Mock Auth
    await page.route("**/auth", async (route) => route.fulfill({ json: { enabled: false } }));

    // Mock initial groups (1 group)
    await page.route("**/groups?with_rules=true", async (route) => {
      await route.fulfill({
        json: {
          groups: [
            {
              id: "g1",
              name: "Test Group",
              rules: [],
              color: "#000000",
              enable: true,
              interface: "",
            },
          ],
        },
      });
    });

    await page.route("**/interfaces", async (route) => route.fulfill({ json: { interfaces: [] } }));
    await groupsPage.goto();
  });

  async function openImportDialog(page: any) {
    // Locate the import button using the tooltip value wrapper
    const wrapper = page.locator('[data-value="Import Rule List"]');
    const btn = wrapper.locator("button");
    await expect(btn).toBeVisible();
    await btn.click();

    const dialog = page.locator("[data-dialog-content]");
    await expect(dialog).toBeVisible();
    return dialog;
  }

  test("should open dialog and import rules", async ({ page }) => {
    const dialog = await openImportDialog(page);
    await expect(dialog.getByText("Import Rule List")).toBeVisible();

    const textarea = dialog.locator("textarea");
    await expect(textarea).toBeVisible();

    // Type rules
    const rulesText = `example.com
192.168.1.1
/regex/`;
    await textarea.fill(rulesText);
    await textarea.blur();

    await expect(dialog.locator(".results-view")).toBeVisible();

    // Check badges in results view specifically (avoid count badges in stats)
    await expect(dialog.locator(".results-view .badge", { hasText: "namespace" })).toBeVisible();
    await expect(dialog.locator(".results-view .badge", { hasText: "IPv4" })).toBeVisible();
    await expect(dialog.locator(".results-view .badge", { hasText: "regex" })).toBeVisible();

    // Check stats (counts)
    await expect(dialog.locator(".count-badge", { hasText: "namespace" })).toContainText("1");

    // Import
    await dialog.getByRole("button", { name: "Import" }).click();

    // Dialog should close
    await expect(dialog).toBeHidden();

    // Check if rules are added to the group
    await expect(page.locator(".rule")).toHaveCount(3);

    // Verify values
    // pattern input has class .pattern-input
    await expect(page.locator(".rule .pattern-input").nth(0)).toHaveValue("example.com");
    await expect(page.locator(".rule .pattern-input").nth(1)).toHaveValue("192.168.1.1");
    await expect(page.locator(".rule .pattern-input").nth(2)).toHaveValue("/regex/");
  });

  test("should handle invalid lines", async ({ page }) => {
    const dialog = await openImportDialog(page);
    const textarea = dialog.locator("textarea");

    // "[" is invalid
    await textarea.fill(`[
valid.com`);
    await textarea.blur();

    await expect(dialog.locator(".results-view")).toBeVisible();

    // Check invalid line
    await expect(dialog.locator(".line-row.invalid")).toBeVisible();
    await expect(dialog.locator(".line-row.invalid")).toContainText("[");

    // Check stats
    await expect(dialog.locator(".count-badge", { hasText: "INVALID" })).toBeVisible();

    // Import
    await dialog.getByRole("button", { name: "Import" }).click();

    // Check rules - only valid one should be imported
    await expect(dialog).toBeHidden();
    await expect(page.locator(".rule")).toHaveCount(1);
    await expect(page.locator(".rule .pattern-input").first()).toHaveValue("valid.com");
  });

  test("should respect rule type selection", async ({ page }) => {
    const dialog = await openImportDialog(page);
    const textarea = dialog.locator("textarea");

    await textarea.fill("*.example.com");
    await textarea.blur();

    await expect(dialog.locator(".results-view .badge")).toBeVisible();

    const selectTrigger = dialog.locator("[data-select-trigger]");
    await selectTrigger.click();

    const option = page.getByRole("option", { name: "Wildcard" });

    await option.click();

    const wildcardBadge = dialog.locator(".results-view .badge", { hasText: "wildcard" });
    await expect(wildcardBadge).toBeVisible({ timeout: 15000 });

    await dialog.getByRole("button", { name: "Import" }).click();

    await expect(page.locator(".rule")).toHaveCount(1);
    await expect(page.locator(".rule")).toContainText("Wildcard");
  });
});

import { expect, test } from "@playwright/test";

import { GroupsPage } from "./pages/GroupsPage";

for (const viewport of [
  { width: 1280, height: 900 },
  { width: 540, height: 800 },
]) {
  test(`interface list stays clickable over the next group (${viewport.width}px)`, async ({
    page,
  }) => {
    await page.setViewportSize(viewport);
    await page.route("**/auth", (route) => route.fulfill({ json: { enabled: false } }));
    await page.route("**/groups?with_rules=true", (route) =>
      route.fulfill({ json: { groups: [] } }),
    );
    await page.route("**/interfaces", (route) =>
      route.fulfill({
        json: {
          interfaces: Array.from({ length: 8 }, (_, i) => ({
            id: `eth${i}`,
            name: `Network ${i}`,
          })),
        },
      }),
    );
    const groups = new GroupsPage(page);
    await groups.goto();
    await groups.createGroup();
    await groups.createGroup();

    const trigger = page.locator(".group-header [data-select-trigger]").first();
    await trigger.click();
    const list = page.getByRole("listbox");
    await expect(list).toBeVisible();
    // Visibility alone misses clipping and overlapping siblings: hit-test the
    // portion of the popup that extends into the next group's rectangle.
    await expect
      .poll(async () =>
        list.evaluate((element) => {
          const next = document.querySelectorAll(".group")[1].getBoundingClientRect();
          const popup = element.getBoundingClientRect();
          const x = Math.max(popup.left, next.left) + 8;
          const y = Math.max(popup.top, next.top) + 8;
          return (
            y < Math.min(popup.bottom, next.bottom) &&
            element.contains(document.elementFromPoint(x, y))
          );
        }),
      )
      .toBe(true);

    await page.getByRole("option", { name: "eth4 Network 4", exact: true }).click();
    await expect(trigger).toContainText("eth4");
    await expect(list).toHaveCount(0);
    await trigger.click();
    await page.keyboard.press("Escape");
    await expect(list).toHaveCount(0);
    await expect(trigger).toBeFocused();
  });
}

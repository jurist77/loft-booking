import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { administratorContact } from "./admin-contact";
import { AdminContact } from "../components/admin-contact";
import { STUDIO } from "./studio";

describe("Administrator contact configuration", () => {
  it("has no invented default telephone number", () => {
    expect(STUDIO.adminPhone).toBeNull();
    const html = renderToStaticMarkup(createElement(AdminContact));
    expect(html).toContain("Контакт администратора появится здесь.");
    expect(html).not.toContain("tel:");
  });
  it.each([null, "", " ", "not-a-phone", "javascript:alert(1)"])("uses the placeholder for invalid configuration %s", (phone) => {
    expect(administratorContact(phone)).toBeNull();
  });
  it("creates a tel link when a number is configured (non-routable test example)", () => {
    const phone = "+7 (000) 000-00-00";
    expect(administratorContact(phone)).toEqual({ label: phone, href: "tel:+70000000000" });
    expect(renderToStaticMarkup(createElement(AdminContact, { phone }))).toContain('href="tel:+70000000000"');
  });
});

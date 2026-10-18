import { describe, expect, it } from "vitest";
import { normalizePhone, validateContact, type ContactInput } from "./validation";

export const validContact: ContactInput = { firstName: "Анна", lastName: "Иванова", phone: "8 (926) 123-45-67", eventType: "День рождения", channel: "Telegram", consent: true };

describe("Russian mobile phone normalization", () => {
  it.each(["89261234567", "+79261234567", "79261234567", "9261234567", "8 (926) 123-45-67"])("normalizes %s", (input) => {
    expect(normalizePhone(input)).toBe("+79261234567");
  });
  it.each(["", "926", "+7 (926) 123", "81234567890", "+74951234567", "+19261234567", "892612345678", "телефон89261234567", "+89261234567", "++79261234567", "+9261234567", "7.926.123.45.67"])("rejects %s", (input) => {
    expect(normalizePhone(input)).toBeNull();
  });
});

describe("Contact validation", () => {
  it("validates a complete form and normalizes the phone", () => {
    expect(validateContact(validContact)).toEqual({ errors: {}, phone: "+79261234567" });
  });
  it("reports all missing required fields", () => {
    const result = validateContact({ firstName: " ", lastName: "", phone: "", eventType: "" });
    expect(Object.keys(result.errors).sort()).toEqual(["eventType", "firstName", "lastName", "phone"]);
  });
  it.each(["Анна-Мария", "O’Connor", "Иван Петров", "Anna"])("accepts name %s", (name) => {
    expect(validateContact({ ...validContact, firstName: name }).errors.firstName).toBeUndefined();
  });
  it("rejects digits, markup, and oversized names", () => {
    for (const name of ["123", "<script>", "а".repeat(81)]) expect(validateContact({ ...validContact, firstName: name }).errors.firstName).toBeDefined();
  });
  it("rejects unexpected event and channel values", () => {
    const { errors } = validateContact({ ...validContact, eventType: "unknown", channel: "Email" });
    expect(errors.eventType).toBeDefined(); expect(errors.channel).toBeDefined();
  });
  it("accepts the demo form without hidden notification or consent requirements and never invents consent", () => {
    const input: ContactInput = { firstName: "Тест", lastName: "Пример", phone: "9261234567", eventType: "Другое" };
    expect(validateContact(input).errors).toEqual({});
    expect(input).not.toHaveProperty("consent");
    expect(input).not.toHaveProperty("channel");
  });
});

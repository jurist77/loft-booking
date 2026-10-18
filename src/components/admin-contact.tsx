import { STUDIO } from "../lib/studio";
import { administratorContact } from "../lib/admin-contact";

export function AdminContact({ phone = STUDIO.adminPhone }: { phone?: string | null }) {
  const contact = administratorContact(phone);
  return (
    <aside className="admin-contact" aria-label="Связаться с администратором">
      <h3>Связаться с администратором</h3>
      {contact ? <a href={contact.href}>{contact.label}</a> : <p>Контакт администратора появится здесь.</p>}
    </aside>
  );
}

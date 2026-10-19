"use client";

import Image from "next/image";
import { useEffect, useRef, useState } from "react";
import { Gallery } from "./gallery";
import { ArrowIcon, SparkIcon } from "./icons";
import { timeLabel } from "@/lib/availability";
import { STUDIO } from "@/lib/studio";
import { assetPath, DEPLOYMENT } from "@/lib/deployment";
import { AdminContact } from "./admin-contact";

function StudioDetails({ onClose, onBook }: { onClose: () => void; onBook: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { dialog.current?.showModal(); }, []);
  return <dialog className="studio-details" ref={dialog} aria-label="О пространстве" onCancel={(event) => { if (event.target === event.currentTarget) { event.preventDefault(); onClose(); } }} onClick={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <div className="studio-details-toolbar"><button className="text-button" type="button" onClick={onClose}>Закрыть описание</button></div>
    <div className="occasion-strip section-shell"><span>Здесь есть место для</span><p>дней рождения <i><SparkIcon /></i> уютных встреч <i><SparkIcon /></i> творческих идей <i><SparkIcon /></i> ваших историй</p></div>
      <section className="space-section section-shell" id="space" aria-labelledby="space-heading"><div className="section-heading"><div><p className="eyebrow">Почувствуйте атмосферу</p><h2 id="space-heading">Больше, чем <em>просто стены.</em></h2></div><p>{STUDIO.description}</p></div><Gallery /><p className="photo-disclaimer"><span aria-hidden="true">*</span> Пока здесь 4 временные иллюстрации. Реальные фотографии студии необходимо добавить перед запуском.</p></section>
      <section className="details-section section-shell" id="details" aria-labelledby="details-heading"><div className="details-card"><div className="details-intro"><span className="detail-spark" aria-hidden="true"><SparkIcon /></span><p className="eyebrow">Всё начинается с комфорта</p><h2 id="details-heading">Устраивайтесь.<br />Здесь <em>вам рады.</em></h2><p>Мы оставили главное: пространство для общения и время, которое не хочется торопить.</p></div><div className="details-list"><article><span className="detail-number">01</span><div><h3>Ваш ритм</h3><p>Каждый день с {timeLabel(STUDIO.open)} до {timeLabel(STUDIO.close)}.<br />Аренда от часа, дальше — с шагом 30 минут.</p></div></article><article><span className="detail-number">02</span><div><h3>Ваша точка встречи</h3><p>{STUDIO.address}.<br /><span className="temporary-label">Временное описание адреса</span></p></div></article><article><span className="detail-number">03</span><div><h3>Простые договорённости</h3><p>Бережно относитесь к пространству и уважайте соседей. Формат события и дополнительные условия уточняются со студией.</p><span className="temporary-label">Предварительные правила аренды</span></div></article></div></div></section>
    <section className="closing-note section-shell"><span aria-hidden="true"><SparkIcon /></span><p>Лучшие моменты — те,<br />что мы <em>проводим вместе.</em></p><button type="button" onClick={onBook} aria-label="Перейти к бронированию"><ArrowIcon /></button></section>
    <footer className="site-footer section-shell"><span className="footer-brand">{STUDIO.name}<span>{STUDIO.tagline}</span></span><p>{DEPLOYMENT.mode === "server" ? <>Онлайн-бронирование студии<br />Без онлайн-оплаты и уведомлений</> : <>Клиентский прототип · этап 1<br />Без реального бронирования и оплаты</>}</p></footer>
  </dialog>;
}

export function Welcome({ onBook }: { onBook?: () => void }) {
  const [detailsOpen, setDetailsOpen] = useState(false);
  const detailsButton = useRef<HTMLButtonElement>(null);
  function closeDetails() {
    setDetailsOpen(false);
    requestAnimationFrame(() => detailsButton.current?.focus());
  }
  return <section className="welcome-screen" data-screen="welcome" aria-labelledby="hero-title">
    <section className="hero section-shell" aria-labelledby="hero-title"><div className="hero-copy"><p className="eyebrow"><span className="tiny-dot" /> Москва · {STUDIO.name}</p><h1 id="hero-title" tabIndex={-1} data-step-heading>Место для<br />ваших <em>особенных</em><br />встреч.</h1><p className="hero-description">Тёплый свет. Близкие люди.<br />Пространство, которое становится вашим.</p><button type="button" className="button button-dark hero-cta" onClick={onBook} disabled={!onBook}>Забронировать <span aria-hidden="true"><ArrowIcon /></span></button><div className="hero-note"><span className="hero-line" />Одна студия. Только ваша компания.</div></div><div className="hero-visual"><div className="hero-image"><Image src={assetPath(STUDIO.photos[0].src)} alt={STUDIO.photos[0].alt} fill sizes="(max-width: 760px) 100vw, 55vw" priority /><span className="image-placeholder-label">Временная иллюстрация</span></div><div className="hero-floating-note"><span className="sun-symbol" aria-hidden="true"><SparkIcon /></span><span>Для маленьких праздников<br />и больших воспоминаний</span></div><span className="hero-photo-number">01 / 04</span></div></section>
    <div className="welcome-support section-shell"><button type="button" className="text-button" ref={detailsButton} onClick={() => setDetailsOpen(true)}>О пространстве</button><AdminContact /></div>
    {detailsOpen && <StudioDetails onClose={closeDetails} onBook={() => { setDetailsOpen(false); onBook?.(); }} />}
  </section>;
}

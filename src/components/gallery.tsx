"use client";

import Image from "next/image";
import { useRef, useState } from "react";
import { STUDIO } from "@/lib/studio";
import { ArrowIcon } from "./icons";
import { assetPath } from "@/lib/deployment";

export function Gallery() {
  const dialog = useRef<HTMLDialogElement>(null);
  const [index, setIndex] = useState(0);
  return <>
    <div className="gallery-grid">{STUDIO.photos.map((photo, i) => <button type="button" className="gallery-item" key={photo.src} aria-label={`Открыть изображение: ${photo.label}`} onClick={() => { setIndex(i); dialog.current?.showModal(); }}><div className="gallery-image"><Image src={assetPath(photo.src)} alt={photo.alt} fill sizes="(max-width: 600px) 75vw, (max-width: 900px) 44vw, 24vw" /><span className="gallery-expand" aria-hidden="true"><ArrowIcon /></span></div><span className="gallery-caption"><span>{photo.label}</span><span className="photo-index">0{i + 1}</span></span></button>)}</div>
    <dialog className="photo-dialog" ref={dialog} aria-label="Просмотр временных иллюстраций" onClick={(e) => { if (e.target === e.currentTarget) dialog.current?.close(); }}>
      <div className="photo-dialog-inner"><button type="button" className="dialog-close" aria-label="Закрыть изображение" onClick={() => dialog.current?.close()}>×</button><Image src={assetPath(STUDIO.photos[index].src)} alt={STUDIO.photos[index].alt} width={1200} height={900} /><div className="dialog-caption"><button type="button" className="icon-button" aria-label="Предыдущее изображение" onClick={() => setIndex((index + 3) % 4)}>←</button><span>{STUDIO.photos[index].label} · {index + 1}/4<br /><small>Временная иллюстрация, не фотография студии</small></span><button type="button" className="icon-button" aria-label="Следующее изображение" onClick={() => setIndex((index + 1) % 4)}>→</button></div></div>
    </dialog>
  </>;
}

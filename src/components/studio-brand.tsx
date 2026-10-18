import Image from "next/image";
import { STUDIO } from "@/lib/studio";
import { assetPath } from "@/lib/deployment";

export function StudioBrand() {
  return <span className="studio-brand">
    <Image className="studio-brand-image" src={assetPath(STUDIO.logo.src)}
      width={STUDIO.logo.width} height={STUDIO.logo.height}
      alt={`${STUDIO.name} — ${STUDIO.tagline}`} unoptimized preload />
  </span>;
}

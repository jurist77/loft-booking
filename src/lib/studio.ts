export const STUDIO = {
  name: "Loft Studio",
  timeZone: "Europe/Moscow",
  open: 7 * 60,
  close: 23 * 60,
  step: 30,
  minimum: 60,
  monthsAhead: 3,
  description: "Собраться с близкими, отметить важное или просто сменить обстановку. Светлое пространство с тёплым характером — для ваших идей и особенных моментов.",
  address: "Москва · точный адрес появится здесь",
  photos: [
    { src: "/images/studio-1.svg", alt: "Временная иллюстрация: общая зона студии", label: "Общее пространство" },
    { src: "/images/studio-2.svg", alt: "Временная иллюстрация: зона отдыха", label: "Место для разговоров" },
    { src: "/images/studio-3.svg", alt: "Временная иллюстрация: стол у окна", label: "Тёплые детали" },
    { src: "/images/studio-4.svg", alt: "Временная иллюстрация: светлая арка", label: "Много естественного света" },
  ],
} as const;

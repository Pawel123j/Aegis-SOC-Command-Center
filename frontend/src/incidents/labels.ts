export const incidentStatuses = {
  new: 'Nowy',
  investigating: 'W analizie',
  contained: 'Opanowany',
  resolved: 'Rozwiązany',
  closed: 'Zamknięty',
} as const;

export const incidentSeverities = {
  low: 'Niska',
  medium: 'Średnia',
  high: 'Wysoka',
  critical: 'Krytyczna',
} as const;

const transitions: Record<keyof typeof incidentStatuses, (keyof typeof incidentStatuses)[]> = {
  new: ['investigating', 'resolved'],
  investigating: ['contained', 'resolved'],
  contained: ['investigating', 'resolved'],
  resolved: ['closed', 'investigating'],
  closed: ['investigating'],
};

export function permittedStatuses(current: keyof typeof incidentStatuses, permissions: string[]) {
  return transitions[current].filter((target) => {
    if (target === 'closed') return permissions.includes('incidents:close');
    if (target === 'investigating' && ['resolved', 'closed'].includes(current))
      return permissions.includes('incidents:reopen');
    return permissions.includes('incidents:edit');
  });
}

export function parseTags(value: string) {
  const tags = value
    .split(',')
    .map((tag) => tag.trim().toLowerCase())
    .filter(Boolean);
  if (tags.length > 20 || tags.some((tag) => tag.length > 64))
    throw new Error('Podaj maksymalnie 20 tagów, każdy do 64 znaków.');
  return [...new Set(tags)];
}

export const riskContextNames: Record<string, string> = {
  confidence: 'Pewność detekcji',
  detection_confidence: 'Pewność detekcji',
  ip_reputation: 'Reputacja adresów IP',
  ioc_reputation: 'Reputacja wskaźników zagrożeń',
  host_criticality: 'Znaczenie hosta',
  host_importance: 'Znaczenie hosta',
  user_importance: 'Znaczenie użytkownika',
  mitre_tactic: 'Taktyki MITRE ATT&CK',
  mitre_tactics: 'Taktyki MITRE ATT&CK',
  attack_tactics: 'Taktyki MITRE ATT&CK',
  confirmed_history: 'Potwierdzona historia zachowania',
  prior_privileges: 'Wcześniejsze uprawnienia użytkownika',
  recurrence: 'Powtarzalność zachowania',
  behavioral_recurrence: 'Powtarzalność zachowania',
};

export const riskStatusNames = {
  known: 'Dane znane',
  unknown: 'Brak danych',
  not_applicable: 'Nie dotyczy',
};

export const confidenceStatusNames = {
  known: 'Znana',
  unknown: 'Brak danych',
  mixed: 'Dostępna tylko dla części danych',
  not_applicable: 'Nie dotyczy',
};

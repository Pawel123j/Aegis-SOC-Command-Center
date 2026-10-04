export const maxYamlBytes = 65536;
export const maxTestEvents = 25;
export const maxTestBytes = 1048576;

export function checkYaml(yaml: string, limit = maxYamlBytes) {
  if (!yaml.trim()) throw new Error('Wklej definicję reguły Sigma w formacie YAML.');
  if (new TextEncoder().encode(yaml).length > limit)
    throw new Error(`Definicja YAML może zawierać najwyżej ${limit / 1024} KiB danych.`);
}

export function checkBody(body: unknown, limit: number) {
  if (new TextEncoder().encode(JSON.stringify(body)).length > limit)
    throw new Error(`Przesłany zestaw przekracza limit ${limit / 1024} KiB danych.`);
}

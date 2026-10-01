import type { ReactNode } from 'react';
import { ApiError } from './api';

export function ErrorNotice({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <div className="notice error" role="alert">
      {error instanceof Error ? error.message : 'Nie udało się pobrać danych.'}
      {error instanceof ApiError && error.requestId && (
        <small>Identyfikator żądania: {error.requestId}</small>
      )}
    </div>
  );
}
export function Empty({
  title = 'Brak danych',
  children,
}: {
  title?: string;
  children?: ReactNode;
}) {
  return (
    <div className="empty">
      <span className="empty-mark" aria-hidden="true">
        ◇
      </span>
      <h3>{title}</h3>
      <p>{children ?? 'Dane pojawią się po przyjęciu i przetworzeniu logów.'}</p>
    </div>
  );
}
export function Badge({ children, tone }: { children: ReactNode; tone?: string }) {
  const safeTone = [
    'critical',
    'high',
    'medium',
    'low',
    'informational',
    'success',
    'failure',
  ].includes(tone ?? '')
    ? tone
    : 'neutral';
  return <span className={`badge ${safeTone}`}>{children}</span>;
}
export function Panel({
  title,
  aside,
  children,
}: {
  title: string;
  aside?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <h2>{title}</h2>
        {aside}
      </div>
      {children}
    </section>
  );
}
export function JsonView({ value }: { value: unknown }) {
  return (
    <pre className="json-view">
      {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
    </pre>
  );
}
export function Loading() {
  return (
    <p className="loading" role="status">
      Pobieranie danych…
    </p>
  );
}
export function Metric({
  label,
  value,
  note,
}: {
  label: string;
  value: number | string | undefined;
  note: string;
}) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>
        {value === undefined
          ? '—'
          : typeof value === 'number'
            ? value.toLocaleString('pl-PL')
            : value}
      </strong>
      <small>{note}</small>
    </div>
  );
}

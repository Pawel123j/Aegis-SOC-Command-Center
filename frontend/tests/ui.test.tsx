import { dashboardFixture } from './dashboardFixtures';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { App } from '../src/App';
import { api } from '../src/api';
import { JsonView } from '../src/components';
import { Sources } from '../src/Sources';
import type { Me } from '../src/types';

const reader: Me = {
  id: 'reader',
  username: 'reader',
  role: 'read_only',
  permissions: ['events:read', 'alerts:read', 'incidents:read', 'detections:read'],
};
beforeEach(() => {
  vi.spyOn(api, 'get').mockImplementation(async (path) =>
    path.startsWith('/dashboard') ? dashboardFixture : { items: [], total: 0, next_cursor: null },
  );
  vi.spyOn(api, 'post').mockResolvedValue({ items: [], total: 0, next_cursor: null });
  vi.spyOn(api, 'subscribe').mockReturnValue(() => undefined);
});

it('renders protected login and clears a failed password while retaining username', async () => {
  vi.spyOn(api, 'restore').mockResolvedValue(null);
  vi.spyOn(api, 'login').mockRejectedValue(new Error('Sesja niedostępna'));
  render(<App />);
  const username = await screen.findByLabelText('Nazwa użytkownika');
  const password = screen.getByLabelText('Hasło');
  fireEvent.change(username, { target: { value: 'analyst' } });
  fireEvent.change(password, { target: { value: 'a-long-test-password' } });
  fireEvent.click(screen.getByRole('button', { name: 'Zaloguj się' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Sesja niedostępna');
  expect(username).toHaveValue('analyst');
  expect(password).toHaveValue('');
  expect(password).toHaveFocus();
});

it('read-only navigation exposes available data and no management sections', async () => {
  vi.spyOn(api, 'restore').mockResolvedValue(reader);
  render(<App />);
  await screen.findByRole('navigation', { name: 'Menu główne' });
  expect(screen.queryByRole('button', { name: /Źródła logów/ })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /Stan systemu/ })).not.toBeInTheDocument();
  expect(await screen.findByText('Zdarzenia · 24 h')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /Zdarzenia/ }));
  expect(await screen.findByLabelText('Zapytanie')).toBeInTheDocument();
  expect(await screen.findByText('Nie znaleziono zdarzeń')).toBeInTheDocument();
});

it('invalid time ranges block a search before making a request', async () => {
  vi.spyOn(api, 'restore').mockResolvedValue(reader);
  render(<App />);
  fireEvent.click(await screen.findByRole('button', { name: /Zdarzenia/ }));
  const from = await screen.findByLabelText('Od · czas lokalny');
  const to = screen.getByLabelText('Do · czas lokalny');
  await waitFor(() => expect(screen.getByRole('button', { name: 'Szukaj' })).toBeEnabled());
  const calls = vi.mocked(api.post).mock.calls.length;
  fireEvent.change(from, { target: { value: '2026-01-01T00:00' } });
  fireEvent.change(to, { target: { value: '2026-02-01T00:00' } });
  fireEvent.click(screen.getByRole('button', { name: 'Szukaj' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('maksymalnie 7 dni');
  expect(vi.mocked(api.post).mock.calls.length).toBe(calls);
});

it('renders raw log text without creating executable markup', () => {
  const payload = '<img src=x onerror=alert(1)><script>attack()</script>';
  const { container } = render(<JsonView value={{ payload }} />);
  expect(container).toHaveTextContent(payload);
  expect(container.querySelector('img,script')).toBeNull();
});

it('retries a successful single-log submission with identical timestamp and body', async () => {
  vi.mocked(api.get).mockImplementation(async (path) => {
    if (path.startsWith('/sources')) return { items: [], next_cursor: null };
    return {
      batch_id: 'receipt',
      accepted_count: 1,
      created_count: 1,
      duplicate_count: 0,
      counts: { projected: 1, processed: 1 },
      records: [
        {
          position: 0,
          event_id: 'event',
          state: 'staged',
          pipeline_state: 'projected',
          detection_state: 'processed',
          error_code: null,
          pipeline_error_code: null,
          pipeline_version: 1,
        },
      ],
    };
  });
  const submit = vi.spyOn(api, 'sourcePost').mockResolvedValue({ batch_id: 'receipt' });
  render(<Sources onEventId={() => undefined} />);
  fireEvent.change(screen.getByLabelText('Klucz do przyjmowania logów'), {
    target: { value: 'temporary-source-token' },
  });
  const button = screen.getByRole('button', { name: 'Prześlij logi' });
  fireEvent.click(button);
  await waitFor(() => expect(submit).toHaveBeenCalledTimes(1));
  await waitFor(() => expect(button).toBeEnabled());
  fireEvent.click(button);
  await waitFor(() => expect(submit).toHaveBeenCalledTimes(2));
  expect(submit.mock.calls[1]).toEqual(submit.mock.calls[0]);
});

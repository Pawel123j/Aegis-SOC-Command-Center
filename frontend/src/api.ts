import type { Me } from './types';

type TokenSet = { access_token: string; csrf_token: string; expires_in: number };
type MemorySession = TokenSet & { expires_at: number };
type Subscriber = (kind: 'logout' | 'session') => void;
const messages: Record<string, string> = {
  unauthorized: 'Zaloguj się ponownie. Sesja wygasła lub dane logowania są niepoprawne.',
  forbidden: 'Twoja rola nie pozwala na tę czynność.',
  validation_error: 'Sprawdź wymagane pola i format danych.',
  invalid_search: 'Sprawdź zapytanie, zakres czasu lub odśwież stronę wyników.',
  archive_unavailable: 'Archiwum zdarzeń jest chwilowo niedostępne. Spróbuj ponownie.',
  version_conflict: 'Dane zmieniły się w innej karcie. Odśwież je przed ponowną zmianą.',
  precondition_failed: 'Dane zmieniły się. Odśwież szczegóły przed ponowną zmianą.',
  precondition_required: 'Odśwież szczegóły, aby pobrać aktualną wersję danych.',
  version_required: 'Odśwież szczegóły, aby pobrać aktualną wersję danych.',
  not_found: 'Nie znaleziono tego zasobu. Mógł zmienić się zakres Twojego dostępu.',
  invalid_incident_transition: 'Ta zmiana statusu nie jest dostępna. Odśwież incydent.',
  incident_closed: 'Incydent jest zamknięty. Otwórz go ponownie przed zmianą.',
  incident_scope_mismatch: 'Alert pochodzi z innego trybu lub sesji replay.',
  incident_not_found: 'Nie znaleziono incydentu. Odśwież listę spraw.',
  alert_not_found: 'Nie znaleziono alertu. Odśwież listę alertów.',
  attachment_not_found: 'To powiązanie jest nieaktualne. Odśwież szczegóły incydentu.',
  alert_already_attached: 'Ten alert jest już powiązany z incydentem.',
  incident_alert_limit: 'Incydent może mieć maksymalnie 100 aktywnych alertów.',
  status_reason_required: 'Podaj uzasadnienie zmiany statusu.',
  invalid_incident_owner: 'Wybierz aktywnego analityka z dostępnej listy.',
  incident_unchanged: 'Zmień co najmniej jedno pole incydentu.',
  invalid_incident_scope:
    'Wybierz alerty z jednego trybu. Replay wymaga jednej sesji i zestawu danych.',
  idempotency_conflict: 'Potwierdzenie operacji nie pasuje do danych. Odśwież formularz.',
  conflict: 'Zasób o takich danych już istnieje.',
  csrf_failed: 'Sesja logowania zmieniła się. Spróbuj zalogować się ponownie.',
  rate_limited: 'Za dużo żądań. Poczekaj chwilę i spróbuj ponownie.',
  ingest_capacity_exceeded: 'Magazyn przyjmowania logów osiągnął limit.',
  duplicate_event_id: 'Każde zdarzenie testu musi mieć inny event_id. Usuń powtórzone rekordy.',
  body_too_large: 'Przesłany zestaw przekracza limit rozmiaru. Test może zawierać najwyżej 64 KiB.',
  rules_unavailable: 'Katalog reguł jest chwilowo niedostępny. Odśwież go przed kolejną zmianą.',
  rule_not_found: 'Nie znaleziono reguły. Odśwież katalog detekcji.',
  rule_unchanged: 'Reguła ma już ten stan. Odśwież katalog detekcji.',
  mitre_evidence_integrity_mismatch:
    'Nie można potwierdzić zgodności mapowania ATT&CK z zachowanym dowodem. Odśwież szczegóły.',
  mitre_snapshot_integrity_mismatch:
    'Zachowane mapowanie ATT&CK nie przeszło kontroli zgodności. Odśwież szczegóły.',
  mitre_case_limit: 'Incydent przekracza limit 100 alertów dla mapowania ATT&CK.',
};

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    public requestId?: string,
  ) {
    super(
      messages[code] ??
        (status === 503 ? 'Usługa jest chwilowo niedostępna.' : 'Nie udało się wykonać operacji.'),
    );
  }
}

export class ApiClient {
  private session: MemorySession | null = null;
  private refreshFlight: Promise<void> | null = null;
  private listeners = new Set<Subscriber>();
  private channel: BroadcastChannel | null = null;

  constructor() {
    if (typeof BroadcastChannel !== 'undefined') {
      this.channel = new BroadcastChannel('aegis-auth-v1');
      this.channel.onmessage = ({ data }: MessageEvent<unknown>) => {
        if (typeof data !== 'object' || data === null) return;
        const message = data as { kind?: string; session?: MemorySession };
        if (message.kind === 'logout') {
          this.session = null;
          this.notify('logout');
        } else if (
          message.kind === 'session' &&
          message.session &&
          typeof message.session.access_token === 'string' &&
          typeof message.session.csrf_token === 'string'
        ) {
          this.session = message.session;
          this.notify('session');
        }
      };
    }
  }

  subscribe(callback: Subscriber) {
    this.listeners.add(callback);
    return () => {
      this.listeners.delete(callback);
    };
  }
  private notify(kind: 'logout' | 'session') {
    this.listeners.forEach((listener) => listener(kind));
  }
  private setSession(tokens: TokenSet) {
    this.session = { ...tokens, expires_at: Date.now() + tokens.expires_in * 1000 };
    this.channel?.postMessage({ kind: 'session', session: this.session });
  }
  private clear() {
    this.session = null;
    this.channel?.postMessage({ kind: 'logout' });
    this.notify('logout');
  }
  private async lock<T>(task: () => Promise<T>): Promise<T> {
    if (typeof navigator !== 'undefined' && navigator.locks)
      return navigator.locks.request('aegis-auth-refresh-v1', task);
    return task();
  }
  private async raw<T>(path: string, init: RequestInit = {}): Promise<T> {
    let response: Response;
    try {
      response = await fetch(`/api/v1${path}`, {
        ...init,
        credentials: 'same-origin',
        cache: 'no-store',
        signal: init.signal ?? AbortSignal.timeout(15000),
        headers: { 'Content-Type': 'application/json', ...init.headers },
      });
    } catch {
      throw new ApiError(0, 'network_error');
    }
    if (!response.ok) {
      const body = (await response.json().catch(() => ({}))) as {
        error?: { code?: string; request_id?: string };
        code?: string;
        request_id?: string;
      };
      throw new ApiError(
        response.status,
        body.error?.code ?? body.code ?? 'http_error',
        body.error?.request_id ?? body.request_id,
      );
    }
    return response.status === 204 ? (undefined as T) : ((await response.json()) as T);
  }
  async login(username: string, password: string): Promise<Me> {
    await this.lock(async () => {
      const csrf = await this.raw<{ csrf_token: string }>('/auth/csrf');
      const tokens = await this.raw<TokenSet>('/auth/login', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf.csrf_token },
        body: JSON.stringify({ username, password }),
      });
      this.setSession(tokens);
    });
    return this.get<Me>('/auth/me');
  }
  async restore(): Promise<Me | null> {
    try {
      await this.refresh();
      return await this.get<Me>('/auth/me');
    } catch (error) {
      if (error instanceof ApiError && error.status === 401) return null;
      throw error;
    }
  }
  private async refresh(): Promise<void> {
    if (this.refreshFlight) return this.refreshFlight;
    if (typeof navigator === 'undefined' || !navigator.locks) {
      this.clear();
      throw new ApiError(401, 'unauthorized');
    }
    const start = this.session?.access_token;
    this.refreshFlight = this.lock(async () => {
      if (
        this.session &&
        this.session.access_token !== start &&
        this.session.expires_at > Date.now() + 30000
      )
        return;
      const csrf = await this.raw<{ csrf_token: string }>('/auth/csrf');
      const tokens = await this.raw<TokenSet>('/auth/refresh', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf.csrf_token },
        body: '{}',
      });
      this.setSession(tokens);
    })
      .catch((error: unknown) => {
        if (error instanceof ApiError && error.status === 401) this.clear();
        throw error;
      })
      .finally(() => {
        this.refreshFlight = null;
      });
    return this.refreshFlight;
  }
  async logout(): Promise<void> {
    await this.lock(async () => {
      const csrf = await this.raw<{ csrf_token: string }>('/auth/csrf');
      await this.raw('/auth/logout', {
        method: 'POST',
        headers: { 'X-CSRF-Token': csrf.csrf_token },
        body: '{}',
      });
    });
    this.clear();
  }
  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    if (!this.session) throw new ApiError(401, 'unauthorized');
    const run = () =>
      this.raw<T>(path, {
        ...init,
        headers: { Authorization: `Bearer ${this.session?.access_token}`, ...init.headers },
      });
    try {
      return await run();
    } catch (error) {
      if (!(error instanceof ApiError) || error.status !== 401) throw error;
      await this.refresh();
      try {
        return await run();
      } catch (failure) {
        if (failure instanceof ApiError && failure.status === 401) this.clear();
        throw failure;
      }
    }
  }
  get<T>(path: string) {
    return this.request<T>(path);
  }
  post<T>(path: string, body: unknown, headers: Record<string, string> = {}) {
    return this.request<T>(path, { method: 'POST', body: JSON.stringify(body), headers });
  }
  patch<T>(path: string, body: unknown, version: number) {
    return this.request<T>(path, {
      method: 'PATCH',
      body: JSON.stringify(body),
      headers: { 'If-Match': `"${version}"` },
    });
  }
  delete<T>(path: string, version: number) {
    return this.request<T>(path, {
      method: 'DELETE',
      headers: { 'If-Match': `"${version}"` },
    });
  }
  sourcePost<T>(token: string, body: unknown, key: string) {
    return this.raw<T>('/events', {
      method: 'POST',
      body: JSON.stringify(body),
      headers: { Authorization: `Bearer ${token}`, 'Idempotency-Key': key },
    });
  }
}

export const api = new ApiClient();

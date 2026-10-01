import { beforeEach, expect, it, vi } from 'vitest';
import { ApiClient, ApiError } from '../src/api';

const me = { id: 'user-id', username: 'analyst', role: 'soc_analyst', permissions: [] };
const tokens = { access_token: 'access-one', csrf_token: 'csrf-one', expires_in: 300 };
function response(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
let handler: (path: string, init: RequestInit) => Response | Promise<Response>;
const fetchMock = vi.fn((path: string, init: RequestInit = {}) =>
  Promise.resolve(handler(path, init)),
);
beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock);
  fetchMock.mockClear();
  let queue = Promise.resolve();
  Object.defineProperty(navigator, 'locks', {
    configurable: true,
    value: {
      request: (_key: string, callback: () => Promise<unknown>) => {
        const result = queue.then(callback);
        queue = result.then(
          () => undefined,
          () => undefined,
        );
        return result;
      },
    },
  });
  handler = (path) => {
    if (path.endsWith('/csrf')) return response({ csrf_token: 'pre-csrf' });
    if (path.endsWith('/login')) return response(tokens);
    if (path.endsWith('/refresh')) return response({ ...tokens, access_token: 'access-two' });
    if (path.endsWith('/me')) return response(me);
    return response({ ok: true });
  };
});

it('uses CSRF before login and retains credentials only in memory', async () => {
  const local = vi.spyOn(Storage.prototype, 'setItem');
  const client = new ApiClient();
  expect(await client.login('analyst', 'a-long-test-password')).toEqual(me);
  const login = fetchMock.mock.calls.find(([path]) => path.endsWith('/login'))!;
  expect(login[1]?.headers).toMatchObject({ 'X-CSRF-Token': 'pre-csrf' });
  const profile = fetchMock.mock.calls.find(([path]) => path.endsWith('/me'))!;
  expect(profile[1]?.headers).toMatchObject({ Authorization: 'Bearer access-one' });
  expect(profile[1]?.credentials).toBe('same-origin');
  expect(profile[1]?.cache).toBe('no-store');
  expect(local).not.toHaveBeenCalled();
});

it('shares one refresh for concurrent expired requests', async () => {
  const client = new ApiClient();
  await client.login('analyst', 'a-long-test-password');
  const previous = handler;
  handler = (path, init) => {
    if (
      path.endsWith('/protected') &&
      (init.headers as Record<string, string>).Authorization === 'Bearer access-one'
    )
      return response({ code: 'unauthorized' }, 401);
    return previous(path, init);
  };
  await Promise.all([client.get('/protected'), client.get('/protected')]);
  expect(fetchMock.mock.calls.filter(([path]) => path.endsWith('/refresh'))).toHaveLength(1);
});

it('clears session after a terminal 401 following refresh', async () => {
  const client = new ApiClient();
  const listener = vi.fn();
  client.subscribe(listener);
  await client.login('analyst', 'a-long-test-password');
  const previous = handler;
  handler = (path, init) =>
    path.endsWith('/protected') ? response({ code: 'unauthorized' }, 401) : previous(path, init);
  await expect(client.get('/protected')).rejects.toMatchObject({ status: 401 });
  expect(listener).toHaveBeenCalledWith('logout');
  fetchMock.mockClear();
  await expect(client.get('/protected')).rejects.toMatchObject({ status: 401 });
  expect(fetchMock).not.toHaveBeenCalled();
});

it('expires safely when browser lacks cross-tab refresh locks', async () => {
  const client = new ApiClient();
  const listener = vi.fn();
  client.subscribe(listener);
  await client.login('analyst', 'a-long-test-password');
  Object.defineProperty(navigator, 'locks', { configurable: true, value: undefined });
  handler = () => response({ code: 'unauthorized' }, 401);
  await expect(client.get('/protected')).rejects.toMatchObject({ status: 401 });
  expect(listener).toHaveBeenCalledWith('logout');
  expect(fetchMock.mock.calls.filter(([path]) => path.endsWith('/refresh'))).toHaveLength(0);
});

it('retains current session when logout is unavailable so the user can retry', async () => {
  const client = new ApiClient();
  const listener = vi.fn();
  client.subscribe(listener);
  await client.login('analyst', 'a-long-test-password');
  const previous = handler;
  handler = (path, init) =>
    path.endsWith('/logout')
      ? response({ code: 'dependency_unavailable' }, 503)
      : previous(path, init);
  await expect(client.logout()).rejects.toMatchObject({ status: 503 });
  expect(listener).not.toHaveBeenCalledWith('logout');
  expect(await client.get('/auth/me')).toEqual(me);
  handler = previous;
  await client.logout();
  expect(listener).toHaveBeenCalledWith('logout');
  await expect(client.get('/auth/me')).rejects.toBeInstanceOf(ApiError);
});

it('preserves If-Match for human changes and uses separate ingestion authority', async () => {
  const client = new ApiClient();
  await client.login('analyst', 'a-long-test-password');
  await client.patch('/alerts/test', { status: 'acknowledged' }, 7);
  expect(fetchMock.mock.calls.at(-1)![1]?.headers).toMatchObject({
    'If-Match': '"7"',
    Authorization: 'Bearer access-one',
  });
  await client.sourcePost(
    'aegis_ingest_example',
    { source_type: 'generic_json', raw_event: {} },
    'unique-receipt',
  );
  expect(fetchMock.mock.calls.at(-1)![1]?.headers).toMatchObject({
    Authorization: 'Bearer aegis_ingest_example',
    'Idempotency-Key': 'unique-receipt',
  });
});

it('does not retry a denied operation or expose unknown server error text', async () => {
  const client = new ApiClient();
  await client.login('analyst', 'a-long-test-password');
  handler = () => response({ code: 'forbidden', message: 'secret internal detail' }, 403);
  await expect(client.get('/protected')).rejects.toMatchObject({
    status: 403,
    message: 'Twoja rola nie pozwala na tę czynność.',
  });
  expect(fetchMock.mock.calls.filter(([path]) => path.endsWith('/refresh'))).toHaveLength(0);
});

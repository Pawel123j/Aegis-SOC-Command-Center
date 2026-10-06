import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import type { Me } from '../types';
import type { AttackTimelinePage } from './types';

export function useAttackTimeline(id: string, user: Me) {
  const authority = useRef(0);
  const requestController = useRef<AbortController | null>(null);
  const authController = useRef<AbortController | null>(null);
  const refreshing = useRef(false);
  const [scope, setScope] = useState({ epoch: 0, expired: false, checking: false });
  const [navigation, setNavigation] = useState({
    limit: 25,
    cursor: null as string | null,
    previous: [] as (string | null)[],
  });
  const params = new URLSearchParams({ limit: String(navigation.limit) });
  if (navigation.cursor) params.set('cursor', navigation.cursor);
  const path = `/incidents/${encodeURIComponent(id)}/attack-timeline?${params}`;
  const [state, setState] = useState<{
    path: string;
    epoch: number;
    data: AttackTimelinePage | null;
    pending: boolean;
    error: unknown;
  }>({ path, epoch: 0, data: null, pending: true, error: null });

  useEffect(() => {
    const counter = authority;
    const requests = requestController;
    const checks = authController;
    const flight = refreshing;
    const unsubscribe = api.subscribe(() => {
      const epoch = ++counter.current;
      requests.current?.abort();
      checks.current?.abort();
      flight.current = false;
      setScope({ epoch, expired: true, checking: false });
      setNavigation((current) => ({ ...current, cursor: null, previous: [] }));
    });
    return () => {
      counter.current++;
      requests.current?.abort();
      checks.current?.abort();
      unsubscribe();
    };
  }, []);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    requestController.current = controller;
    void Promise.resolve().then(async () => {
      if (!active || scope.expired) return;
      const epoch = scope.epoch;
      setState({ path, epoch, data: null, pending: true, error: null });
      try {
        const data = await api.request<AttackTimelinePage>(path, {
          signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]),
        });
        if (active && authority.current === epoch)
          setState({ path, epoch, data, pending: false, error: null });
      } catch (error) {
        if (active && authority.current === epoch)
          setState({ path, epoch, data: null, pending: false, error });
      }
    });
    return () => {
      active = false;
      controller.abort();
    };
  }, [path, scope.epoch, scope.expired]);

  const visible = !scope.expired && state.path === path && state.epoch === scope.epoch;
  function isCurrent() {
    return visible && !state.pending && authority.current === state.epoch;
  }
  function navigate(next: typeof navigation) {
    if (scope.checking || scope.expired || authority.current !== scope.epoch) return;
    requestController.current?.abort();
    setScope({ epoch: ++authority.current, expired: false, checking: false });
    setNavigation(next);
  }
  async function refresh(onVerified?: () => void | Promise<void>) {
    if (refreshing.current) return;
    refreshing.current = true;
    requestController.current?.abort();
    authController.current?.abort();
    const controller = new AbortController();
    authController.current = controller;
    const epoch = ++authority.current;
    setScope({ epoch, expired: true, checking: true });
    setState({ path, epoch, data: null, pending: false, error: null });
    try {
      const current = await api.request<Me>('/auth/me', {
        signal: AbortSignal.any([controller.signal, AbortSignal.timeout(15000)]),
      });
      if (authority.current !== epoch) return;
      if (
        current.id !== user.id ||
        current.role !== user.role ||
        current.permissions.length !== user.permissions.length ||
        !user.permissions.every((permission) => current.permissions.includes(permission))
      )
        throw new Error('Konto lub uprawnienia zmieniły się. Otwórz sprawę z menu bieżącej sesji.');
      if (onVerified) {
        await onVerified();
        if (authority.current !== epoch) return;
      }
      setNavigation((current) => ({ ...current, cursor: null, previous: [] }));
      setScope({ epoch: ++authority.current, expired: false, checking: false });
    } catch (error) {
      if (authority.current === epoch) {
        setState({ path, epoch, data: null, pending: false, error });
        setScope({ epoch, expired: true, checking: false });
      }
    } finally {
      if (authority.current === epoch || authority.current === epoch + 1)
        refreshing.current = false;
    }
  }
  return {
    data: visible ? state.data : null,
    error: state.epoch === scope.epoch ? state.error : null,
    pending: !scope.expired && (!visible || state.pending),
    expired: scope.expired,
    checking: scope.checking,
    refresh,
    isCurrent,
    limit: navigation.limit,
    changeLimit: (limit: number) => navigate({ limit, cursor: null, previous: [] }),
    pagination: {
      previous: navigation.previous.length,
      hasNext: Boolean(visible && state.data?.next_cursor),
      pending: !visible || state.pending || scope.checking,
      onNext: () => {
        if (!isCurrent() || !state.data?.next_cursor) return;
        navigate({
          ...navigation,
          cursor: state.data.next_cursor,
          previous: [...navigation.previous, navigation.cursor],
        });
      },
      onPrevious: () => {
        if (!isCurrent() || !navigation.previous.length) return;
        navigate({
          ...navigation,
          cursor: navigation.previous.at(-1) ?? null,
          previous: navigation.previous.slice(0, -1),
        });
      },
    },
  };
}

import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../api';

export function useIntelligenceScope() {
  const generation = useRef(0);
  const [state, setState] = useState({ epoch: 0, expired: false });
  const capture = useCallback(() => generation.current, []);
  const isCurrent = useCallback((epoch: number) => generation.current === epoch, []);
  const resume = useCallback(() => {
    setState({ epoch: ++generation.current, expired: false });
  }, []);
  useEffect(() => {
    const counter = generation;
    const unsubscribe = api.subscribe(() => {
      setState({ epoch: ++counter.current, expired: true });
    });
    return () => {
      counter.current++;
      unsubscribe();
    };
  }, []);
  return { ...state, capture, isCurrent, resume };
}
export type IntelligenceScope = ReturnType<typeof useIntelligenceScope>;

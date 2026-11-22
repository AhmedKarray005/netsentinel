// Which analysis is selected, shared by every page (React "context" = app-wide state).
import { createContext, useCallback, useContext, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { api } from "./api";
import type { Analysis } from "./types";

interface AnalysisState {
  analyses: Analysis[];
  selectedId: number | null;
  select: (id: number | null) => void;
  refresh: () => Promise<void>;
  error: string | null;
  loading: boolean;
}

const Ctx = createContext<AnalysisState | null>(null);
const STORAGE_KEY = "netsentinel.selectedAnalysis";

function readStored(): number | null {
  try {
    const value = Number(window.localStorage.getItem(STORAGE_KEY));
    return Number.isInteger(value) && value > 0 ? value : null;
  } catch {
    return null; // storage can be blocked (private mode): just forget the choice
  }
}

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(readStored);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const select = useCallback((id: number | null) => {
    setSelectedId(id);
    try {
      if (id === null) window.localStorage.removeItem(STORAGE_KEY);
      else window.localStorage.setItem(STORAGE_KEY, String(id));
    } catch {
      /* ignore */
    }
  }, []);

  const refresh = useCallback(async () => {
    try {
      const page = await api.listAnalyses(100, 0);
      setAnalyses(page.items);
      setError(null);
      // Keep the selection if it still exists, else pick the newest analysis.
      setSelectedId((current) =>
        current !== null && page.items.some((a) => a.id === current)
          ? current
          : (page.items[0]?.id ?? null),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <Ctx.Provider value={{ analyses, selectedId, select, refresh, error, loading }}>
      {children}
    </Ctx.Provider>
  );
}

export function useAnalyses(): AnalysisState {
  const value = useContext(Ctx);
  if (!value) throw new Error("useAnalyses must be used inside <AnalysisProvider>");
  return value;
}

/** Load data when `deps` change; returns {data, error, loading, reload}. */
export function useLoad<T>(load: () => Promise<T>, deps: unknown[]) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let cancelled = false; // ignore answers that arrive after the user changed filters
    setLoading(true);
    load()
      .then((value) => {
        if (!cancelled) {
          setData(value);
          setError(null);
        }
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  return { data, error, loading, reload: () => setTick((t) => t + 1) };
}

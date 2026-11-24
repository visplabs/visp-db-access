import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { useInRouterContext, useLocation } from 'react-router-dom';
import { CheckCircle2, CircleAlert, X } from 'lucide-react';
import { Button } from '.';
const ToastContext = createContext<
  (text: string, tone?: 'success' | 'error') => void
>(() => undefined);
export const useToast = () => useContext(ToastContext);

type Item = {
  id: string;
  text: string;
  tone: 'success' | 'error';
  at: number;
};
/** A toast older than this when the page changes belongs to the page left
 * behind; a younger one was raised by the action that changed the page. */
const CARRIES_OVER_MS = 1000;

/** Calls `onChange` when the path changes (not on the first render). */
function RouteWatcher({ onChange }: { onChange: () => void }) {
  const { pathname } = useLocation();
  const first = useRef(pathname);
  useEffect(() => {
    if (pathname === first.current) return;
    first.current = pathname;
    onChange();
  }, [pathname, onChange]);
  return null;
}

/**
 * Short feedback that needs no answer. Toasts sit in the top bar's own band,
 * centred, so they never cover an action bar at the bottom of a screen,
 * a dialog, or content to copy; only the newest shows. They are announced
 * politely and never take focus. A toast closes after six seconds, when
 * dismissed, or when the person goes to another page. Show nothing when the
 * screen already says what happened.
 */
export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Item[]>([]);
  const routed = useInRouterContext();
  const sequence = useRef(0);
  const timers = useRef(new Set<ReturnType<typeof setTimeout>>());
  useEffect(() => {
    const pending = timers.current;
    return () => {
      pending.forEach(clearTimeout);
      pending.clear();
    };
  }, []);
  const toast = useCallback(
    (text: string, tone: 'success' | 'error' = 'success') => {
      // crypto.randomUUID() throws outside secure contexts (plain http on a LAN).
      const id = String(++sequence.current);
      // The same words again replace the earlier toast: one "Checked", not two.
      setItems((items) => [
        ...items.filter((item) => item.text !== text || item.tone !== tone),
        { id, text, tone, at: Date.now() },
      ]);
      const timer = setTimeout(() => {
        timers.current.delete(timer);
        setItems((items) => items.filter((item) => item.id !== id));
      }, 6000);
      timers.current.add(timer);
    },
    [],
  );
  const leavePage = useCallback(() => {
    const now = Date.now();
    setItems((items) => {
      const kept = items.filter((item) => now - item.at < CARRIES_OVER_MS);
      return kept.length === items.length ? items : kept;
    });
  }, []);
  return (
    <ToastContext.Provider value={toast}>
      {routed && <RouteWatcher onChange={leavePage} />}
      {children}
      {/* A polite live region (like role="status", without adding one more
          status to the page): read out, never focused. */}
      <div className="toasts" aria-live="polite">
        {items.map((item) => (
          <div className={`toast ${item.tone}`} key={item.id}>
            {item.tone === 'success' ? (
              <CheckCircle2 size={17} aria-hidden="true" />
            ) : (
              <CircleAlert size={17} aria-hidden="true" />
            )}
            <span>{item.text}</span>
            <Button
              variant="ghost"
              aria-label="Dismiss notification"
              onClick={() =>
                setItems((items) =>
                  items.filter((value) => value.id !== item.id),
                )
              }
            >
              <X size={15} />
            </Button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

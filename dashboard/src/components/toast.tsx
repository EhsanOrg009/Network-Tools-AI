import { createContext, useCallback, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { IconCheck, IconAlert, IconX } from "./icons";

interface Toast {
  id: number;
  text: string;
  kind: "success" | "error" | "info";
}
interface ToastCtx {
  push: (text: string, kind?: Toast["kind"]) => void;
}

const Ctx = createContext<ToastCtx>({ push: () => {} });

export function useToast() {
  return useContext(Ctx);
}

let nextId = 1;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const push = useCallback((text: string, kind: Toast["kind"] = "success") => {
    const id = nextId++;
    setToasts((t) => [...t, { id, text, kind }]);
    window.setTimeout(() => {
      setToasts((t) => t.filter((x) => x.id !== id));
    }, 4200);
  }, []);
  const value = useMemo(() => ({ push }), [push]);
  return (
    <Ctx.Provider value={value}>
      {children}
      <div className="toast-stack">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`}>
            {t.kind === "success" ? <IconCheck size={16} /> : <IconAlert size={16} />}
            <span style={{ flex: 1 }}>{t.text}</span>
            <button
              className="btn ghost sm"
              aria-label="بستن اعلان"
              onClick={() => setToasts((x) => x.filter((y) => y.id !== t.id))}
              style={{ padding: "2px 6px" }}
            >
              <IconX size={13} />
            </button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}

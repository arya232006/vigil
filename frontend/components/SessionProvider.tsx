"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import { getJson } from "@/lib/api";
import { SessionContext, type Account } from "@/lib/session";

/** Asks the API who is signed in. The session cookie is HttpOnly, so scripts on the page can't read it. */
export function SessionProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [account, setAccount] = useState<Account | null>(null);
  const [google, setGoogle] = useState(false);

  useEffect(() => {
    let current = true;
    getJson<{ user: Account | null; google: boolean }>("/api/auth/me")
      .then((r) => {
        if (!current) return;
        setAccount(r.user);
        setGoogle(r.google);
      })
      .catch(() => current && setAccount(null))
      .finally(() => current && setReady(true));
    return () => {
      current = false;
    };
  }, []);

  const session = useMemo(() => ({ ready, account, google, setAccount }), [ready, account, google]);
  return <SessionContext.Provider value={session}>{children}</SessionContext.Provider>;
}

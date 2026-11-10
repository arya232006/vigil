"use client";

import Link from "next/link";
import { useState } from "react";
import { signOut } from "@/lib/api";
import { rememberSignedIn, useSession } from "@/lib/session";

/** "Sign in" for guests; the account's email and "Sign out" for signed-in users. */
export function AccountControls() {
  const { ready, account } = useSession();
  const [busy, setBusy] = useState(false);

  if (!account) {
    // Shown from the first paint. While the session is loading, it stays hidden only for people who were signed in.
    return <Link href="/sign-in" className={`tile ${ready ? "" : "[html[data-signed-in]_&]:invisible"}`}>Sign in</Link>;
  }

  const name = account.email ?? account.username;

  const leave = async () => {
    setBusy(true);
    try {
      await signOut();
      rememberSignedIn(false);
      window.location.assign("/"); // a full load, so nothing from this account stays in memory
    } catch {
      setBusy(false);
    }
  };

  return (
    <>
      <span className="tile hidden max-w-56 truncate md:inline-block" title={name ?? undefined}>{name}</span>
      <button type="button" className="tile cursor-pointer" onClick={leave} disabled={busy}>Sign out</button>
    </>
  );
}

"use client";

import Link from "next/link";
import { useState } from "react";
import { signOut } from "@/lib/api";
import { useSession } from "@/lib/session";

/** "Sign in" for guests; the account's email and "Sign out" for signed-in users. */
export function AccountControls() {
  const { ready, account } = useSession();
  const [busy, setBusy] = useState(false);

  if (!ready) return null;
  if (!account) return <Link href="/sign-in" className="tile">Sign in</Link>;

  const leave = async () => {
    setBusy(true);
    try {
      await signOut();
      window.location.assign("/"); // a full load, so nothing from this account stays in memory
    } catch {
      setBusy(false);
    }
  };

  return (
    <>
      <span className="tile hidden max-w-56 truncate md:inline-block" title={account.email}>{account.email}</span>
      <button type="button" className="tile cursor-pointer" onClick={leave} disabled={busy}>Sign out</button>
    </>
  );
}

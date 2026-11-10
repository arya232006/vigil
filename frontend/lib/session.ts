"use client";

import { createContext, useContext } from "react";

export interface Account {
  id: string;
  email: string | null;
  username: string | null;
}

export interface Session {
  /** False until the server has said who this is, so pages don't briefly treat a signed-in user as a guest. */
  ready: boolean;
  account: Account | null;
  /** Whether this server has Google sign-in set up. */
  google: boolean;
  setAccount: (account: Account | null) => void;
}

export const SessionContext = createContext<Session>({ ready: false, account: null, google: false, setAccount: () => {} });

const SIGNED_IN_HINT = "vigil_signed_in";

/** Runs before the first paint, so a returning user doesn't see "Sign in" flash. Only a hint: the API still decides. */
export const SIGNED_IN_HINT_SCRIPT = `try{if(localStorage.getItem("${SIGNED_IN_HINT}"))document.documentElement.dataset.signedIn=""}catch(e){}`;

export function rememberSignedIn(signedIn: boolean) {
  try {
    if (signedIn) localStorage.setItem(SIGNED_IN_HINT, "1");
    else localStorage.removeItem(SIGNED_IN_HINT);
  } catch {
    // storage can be blocked; the hint only affects the first paint
  }
}

export const useSession = () => useContext(SessionContext);

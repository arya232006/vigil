"use client";

import { createContext, useContext } from "react";

export interface Account {
  id: string;
  email: string;
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

export const useSession = () => useContext(SessionContext);

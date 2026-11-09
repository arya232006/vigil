"use client";

import { useAuth } from "@clerk/nextjs";
import { useLayoutEffect } from "react";
import { setAuthTokenGetter } from "@/lib/api";

/** Connects the API client to the session. A layout effect, so it is ready before any page's data-fetching effect. */
export function AuthBridge() {
  const { getToken } = useAuth();
  useLayoutEffect(() => {
    setAuthTokenGetter(() => getToken());
  }, [getToken]);
  return null;
}

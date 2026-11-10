"use client";

import { useEffect, useState } from "react";
import { useSession, type Account } from "./session";
import type { ChainVerify, JobInfo, Report } from "./types";

export const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const JOB_TIMEOUT_MS = 60_000;
const POLL_INTERVAL_MS = 1_000;

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

const FRIENDLY: Record<number, string> = {
  401: "Please sign in again to continue.",
  429: "Too many requests. Wait a minute and try again.",
  413: "That email is too large (the limit is about 2 MB).",
  404: "That report or job no longer exists. Submit it again.",
};

async function request(path: string, init?: RequestInit): Promise<Response> {
  let res: Response;
  try {
    res = await fetch(`${API}${path}`, { ...init, credentials: "include" });
  } catch {
    throw new ApiError(`Can't reach the Vigil API at ${API}. Is the backend running?`, 0);
  }
  if (res.ok) return res;
  const body = await res.json().catch(() => null);
  const detail = typeof body?.detail === "string" ? body.detail : null;
  const validation = res.status === 422 ? "That input isn't valid. Check it isn't empty or too long." : null;
  const friendly = path.startsWith("/api/auth/") ? undefined : FRIENDLY[res.status]; // sign-in errors say what to fix
  throw new ApiError(friendly ?? validation ?? detail ?? `Request failed (HTTP ${res.status})`, res.status);
}

export async function getJson<T>(path: string): Promise<T> {
  return (await request(path)).json();
}

function postJson<T>(path: string, body?: unknown): Promise<T> {
  return request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  }).then((r) => r.json());
}

export async function investigate(
  input: string,
  fresh: boolean,
  onProgress: (status: "queued" | "running") => void,
): Promise<JobInfo> {
  let job = await postJson<JobInfo>("/api/jobs", { input, type: "auto", fresh });
  const started = Date.now();
  while (job.status === "queued" || job.status === "running") {
    onProgress(job.status);
    if (Date.now() - started > JOB_TIMEOUT_MS) {
      throw new ApiError("The analysis timed out. Try again.", 0);
    }
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    job = await getJson<JobInfo>(`/api/jobs/${job.job_id}`);
  }
  if (job.status === "failed") throw new ApiError(job.error ?? "The analysis failed. Try again.", 0);
  return job;
}

export const signIn = (identifier: string, password: string) =>
  postJson<{ user: Account }>("/api/auth/login", { identifier, password });
export const signUp = (name: { email: string } | { username: string }, password: string) =>
  postJson<{ user: Account }>("/api/auth/signup", { ...name, password });
export const generateUsername = () => getJson<{ username: string }>("/api/auth/username");
export const signOut = () => postJson<unknown>("/api/auth/logout");

export const analyzeEmail = (raw: string) => postJson<Report>("/api/analyze/email", { raw, live_dns: true });
export const anchorReport = (id: string) => postJson<unknown>(`/api/reports/${id}/anchor`);
export const chainVerify = (id: string) => getJson<ChainVerify>(`/api/reports/${id}/chain-verify`);
export const getCanonical = async (id: string) => (await request(`/api/reports/${id}/canonical`)).text();

export const errorMessage = (e: unknown) => (e instanceof Error ? e.message : "Something went wrong.");

/** GET `path` (skipped when null). Change `reloadKey` to fetch again. */
export function useApi<T>(path: string | null, reloadKey: number = 0) {
  const { ready, account } = useSession();
  const userId = account?.id ?? "";
  const key = path === null ? null : `${path}#${reloadKey}#${userId}`;
  const [state, setState] = useState<{ key: string | null; data?: T; error?: string }>({ key: null });

  useEffect(() => {
    if (path === null || !ready) return; // wait for the session, so results are keyed to the right account
    let current = true;
    const k = `${path}#${reloadKey}#${userId}`;
    getJson<T>(path).then(
      (data) => current && setState({ key: k, data }),
      (e) => current && setState({ key: k, error: errorMessage(e) }),
    );
    return () => {
      current = false;
    };
  }, [path, reloadKey, ready, userId]);

  const settled = state.key === key;
  return {
    data: settled ? state.data : undefined,
    error: settled ? state.error : undefined,
    loading: path !== null && !settled,
  };
}

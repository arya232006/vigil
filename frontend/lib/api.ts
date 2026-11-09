"use client";

import { useAuth } from "@clerk/nextjs";
import { useEffect, useState } from "react";
import type { ChainVerify, JobInfo, Report } from "./types";

export const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

const JOB_TIMEOUT_MS = 60_000;
const POLL_INTERVAL_MS = 1_000;

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

let getAuthToken: () => Promise<string | null> = async () => null;

export function setAuthTokenGetter(getter: () => Promise<string | null>) {
  getAuthToken = getter;
}

const FRIENDLY: Record<number, string> = {
  401: "Please sign in again to continue.",
  429: "Too many requests. Wait a minute and try again.",
  413: "That email is too large (the limit is about 2 MB).",
  404: "That report or job no longer exists. Submit it again.",
};

async function request(path: string, init?: RequestInit): Promise<Response> {
  // A signed-in user must never fall back to a guest request: their report would be saved with no owner.
  let token: string | null;
  try {
    token = await getAuthToken();
  } catch {
    throw new ApiError("Your session could not be confirmed. Reload the page and try again.", 401);
  }
  const headers = new Headers(init?.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);

  let res: Response;
  try {
    res = await fetch(`${API}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(`Can't reach the Vigil API at ${API}. Is the backend running?`, 0);
  }
  if (res.ok) return res;
  const body = await res.json().catch(() => null);
  const detail = typeof body?.detail === "string" ? body.detail : null;
  const validation = res.status === 422 ? "That input isn't valid. Check it isn't empty or too long." : null;
  throw new ApiError(FRIENDLY[res.status] ?? validation ?? detail ?? `Request failed (HTTP ${res.status})`, res.status);
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

export const analyzeEmail = (raw: string) => postJson<Report>("/api/analyze/email", { raw, live_dns: true });
export const anchorReport = (id: string) => postJson<unknown>(`/api/reports/${id}/anchor`);
export const chainVerify = (id: string) => getJson<ChainVerify>(`/api/reports/${id}/chain-verify`);
export const getCanonical = async (id: string) => (await request(`/api/reports/${id}/canonical`)).text();

export const errorMessage = (e: unknown) => (e instanceof Error ? e.message : "Something went wrong.");

/** GET `path` (skipped when null). Change `reloadKey` to fetch again. */
export function useApi<T>(path: string | null, reloadKey: number = 0) {
  const { isLoaded, userId } = useAuth();
  const key = path === null ? null : `${path}#${reloadKey}#${userId ?? ""}`;
  const [state, setState] = useState<{ key: string | null; data?: T; error?: string }>({ key: null });

  useEffect(() => {
    if (path === null || !isLoaded) return; // wait for the session, so the first request isn't sent as a guest
    let current = true;
    const k = `${path}#${reloadKey}#${userId ?? ""}`;
    getJson<T>(path).then(
      (data) => current && setState({ key: k, data }),
      (e) => current && setState({ key: k, error: errorMessage(e) }),
    );
    return () => {
      current = false;
    };
  }, [path, reloadKey, isLoaded, userId]);

  const settled = state.key === key;
  return {
    data: settled ? state.data : undefined,
    error: settled ? state.error : undefined,
    loading: path !== null && !settled,
  };
}

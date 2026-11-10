"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { Button, Card, ErrorNote } from "@/components/ui";
import { API, errorMessage, generateUsername, signIn, signUp } from "@/lib/api";
import { useSession } from "@/lib/session";

const MIN_PASSWORD = 10;
const FIELD = "w-full border border-(--l-ink) bg-(--l-paper) px-3 py-2 text-base";
const INPUT = `mt-1 ${FIELD}`;
const NAME_FIELD = { autoCapitalize: "none", autoCorrect: "off", spellCheck: false } as const;

function EyeIcon({ crossed }: { crossed: boolean }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-5 w-5" aria-hidden>
      <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z" />
      <circle cx="12" cy="12" r="3" />
      {crossed && <path d="M4 4l16 16" />}
    </svg>
  );
}

/** Only paths on this site, so a crafted link can't send someone elsewhere after they sign in. */
function safeNext(value: string | null): string {
  return value && /^\/(?![/\\])/.test(value) ? value : "/investigate";
}

type Method = "email" | "username";

export function AuthForm({ mode }: { mode: "sign-in" | "sign-up" }) {
  const creating = mode === "sign-up";
  const router = useRouter();
  const params = useSearchParams();
  const next = safeNext(params.get("next"));
  const { ready, account, google, setAccount } = useSession();
  const [method, setMethod] = useState<Method>("email");
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(
    params.get("error") === "google" ? "Google sign-in didn’t work. Try again." : null,
  );
  const [busy, setBusy] = useState(false);
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    if (ready && account) router.replace(next);
  }, [ready, account, next, router]);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { user } = creating
        ? await signUp(method === "email" ? { email: identifier } : { username: identifier }, password)
        : await signIn(identifier, password);
      setAccount(user);
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  };

  const chooseMethod = (choice: Method) => {
    if (choice === method) return;
    setMethod(choice);
    setIdentifier("");
    setError(null);
  };

  const generate = async () => {
    setGenerating(true);
    setError(null);
    try {
      setIdentifier((await generateUsername()).username);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setGenerating(false);
    }
  };

  const methodButton = (value: Method, label: string) => (
    <button
      type="button"
      aria-pressed={method === value}
      onClick={() => chooseMethod(value)}
      className={`terminal flex-1 cursor-pointer border border-(--l-ink) px-3 py-0.5 text-xl ${
        method === value ? "bg-(--l-ink) text-(--l-paper)" : "bg-(--l-paper) hover:bg-sunken"
      }`}
    >
      {label}
    </button>
  );

  const other = creating ? "/sign-in" : "/sign-up";
  const otherHref = next === "/investigate" ? other : `${other}?next=${encodeURIComponent(next)}`;
  const usingUsername = creating && method === "username";

  return (
    <Card title={creating ? "account.create" : "account.sign-in"} className="w-full max-w-md">
      <h1 className="display text-5xl">{creating ? "Create Account" : "Sign In"}</h1>
      <form onSubmit={submit} className="mt-6 space-y-4">
        {creating && (
          <div className="flex gap-1.5" role="group" aria-label="Sign up with">
            {methodButton("email", "Email")}
            {methodButton("username", "Username")}
          </div>
        )}
        {!creating && (
          <label className="block text-sm font-medium">
            Email or username
            <input className={INPUT} type="text" name="identifier" autoComplete="username" required {...NAME_FIELD}
              value={identifier} onChange={(e) => setIdentifier(e.target.value)} />
          </label>
        )}
        {creating && method === "email" && (
          <label className="block text-sm font-medium">
            Email
            <input className={INPUT} type="email" name="email" autoComplete="email" required value={identifier}
              onChange={(e) => setIdentifier(e.target.value)} />
          </label>
        )}
        {usingUsername && (
          <div>
            <label htmlFor="username" className="block text-sm font-medium">Username</label>
            <div className="mt-1 flex gap-1.5">
              <input id="username" className={`${FIELD} min-w-0 flex-1`} type="text" name="username" autoComplete="username"
                required minLength={3} maxLength={30} pattern="[A-Za-z0-9][A-Za-z0-9_\-]{1,28}[A-Za-z0-9]"
                title="3 to 30 letters, numbers, hyphens or underscores, starting and ending with a letter or number"
                {...NAME_FIELD} value={identifier} onChange={(e) => setIdentifier(e.target.value)} />
              <Button type="button" onClick={generate} disabled={generating}>
                {generating ? "…" : "Generate"}
              </Button>
            </div>
          </div>
        )}
        <div>
          <label htmlFor="password" className="block text-sm font-medium">Password</label>
          <div className="relative mt-1">
            <input id="password" className={`${FIELD} pr-12`} type={showPassword ? "text" : "password"} name="password" required
              minLength={creating ? MIN_PASSWORD : undefined} maxLength={128}
              autoComplete={creating ? "new-password" : "current-password"} value={password}
              onChange={(e) => setPassword(e.target.value)} />
            <button
              type="button"
              className="absolute inset-y-0 right-0 flex w-11 cursor-pointer items-center justify-center hover:bg-(--l-ink) hover:text-(--l-paper)"
              aria-label={showPassword ? "Hide password" : "Show password"}
              aria-pressed={showPassword}
              title={showPassword ? "Hide password" : "Show password"}
              onClick={() => setShowPassword((shown) => !shown)}
            >
              <EyeIcon crossed={showPassword} />
            </button>
          </div>
        </div>
        {creating && (
          <p className="text-sm leading-snug text-ink-2">
            Use at least {MIN_PASSWORD} characters.{" "}
            {usingUsername
              ? "Save your username and password somewhere safe. Without an email, this account can’t be recovered."
              : "We can’t reset passwords yet, so keep yours somewhere safe."}
          </p>
        )}
        {error && <ErrorNote>{error}</ErrorNote>}
        <Button variant="primary" type="submit" disabled={busy}>
          {busy ? "One moment…" : creating ? "Create account" : "Sign in"}
        </Button>
      </form>
      {google && (
        <a
          href={`${API}/api/auth/google/start?next=${encodeURIComponent(next)}`}
          className="terminal mt-3 block border border-(--l-ink) bg-(--l-paper) px-3 py-1 text-center text-xl leading-tight hover:bg-(--l-ink) hover:text-(--l-paper)"
        >
          Continue with Google
        </a>
      )}
      <p className="mt-5 text-sm">
        {creating ? "Already have an account? " : "New to Vigil? "}
        <Link href={otherHref} className="underline">{creating ? "Sign in" : "Create an account"}</Link>
      </p>
    </Card>
  );
}

import Link from "next/link";
import { Suspense } from "react";
import { brandFonts } from "@/app/fonts";
import "@/app/(marketing)/landing.css";
import { AuthForm } from "@/components/AuthForm";
import { Logo } from "@/components/Logo";

export function AuthPage({ mode }: { mode: "sign-in" | "sign-up" }) {
  return (
    <div className={`landing app-shell ${brandFonts}`}>
      <div className="flex min-h-svh flex-col bg-(--l-pink)">
        <nav className="bg-(--l-ink) p-1.5">
          <Link href="/" className="tile inline-block" aria-label="Vigil home"><Logo /></Link>
        </nav>
        <main className="flex flex-1 items-center justify-center px-4 py-10">
          <Suspense>
            <AuthForm mode={mode} />
          </Suspense>
        </main>
      </div>
    </div>
  );
}

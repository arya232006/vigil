"use client";

import { useRouter } from "next/navigation";
import { useEffect, type ReactNode } from "react";
import { Loading } from "@/components/ui";
import { useSession } from "@/lib/session";

/** Shows its children to signed-in users and sends guests to sign in. The API enforces this too; this is for the UI. */
export function RequireAccount({ next, children }: { next: string; children: ReactNode }) {
  const { ready, account } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (ready && !account) router.replace(`/sign-in?next=${encodeURIComponent(next)}`);
  }, [ready, account, next, router]);

  return account ? children : <Loading />;
}

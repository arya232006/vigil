import type { ReactNode } from "react";
import { RequireAccount } from "@/components/RequireAccount";

export default function DashboardLayout({ children }: { children: ReactNode }) {
  return <RequireAccount next="/dashboard">{children}</RequireAccount>;
}

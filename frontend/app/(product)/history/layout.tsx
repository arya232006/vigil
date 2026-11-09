import type { ReactNode } from "react";
import { RequireAccount } from "@/components/RequireAccount";

export default function HistoryLayout({ children }: { children: ReactNode }) {
  return <RequireAccount next="/history">{children}</RequireAccount>;
}

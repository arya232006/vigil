import Link from "next/link";
import { AccountControls } from "@/components/AccountControls";
import { Logo } from "@/components/Logo";

/** The top bar for marketing pages other than the landing page. */
export function TopBar() {
  return (
    <nav className="flex flex-wrap items-start justify-between gap-1.5">
      <Link href="/" className="tile" aria-label="Vigil home"><Logo /></Link>
      <div className="flex items-center gap-1.5">
        <AccountControls />
        <Link href="/investigate" className="tile tile-dark">Investigate</Link>
      </div>
    </nav>
  );
}

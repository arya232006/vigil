import { brandFonts } from "../../fonts";
import "../../(marketing)/landing.css";

export default function DashboardLayout({ children }: LayoutProps<"/dashboard">) {
  return <div className={`landing ${brandFonts}`}>{children}</div>;
}

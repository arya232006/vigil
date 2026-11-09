import { Nav } from "@/components/Nav";
import { brandFonts } from "../fonts";
import "../(marketing)/landing.css";

export default function ProductLayout({ children }: LayoutProps<"/">) {
  return (
    <div className={`landing app-shell ${brandFonts}`}>
      <div className="flex min-h-svh flex-col bg-(--l-pink)">
        <Nav />
        <main className="mx-auto w-full max-w-[1240px] flex-1 px-4 py-10 sm:px-8">{children}</main>
      </div>
    </div>
  );
}

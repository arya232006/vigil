import { Nav } from "@/components/Nav";

export default function ProductLayout({ children }: LayoutProps<"/">) {
  return (
    <>
      <Nav />
      {/* Branded pages (`.landing`) run edge to edge. */}
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6 has-[.landing]:max-w-none has-[.landing]:p-0!">{children}</main>
    </>
  );
}

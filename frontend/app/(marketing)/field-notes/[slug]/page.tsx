import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { TopBar } from "../../TopBar";
import { NOTES, noteHref } from "../notes";

type Props = { params: Promise<{ slug: string }> };

export function generateStaticParams() {
  return NOTES.map(({ slug }) => ({ slug }));
}

export async function generateMetadata({ params }: Props): Promise<Metadata> {
  const { slug } = await params;
  const note = NOTES.find((n) => n.slug === slug);
  return note ? { title: `${note.title} · Vigil`, description: note.summary } : {};
}

export default async function FieldNotePage({ params }: Props) {
  const { slug } = await params;
  const note = NOTES.find((n) => n.slug === slug);
  if (!note) notFound();
  const { Art } = note;
  const others = NOTES.filter((n) => n.slug !== slug);

  return (
    <div className="bg-(--l-green)">
      <TopBar />

      <article className="mx-auto w-full max-w-[820px] px-4 pt-14 pb-20 sm:pt-20">
        <p className="terminal text-xl">Vigil Field Notes</p>
        <span className="note-tag terminal mt-5 inline-block bg-(--l-ink)">{note.tag}</span>
        <h1 className="note-title-large mt-3">{note.title}</h1>
        <p className="mt-6 text-2xl leading-snug tracking-tight text-[rgb(30_30_30/0.9)]">{note.lead}</p>
        <div className="note-art relative mt-10 aspect-820/519 w-full">
          <Art />
        </div>

        {note.body}

        <div className="mt-16 border-t border-dashed border-(--l-ink) pt-8">
          <p className="display text-3xl">Spotted Something?</p>
          <Link href="/investigate" className="tile tile-dark mt-5 inline-block">Run an investigation</Link>
        </div>
      </article>

      <aside className="mx-auto w-full max-w-[820px] px-4 pb-20">
        <h2 className="terminal text-2xl">More field notes</h2>
        <div className="mt-6 grid gap-8 sm:grid-cols-2">
          {others.map((other) => (
            <Link key={other.slug} href={noteHref(other)} className="note-link block border-l border-dashed border-(--l-ink) pb-6 pl-2">
              <span className="note-tag terminal inline-block bg-(--l-ink)">{other.tag}</span>
              <h3 className="note-title mt-1">{other.title}</h3>
              <p className="note-body mt-2.5">{other.summary}</p>
            </Link>
          ))}
        </div>
      </aside>

      <footer className="flex flex-wrap items-center justify-between gap-x-8 gap-y-3 bg-(--l-ink) px-4 py-7 text-lg tracking-tight text-(--l-paper) sm:px-8">
        <span>Vigil © 2026</span>
        <Link href="/" className="hover:underline">Back to home</Link>
      </footer>
    </div>
  );
}

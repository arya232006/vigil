import Link from "next/link";
import { InspectedMessageArt } from "./field-notes/art";
import { NOTES, noteHref } from "./field-notes/notes";

export function FieldNotes() {
  const [featured, ...rest] = NOTES;
  return (
    <section className="relative flex min-h-svh flex-col bg-(--l-green)">
      <h2 className="note-tab terminal absolute top-0 left-0 bg-(--l-ink)">Vigil Field Notes</h2>

      <div className="mx-auto grid w-full max-w-[1140px] gap-y-14 px-4 pt-16 pb-10 xl:grid-cols-[820px_269px] xl:gap-x-[51px] xl:px-0 xl:pt-[126px]">
        <Link href={noteHref(featured)} className="note-link block">
          <div className="note-art relative aspect-820/519 w-full">
            <InspectedMessageArt />
          </div>
          <span className="note-tag-large terminal mt-5 inline-block bg-[#e551ba]">{featured.tag}</span>
          <h3 className="note-title-large mt-10">{featured.title}</h3>
          <p className="note-body mt-2.5 max-w-2xl">{featured.summary}</p>
        </Link>

        <div className="flex flex-col gap-[61px]">
          {rest.map((note) => (
            <Link key={note.slug} href={noteHref(note)} className="note-link block border-l border-dashed border-(--l-ink) pb-[50px] pl-2">
              <span className="note-tag terminal inline-block bg-(--l-ink)">{note.tag}</span>
              <h3 className="note-title mt-1">{note.title}</h3>
              <p className="note-body mt-2.5">{note.summary}</p>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}

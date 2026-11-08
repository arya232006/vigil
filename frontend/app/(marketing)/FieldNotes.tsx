import Link from "next/link";

const FEATURED = {
  href: "/models",
  tag: "Hard Case",
  title: "The Scary Text That Was Actually Fine",
  text: "A keyword filter would flag a genuine bank OTP. Vigil reads “do not share” and rates it Low Risk.",
};

const NOTES = [
  {
    href: "/investigate",
    tag: "Blockchain",
    title: "How A Rewritten Database Still Got Caught",
    text: "A verdict was edited and its stored hash rewritten. The on-chain record still exposed the change.",
  },
  {
    href: "/investigate",
    tag: "Prompt Injection",
    title: "The Message That Told Our AI To Stand Down",
    text: "It asked to be marked legitimate and to have AnyDesk installed. It scored 87/100, High Risk.",
  },
];

/** A fishing hook through an envelope, inside a scope reticle. */
function HookArt() {
  return (
    <svg
      viewBox="0 0 400 300"
      fill="none"
      stroke="var(--l-ink)"
      strokeWidth="4.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="absolute inset-0 m-auto h-[82%] w-full"
      aria-hidden
    >
      <circle cx="200" cy="160" r="122" strokeDasharray="168 23.6" strokeDashoffset="-11.8" />
      <path d="M200 26v30M200 264v30M66 160h30M304 160h30" />
      <path d="m118 78 8 8M282 78l-8 8M118 242l8-8M282 242l-8-8" />
      <rect x="128" y="120" width="144" height="92" rx="7" fill="#fbd3dd" />
      <path d="m130 124 70 52 70-52" />
      <path d="M200 8v44" strokeWidth="2.5" strokeDasharray="1 8" />
      <circle cx="200" cy="60" r="8" />
      <path d="M200 68v102a30 30 0 0 1-60 0v-16" stroke="#fbd3dd" strokeWidth="12" />
      <path d="M200 68v102a30 30 0 0 1-60 0v-16" strokeWidth="6" />
      <path d="m140 154-11 15M140 154l12 13" strokeWidth="6" />
    </svg>
  );
}

export function FieldNotes() {
  return (
    <section className="relative flex min-h-svh flex-col bg-(--l-green)">
      <h2 className="note-tab terminal absolute top-0 left-0 bg-(--l-ink)">Vigil Field Notes</h2>

      <div className="mx-auto grid w-full max-w-[1140px] gap-y-14 px-4 pt-16 pb-10 xl:grid-cols-[820px_269px] xl:gap-x-[51px] xl:px-0 xl:pt-[126px]">
        <Link href={FEATURED.href} className="note-link block">
          <div className="note-art relative aspect-820/519 w-full">
            <HookArt />
          </div>
          <span className="note-tag-large terminal mt-5 inline-block bg-[#e551ba]">{FEATURED.tag}</span>
          <h3 className="note-title-large mt-10">{FEATURED.title}</h3>
          <p className="note-body mt-2.5 max-w-2xl">{FEATURED.text}</p>
        </Link>

        <div className="flex flex-col gap-[61px]">
          {NOTES.map((note) => (
            <Link key={note.title} href={note.href} className="note-link block border-l border-dashed border-(--l-ink) pb-[50px] pl-2">
              <span className="note-tag terminal inline-block bg-(--l-ink)">{note.tag}</span>
              <h3 className="note-title mt-1">{note.title}</h3>
              <p className="note-body mt-2.5">{note.text}</p>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}

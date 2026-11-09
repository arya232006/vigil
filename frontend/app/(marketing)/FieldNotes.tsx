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

/** A message holding a one-time code, examined under a lens and found to be fine. */
function InspectedMessageArt() {
  return (
    <svg
      viewBox="0 0 400 300"
      fill="none"
      stroke="var(--l-ink)"
      strokeWidth="5"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="absolute inset-0 m-auto h-[80%] w-full"
      aria-hidden
    >
      <g transform="translate(-20 0)">
        <path
          d="M84 50h202a14 14 0 0 1 14 14v122a14 14 0 0 1-14 14H148l-38 34v-34H84a14 14 0 0 1-14-14V64a14 14 0 0 1 14-14Z"
          fill="#fbd3dd"
        />
        <path d="M96 78h168M96 96h104M96 176h120" />
        {[96, 128, 160, 192, 224, 256].map((x) => (
          <g key={x}>
            <rect x={x} y="112" width="24" height="36" rx="3" />
            <circle cx={x + 12} cy="130" r="4" fill="var(--l-ink)" stroke="none" />
          </g>
        ))}
        <path d="m326 234 44 44" strokeWidth="13" />
        <circle cx="292" cy="200" r="48" fill="#fdecf1" strokeWidth="6" />
        <path d="m268 201 17 18 32-38" strokeWidth="7" />
      </g>
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
            <InspectedMessageArt />
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

const REPORT_EXCERPT = `{
  "input_type": "url",
  "risk_level": "high_risk",
  "risk_score": 100,
  "findings": [{
    "id": "F3",
    "module": "tls",
    "severity": "high",
    "title": "Hostname does not
      match certificate",
    "source": "TLS handshake
      + X.509 parsing"
  }]
}`;

const COLUMNS = [
  {
    label: "An Opinion Isn't Evidence",
    text: "Ask a language model whether a message is a scam and you get an opinion. Its answer can shift with the wording, the message itself can talk it out of that answer, and it cannot show you what it actually checked.",
  },
  {
    label: "So We Separated The Jobs",
    text: "Passive checks inspect certificates, redirects, domains, threat feeds and email headers. A rule engine sets the risk level from what they find. Our self-hosted, fine-tuned model adds its reading of a message and explains the findings.",
  },
];

const NOTES = [
  { label: "Findings, Not Feelings", text: "Every point in a report links to the check behind it." },
  { label: "Honest Coverage", text: "Checks that could not run are listed on the report." },
  { label: "Tamper-Evident", text: "A report's hash can be anchored on-chain." },
];

export function WhyEvidence() {
  const body = "text-[rgb(30_30_30/0.86)]";
  return (
    <div className="mt-16 mb-20">
      <div className="grid gap-10 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_260px] lg:gap-x-10">
        {COLUMNS.map((column) => (
          <div key={column.label} className="border-l border-(--l-ink) pl-3">
            <h3 className="code text-sm">{column.label}</h3>
            <p className={`mt-12 text-[24px] leading-[1.1] ${body}`}>{column.text}</p>
          </div>
        ))}
        <aside>
          <h3 className="code text-sm">[report.json]</h3>
          <pre className="code mt-4 text-xs leading-[1.3] break-words whitespace-pre-wrap">{REPORT_EXCERPT}</pre>
        </aside>
      </div>

      <div className="mt-16 grid max-w-[800px] gap-8 sm:grid-cols-3">
        {NOTES.map((note) => (
          <div key={note.label} className="border-l border-(--l-ink) pl-3">
            <h3 className="code text-sm">{note.label}</h3>
            <p className={`mt-10 text-[17px] leading-[1.2] ${body}`}>{note.text}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

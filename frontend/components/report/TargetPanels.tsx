import { Card, CopyButton, Field, Mono, Tag } from "@/components/ui";
import { defang } from "@/lib/format";
import type { Report, Tls } from "@/lib/types";

const NEW_DOMAIN_DAYS = 30;

const TLS_VERDICT: Record<Tls["verdict"], { label: string; tone: "good" | "danger" | "neutral" }> = {
  valid: { label: "Valid", tone: "good" },
  suspicious: { label: "Suspicious", tone: "danger" },
  potentially_compromised: { label: "Potentially compromised", tone: "danger" },
  unavailable: { label: "Unavailable", tone: "neutral" },
};

function TlsCard({ tls }: { tls: Tls }) {
  const verdict = TLS_VERDICT[tls.verdict];
  return (
    <Card title="TLS certificate">
      <div className="mb-2">
        <Tag tone={verdict.tone}>{verdict.label}</Tag>
      </div>
      <dl>
        {tls.subject_cn && <Field label="Subject">{tls.subject_cn}</Field>}
        {tls.issuer && <Field label="Issuer">{[tls.issuer, tls.issuer_org].filter(Boolean).join(" · ")}</Field>}
        {tls.not_after && (
          <Field label="Expires">
            {tls.not_after.slice(0, 10)}
            {tls.days_remaining != null && ` (${tls.days_remaining} days)`}
          </Field>
        )}
        {tls.hostname_match != null && <Field label="Hostname match">{tls.hostname_match ? "Yes" : "No"}</Field>}
        {tls.protocol && <Field label="Protocol">{tls.protocol}</Field>}
        {tls.key_type && <Field label="Key">{`${tls.key_type} ${tls.key_bits ?? ""}`}</Field>}
        {tls.signature_algorithm && <Field label="Signature">{tls.signature_algorithm}</Field>}
        {tls.san.length > 0 && <Field label="Names (SAN)">{tls.san.slice(0, 8).join(", ")}</Field>}
      </dl>
      {tls.chain.length > 0 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-xs text-accent">Certificate chain ({tls.chain.length})</summary>
          <ol className="mt-2 space-y-1 text-xs">
            {tls.chain.map((cert, i) => (
              <li key={i} className="rounded bg-sunken p-2 break-words">
                <span className="font-medium">{cert.subject}</span>
                <span className="text-ink-3">
                  {" "}issued by {cert.issuer}
                  {cert.org ? ` (${cert.org})` : ""} · {cert.key} · until {cert.not_after}
                </span>
              </li>
            ))}
          </ol>
        </details>
      )}
      <p className="mt-3 text-xs text-ink-3">
        A valid certificate only means the connection is encrypted, not that the site is legitimate.
      </p>
    </Card>
  );
}

export function TargetPanels({ report }: { report: Report }) {
  const { target, tls } = report;
  if (!target) return null;
  const isNew = target.domain_age_days != null && target.domain_age_days < NEW_DOMAIN_DAYS;

  return (
    <>
      <Card title="Target">
        <dl>
          {target.final_url && (
            <Field label="Final URL">
              <Mono>{defang(target.final_url)}</Mono> <CopyButton value={target.final_url} />
            </Field>
          )}
          {target.registered_domain && <Field label="Domain"><Mono>{defang(target.registered_domain)}</Mono></Field>}
          {target.ip_addresses.length > 0 && <Field label="IP addresses"><Mono>{target.ip_addresses.join(", ")}</Mono></Field>}
          {target.page_title && <Field label="Page title">{target.page_title}</Field>}
          {target.domain_age_days != null && (
            <Field label="Domain age">
              {target.domain_age_days} days {isNew && <Tag tone="danger">New domain</Tag>}
            </Field>
          )}
          {target.registrar && <Field label="Registrar">{target.registrar}</Field>}
        </dl>
      </Card>

      {target.redirect_chain.length > 0 && (
        <Card title={`Redirect chain (${target.redirect_chain.length})`}>
          <ol className="space-y-2 border-l border-line pl-4">
            {target.redirect_chain.map((hop, i) => (
              <li key={i} className="text-sm">
                <Mono>{defang(hop.url)}</Mono>
                <span className="block text-xs text-ink-3">
                  {[hop.status && `HTTP ${hop.status}`, hop.ip].filter(Boolean).join(" · ")}
                </span>
              </li>
            ))}
          </ol>
        </Card>
      )}

      {tls && <TlsCard tls={tls} />}
    </>
  );
}

import Link from "next/link";
import { Card, Field, Mono, Tag } from "@/components/ui";
import { defang } from "@/lib/format";
import type { EmailInfo } from "@/lib/types";

function authTone(result?: string | null): "good" | "danger" | "neutral" {
  if (result === "pass") return "good";
  if (result === "fail" || result === "softfail") return "danger";
  return "neutral";
}

function Aligned({ value }: { value?: boolean | null }) {
  if (value == null) return null;
  return <span className="ml-2 text-xs text-ink-3">{value ? "aligned" : "not aligned"}</span>;
}

export function EmailPanel({ email }: { email: EmailInfo }) {
  const { auth } = email;
  const replyDomains = email.reply_to.map((address) => address.split("@").pop()?.toLowerCase());
  const replyDiverted = Boolean(email.from_domain) && replyDomains.some((d) => d !== email.from_domain?.toLowerCase());

  return (
    <>
      <Card title="Authentication">
        <dl>
          <Field label="SPF"><Tag tone={authTone(auth.spf)}>{auth.spf ?? "not evaluated"}</Tag><Aligned value={auth.spf_aligned} /></Field>
          <Field label="DKIM"><Tag tone={authTone(auth.dkim)}>{auth.dkim ?? "not evaluated"}</Tag><Aligned value={auth.dkim_aligned} /></Field>
          <Field label="DMARC"><Tag tone={authTone(auth.dmarc)}>{auth.dmarc ?? "not evaluated"}</Tag></Field>
          {email.dmarc_policy && <Field label="DMARC policy">{email.dmarc_policy}</Field>}
        </dl>
      </Card>

      <Card title="Sender identity">
        <dl>
          {email.display_name && <Field label="Display name">{email.display_name}</Field>}
          {email.from_address && (
            <Field label="From">
              <Mono>{defang(email.from_address)}</Mono> {email.sender_is_freemail && <Tag>free webmail</Tag>}
            </Field>
          )}
          {email.reply_to.length > 0 && (
            <Field label="Reply-To">
              <Mono>{email.reply_to.map(defang).join(", ")}</Mono> {replyDiverted && <Tag tone="danger">different domain</Tag>}
            </Field>
          )}
          {email.return_path && <Field label="Return-Path"><Mono>{defang(email.return_path)}</Mono></Field>}
          {email.subject && <Field label="Subject">{email.subject}</Field>}
        </dl>
        {email.body_report_id && (
          <Link href={`/reports/${email.body_report_id}`} className="mt-1 -mb-1 inline-block py-1 text-xs text-accent hover:underline">
            Open the analysis of the email body
          </Link>
        )}
      </Card>

      {email.link_mismatches.length > 0 && (
        <Card title="Deceptive links">
          <ul className="space-y-2 text-sm">
            {email.link_mismatches.map((link, i) => (
              <li key={i} className="break-words">
                Shows <strong>{defang(link.text_domain)}</strong>, actually goes to{" "}
                <strong className="text-risk-high">{defang(link.href_domain)}</strong>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {email.attachments.length > 0 && (
        <Card title="Attachments (never opened)">
          <ul className="space-y-2 text-sm">
            {email.attachments.map((file, i) => (
              <li key={i}>
                <Mono>{file.filename}</Mono> {file.risky && <Tag tone="danger">risky</Tag>}
                <span className="block text-xs text-ink-3">
                  {file.detected_type ?? file.content_type} · {file.size.toLocaleString()} bytes
                  {file.reasons.length > 0 && ` · ${file.reasons.join("; ")}`}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </>
  );
}

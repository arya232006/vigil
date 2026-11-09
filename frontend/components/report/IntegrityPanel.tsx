"use client";

import { Show, SignInButton } from "@clerk/nextjs";
import { useCallback, useEffect, useState } from "react";
import { Button, Card, CopyButton, ErrorNote, Field, Mono } from "@/components/ui";
import { anchorReport, chainVerify, errorMessage, getCanonical, useApi } from "@/lib/api";
import { browserVerifyAvailable, verifyInBrowser } from "@/lib/chain";
import { formatTime, reportDomain, shortHash } from "@/lib/format";
import type { ChainLookup, ChainStatus, ChainVerify, Report } from "@/lib/types";

type Busy = "anchor" | "verify" | "browser" | null;

function Verdict({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  return (
    <p role="status" className={`rounded-md px-3 py-2 text-sm font-medium text-white ${ok ? "bg-risk-ok" : "bg-risk-high"}`}>
      <span aria-hidden>{ok ? "✓ " : "✗ "}</span>
      {children}
    </p>
  );
}

export function IntegrityPanel({ report }: { report: Report }) {
  const id = report.report_id;
  const { data: status } = useApi<ChainStatus>("/api/chain/status");
  const connected = status?.connected === true;
  const [verify, setVerify] = useState<ChainVerify | null>(null);
  const [browserResult, setBrowserResult] = useState<{ ok: boolean; reporterOk: boolean; onchainHash: string; computedHash: string } | null>(null);
  const [busy, setBusy] = useState<Busy>(null);
  const [error, setError] = useState<string | null>(null);
  const [lookupVersion, setLookupVersion] = useState(0);

  const domain = reportDomain(report);
  const { data: lookup } = useApi<ChainLookup>(
    connected && domain ? `/api/chain/lookup?domain=${encodeURIComponent(domain)}` : null,
    lookupVersion,
  );

  useEffect(() => {
    if (!connected) return;
    let current = true;
    chainVerify(id).then(
      (result) => current && setVerify(result),
      (e) => current && setError(errorMessage(e)),
    );
    return () => {
      current = false;
    };
  }, [connected, id]);

  const run = useCallback(async (kind: Exclude<Busy, null>, action: () => Promise<void>) => {
    setBusy(kind);
    setError(null);
    try {
      await action();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  }, []);

  const anchor = () =>
    run("anchor", async () => {
      await anchorReport(id);
      setVerify(await chainVerify(id));
      setLookupVersion((v) => v + 1);
    });

  const recheck = () =>
    run("verify", async () => {
      setBrowserResult(null);
      setVerify(await chainVerify(id));
    });

  const checkInBrowser = (registryId: number) =>
    run("browser", async () => {
      setBrowserResult(await verifyInBrowser(registryId, await getCanonical(id)));
    });

  const anchored = verify?.anchored === true;

  return (
    <Card title="Integrity and blockchain">
      <dl>
        <Field label="Report hash">
          <Mono>{report.report_hash}</Mono> <CopyButton value={report.report_hash} />
        </Field>
        {anchored && verify.registry_id != null && <Field label="Registry record">#{verify.registry_id}</Field>}
        {anchored && verify.tx_hash && (
          <Field label="Transaction">
            <Mono>{shortHash(verify.tx_hash)}</Mono> <CopyButton value={verify.tx_hash} />{" "}
            {verify.explorer_url && (
              <a href={verify.explorer_url} target="_blank" rel="noreferrer" className="-my-1 inline-block py-1 text-xs text-accent hover:underline">
                View on Etherscan
              </a>
            )}
          </Field>
        )}
        {anchored && verify.onchain_timestamp && <Field label="Anchored">{formatTime(verify.onchain_timestamp)}</Field>}
        {anchored && verify.onchain_hash && verify.integrity_ok === false && (
          <>
            <Field label="On-chain hash"><Mono>{verify.onchain_hash}</Mono></Field>
            <Field label="Recomputed"><Mono>{verify.recomputed_hash}</Mono></Field>
          </>
        )}
        {connected && domain && lookup && (
          <Field label="This domain">{`${lookup.count} on-chain ${lookup.count === 1 ? "report" : "reports"}, matched by hash`}</Field>
        )}
      </dl>

      <div className="mt-3 space-y-2">
        {anchored && verify.integrity_ok != null && (
          <Verdict ok={verify.integrity_ok}>
            {verify.integrity_ok
              ? "This report matches its on-chain record."
              : "This report was changed after it was anchored. It no longer matches its on-chain record."}
          </Verdict>
        )}
        {browserResult && (
          <Verdict ok={browserResult.ok}>
            {browserResult.ok
              ? "Your browser hashed this report and got the same value the chain holds."
              : !browserResult.reporterOk
                ? "This on-chain record was not written by Vigil, so it cannot vouch for this report."
                : `Your browser computed ${shortHash(browserResult.computedHash)}, but the chain holds ${shortHash(browserResult.onchainHash)}.`}
          </Verdict>
        )}
        {verify?.detail && <p className="text-sm text-risk-warn">{verify.detail}</p>}
        {error && <ErrorNote>{error}</ErrorNote>}
      </div>

      {connected ? (
        <div className="mt-3 flex flex-wrap gap-2">
          {verify && !anchored && (
            <>
              <Show when="signed-in">
                <Button variant="primary" onClick={anchor} disabled={busy !== null}>
                  {busy === "anchor" ? "Waiting for the transaction…" : "Register on-chain"}
                </Button>
              </Show>
              <Show when="signed-out">
                <SignInButton>
                  <Button variant="primary">Sign in to register on-chain</Button>
                </SignInButton>
              </Show>
            </>
          )}
          {anchored && (
            <Button onClick={recheck} disabled={busy !== null}>
              {busy === "verify" ? "Verifying…" : "Verify against chain"}
            </Button>
          )}
          {anchored && browserVerifyAvailable && verify.registry_id != null && (
            <Button onClick={() => checkInBrowser(verify.registry_id!)} disabled={busy !== null}>
              {busy === "browser" ? "Hashing…" : "Verify independently in browser"}
            </Button>
          )}
        </div>
      ) : (
        status && <p className="mt-3 text-sm text-ink-3">On-chain registry unavailable: {status.detail}</p>
      )}

      <p className="mt-3 text-xs text-ink-3">
        Only hashes go on-chain, never the link, message or email. A blockchain record proves this report&apos;s integrity
        and history, not that its conclusions are true.
      </p>
    </Card>
  );
}

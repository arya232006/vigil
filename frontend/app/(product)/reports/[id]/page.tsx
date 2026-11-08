"use client";

import { Suspense } from "react";
import { useParams, useSearchParams } from "next/navigation";
import { ReportView } from "@/components/report/ReportView";
import { ErrorNote, Loading } from "@/components/ui";
import { useApi } from "@/lib/api";
import type { Report } from "@/lib/types";

function ReportLoader() {
  const { id } = useParams<{ id: string }>();
  const cached = useSearchParams().get("cached") === "1";
  const { data, error, loading } = useApi<Report>(`/api/reports/${id}`);

  if (loading) return <Loading>Loading report…</Loading>;
  if (error) return <ErrorNote>{error}</ErrorNote>;
  return data ? <ReportView report={data} cached={cached} /> : null;
}

export default function ReportPage() {
  return (
    <Suspense fallback={<Loading>Loading report…</Loading>}>
      <ReportLoader />
    </Suspense>
  );
}

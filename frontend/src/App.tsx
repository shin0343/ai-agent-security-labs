import { Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { SessionGate } from "./components/SessionGate";
import { useSession } from "./state/SessionContext";
import { WorkspaceProvider } from "./state/WorkspaceContext";
import { AuditCasesPage } from "./pages/AuditCasesPage";
import { CaseDetailPage } from "./pages/CaseDetailPage";
import { EvaluationDetailPage } from "./pages/EvaluationDetailPage";
import { EvaluationPage } from "./pages/EvaluationPage";
import { EvidencePage } from "./pages/EvidencePage";
import { FindingPage } from "./pages/FindingPage";
import { InvestigationDetailPage } from "./pages/InvestigationDetailPage";
import { InvestigationsPage } from "./pages/InvestigationsPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { OverviewPage } from "./pages/OverviewPage";
import { PoliciesPage } from "./pages/PoliciesPage";
import { ApprovalDetailPage } from "./pages/ApprovalDetailPage";
import { TraceDetailPage } from "./pages/TraceDetailPage";
import { TracesPage } from "./pages/TracesPage";

export function App() {
  const { session, checking } = useSession();

  if (checking) {
    return <SessionGate />;
  }
  if (!session) {
    return <SessionGate />;
  }

  return (
    <WorkspaceProvider>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<OverviewPage />} />
          <Route path="investigations" element={<InvestigationsPage />} />
          <Route path="investigations/findings/:findingId" element={<FindingPage />} />
          <Route path="investigations/evidence/:eventId" element={<EvidencePage />} />
          <Route path="investigations/:investigationId" element={<InvestigationDetailPage />} />
          <Route path="traces" element={<TracesPage />} />
          <Route path="traces/:runId" element={<TraceDetailPage />} />
          <Route path="policies" element={<PoliciesPage />} />
          <Route path="policies/approvals/:approvalId" element={<ApprovalDetailPage />} />
          <Route path="evaluation" element={<EvaluationPage />} />
          <Route path="evaluation/:evaluationId" element={<EvaluationDetailPage />} />
          <Route path="audit" element={<AuditCasesPage />} />
          <Route path="audit/cases/:caseId" element={<CaseDetailPage />} />
          <Route path="cases" element={<Navigate to="/audit?tab=cases" replace />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </WorkspaceProvider>
  );
}

import { NavLink, Route, Routes } from "react-router-dom";
import { ErrorMessage } from "./components";
import { AlertsPage } from "./pages/AlertsPage";
import { OverviewPage } from "./pages/OverviewPage";
import { TrafficPage } from "./pages/TrafficPage";
import { UploadPage } from "./pages/UploadPage";
import { useAnalyses } from "./state";

function AnalysisPicker() {
  const { analyses, selectedId, select } = useAnalyses();
  if (analyses.length === 0) return null;
  return (
    <label className="picker">
      Capture
      <select value={selectedId ?? ""} onChange={(e) => select(Number(e.target.value))}>
        {analyses.map((a) => (
          <option key={a.id} value={a.id}>
            #{a.id} {a.filename} ({a.alert_count} alerts)
          </option>
        ))}
      </select>
    </label>
  );
}

export function App() {
  const { error } = useAnalyses();
  return (
    <>
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            N
          </span>
          NetSentinel
        </div>
        <nav className="nav" aria-label="Main">
          <NavLink to="/" end>
            Overview
          </NavLink>
          <NavLink to="/traffic">Traffic</NavLink>
          <NavLink to="/alerts">Alerts</NavLink>
          <NavLink to="/upload">Analyze a capture</NavLink>
        </nav>
        <AnalysisPicker />
      </header>
      <main>
        <ErrorMessage error={error} />
        <Routes>
          <Route path="/" element={<OverviewPage />} />
          <Route path="/traffic" element={<TrafficPage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/upload" element={<UploadPage />} />
          <Route path="*" element={<p className="empty">Page not found.</p>} />
        </Routes>
      </main>
    </>
  );
}

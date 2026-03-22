import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import NetworkScanner from "./pages/NetworkScanner";
import WebVulnScanner from "./pages/WebVulnScanner";
import PasswordTools from "./pages/PasswordTools";
import OsintEngine from "./pages/OsintEngine";
import ReportGenerator from "./pages/ReportGenerator";
import ScanHistory from "./pages/ScanHistory";
import Login from "./pages/Login";
import SSLChecker from "./pages/SSLChecker";
import CVESearch from "./pages/CVESearch";
import SubdomainTakeover from "./pages/SubdomainTakeover";
import ScheduledScans from "./pages/ScheduledScans";
import Settings from "./pages/Settings";
import EmailSecurity from "./pages/EmailSecurity";
import AuthenticatedScanner from "./pages/AuthenticatedScanner";
import APIScanner from "./pages/APIScanner";

function ProtectedRoute({ children }) {
  const token = localStorage.getItem("gr_token");
  return token ? children : <Navigate to="/login" />;
}

function Layout({ children }) {
  return (
    <div style={{ display: "flex", minHeight: "100vh" }}>
      <Sidebar />
      <main style={{ flex: 1, background: "var(--gr-bg)", overflowY: "auto" }}>
        {children}
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/apiscan"
          element={
            <ProtectedRoute>
              <Layout>
                <APIScanner />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/authscan"
          element={
            <ProtectedRoute>
              <Layout>
                <AuthenticatedScanner />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/emailsecurity"
          element={
            <ProtectedRoute>
              <Layout>
                <EmailSecurity />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/settings"
          element={
            <ProtectedRoute>
              <Layout>
                <Settings />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/schedules"
          element={
            <ProtectedRoute>
              <Layout>
                <ScheduledScans />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/takeover"
          element={
            <ProtectedRoute>
              <Layout>
                <SubdomainTakeover />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/cve"
          element={
            <ProtectedRoute>
              <Layout>
                <CVESearch />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/ssl"
          element={
            <ProtectedRoute>
              <Layout>
                <SSLChecker />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route path="/login" element={<Login />} />
        <Route
          path="/"
          element={
            <ProtectedRoute>
              <Layout>
                <Dashboard />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/network"
          element={
            <ProtectedRoute>
              <Layout>
                <NetworkScanner />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/webvuln"
          element={
            <ProtectedRoute>
              <Layout>
                <WebVulnScanner />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/password"
          element={
            <ProtectedRoute>
              <Layout>
                <PasswordTools />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/osint"
          element={
            <ProtectedRoute>
              <Layout>
                <OsintEngine />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/reports"
          element={
            <ProtectedRoute>
              <Layout>
                <ReportGenerator />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/history"
          element={
            <ProtectedRoute>
              <Layout>
                <ScanHistory />
              </Layout>
            </ProtectedRoute>
          }
        />
      </Routes>
    </BrowserRouter>
  );
}

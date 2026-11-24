import '@fontsource-variable/geist';
import '@fontsource-variable/geist-mono';
import { StrictMode, Suspense, lazy } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Link, Navigate, Route, Routes } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import * as Tooltip from '@radix-ui/react-tooltip';
import './styles.css';
import './styles/refinement.css';
import './styles/redesign.css';
import './styles/redesign-approvals.css';
import './styles/redesign-sessions.css';
import './styles/redesign-connect.css';
import './styles/redesign-overview.css';
import { ApiError } from './api/errors';
import { PreferencesProvider } from './lib/preferences';
import { ThemeProvider } from './lib/theme';
import { Shell } from './components/shell';
import { ToastProvider } from './components/ui/toast';
import { Empty, RouteBoundary, Skeleton } from './components/ui';
import { Login } from './features/auth/login';
import { AdminOnly, Session } from './features/auth/session';
const HelpDocument = lazy(() =>
  import('./features/help/doc').then((module) => ({
    default: module.HelpDocument,
  })),
);
const OverviewPage = lazy(() =>
  import('./features/overview/overview').then((module) => ({
    default: module.OverviewPage,
  })),
);
const Clusters = lazy(() =>
  import('./features/clusters/list').then((module) => ({
    default: module.Clusters,
  })),
);
const ClusterDetail = lazy(() =>
  import('./features/clusters/detail').then((module) => ({
    default: module.ClusterDetail,
  })),
);
const ConsolePage = lazy(() =>
  import('./features/console/console').then((module) => ({
    default: module.ConsolePage,
  })),
);
const ApprovalsPage = lazy(() =>
  import('./features/approvals/approvals').then((module) => ({
    default: module.ApprovalsPage,
  })),
);
const HistoryPage = lazy(() =>
  import('./features/history/history').then((module) => ({
    default: module.HistoryPage,
  })),
);
const AgentsPage = lazy(() =>
  import('./features/agents/agents').then((module) => ({
    default: module.AgentsPage,
  })),
);
const SessionPage = lazy(() =>
  import('./features/agents/session-page').then((module) => ({
    default: module.SessionPage,
  })),
);
const UsersPage = lazy(() =>
  import('./features/admin/users').then((module) => ({
    default: module.UsersPage,
  })),
);
const AccessPage = lazy(() =>
  import('./features/admin/access').then((module) => ({
    default: module.AccessPage,
  })),
);
const AuditPage = lazy(() =>
  import('./features/admin/audit').then((module) => ({
    default: module.AuditPage,
  })),
);
const SettingsPage = lazy(() =>
  import('./features/admin/settings').then((module) => ({
    default: module.SettingsPage,
  })),
);
const KitchenSink = import.meta.env.DEV
  ? lazy(() =>
      import('./components/ui/kitchen-sink').then((module) => ({
        default: module.KitchenSink,
      })),
    )
  : null;
const cache = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15000,
      retry: (count, error) =>
        !(error instanceof ApiError && error.status < 500) && count < 1,
      refetchOnWindowFocus: true,
    },
    mutations: { retry: false },
  },
});
const root = document.getElementById('root');
if (root)
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={cache}>
        <Tooltip.Provider delayDuration={300}>
          <ThemeProvider>
            <PreferencesProvider>
              <ToastProvider>
                <BrowserRouter>
                  <RouteBoundary>
                    <Routes>
                      <Route path="/login" element={<Login />} />
                      <Route
                        path="/help/:name"
                        element={
                          <Suspense
                            fallback={
                              <main className="help-body">
                                <Skeleton />
                              </main>
                            }
                          >
                            <HelpDocument />
                          </Suspense>
                        }
                      />
                      <Route
                        element={
                          <Session>
                            <Shell />
                          </Session>
                        }
                      >
                        <Route
                          index
                          element={<Navigate to="/overview" replace />}
                        />
                        <Route path="/overview" element={<OverviewPage />} />
                        <Route path="/clusters" element={<Clusters />} />
                        <Route
                          path="/clusters/:id"
                          element={<ClusterDetail />}
                        />
                        <Route path="/console" element={<ConsolePage />} />
                        <Route path="/approvals" element={<ApprovalsPage />} />
                        <Route path="/history" element={<HistoryPage />} />
                        <Route path="/agents" element={<AgentsPage />} />
                        <Route
                          path="/agents/:agentId/sessions/:sessionId"
                          element={<SessionPage />}
                        />
                        <Route
                          path="/users"
                          element={
                            <AdminOnly>
                              <UsersPage />
                            </AdminOnly>
                          }
                        />
                        <Route path="/access" element={<AccessPage />} />
                        <Route
                          path="/audit"
                          element={
                            <AdminOnly>
                              <AuditPage />
                            </AdminOnly>
                          }
                        />
                        <Route path="/settings" element={<SettingsPage />} />
                        <Route
                          path="/ui"
                          element={
                            KitchenSink ? (
                              <AdminOnly>
                                <KitchenSink />
                              </AdminOnly>
                            ) : (
                              <Navigate to="/missing" replace />
                            )
                          }
                        />
                        <Route
                          path="*"
                          element={
                            <>
                              <h1>Page not found</h1>
                              <Empty
                                title="This page isn’t here"
                                description="Check the address or return to your workspace."
                                action={
                                  <Link
                                    className="button primary"
                                    to="/overview"
                                  >
                                    Back to overview
                                  </Link>
                                }
                              />
                            </>
                          }
                        />
                      </Route>
                    </Routes>
                  </RouteBoundary>
                </BrowserRouter>
              </ToastProvider>
            </PreferencesProvider>
          </ThemeProvider>
        </Tooltip.Provider>
      </QueryClientProvider>
    </StrictMode>,
  );

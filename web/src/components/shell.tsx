import { Suspense, useEffect, useMemo, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import * as Dropdown from '@radix-ui/react-dropdown-menu';
import {
  Activity,
  Database,
  Terminal,
  CheckCheck,
  History,
  Users,
  KeyRound,
  ScrollText,
  Settings,
  Menu,
  X,
  Search,
  PanelLeftClose,
  PanelLeftOpen,
  Sun,
  Moon,
  Monitor,
  ChevronDown,
  LogOut,
  Bot,
} from 'lucide-react';
import type { Cluster, Project, Grant, Page } from '../api/types';
import { useAction, useResource } from '../lib/query';
import { useUser } from '../features/auth/session';
import { useTheme } from '../lib/theme';
import { BrandMark } from './ui/brand';
import { CommandPalette } from './command-palette';
import { SessionRecovery } from './session-recovery';
import { PopoverLayerContext } from '../lib/popover-layer';
import { useMedia } from '../lib/media';
import { modifierLabel } from '../lib/platform';
import {
  AccountName,
  Button,
  Field,
  Modal,
  RouteBoundary,
  Skeleton,
} from './ui';
const navigation = [
  { to: '/overview', text: 'Overview', icon: Activity },
  { to: '/clusters', text: 'Clusters', icon: Database },
  { to: '/console', text: 'Console', icon: Terminal },
  { to: '/approvals', text: 'Approvals', icon: CheckCheck },
  { to: '/history', text: 'History', icon: History },
  { to: '/agents', text: 'Agents', icon: Bot },
];
const administration = [
  { to: '/users', text: 'Users', icon: Users },
  { to: '/access', text: 'Access', icon: KeyRound },
  { to: '/audit', text: 'Audit log', icon: ScrollText },
  { to: '/settings', text: 'Settings', icon: Settings },
];
const noClusters: Cluster[] = [];
const focusableSelector =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
export function Shell() {
  const cache = useQueryClient();
  const [popoverLayer, setPopoverLayer] = useState<HTMLElement | null>(null);
  const user = useUser(),
    location = useLocation(),
    navigate = useNavigate();
  const [collapsed, setCollapsed] = useState(false),
    [command, setCommand] = useState(false),
    [mobileOpen, setMobileOpen] = useState(false),
    [shortcuts, setShortcuts] = useState(false),
    [password, setPassword] = useState(false);
  const phone = useMedia('(max-width: 600px)');
  useEffect(() => {
    if (!phone) setMobileOpen(false);
  }, [phone]);
  const { theme, setTheme } = useTheme();
  const projects = useResource<{ items: Project[] }>('/projects');
  const clusters = useResource<{ items: Cluster[] }>('/clusters');
  const grantDirectory = useResource<Page<Grant>>(
    '/grants?limit=1',
    user?.org_role !== 'admin',
  );
  const canManageAccess =
    user?.org_role === 'admin' || grantDirectory.isSuccess;
  const isAdmin = user?.org_role === 'admin';
  const adminLinks = useMemo(
    () =>
      administration.filter(
        (item) => isAdmin || (item.to === '/access' && canManageAccess),
      ),
    [isAdmin, canManageAccess],
  );
  const palettePages = useMemo(
    () => [
      ...navigation,
      ...adminLinks,
      ...(isAdmin ? [] : [{ to: '/settings', text: 'Settings' }]),
    ],
    [adminLinks, isAdmin],
  );
  const overview = useResource<{ pending_approvals: number }>('/overview');
  const mod = modifierLabel();
  const [rememberedProject, setRememberedProject] = useState('all');
  const logout = useAction(''),
    changePassword = useAction('Password changed');
  useEffect(() => {
    const listener = (event: KeyboardEvent) => {
      const dialog =
        event.target instanceof Element &&
        event.target.closest('[role="dialog"]');
      if (
        mobileOpen ||
        (dialog && !dialog.classList.contains('palette-dialog'))
      )
        return;
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setCommand((value) => !value);
      }
      if (
        event.key === '?' &&
        !(
          event.target instanceof HTMLElement &&
          (event.target.matches('input,textarea,select') ||
            event.target.isContentEditable)
        )
      ) {
        event.preventDefault();
        setShortcuts(true);
      }
    };
    window.addEventListener('keydown', listener);
    return () => window.removeEventListener('keydown', listener);
  }, [mobileOpen]);
  const closeMobileNav = () => {
    setMobileOpen(false);
    requestAnimationFrame(() =>
      document.querySelector<HTMLElement>('.mobile-menu')?.focus(),
    );
  };
  useEffect(() => {
    if (!mobileOpen) return;
    document.querySelector<HTMLElement>('.sidebar nav a')?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        closeMobileNav();
        return;
      }
      if (event.key !== 'Tab') return;
      // Keep focus on visible controls inside the drawer.
      const focusable = [
        ...document.querySelectorAll<HTMLElement>(
          `.sidebar :is(${focusableSelector})`,
        ),
      ].filter((element) => element.getClientRects().length > 0);
      if (focusable.length === 0) return;
      const index = focusable.indexOf(document.activeElement as HTMLElement);
      const next = event.shiftKey
        ? index <= 0
          ? focusable.length - 1
          : index - 1
        : index === -1 || index === focusable.length - 1
          ? 0
          : index + 1;
      event.preventDefault();
      focusable[next]?.focus();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [mobileOpen]);
  const current = clusters.data?.items.find(
    (cluster) =>
      location.pathname.includes(cluster.id) ||
      new URLSearchParams(location.search).get('cluster_id') === cluster.id,
  );
  // The header shows the scope of the page on screen. The cluster list is
  // filtered by project; a cluster page belongs to one project; every other
  // page is workspace-wide and shows all projects.
  const onClusterList = location.pathname === '/clusters';
  const listProject = onClusterList
    ? (new URLSearchParams(location.search).get('project_id') ?? 'all')
    : null;
  const project = listProject ?? current?.project_id ?? 'all';
  const projectName =
    projects.data?.items.find((item) => item.id === project)?.name ??
    'All projects';
  const workspaceWide = listProject === null && !current;
  useEffect(() => {
    if (listProject !== null) setRememberedProject(listProject);
  }, [listProject]);
  const clustersLink =
    rememberedProject === 'all'
      ? '/clusters'
      : `/clusters?project_id=${encodeURIComponent(rememberedProject)}`;
  const detailTab =
    new URLSearchParams(location.search).get('tab') ?? 'console';
  const workspace =
    location.pathname === '/console' ||
    (/^\/clusters\/[^/]+$/.test(location.pathname) && detailTab === 'console');
  const page =
    current && location.pathname.startsWith('/clusters/')
      ? ((
          {
            console: 'Console',
            schema: 'Schema',
            health: 'Health',
            access: 'Access',
            policy: 'Policy',
            settings: 'Settings',
          } as Record<string, string>
        )[detailTab] ?? 'Cluster')
      : ([...navigation, ...administration].find((item) =>
          location.pathname.startsWith(item.to),
        )?.text ?? 'Cluster');
  useEffect(() => {
    document.title = `${page}${current ? ` · ${current.name}` : ''} — visp`;
  }, [page, current]);
  return (
    <PopoverLayerContext.Provider value={popoverLayer}>
      <div
        className={`app ${collapsed ? 'collapsed' : ''} ${mobileOpen ? 'mobile-nav-open' : ''}`}
      >
        <a className="skip-link" href="#main-content">
          Skip to content
        </a>
        {mobileOpen && (
          <button
            className="nav-backdrop"
            aria-hidden="true"
            tabIndex={-1}
            onClick={closeMobileNav}
          />
        )}
        <div
          className="sidebar"
          role={mobileOpen ? 'dialog' : 'complementary'}
          aria-label={mobileOpen ? 'Workspace navigation' : undefined}
          aria-modal={mobileOpen || undefined}
          onClick={(event) => {
            if (mobileOpen && (event.target as HTMLElement).closest('a'))
              closeMobileNav();
          }}
        >
          <NavLink className="brand" to="/overview" aria-label="visp overview">
            <BrandMark size={28} />
            <span>
              <strong>visp</strong>
            </span>
          </NavLink>
          <div className="workspace-label">Workspace</div>
          <nav aria-label="Main navigation">
            {navigation.map((item) => (
              <NavLink
                to={item.to === '/clusters' ? clustersLink : item.to}
                key={item.to}
                title={item.text}
              >
                <item.icon size={16} strokeWidth={1.5} />
                <span>{item.text}</span>
                {item.to === '/approvals' &&
                  !!overview.data?.pending_approvals && (
                    <b className="count">{overview.data.pending_approvals}</b>
                  )}
              </NavLink>
            ))}
          </nav>
          {adminLinks.length > 0 && (
            <>
              <div className="workspace-label">Administration</div>
              <nav aria-label="Administration">
                {adminLinks.map((item) => (
                  <NavLink to={item.to} key={item.to} title={item.text}>
                    <item.icon size={16} strokeWidth={1.5} />
                    <span>{item.text}</span>
                  </NavLink>
                ))}
              </nav>
            </>
          )}
          {user?.org_role !== 'admin' && (
            <nav aria-label="Personal settings">
              <NavLink to="/settings" title="Settings">
                <Settings size={18} />
                <span>Settings</span>
              </NavLink>
            </nav>
          )}
          <div className="sidebar-bottom">
            {phone ? (
              <Button variant="ghost" onClick={closeMobileNav}>
                <X size={18} /> Close navigation
              </Button>
            ) : (
              <Button
                variant="ghost"
                aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                onClick={() => setCollapsed((value) => !value)}
              >
                {collapsed ? (
                  <PanelLeftOpen size={18} />
                ) : (
                  <PanelLeftClose size={18} />
                )}
                <span>Collapse sidebar</span>
              </Button>
            )}
          </div>
        </div>
        <div className="main-shell" inert={mobileOpen && phone}>
          <header className="topbar">
            <Button
              variant="ghost"
              className="mobile-menu"
              aria-label="Open navigation"
              aria-expanded={mobileOpen}
              onClick={() =>
                mobileOpen ? closeMobileNav() : setMobileOpen(true)
              }
            >
              {mobileOpen ? <X size={20} /> : <Menu size={20} />}
            </Button>
            <Dropdown.Root modal={false}>
              <Dropdown.Trigger asChild>
                <Button
                  variant="ghost"
                  className="project-switcher"
                  aria-label={`Project: ${projectName}${workspaceWide ? ' (this page shows every project)' : ''}`}
                  title={
                    workspaceWide
                      ? 'This page shows every project'
                      : `Showing ${projectName}`
                  }
                >
                  {projectName}
                  <ChevronDown size={14} />
                </Button>
              </Dropdown.Trigger>
              <Dropdown.Portal container={popoverLayer}>
                <Dropdown.Content className="dropdown" align="start">
                  <Dropdown.RadioGroup
                    value={project}
                    onValueChange={(value) => {
                      setRememberedProject(value);
                      navigate(
                        value === 'all'
                          ? '/clusters'
                          : `/clusters?project_id=${encodeURIComponent(value)}`,
                      );
                    }}
                  >
                    {[
                      { value: 'all', label: 'All projects' },
                      ...(projects.data?.items.map((item) => ({
                        value: item.id,
                        label: item.name,
                      })) ?? []),
                    ].map((item) => (
                      <Dropdown.RadioItem key={item.value} value={item.value}>
                        {item.label}
                        {project === item.value && <span>✓</span>}
                      </Dropdown.RadioItem>
                    ))}
                  </Dropdown.RadioGroup>
                </Dropdown.Content>
              </Dropdown.Portal>
            </Dropdown.Root>
            <div className="topbar-right">
              <Button
                className="search-trigger"
                aria-label={`Jump to a page or cluster (${mod} K)`}
                onClick={() => setCommand(true)}
              >
                <Search size={15} />
                <kbd>{mod} K</kbd>
              </Button>
              <Dropdown.Root modal={false}>
                <Dropdown.Trigger asChild>
                  <button className="avatar" aria-label="User menu">
                    {user?.name
                      .split(' ')
                      .map((part) => part[0])
                      .join('')
                      .slice(0, 2)}
                  </button>
                </Dropdown.Trigger>
                <Dropdown.Portal container={popoverLayer}>
                  <Dropdown.Content className="dropdown" align="end">
                    <div className="user-label">
                      <strong>{user?.name}</strong>
                      <small>{user?.email}</small>
                    </div>
                    <Dropdown.Separator />
                    {[
                      { value: 'light' as const, label: 'Light', icon: Sun },
                      { value: 'dark' as const, label: 'Dark', icon: Moon },
                      {
                        value: 'system' as const,
                        label: 'System',
                        icon: Monitor,
                      },
                    ].map((item) => (
                      <Dropdown.Item
                        key={item.value}
                        onSelect={() => setTheme(item.value)}
                      >
                        <item.icon size={15} />
                        {item.label}
                        {theme === item.value && <span>✓</span>}
                      </Dropdown.Item>
                    ))}
                    <Dropdown.Separator />
                    <Dropdown.Item
                      onSelect={() => navigate('/settings?tab=preferences')}
                    >
                      Preferences
                    </Dropdown.Item>
                    <Dropdown.Item onSelect={() => setShortcuts(true)}>
                      Keyboard shortcuts <kbd>?</kbd>
                    </Dropdown.Item>
                    <Dropdown.Item onSelect={() => setPassword(true)}>
                      <KeyRound size={15} />
                      Change password
                    </Dropdown.Item>
                    <Dropdown.Item
                      onSelect={() =>
                        logout.mutate(
                          { path: '/auth/logout' },
                          {
                            onSuccess: () => {
                              cache.clear();
                              navigate('/login', { replace: true });
                            },
                          },
                        )
                      }
                    >
                      <LogOut size={15} />
                      Log out
                    </Dropdown.Item>
                  </Dropdown.Content>
                </Dropdown.Portal>
              </Dropdown.Root>
            </div>
          </header>
          <SessionRecovery />
          <main
            className={`page ${workspace ? 'workspace-page' : ''} ${current ? 'environment-frame' : ''}`}
            data-environment={current?.environment}
            id="main-content"
            tabIndex={-1}
          >
            <RouteBoundary key={location.pathname}>
              <Suspense
                fallback={
                  <>
                    <h1>Loading workspace</h1>
                    <Skeleton />
                  </>
                }
              >
                <Outlet />
              </Suspense>
            </RouteBoundary>
          </main>
        </div>
        <div
          id="workspace-popovers"
          ref={setPopoverLayer}
          className="popover-layer"
          role="region"
          aria-label="Workspace menus"
        />
        <CommandPalette
          open={command}
          onOpenChange={setCommand}
          pages={palettePages}
          clusters={clusters.data?.items ?? noClusters}
        />
        <Modal
          open={shortcuts}
          onOpenChange={setShortcuts}
          title="Keyboard shortcuts"
          description={`Shortcuts use the ${mod === '⌘' ? 'Command (⌘)' : 'Ctrl'} key on this computer.`}
        >
          <dl className="review-policy">
            <dt>Jump to a page or action</dt>
            <dd>
              <kbd>{mod} K</kbd>
            </dd>
            <dt>Run SQL / request approval</dt>
            <dd>
              <kbd>{mod} Enter</kbd>
            </dd>
            <dt>Cancel running query / close dialog</dt>
            <dd>
              <kbd>Esc</kbd>
            </dd>
            <dt>New query tab</dt>
            <dd>
              <kbd>{mod} Alt T</kbd>
            </dd>
            <dt>Results</dt>
            <dd>Arrow keys to move, Enter to inspect</dd>
            <dt>Leave SQL editor</dt>
            <dd>
              <kbd>Tab</kbd>
            </dd>
            <dt>Show this help</dt>
            <dd>
              <kbd>?</kbd>
            </dd>
          </dl>
        </Modal>
        <Modal
          open={password}
          onOpenChange={setPassword}
          title="Change password"
        >
          <form
            onSubmit={(event) => {
              event.preventDefault();
              const body = Object.fromEntries(
                new FormData(event.currentTarget),
              );
              changePassword.mutate(
                { path: '/auth/change-password', body },
                { onSuccess: () => setPassword(false) },
              );
            }}
          >
            <AccountName email={user?.email} />
            <Field label="Current password">
              <input
                name="current_password"
                type="password"
                required
                autoComplete="current-password"
              />
            </Field>
            <Field label="New password" hint="At least 12 characters.">
              <input
                name="new_password"
                type="password"
                required
                minLength={12}
                autoComplete="new-password"
              />
            </Field>
            <div className="dialog-actions">
              <Button
                type="submit"
                variant="primary"
                disabled={changePassword.isPending}
              >
                Change password
              </Button>
            </div>
          </form>
        </Modal>
      </div>
    </PopoverLayerContext.Provider>
  );
}

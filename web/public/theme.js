/* global document, localStorage, matchMedia */
// Runs before the page paints. The same rule as in src/lib/theme.tsx: dark
// unless the person chose light, or chose to follow the system.
(function () {
  var stored = null;
  try {
    stored = localStorage.getItem('vda.theme');
  } catch {
    // Storage can be unavailable; the default applies.
  }
  var dark =
    stored === 'system'
      ? matchMedia('(prefers-color-scheme: dark)').matches
      : stored !== 'light';
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
})();

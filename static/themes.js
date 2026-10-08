/* Apply the saved theme before the first paint; theme changes never reload data. */
(() => {
  const key = 'opennds-theme';
  const valid = value => value === 'classic' || value === 'hacker';
  const normalize = value => valid(value) ? value : 'hacker';
  const root = document.documentElement;
  const sync = () => document.querySelectorAll('[data-theme-select]').forEach(select => {
    select.value = root.dataset.theme;
  });
  function apply(value, persist = false) {
    const theme = normalize(value);
    const changed = root.dataset.theme !== theme;
    root.dataset.theme = theme;
    if (persist) {
      try { localStorage.setItem(key, theme); } catch (_) { /* Session selection still works. */ }
    }
    sync();
    if (changed) window.dispatchEvent(new Event('opennds-themechange'));
  }
  let saved;
  try { saved = localStorage.getItem(key); } catch (_) { /* Use the default when storage is unavailable. */ }
  apply(saved);
  document.addEventListener('DOMContentLoaded', () => {
    sync();
    document.querySelectorAll('[data-theme-select]').forEach(select => {
      select.addEventListener('change', () => apply(select.value, true));
    });
  });
  window.addEventListener('storage', event => {
    if (event.key === key || event.key === null) apply(event.key === null ? null : event.newValue);
  });
  window.OpenNDSTheme = { set: value => apply(value, true), get: () => root.dataset.theme };
})();

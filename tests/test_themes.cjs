// Dependency-free tests for preferences restored before paint and synced between tabs.
const fs = require('node:fs'), vm = require('node:vm'), assert = require('node:assert/strict');
const source = fs.readFileSync('static/themes.js', 'utf8');
function fixture(saved, unavailable = false) {
  const root = { dataset: { theme: 'hacker' } }, events = [], windowEvents = {}, documentEvents = {};
  const selectors = [{ value: 'hacker' }, { value: 'hacker' }];
  selectors.forEach(select => select.addEventListener = (_, handler) => { select.change = handler; });
  const stored = new Map(saved === undefined ? [] : [['opennds-theme', saved]]);
  const context = {
    document: { documentElement: root, querySelectorAll: () => selectors,
      addEventListener: (name, callback) => { documentEvents[name] = callback; } },
    window: { addEventListener: (name, callback) => { windowEvents[name] = callback; },
      dispatchEvent: event => { events.push(event.type); } },
    Event: class { constructor(type) { this.type = type; } },
    localStorage: { getItem: key => { if (unavailable) throw Error('Unavailable'); return stored.get(key) ?? null; },
      setItem: (key, value) => { if (unavailable) throw Error('Unavailable'); stored.set(key, value); } },
  };
  vm.runInNewContext(source, context);
  return { root, events, selectors, stored, context, ready: () => documentEvents.DOMContentLoaded(),
    storage: event => windowEvents.storage(event) };
}
let f = fixture('classic');
assert.equal(f.root.dataset.theme, 'classic', 'saved theme must restore before DOM ready');
f.ready();
assert.ok(f.selectors.every(select => select.value === 'classic'));
f.selectors[1].value = 'hacker'; f.selectors[1].change();
assert.equal(f.stored.get('opennds-theme'), 'hacker');
assert.ok(f.selectors.every(select => select.value === 'hacker'));
const eventCount = f.events.length;
f.context.window.OpenNDSTheme.set('hacker');
assert.equal(f.events.length, eventCount, 'same theme must not trigger a redraw');
f.storage({ key: 'opennds-theme', newValue: 'classic' });
assert.equal(f.context.window.OpenNDSTheme.get(), 'classic');
assert.equal(f.stored.get('opennds-theme'), 'hacker', 'storage events must not write back');
f.storage({ key: 'unrelated', newValue: 'hacker' });
assert.equal(f.root.dataset.theme, 'classic');
f.storage({ key: null });
assert.equal(f.root.dataset.theme, 'hacker');
for (const saved of [undefined, 'unknown']) assert.equal(fixture(saved).root.dataset.theme, 'hacker');
f = fixture(undefined, true); f.ready(); f.context.window.OpenNDSTheme.set('classic');
assert.equal(f.root.dataset.theme, 'classic', 'theme switching works even without storage');
console.log('PASS: early restore, selectors, persistence, cross-tab events, invalid/blocked storage, redraw only on change');

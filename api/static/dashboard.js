/* pentest-tools dashboard
 * Polls the local FastAPI surface, renders engagements / findings / chains.
 * No build step. Plain JS. Same-origin only.
 */

(function () {
  'use strict';

  // ─── Config ─────────────────────────────────────────────────────────
  const API = ''; // same-origin; the dashboard is served from FastAPI
  const REFRESH_MS = 4000;

  // ─── Tiny helpers ───────────────────────────────────────────────────
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function el(tag, attrs, children) {
    const e = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (k === 'class') e.className = v;
        else if (k === 'text') e.textContent = v;
        else if (k === 'html') e.innerHTML = v; // only for trusted internal calls
        else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2).toLowerCase(), v);
        else if (v != null) e.setAttribute(k, v);
      }
    }
    if (children) {
      for (const c of [].concat(children)) {
        if (c == null) continue;
        e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
      }
    }
    return e;
  }

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatTime(iso) {
    if (!iso) return '—';
    try {
      const d = new Date(iso);
      return d.toLocaleString();
    } catch (e) { return iso; }
  }

  async function api(path, opts) {
    const r = await fetch(API + path, opts);
    if (!r.ok) {
      const text = await r.text().catch(() => '');
      throw new Error('API ' + r.status + ' on ' + path + ': ' + text.slice(0, 200));
    }
    return r.json();
  }

  // ─── State ──────────────────────────────────────────────────────────
  const state = {
    engagements: [],
    selectedId: null,
    selectedFindings: [],
    selectedChains: [],
    selectedStages: [],
    selectedSummary: null,
    severityFilter: null, // null, 'critical', 'high', 'medium', 'low', 'info'
    activeTab: 'engagements',
    healthOk: false,
    pollTimer: null,
    ws: null,
  };

  // ─── Health + version ───────────────────────────────────────────────
  async function refreshHealth() {
    try {
      await api('/health');
      const ver = await api('/version');
      state.healthOk = true;
      $('#health-dot').classList.add('ok');
      $('#health-dot').classList.remove('bad');
      $('#health-label').textContent = 'connected';
      $('#version-badge').textContent = 'v' + (ver.version || '?');
    } catch (e) {
      state.healthOk = false;
      $('#health-dot').classList.add('bad');
      $('#health-dot').classList.remove('ok');
      $('#health-label').textContent = 'disconnected';
    }
  }

  // ─── Engagements ────────────────────────────────────────────────────
  async function refreshEngagements() {
    try {
      const list = await api('/engagements?limit=50');
      state.engagements = Array.isArray(list) ? list : [];
      renderEngagementList();
      // If we had a selection, refresh its detail in-place
      if (state.selectedId) {
        const stillExists = state.engagements.find(function (e) { return e.id === state.selectedId; });
        if (stillExists) refreshEngagementDetail(state.selectedId);
      }
      $('#engagement-count').textContent = state.engagements.length + ' total';
    } catch (e) {
      console.warn(e);
    }
  }

  function renderEngagementList() {
    const list = $('#engagement-list');
    list.innerHTML = '';
    if (!state.engagements.length) {
      list.appendChild(el('div', { class: 'empty-state' }, [
        el('p', { text: 'No engagements yet.' }),
        el('p', { class: 'hint', html: 'Run <code>pttools start &lt;target&gt;</code> in another terminal.' }),
      ]));
      return;
    }
    for (const eng of state.engagements) {
      const row = el('a', {
        class: 'engagement-row' + (eng.id === state.selectedId ? ' active' : ''),
        href: '#engagement-' + escapeHtml(eng.id),
        'data-engagement-id': eng.id,
        onClick: function (ev) {
          ev.preventDefault();
          selectEngagement(eng.id);
        },
      }, [
        el('div', { class: 'er-target', text: eng.target || eng.id }),
        el('div', { class: 'er-meta' }, [
          el('span', { text: formatTime(eng.created_at || eng.start_time) }),
          el('span', { text: 'phase: ' + (eng.current_phase || eng.phase || 'unknown') }),
        ]),
      ]);
      list.appendChild(row);
    }
  }

  async function selectEngagement(id) {
    state.selectedId = id;
    renderEngagementList();
    await refreshEngagementDetail(id);
    openWebSocket(id);
  }

  async function refreshEngagementDetail(id) {
    try {
      const detail = await api('/engagements/' + encodeURIComponent(id));
      const findings = await api('/engagements/' + encodeURIComponent(id) + '/findings');
      const chains = await api('/engagements/' + encodeURIComponent(id) + '/chains');
      const stages = await api('/engagements/' + encodeURIComponent(id) + '/stages');
      state.selectedSummary = detail.summary || {};
      state.selectedFindings = findings || [];
      state.selectedChains = chains || [];
      state.selectedStages = stages || [];
      renderEngagementDetail(detail.engagement || {});
    } catch (e) {
      console.warn(e);
    }
  }

  function renderEngagementDetail(eng) {
    const root = $('#engagement-detail');
    root.innerHTML = '';

    const head = el('header', { class: 'ed-head' }, [
      el('div', {}, [
        el('div', { class: 'ed-target', text: eng.target || eng.id || '—' }),
        el('div', { class: 'ed-meta' }, [
          el('span', { text: 'id: ' + (eng.id || '—') }),
          el('span', { text: 'phase: ' + (eng.current_phase || eng.phase || '—') }),
          el('span', { text: 'started: ' + formatTime(eng.created_at || eng.start_time) }),
        ]),
      ]),
      el('div', { class: 'panel-actions' }, [
        el('button', {
          class: 'btn ghost',
          text: 'sarif',
          title: 'Download SARIF v2.1',
          onClick: function () { downloadSarif(eng.id); },
        }),
      ]),
    ]);
    root.appendChild(head);

    // Summary cells
    const sum = state.selectedSummary || {};
    const cells = [
      ['Critical', sum.critical || 0],
      ['High', sum.high || 0],
      ['Medium', sum.medium || 0],
      ['Low', sum.low || 0],
      ['Confirmed', sum.confirmed || 0],
      ['Total', sum.total || (state.selectedFindings || []).length],
    ];
    const summaryRow = el('div', { class: 'summary-row' });
    for (const [label, num] of cells) {
      summaryRow.appendChild(el('div', { class: 'summary-cell' }, [
        el('div', { class: 'sc-num', text: String(num) }),
        el('div', { class: 'sc-label', text: label }),
      ]));
    }
    root.appendChild(summaryRow);

    // Findings table with severity filter
    root.appendChild(renderFindingsSection());

    // Stage timeline
    root.appendChild(renderStageSection());

    // Attack chain visualization
    root.appendChild(renderChainSection());
  }

  function renderFindingsSection() {
    const wrap = el('div');
    wrap.appendChild(el('div', { class: 'section-head' }, [
      el('h3', { text: 'Findings' }),
      renderFilterBar(),
    ]));

    let findings = state.selectedFindings || [];
    if (state.severityFilter) {
      findings = findings.filter(function (f) { return (f.severity || '').toLowerCase() === state.severityFilter; });
    }

    if (!findings.length) {
      wrap.appendChild(el('div', { class: 'empty-state', text: 'No findings yet.' }));
      return wrap;
    }

    const table = el('table', { class: 'findings-table' }, [
      el('thead', {}, [
        el('tr', {}, [
          el('th', { text: '' }),
          el('th', { text: 'Severity' }),
          el('th', { text: 'Title' }),
          el('th', { text: 'CVE' }),
          el('th', { text: 'Host' }),
          el('th', { text: 'Time' }),
        ]),
      ]),
      el('tbody', {}, findings.map(function (f) {
        return el('tr', {
          class: 'f-row',
          'data-finding-id': f.id || f.finding_id || '',
          onClick: function () { openFindingModal(f); },
        }, [
          el('td', {}, [f.confirmed ? el('span', { class: 'f-confirmed', title: 'PoC-confirmed' }) : null]),
          el('td', {}, [el('span', { class: 'f-sev ' + (f.severity || 'info').toLowerCase(), text: (f.severity || 'info').toUpperCase() })]),
          el('td', { text: f.title || f.name || '(untitled)' }),
          el('td', { text: f.cve || '—' }),
          el('td', { text: f.host || f.target || '—' }),
          el('td', { text: formatTime(f.created_at || f.timestamp) }),
        ]);
      })),
    ]);
    wrap.appendChild(table);
    return wrap;
  }

  function renderFilterBar() {
    const sevs = ['critical', 'high', 'medium', 'low', 'info'];
    const bar = el('div', { class: 'filter-bar' });
    bar.appendChild(el('a', {
      class: state.severityFilter ? '' : 'on',
      text: 'all',
      onClick: function () { state.severityFilter = null; renderEngagementDetail({ id: state.selectedId }); },
    }));
    for (const s of sevs) {
      bar.appendChild(el('a', {
        class: state.severityFilter === s ? 'on' : '',
        text: s,
        onClick: function () {
          state.severityFilter = s;
          renderEngagementDetail({ id: state.selectedId });
        },
      }));
    }
    return bar;
  }

  function renderStageSection() {
    const wrap = el('div');
    wrap.appendChild(el('div', { class: 'section-head' }, [
      el('h3', { text: 'Workflow timeline' }),
      el('span', { class: 'hint', text: 'Stages recorded during execution' }),
    ]));

    const stages = state.selectedStages || [];
    if (!stages.length) {
      wrap.appendChild(el('div', { class: 'empty-state', text: 'No stage records yet.' }));
      return wrap;
    }

    const timeline = el('div', { class: 'stage-timeline' });
    for (const s of stages) {
      timeline.appendChild(el('div', { class: 'stage-card stage-' + (s.status || 'unknown') }, [
        el('div', { class: 'stage-title', text: (s.title || s.stage || '').toString() }),
        el('div', { class: 'stage-meta', text: (s.stage || 'stage') + ' · ' + (s.status || 'unknown') + ' · ' + Math.round((s.progress || 0) * 100) + '%' }),
        s.details ? el('div', { class: 'stage-details', text: s.details }) : null,
        el('div', { class: 'stage-time', text: formatTime(s.recorded_at) }),
      ]));
    }
    wrap.appendChild(timeline);
    return wrap;
  }

  function renderChainSection() {
    const wrap = el('div');
    wrap.appendChild(el('div', { class: 'section-head' }, [
      el('h3', { text: 'Attack chains' }),
      el('span', { class: 'hint', text: (state.selectedChains || []).length + ' chain(s)' }),
    ]));
    if (!state.selectedChains.length) {
      wrap.appendChild(el('div', { class: 'empty-state', text: 'No chains constructed yet.' }));
      return wrap;
    }
    for (const chain of state.selectedChains) {
      const viz = el('div', { class: 'chain-viz' });
      const steps = (chain.steps || chain.nodes || []).slice(0, 20);
      if (!steps.length) {
        viz.appendChild(el('div', { class: 'empty-state', text: 'Chain has no steps recorded.' }));
      } else {
        steps.forEach(function (step, i) {
          viz.appendChild(el('div', { class: 'chain-step' }, [
            el('div', { class: 'cs-marker', text: String(i + 1).padStart(2, '0') }),
            el('div', { class: 'cs-body' }, [
              el('div', { class: 'cs-title', text: step.title || step.name || step.description || ('Step ' + (i + 1)) }),
              step.description && step.description !== step.title
                ? el('div', { class: 'cs-desc', text: step.description })
                : null,
            ]),
          ]));
        });
      }
      wrap.appendChild(viz);
    }
    return wrap;
  }

  // ─── Finding modal ──────────────────────────────────────────────────
  function openFindingModal(f) {
    const body = $('#finding-modal-body');
    const title = $('#finding-modal-title');
    title.textContent = f.title || f.name || 'Finding';

    const fields = [
      ['Severity', (f.severity || 'info').toUpperCase()],
      ['CVSS', f.cvss || '—'],
      ['CVE', f.cve || '—'],
      ['Host', f.host || f.target || '—'],
      ['Confirmed', f.confirmed ? 'yes' : 'no'],
      ['Discovered', formatTime(f.created_at || f.timestamp)],
      ['ATT&CK', f.attack || f.mitre || '—'],
    ];
    const dl = el('dl');
    for (const [k, v] of fields) {
      dl.appendChild(el('dt', { text: k }));
      dl.appendChild(el('dd', { text: String(v) }));
    }
    body.innerHTML = '';
    body.appendChild(dl);
    if (f.description) {
      body.appendChild(el('dt', { text: 'Description' }));
      body.appendChild(el('dd', { text: f.description }));
    }
    if (f.poc || f.evidence) {
      body.appendChild(el('dt', { text: 'PoC / evidence' }));
      const pre = el('pre');
      pre.textContent = String(f.poc || f.evidence);
      body.appendChild(pre);
    }
    if (f.remediation) {
      body.appendChild(el('dt', { text: 'Remediation' }));
      body.appendChild(el('dd', { text: f.remediation }));
    }

    $('#finding-modal').classList.remove('hidden');
  }
  function closeFindingModal() {
    $('#finding-modal').classList.add('hidden');
  }

  // ─── SARIF download ─────────────────────────────────────────────────
  async function downloadSarif(id) {
    try {
      const sarif = await api('/engagements/' + encodeURIComponent(id) + '/sarif');
      const blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/sarif+json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'pentest-tools-' + id + '.sarif.json';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      alert('SARIF export failed: ' + e.message);
    }
  }

  // ─── Live updates via WebSocket ─────────────────────────────────────
  function openWebSocket(id) {
    if (state.ws) {
      try { state.ws.close(); } catch (e) {}
      state.ws = null;
    }
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const url = proto + '//' + location.host + '/engagements/' + encodeURIComponent(id) + '/stream';
    try {
      state.ws = new WebSocket(url);
      state.ws.onmessage = function (ev) {
        try {
          const msg = JSON.parse(ev.data);
          if (msg.type === 'finding' && msg.data) {
            state.selectedFindings = (state.selectedFindings || []).concat([msg.data]);
            renderEngagementDetail({ id: state.selectedId });
          } else if (msg.type === 'summary' && msg.data) {
            state.selectedSummary = msg.data;
          }
        } catch (e) { /* ignore */ }
      };
      state.ws.onerror = function () { /* fall back to polling */ };
      state.ws.onclose = function () { state.ws = null; };
    } catch (e) {
      // WebSocket not available; polling will keep us current
    }
  }

  // ─── Catalog tabs (agents / tools) ──────────────────────────────────
  async function loadCatalog() {
    try {
      const agents = await api('/agents');
      const grid = $('#agent-grid');
      grid.innerHTML = '';
      for (const a of agents) {
        grid.appendChild(el('div', { class: 'card' }, [
          el('div', { class: 'c-name', text: a.name }),
          el('div', { class: 'c-desc', text: a.description || '' }),
        ]));
      }
      $('#agent-count').textContent = agents.length + ' agents';
    } catch (e) { /* tab loads on first open */ }

    try {
      const tools = await api('/tools');
      const grid = $('#tool-grid');
      grid.innerHTML = '';
      if (!tools.length) {
        grid.appendChild(el('div', { class: 'empty-state', text: 'No tool registry exported. Tools are still callable from agents.' }));
      } else {
        for (const t of tools) {
          grid.appendChild(el('div', { class: 'card' }, [
            el('div', { class: 'c-name', text: t.name }),
            el('div', { class: 'c-desc', text: t.description || '' }),
            t.category ? el('span', { class: 'c-tag', text: t.category }) : null,
          ]));
        }
      }
      $('#tool-count').textContent = tools.length + ' tools';
    } catch (e) { /* */ }
  }

  // ─── Tabs ───────────────────────────────────────────────────────────
  function activateTab(name) {
    state.activeTab = name;
    $$('.topnav a').forEach(function (a) { a.classList.toggle('nav-active', a.dataset.tab === name); });
    $$('section.panel').forEach(function (p) { p.classList.add('hidden'); });
    const target = $('#tab-' + name);
    if (target) target.classList.remove('hidden');
    if (name === 'agents' || name === 'tools') {
      loadCatalog();
    }
  }

  // ─── Wire it up ─────────────────────────────────────────────────────
  function init() {
    // Tabs
    $$('.topnav a').forEach(function (a) {
      a.addEventListener('click', function (ev) {
        ev.preventDefault();
        activateTab(a.dataset.tab);
      });
    });

    // Refresh
    $('#btn-refresh').addEventListener('click', refreshEngagements);

    // Modal close
    $('#finding-modal-close').addEventListener('click', closeFindingModal);
    $('#finding-modal').addEventListener('click', function (ev) {
      if (ev.target === ev.currentTarget) closeFindingModal();
    });
    document.addEventListener('keydown', function (ev) {
      if (ev.key === 'Escape') closeFindingModal();
    });

    // Initial load
    refreshHealth();
    refreshEngagements();
    activateTab('engagements');

    // Polling
    state.pollTimer = setInterval(function () {
      refreshHealth();
      refreshEngagements();
    }, REFRESH_MS);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

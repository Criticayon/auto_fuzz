let polling = true;
let logAtBottom = true;
let chartInstances = {};
let _lastChartData = null;
let _engineAvailable = false;
let _engineChecked = false;
let _engineFailed = false;
let _notifKeys = new Set();       // 通知去重（已关闭的通知 key）
// 从 localStorage 恢复已关闭的通知，让它们跨页面刷新不重新出现
try {
  var saved = localStorage.getItem('af_dismissed');
  if (saved) {
    var arr = JSON.parse(saved);
    for (var i = 0; i < arr.length; i++) _notifKeys.add(arr[i]);
  }
} catch(e) {}
let _phase4Running = false;       // 普通模式 Phase 4 是否在运行
let _efCards = {};                // Full EasyFuzz 状态卡片（按项目名索引）

function addNotification(type, title, msg, keySuffix) {
  const stack = document.getElementById('notifStack');
  if (!stack) return;
  // dedup key: type + suffix 保证稳定，不受 msg 内容变化影响
  var key = type;
  if (keySuffix) key += '|' + keySuffix;
  if (_notifKeys.has(key)) return;
  _notifKeys.add(key);
  // 持久化到 localStorage，刷新页面后不再弹出同一条通知
  try { localStorage.setItem('af_dismissed', JSON.stringify([..._notifKeys])); } catch(e) {}
  const icons = {'fuzz-done':'✅','phase4-done':'🎯','stale':'⚠️'};
  const card = document.createElement('div');
  card.className = 'notif-card notif-' + type;
  card.innerHTML = '<button class="notif-close">&times;</button>' +
    '<span class="notif-icon">' + (icons[type]||'📌') + '</span>' +
    '<div class="notif-body"><div class="notif-title">' + title + '</div><div class="notif-msg">' + msg + '</div></div>';
  card.querySelector('.notif-close').onclick = function() { card.remove(); };
  stack.prepend(card);
}

async function api(url, opts) {
  try { return await (await fetch(url, opts || {})).json(); }
  catch { return null; }
}

async function checkEngine() {
  const gs = document.getElementById('globalStatus');
  const r = await api('/api/check-engine');
  _engineChecked = true;
  if (r && r.available) {
    _engineAvailable = true;
    _engineFailed = false;
    // Don't overwrite if updateDashboard already set a running/idle state
    const currentBadge = gs.querySelector('.badge');
    if (currentBadge && currentBadge.textContent.trim() === 'Starting...') {
      gs.innerHTML = '<span class="badge badge-yellow"><span class="status-dot green"></span>Waiting for task...</span>';
    }
  } else {
    _engineAvailable = false;
    _engineFailed = true;
    gs.innerHTML = '<span class="badge badge-red"><span class="status-dot red"></span>Engine Error</span>';
  }
}

function switchPage(pageName) {
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.page').forEach(el => el.classList.remove('active'));
  const navEl = document.querySelector(`.nav-item[data-page="${pageName}"]`);
  const pageEl = document.querySelector(`.page[data-page="${pageName}"]`);
  if (navEl) navEl.classList.add('active');
  if (pageEl) pageEl.classList.add('active');

  // Auto-load content when switching to certain pages
  if (pageName === 'report') {
    loadSummary();
  }
  if (pageName === 'pipeline') {
    updateSelectedInfo();
    // Load EasyFuzz commands when switching to pipeline
    if (document.getElementById('easyfuzzToggle').checked) {
      loadEasyFuzzCommands();
    }
  }
  if (pageName === 'dashboard' && _lastChartData) {
    // Re-render charts after page becomes visible (canvases lose dimensions when hidden)
    setTimeout(() => updateCharts(_lastChartData), 50);
  }
  if (pageName === 'issues') {
    loadIssueFiles();
    loadGitHubIssues();
  }
}

// Summary loading (extracted from old showSummary)
async function loadSummary() {
  const target = document.getElementById('targetSelect').value;
  const wrapper = document.getElementById('summaryWrapper');
  const empty = document.getElementById('reportEmpty');
  if (!target) {
    wrapper.style.display = 'none';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';
  wrapper.style.display = 'block';
  document.getElementById('summaryTarget').textContent = target;
  const box = document.getElementById('summaryBox');
  box.innerHTML = '<div class="loading-skeleton"><div class="bar" style="width:60%;height:24px;margin-bottom:20px;"></div><div class="bar" style="width:40%;height:14px;margin-bottom:12px;"></div><div class="bar" style="width:100%;height:14px;margin-bottom:12px;"></div><div class="bar" style="width:80%;height:14px;margin-bottom:12px;"></div><div class="bar" style="width:55%;height:14px;margin-bottom:24px;"></div><div class="bar" style="width:45%;height:14px;margin-bottom:12px;"></div><div class="bar" style="width:90%;height:14px;margin-bottom:12px;"></div><div class="bar" style="width:70%;height:14px;"></div></div>';
  const d = await api('/api/summary?target=' + encodeURIComponent(target));
  if (d && d.content) {
    box.innerHTML = marked.parse(d.content);
  } else {
    box.innerHTML = '<div style="text-align:center;color:#656d76;padding:60px 20px;font-size:15px;">No SUMMARY.md found for <strong>' + target + '</strong>. Run fuzzing and Phase 4 first to generate reports.</div>';
  }
}

function updateCharts(d) {
  const row = document.getElementById('chartsRow');
  if (!d || !d.strategies || !d.strategies.length) {
    row.style.display = 'none';
    return;
  }
  row.style.display = 'grid';
  // Force layout so canvases have valid dimensions
  row.offsetHeight;

  const names = d.strategies.map(s => s.name || '?');
  const edges = d.strategies.map(s => parseInt(s.edge_found) || 0);
  const crashes = d.strategies.map(s => parseInt(s.unique_crashes) || 0);
  const speeds = d.strategies.map(s => {
    const v = parseFloat(s.exec_speed);
    return isNaN(v) ? 0 : v;
  });

  function niceScale(data, defaultMax, defaultStep) {
    const max = Math.max(...data);
    if (max <= 0) return { max: defaultMax, step: defaultStep };
    if (max <= defaultMax) return { max: defaultMax, step: defaultStep };
    const mag = Math.pow(10, Math.floor(Math.log10(max)));
    const norm = max / mag;
    const step = Math.max(1, Math.round(norm <= 2 ? mag / 5 : norm <= 5 ? mag / 2 : mag));
    return { max: Math.ceil(max / step) * step, step };
  }

  function makeChart(id, label, data, color, bg, scale) {
    if (chartInstances[id]) chartInstances[id].destroy();
    const canvas = document.getElementById(id);
    canvas.style.display = 'block';
    const parent = canvas.parentElement;
    // Set explicit canvas pixel dimensions based on parent size and DPR
    const dpr = window.devicePixelRatio || 1;
    const rect = parent.getBoundingClientRect();
    const w = rect.width || parent.clientWidth || 200;
    const h = rect.height || parent.clientHeight || 200;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';
    chartInstances[id] = new Chart(canvas, {
      type: 'bar',
      data: { labels: names, datasets: [{ label, data, backgroundColor: bg, borderColor: color, borderWidth: 1, borderRadius: 3, barPercentage: 0.2, categoryPercentage: 0.5 }] },
      options: {
        responsive: false, maintainAspectRatio: false, devicePixelRatio: 1,
        animation: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { font: { size: 10, weight: '600' }, maxRotation: 0, autoSkip: false }, grid: { display: false } },
          y: { beginAtZero: true, max: scale.max, ticks: { font: { size: 10, weight: '600' }, stepSize: scale.step }, grid: { color: '#eaeef2' } }
        }
      }
    });
  }

  // Create charts sequentially with layout settling between each
  function createSeq(idx) {
    const charts = [
      { id: 'chartEdges', label: 'Edges', data: edges, color: '#0969da', bg: 'rgba(9,105,218,0.6)', scale: niceScale(edges, 800, 100) },
      { id: 'chartCrashes', label: 'Crashes', data: crashes, color: '#cf222e', bg: 'rgba(207,34,46,0.6)', scale: niceScale(crashes, 8, 1) },
      { id: 'chartSpeed', label: 'Exec/s', data: speeds, color: '#d4940c', bg: 'rgba(212,148,12,0.6)', scale: niceScale(speeds, 80, 10) }
    ];
    if (idx >= charts.length) return;
    makeChart(charts[idx].id, charts[idx].label, charts[idx].data, charts[idx].color, charts[idx].bg, charts[idx].scale);
    setTimeout(() => createSeq(idx + 1), 30);
  }
  createSeq(0);
}

function updateDashboard() {
  const target = document.getElementById('targetSelect').value;
  const noTarget = !target;
  loadManifest();

  // 清除按钮：不依赖 API，立即更新
  document.getElementById('clsPhase1').disabled = noTarget;
  document.getElementById('clsPhase2').disabled = noTarget;
  document.getElementById('clsPhase3').disabled = noTarget;
  document.getElementById('clsPhase4').disabled = noTarget;
  document.getElementById('btnClean').disabled = noTarget;

  api('/api/status' + (target ? `?target=${encodeURIComponent(target)}` : '')).then(d => {
    if (!d) {
      document.getElementById('globalStatus').innerHTML = '<span class="badge badge-red"><span class="status-dot gray"></span>Offline</span>';
      return;
    }
    document.getElementById('stratCount').textContent = d.total_strategies || '\u2014';
    document.getElementById('procCount').textContent = d.process_count;
    document.getElementById('totalEdges').textContent = (d.total_edges||0).toLocaleString();
    document.getElementById('totalCrashes').textContent = (d.total_crashes||0).toLocaleString();
    document.getElementById('staleCount').textContent = d.stale_count || 0;

    // 过期策略通知（堆叠通知，不会自动消失）
    const staleStrats = (d.strategies||[]).filter(s => s.stale).map(s => s.name);
    if (target && staleStrats.length) {
      addNotification('stale', 'Stale Strategies (' + staleStrats.length + ')',
        staleStrats.join(', '));
    }

    // Full EasyFuzz 状态卡片（多项目持久卡片）
    const efSection = document.getElementById('easyfuzzStatusSection');
    const efCardContainer = document.getElementById('efCardContainer');
    const ef = d.full_easyfuzz;
    const curTarget = d.current_target || target;
    if (ef && (ef.running || ef.elapsed_min > 0)) {
      efSection.style.display = 'block';
      const total = ef.total_min;
      const totalEstimated = total + 10;
      const elapsed = Math.round(ef.elapsed_min);
      const remaining = Math.max(0, Math.round(totalEstimated - elapsed));
      const elapsedStr = elapsed >= 60 ? Math.floor(elapsed/60)+'h '+elapsed%60+'m' : elapsed+'m';
      const remainStr = '约' + (remaining >= 60 ? Math.floor(remaining/60)+'h '+remaining%60+'m' : remaining+'m');
      const totalStr = total >= 60 ? Math.floor(total/60)+'h '+total%60+'m' : total+'m';
      const pct = ef.running ? Math.min(99, Math.round((elapsed / totalEstimated) * 100)) : 100;
      // 查找或创建该项目的卡片
      let card = _efCards[curTarget];
      if (!card) {
        card = document.createElement('div');
        card.className = 'easyfuzz-status-card';
        card.dataset.project = curTarget;
        card.innerHTML =
          '<div class="ef-row"><span class="ef-label">Project</span><span class="ef-value ef-project-name">' + curTarget + '</span></div>' +
          '<div class="ef-row"><span class="ef-label">Status</span><span class="ef-value ef-status-text"></span></div>' +
          '<div class="ef-row"><span class="ef-label">Elapsed</span><span class="ef-value ef-elapsed"></span></div>' +
          '<div class="ef-row"><span class="ef-label">Remaining</span><span class="ef-value ef-remaining"></span></div>' +
          '<div class="ef-row"><span class="ef-label">Fuzz Time</span><span class="ef-value ef-fuzz-time"></span></div>' +
          '<div class="ef-progress-bar"><div class="ef-progress-fill"><span class="ef-progress-text"></span></div></div>';
        efCardContainer.appendChild(card);
        _efCards[curTarget] = card;
      }
      // 更新卡片内容
      card.querySelector('.ef-elapsed').textContent = elapsedStr;
      card.querySelector('.ef-remaining').textContent = remainStr;
      card.querySelector('.ef-fuzz-time').textContent = totalStr;
      const fill = card.querySelector('.ef-progress-fill');
      const pctText = card.querySelector('.ef-progress-text');
      fill.style.width = pct + '%';
      pctText.textContent = pct + '%';
      const statusEl = card.querySelector('.ef-status-text');
      if (ef.running) {
        statusEl.textContent = 'Running...';
        statusEl.className = 'ef-value ef-status-running';
      } else {
        statusEl.textContent = 'Completed';
        statusEl.className = 'ef-value ef-status-done';
      }
    }

    _lastChartData = d;
    try { updateCharts(d); } catch (e) { /* chart.js not available */ }

    // Sync EasyFuzz toggle with server state
    if (d.easyfuzz_enabled !== undefined) {
      const toggle = document.getElementById('easyfuzzToggle');
      if (toggle.checked !== d.easyfuzz_enabled) {
        toggle.checked = d.easyfuzz_enabled;
        updateEasyFuzzUI(d.easyfuzz_enabled);
      }
    }

    const running = d.pipeline_running || d.running;
    const gs = document.getElementById('globalStatus');
    if (d.pipeline_running) {
      gs.innerHTML = '<span class="badge badge-green"><span class="status-dot green pulsing"></span>Pipeline Running</span>';
    } else if (d.running) {
      gs.innerHTML = '<span class="badge badge-green"><span class="status-dot green pulsing"></span>AFL++ Running</span>';
    } else if (_engineChecked && _engineAvailable) {
      gs.innerHTML = '<span class="badge badge-yellow"><span class="status-dot green"></span>Waiting for task...</span>';
    } else if (_engineChecked && !_engineAvailable) {
      // Engine Error already shown by checkEngine() — keep it
    } else {
      // Engine not checked yet — keep "Starting..."
    }

    // 按钮状态
    const pipelineBusy = d.pipeline_running || false;
    const easyfuzzOn = document.getElementById('easyfuzzToggle').checked;
    document.getElementById('btnPhase1').disabled = running || noTarget;
    document.getElementById('btnPhase2').disabled = running || noTarget;
    document.getElementById('btnPhase3').disabled = easyfuzzOn ? noTarget : (pipelineBusy || noTarget);
    document.getElementById('btnPhase4').disabled = pipelineBusy || noTarget || easyfuzzOn;
    document.getElementById('btnPhase5').disabled = noTarget || easyfuzzOn;
    document.getElementById('btnClean').disabled = running || noTarget;
    // Stop All 按钮：有正在跑的进程才显示
    // 根据运行状态更新 Phase 3 按钮和提示
    const hasRunning = d.running;
    document.getElementById('btnStopAll').style.display = hasRunning ? 'inline-block' : 'none';
    // 常驻按钮，不做显示隐藏
    const tt = document.querySelector('.tooltip-wrap .tooltip-text');
    if (tt) {
      tt.style.display = noTarget ? 'none' : '';
      tt.textContent = hasRunning
        ? '追加新策略到当前正在跑的 fuzz 进程中'
        : '启动所有选中的策略进行 fuzz';
    }

    // 项目显示 + 动画条
    const pBar = document.getElementById('projectBar');
    const pName = document.getElementById('currentProject');
    const aFill = document.getElementById('activityFill');
    const aLabel = document.getElementById('activityLabel');
    if (d.current_target) {
      pBar.style.display = 'flex';
      pBar.className = 'project-bar' + (running ? ' running' : '');
      pName.textContent = d.current_target;
      if (running) {
        aFill.className = 'fill active';
        aLabel.textContent = d.pipeline_running ? 'Pipeline Running...' : 'Fuzzing...';
      } else {
        aFill.className = 'fill idle';
        aLabel.textContent = d.running ? 'Fuzzing' : 'Idle';
      }
    } else {
      pBar.style.display = 'none';
    }

    // 策略表格（含展开命令）
    const sBody = document.getElementById('strategiesBody');
    if (d.strategies && d.strategies.length) {
      sBody.innerHTML = d.strategies.map((s, idx) => {
        const rt = s.run_time ? (t=>{const h=Math.floor(t/3600),m=Math.floor((t%3600)/60);return h?h+'h '+m+'m':m?m+'m':t+'s'})(parseInt(s.run_time)) : '\u2014';
        const expanded = window._expandedRows || new Set();
        const showCmd = expanded.has(idx);
        const cmdRow = s.full_cmd ? `<tr class="cmd-detail" id="cmd_${idx}" style="${showCmd?'':'display:none;'}"><td colspan="11"><pre>${s.full_cmd}</pre></td></tr>` : '';
        const staleHtml = s.stale ? '<span class="stale-icon">\u26a0<span class="stale-tip">Edges unchanged for 2+ hours</span></span>' : '';
        return `<tr class="strategy-row" onclick="toggleCmd(${idx})"><td><span class="arrow ${showCmd?'open':''}" id="arrow_${idx}">\u25b6</span></td><td><strong>${s.name}</strong>${staleHtml}</td><td class="pid-cell">${s.pid||'\u2014'}</td><td class="edges">${s.edge_found||0}</td><td class="crashes">${s.unique_crashes||0}</td><td>${s.paths_total||0}</td><td class="speed">${s.exec_speed||'\u2014'}${s.exec_speed?'/s':''}</td><td>${s.cycles_done||0}</td><td>${s.bitmap_cvg||'\u2014'}</td><td>${rt}</td><td><button class="kill-btn" onclick="event.stopPropagation();killStrategy(${s.pid})" ${s.pid?'':'disabled'}>Stop</button></td></tr>${cmdRow}`;
      }).join('');
    } else {
      sBody.innerHTML = '<tr><td colspan="11" style="text-align:center;color:#8b949e;">No active strategies</td></tr>';
    }

    // 已终止策略表格（仅选了项目才显示）
    const killedSection = document.getElementById('killedSection');
    const killedBody = document.getElementById('killedBody');
    const hasTarget = !!document.getElementById('targetSelect').value;
    if (hasTarget && d.killed && d.killed.length) {
      killedSection.style.display = 'block';
      killedBody.innerHTML = d.killed.map(function(k, idx) {
        const expanded = window._expandedKilledRows && window._expandedKilledRows.has(idx);
        const showCmd = expanded && k.full_cmd;
        const cmdRow = k.full_cmd ? '<tr class="cmd-detail" id="killed_cmd_' + idx + '" style="' + (showCmd?'':'display:none;') + '"><td colspan="10"><pre>' + k.full_cmd + '</pre></td></tr>' : '';
        return '<tr class="strategy-row" onclick="toggleKilledCmd(' + idx + ')"><td><span class="arrow ' + (showCmd?'open':'') + '" id="killed_arrow_' + idx + '">\u25b6</span></td><td><strong>' + (k.name||'?') + '</strong></td><td>' + (k.pid||'\u2014') + '</td><td>' + (k.edges||'0') + '</td><td>' + (k.crashes||'0') + '</td><td>' + (k.paths||'0') + '</td><td>' + (k.speed||'\u2014') + '</td><td>' + (k.cycles||'0') + '</td><td>' + (k.bitmap||'\u2014') + '</td><td>' + (k.runtime||'\u2014') + '</td></tr>' + cmdRow;
      }).join('');
    } else {
      killedSection.style.display = 'none';
    }
  });

  api('/api/log' + (target ? `?target=${encodeURIComponent(target)}` : '')).then(d => {
    if (d && d.log) {
      const box = document.getElementById('logBox');
      const wasAtBottom = logAtBottom;
      box.textContent = d.log;
      if (wasAtBottom) {
        box.scrollTop = box.scrollHeight;
      }
    }
  });
}

function toggleCmd(idx) {
  const row = document.getElementById('cmd_' + idx);
  const arrow = document.getElementById('arrow_' + idx);
  if (row) {
    const show = row.style.display !== 'table-row';
    row.style.display = show ? 'table-row' : 'none';
    if (arrow) arrow.className = 'arrow' + (show ? ' open' : '');
    if (!window._expandedRows) window._expandedRows = new Set();
    if (show) window._expandedRows.add(idx);
    else window._expandedRows.delete(idx);
  }
}

function toggleKilledCmd(idx) {
  const row = document.getElementById('killed_cmd_' + idx);
  const arrow = document.getElementById('killed_arrow_' + idx);
  if (row) {
    const show = row.style.display !== 'table-row';
    row.style.display = show ? 'table-row' : 'none';
    if (arrow) arrow.className = 'arrow' + (show ? ' open' : '');
    if (!window._expandedKilledRows) window._expandedKilledRows = new Set();
    if (show) window._expandedKilledRows.add(idx);
    else window._expandedKilledRows.delete(idx);
  }
}

async function showSummary() {
  switchPage('report');
}

async function loadManifest() {
  const target = document.getElementById('targetSelect').value;
  const panel = document.getElementById('strategyPanel');
  const empty = document.getElementById('strategiesEmpty');
  const list = document.getElementById('strategyList');
  const count = document.getElementById('strategyCount');
  if (!target) { panel.style.display = 'none'; empty.style.display = 'block'; return; }
  empty.style.display = 'none';
  const prevChecked = new Set();
  document.querySelectorAll('.strategy-cb:checked').forEach(cb => prevChecked.add(cb.value));
  const d = await api(`/api/manifest?target=${encodeURIComponent(target)}`);
  if (d && d.strategies && d.strategies.length) {
    panel.style.display = 'block';
    document.getElementById('strategiesNoPhase2').style.display = 'none';
    document.getElementById('strategiesRefSection').style.display = '';
    document.getElementById('strategiesStartSection').style.display = '';
    document.getElementById('strategyList').style.display = '';
    document.getElementById('selectAllLabel').style.display = '';
    count.textContent = `${d.strategies.length} available (batch_size=${d.batch_size||4})`;
    list.innerHTML = d.strategies.map(s => {
      const wasChecked = prevChecked.has(String(s.id));
      const p = s.priority||'medium';
      const pBg = {critical:'#e1e4e8', high:'#ffebe9', medium:'#fff8c5', low:'#dafbe1'}[p]||'#fff8c5';
      const pFg = {critical:'#000000', high:'#cf222e', medium:'#9a6700', low:'#1a7f37'}[p]||'#9a6700';
      return `<div style="display:flex;align-items:flex-start;gap:10px;padding:10px 14px;background:#fefcf8;border:1px solid #d0d7de;border-radius:6px;">
        <input type="checkbox" class="strategy-cb" value="${s.id}" data-name="${s.name||'id_'+s.id}" ${wasChecked?'checked':''} onchange="updateSelectAll()" style="margin-top:3px;">
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
            <strong style="font-size:14px;">${s.name||'id_'+s.id}</strong>
            <span style="font-size:11px;padding:1px 6px;border-radius:4px;background:${pBg};color:${pFg};">${p}</span>
            <span style="font-size:11px;color:#656d76;">score: ${s.vuln_score||'?'}</span>
            <span style="font-size:11px;padding:1px 6px;border-radius:4px;background:#ddf4ff;color:#0969da;">cvg: ${s.expected_cvg||'?'}%</span>
          </div>
          <div style="font-family:'Cascadia Code','JetBrains Mono','Fira Code',Consolas,monospace;font-size:12px;color:#24292f;background:#faf5ed;padding:8px 12px;border-radius:4px;white-space:pre-wrap;word-break:break-all;line-height:1.5;">${s.command||'N/A'}</div>
        </div>
      </div>`;
    }).join('');
    updateSelectAll();
  } else {
    panel.style.display = 'block';
    document.getElementById('strategiesNoPhase2').style.display = 'block';
    document.getElementById('strategiesRefSection').style.display = 'none';
    document.getElementById('strategiesStartSection').style.display = 'none';
    document.getElementById('strategyList').style.display = 'none';
    document.getElementById('selectAllLabel').style.display = 'none';
    count.textContent = '';
  }
}

function toggleAllStrategies() {
  const checked = document.getElementById('selectAllStrategies').checked;
  document.querySelectorAll('.strategy-cb').forEach(cb => cb.checked = checked);
}

function updateSelectAll() {
  const all = document.querySelectorAll('.strategy-cb');
  const checked = document.querySelectorAll('.strategy-cb:checked');
  document.getElementById('selectAllStrategies').checked = all.length === checked.length;
}

function getSelectedStrategyIds() {
  return Array.from(document.querySelectorAll('.strategy-cb:checked')).map(cb => cb.value).join(',');
}

function getSelectedStrategyNames() {
  return Array.from(document.querySelectorAll('.strategy-cb:checked')).map(cb => cb.getAttribute('data-name'));
}

function startFuzzFromStrategies() {
  const names = getSelectedStrategyNames();
  if (!names.length) return;
  // Save selected info to display on Pipeline page
  window._selectedNames = names;
  window._selectedRef = document.getElementById('refEnabled').checked ? document.getElementById('refTextInput').value.trim() : '';
  switchPage('pipeline');
  updateSelectedInfo();
}

function updateSelectedInfo() {
  const info = document.getElementById('selectedInfo');
  const names = window._selectedNames || [];
  const ref = window._selectedRef || '';
  if (!names.length) { info.style.display = 'none'; return; }
  info.style.display = 'block';
  document.getElementById('selectedInfoCount').textContent = names.length + ' selected';
  document.getElementById('selectedInfoList').innerHTML = names.map(n =>
    '<span class="tag">' + n + '</span>'
  ).join('');
  const refEl = document.getElementById('selectedInfoRef');
  const refText = document.getElementById('selectedInfoRefText');
  if (ref) {
    refEl.style.display = 'block';
    refText.textContent = ref.length > 120 ? ref.slice(0, 120) + '...' : ref;
  } else {
    refEl.style.display = 'none';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const box = document.getElementById('logBox');
  box.addEventListener('scroll', () => {
    const threshold = 30;
    logAtBottom = (box.scrollTop + box.clientHeight >= box.scrollHeight - threshold);
  });

  // Sidebar navigation clicks
  document.querySelectorAll('.nav-item').forEach(el => {
    el.addEventListener('click', () => {
      switchPage(el.dataset.page);
    });
  });
});

async function startPipeline(phase) {
  const target = document.getElementById('targetSelect').value;
  if (!target) { alert('Please select a target project first.'); return; }
  const btnId = {1:'btnPhase1', 2:'btnPhase2', 3:'btnPhase3', 4:'btnPhase4'}[phase] || 'btnPhase1';
  const btn = document.getElementById(btnId);
  const status = document.getElementById('pipelineStatus');
  btn.disabled = true;
  status.textContent = 'Starting...';
  status.style.color = '#9a6700';

  if (phase === 3 && !document.getElementById('easyfuzzToggle').checked) {
    const refEnabled = document.getElementById('refEnabled').checked;
    let ids = getSelectedStrategyIds();
    if (!ids) {
      // 没有手动选中的策略 — 检查是否有 afl-fuzz 在跑
      const statusData = await api('/api/status?target=' + encodeURIComponent(target));
      const hasRunning = statusData && statusData.running;
      if (hasRunning) {
        // 有进程在跑但没选策略 — 提示用户
        alert('请至少选择一个要追加的策略');
        btn.disabled = false;
        return;
      }
      // 没有进程在跑 — 自动选中全部策略
      document.querySelectorAll('.strategy-cb').forEach(cb => cb.checked = true);
      ids = getSelectedStrategyIds();
      if (!ids) {
        alert('没有可用策略，请先运行 Phase 2: Prep');
        btn.disabled = false;
        return;
      }
    }
    const sel = await api(`/api/manifest/select?target=${encodeURIComponent(target)}&strategy_ids=${ids}`, {method:'POST'});
    if (!sel || sel.error) {
      status.textContent = sel && sel.error ? sel.error : 'Failed to save strategy selection';
      status.style.color = '#cf222e';
      btn.disabled = false;
      return;
    }
  }

  let url = `/api/pipeline/start?target=${encodeURIComponent(target)}&phase=${phase}`;
  const r = await api(url, {method:'POST'});
  btn.disabled = false;
  status.style.color = '#656d76';
  if (r && r.status === 'started') {
    status.textContent = `Phase ${phase} running on ${target}`;
    status.style.color = '#1a7f37';
    // 立即刷新右上角 badge 为 Running
    document.getElementById('globalStatus').innerHTML = '<span class="badge badge-green"><span class="status-dot green pulsing"></span>Running</span>';
    setTimeout(updateDashboard, 200);

    // Phase 4 (普通模式): 标记以便完成时通知
    if (phase === 4 && !document.getElementById('easyfuzzToggle').checked) {
      _phase4Running = true;
    }
  } else {
    const msg = r && r.error ? r.error : 'Failed to start';
    status.textContent = msg;
    status.style.color = '#cf222e';
    if (msg === 'pipeline already running') {
      alert('Pipeline is already running. Please stop it first or wait for it to complete.');
    }
  }
}

async function killStrategy(pid) {
  if (!pid) return;
  if (!confirm('Stop this afl-fuzz process (PID: ' + pid + ')?')) return;
  var allRows = document.querySelectorAll('#strategiesBody tr.strategy-row');
  var strategyData = {};
  for (var i = 0; i < allRows.length; i++) {
    var cells = allRows[i].cells;
    if (cells.length >= 2) {
      var rowPid = cells[2].textContent.trim();
      if (rowPid === String(pid)) {
        var cmdRow = document.getElementById('cmd_' + i);
        strategyData = {
          name: cells[1].textContent.replace(/[\u26a0\u26a1].*$/, '').trim(),
          pid: pid,
          edges: cells[3].textContent.trim(),
          crashes: cells[4].textContent.trim(),
          paths: cells[5].textContent.trim(),
          speed: cells[6].textContent.trim(),
          cycles: cells[7].textContent.trim(),
          bitmap: cells[8].textContent.trim(),
          runtime: cells[9].textContent.trim(),
          full_cmd: cmdRow ? cmdRow.querySelector('pre').textContent : ''
        };
        break;
      }
    }
  }
  var target = document.getElementById('targetSelect').value;
  var r = await api('/api/strategy/kill?pid=' + pid + '&target=' + encodeURIComponent(target), {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({strategy: strategyData})
  });
  if (r && r.status === 'killed') {
    updateDashboard();
  }
}

async function stopAllStrategies() {
  if (!confirm('Stop all running AFL++ strategies?')) return;
  await api('/api/pipeline/stop', {method:'POST'});
  updateDashboard();
}

async function cleanWorkspace() {
  const target = document.getElementById('targetSelect').value;
  if (!target) { alert('Please select a target project first.'); return; }
  if (!confirm(`Clean all fuzz workspace for "${target}"?\n\nThis will:\n- Kill all afl-fuzz processes for this project\n- Delete container fuzz workspace\n- Delete host output directory\n\nThis cannot be undone!`)) return;
  const status = document.getElementById('pipelineStatus');
  status.textContent = 'Cleaning...';
  status.style.color = '#9a6700';
  const r = await api(`/api/workspace/clean?target=${encodeURIComponent(target)}`, {method:'POST'});
  if (r && r.status === 'cleaned') {
    status.textContent = `Workspace cleaned for ${target}`;
    status.style.color = '#1a7f37';
    // 清除本地状态
    window._selectedNames = [];
    window._selectedRef = '';
    document.querySelectorAll('.strategy-cb').forEach(cb => cb.checked = false);
    // 清除本地状态
    _notifKeys = new Set();
    _phase4Running = false;
    _efCards = {};
    document.getElementById('efCardContainer').innerHTML = '';
    try { localStorage.removeItem('af_dismissed'); } catch(e) {}
    // 强制刷新界面
    loadManifest();
    updateDashboard();
    if (document.getElementById('easyfuzzToggle').checked) loadEasyFuzzCommands();
  } else {
    status.textContent = r && r.error ? r.error : 'Failed to clean';
    status.style.color = '#cf222e';
  }
}

async function cleanPhase(phase) {
  const target = document.getElementById('targetSelect').value;
  if (!target) return;
  const phaseNames = {1:'Analyze',2:'Prep',3:'Fuzz',4:'Issues',5:'Summary'};
  if (!confirm(`Clear all files generated by Phase ${phase} (${phaseNames[phase]}) for "${target}"?`)) return;
  const status = document.getElementById('pipelineStatus');
  status.textContent = `Clearing Phase ${phase} output...`;
  status.style.color = '#9a6700';
  const r = await api(`/api/phase/clean?target=${encodeURIComponent(target)}&phase=${phase}`, {method:'POST'});
  if (r && r.status === 'cleaned') {
    status.textContent = `Phase ${phase} output cleared`;
    status.style.color = '#1a7f37';
    updateDashboard();
  } else {
    status.textContent = r && r.error ? r.error : 'Failed to clear';
    status.style.color = '#cf222e';
  }
}

async function stopAll() {
  const status = document.getElementById('pipelineStatus');
  status.textContent = 'Stopping...';
  const r = await api('/api/pipeline/stop', {method:'POST'});
  if (r) {
    status.textContent = r.total_crashes ? `Stopped (${r.total_crashes} crashes collected)` : 'Stopped';
  }
}

function toggleRefPanel() {
  const panel = document.getElementById('refPanel');
  const arrow = document.getElementById('refArrow');
  if (!panel || !arrow) return;
  const show = panel.style.display !== 'block';
  panel.style.display = show ? 'block' : 'none';
  arrow.className = 'arrow' + (show ? ' open' : '');
}

function onRefFileSelect(event) {
  var file = event.target.files[0];
  if (!file) return;
  document.getElementById('refFileName').textContent = file.name;
  var reader = new FileReader();
  reader.onload = function(e) {
    var ta = document.getElementById('refTextInput');
    var prefix = ta.value ? ta.value + '\\n\\n' : '';
    ta.value = prefix + '> From ' + file.name + ':\\n' + e.target.result;
  };
  reader.readAsText(file);
}

async function clearRefContext() {
  document.getElementById('refTextInput').value = '';
  document.getElementById('refFileName').textContent = '';
  var target = document.getElementById('targetSelect').value;
  if (target) {
    await api('/api/ref-context?target=' + encodeURIComponent(target), {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({text: ''})
    });
  }
  var saved = document.getElementById('refSaved');
  saved.style.display = 'inline';
  saved.textContent = 'Cleared';
  setTimeout(function() { saved.style.display = 'none'; saved.textContent = '\u2713 Saved'; }, 2000);
}

async function saveRefContext() {
  const target = document.getElementById('targetSelect').value;
  if (!target) return;
  const text = document.getElementById('refTextInput').value.trim();
  const enabled = document.getElementById('refEnabled').checked;
  const saved = document.getElementById('refSaved');
  const r = await api(`/api/ref-context?target=${encodeURIComponent(target)}`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({text: text, enabled: enabled})
  });
  if (r && r.status === 'saved') {
    saved.style.display = 'inline';
    setTimeout(() => saved.style.display = 'none', 2000);
  }
}

async function loadRefContext() {
  const target = document.getElementById('targetSelect').value;
  if (!target) return;
  const r = await api(`/api/ref-context?target=${encodeURIComponent(target)}`);
  if (r) {
    document.getElementById('refTextInput').value = r.text || '';
    document.getElementById('refEnabled').checked = r.enabled !== false;
  }
}

// ──────────────────────────────────────────────
// EasyFuzz Functions
// ──────────────────────────────────────────────

async function onEasyFuzzToggle() {
  const enabled = document.getElementById('easyfuzzToggle').checked;
  await api('/api/easyfuzz/toggle?enabled=' + enabled, {method:'POST'});
  updateEasyFuzzUI(enabled);
}

function updateEasyFuzzUI(enabled) {
  const panel = document.getElementById('easyfuzzCommandPanel');
  if (panel) panel.style.display = enabled ? 'block' : 'none';

  // Show/hide Strategies nav item
  const stratNav = document.querySelector('.nav-item[data-page="strategies"]');
  if (stratNav) stratNav.style.display = enabled ? 'none' : '';

  // Update phase button labels
  const btn1 = document.getElementById('btnPhase1');
  const btn2 = document.getElementById('btnPhase2');
  const btn3 = document.getElementById('btnPhase3');
  const btn4 = document.getElementById('btnPhase4');
  const btn5 = document.getElementById('btnPhase5');
  const cls3 = document.getElementById('clsPhase3');
  const cls4 = document.getElementById('clsPhase4');
  const fullGroup = document.getElementById('fullEasyFuzzGroup');
  const gear = document.getElementById('btnFullEasyFuzzSettings');
  const efSummaryGroup = document.getElementById('easyFuzzSummaryGroup');
  if (enabled) {
    btn1.textContent = 'Phase 1: Easy-Fuzz';
    btn2.textContent = 'Phase 2: Issues';
    btn3.style.display = 'none';
    if (cls3) cls3.style.display = 'none';
    btn4.style.display = 'none';
    btn5.style.display = 'none';
    if (cls4) cls4.style.display = 'none';
    if (fullGroup) fullGroup.style.display = '';
    if (efSummaryGroup) efSummaryGroup.style.display = '';
    if (gear) gear.style.display = 'block';
    document.getElementById('selectAllLabel') && (document.getElementById('selectAllLabel').style.display = 'none');
    document.getElementById('strategiesStartSection') && (document.getElementById('strategiesStartSection').style.display = 'none');
  } else {
    btn1.textContent = 'Phase 1: Analyze';
    btn2.textContent = 'Phase 2: Prep';
    btn3.textContent = 'Phase 3: Fuzz';
    btn3.style.display = '';
    btn3.onclick = function() { startPipeline(3); };
    if (btn3.nextElementSibling) btn3.nextElementSibling.textContent = '启动 fuzz 策略';
    btn4.style.display = '';
    btn5.style.display = '';
    if (cls3) cls3.style.display = '';
    if (cls4) cls4.style.display = '';
    if (fullGroup) fullGroup.style.display = 'none';
    if (efSummaryGroup) efSummaryGroup.style.display = 'none';
    if (gear) gear.style.display = 'none';
    document.getElementById('selectAllLabel') && (document.getElementById('selectAllLabel').style.display = '');
    document.getElementById('strategiesStartSection') && (document.getElementById('strategiesStartSection').style.display = '');
  }

  if (enabled && document.getElementById('targetSelect').value) {
    loadEasyFuzzCommands();
  }
}

async function loadEasyFuzzCommands() {
  const target = document.getElementById('targetSelect').value;
  if (!target) return;
  const d = await api(`/api/easyfuzz/commands?target=${encodeURIComponent(target)}`);
  const list = document.getElementById('easyfuzzCmdList');
  const select = document.getElementById('easyfuzzCmdSelect');
  const editor = document.getElementById('easyfuzzCmdEditor');

  if (!d || !d.commands || !d.commands.length) {
    list.innerHTML = '<div style="text-align:center;padding:20px;color:#656d76;font-size:13px;">No commands saved yet. Run EasyFuzz Phase 1 first.</div>';
    editor.style.display = 'none';
    return;
  }

  list.innerHTML = d.commands.map(function(c, idx) {
    return '<div style="background:#fefcf8;border:1px solid #d0d7de;border-radius:6px;padding:10px 14px;">' +
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">' +
        '<strong style="font-size:13px;">#' + (idx+1) + ' ' + (c.name || 'strategy_' + c.id) + '</strong>' +
        (c.description ? '<span style="font-size:11px;color:#656d76;">— ' + c.description + '</span>' : '') +
      '</div>' +
      '<div style="font-family:\'Cascadia Code\',\'JetBrains Mono\',Consolas,monospace;font-size:11px;color:#24292f;background:#faf5ed;padding:6px 10px;border-radius:4px;white-space:pre-wrap;word-break:break-all;line-height:1.4;">' + (c.command || c.cmd || 'N/A') + '</div>' +
    '</div>';
  }).join('');

  // Populate the edit dropdown
  select.innerHTML = '<option value="">-- Select a command to edit --</option>' +
    d.commands.map(function(c, idx) {
      return '<option value="' + idx + '">#' + (idx+1) + ' ' + (c.name || 'strategy_' + c.id) + '</option>';
    }).join('');
  editor.style.display = 'block';
  document.getElementById('easyfuzzCmdTextarea').value = '';
}

function onEasyFuzzCmdSelect() {
  const select = document.getElementById('easyfuzzCmdSelect');
  const textarea = document.getElementById('easyfuzzCmdTextarea');
  const idx = parseInt(select.value);
  if (isNaN(idx)) { textarea.value = ''; return; }
  // We need to fetch the commands again to get the full data
  const target = document.getElementById('targetSelect').value;
  api(`/api/easyfuzz/commands?target=${encodeURIComponent(target)}`).then(d => {
    if (d && d.commands && d.commands[idx]) {
      textarea.value = d.commands[idx].command || d.commands[idx].cmd || '';
    }
  });
}

async function saveEasyFuzzCommand() {
  const target = document.getElementById('targetSelect').value;
  const select = document.getElementById('easyfuzzCmdSelect');
  const textarea = document.getElementById('easyfuzzCmdTextarea');
  const saved = document.getElementById('easyfuzzCmdSaved');
  const idx = parseInt(select.value);
  if (isNaN(idx) || !target || !textarea.value.trim()) return;

  const d = await api(`/api/easyfuzz/commands?target=${encodeURIComponent(target)}`);
  if (d && d.commands && d.commands[idx]) {
    d.commands[idx].command = textarea.value.trim();
    if (!d.commands[idx].cmd) d.commands[idx].cmd = d.commands[idx].command;
    await api('/api/easyfuzz/commands?target=' + encodeURIComponent(target), {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(d)
    });
    saved.style.display = 'inline';
    setTimeout(function() { saved.style.display = 'none'; }, 2000);
    loadEasyFuzzCommands();
  }
}

async function addNewEasyFuzzCommand() {
  const target = document.getElementById('targetSelect').value;
  if (!target) return;
  const newCmd = prompt('Enter the new afl-fuzz command:');
  if (!newCmd || !newCmd.trim()) return;
  const name = prompt('Enter a name for this strategy (optional):') || 'custom_' + Date.now();

  const d = await api(`/api/easyfuzz/commands?target=${encodeURIComponent(target)}`);
  const commands = (d && d.commands) ? d.commands : [];
  commands.push({
    id: commands.length + 1,
    name: name,
    description: 'User-added custom strategy',
    command: newCmd.trim(),
    output_dir: 'out_' + name,
    timestamp: new Date().toISOString()
  });
  d.commands = commands;
  await api('/api/easyfuzz/commands?target=' + encodeURIComponent(target), {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(d)
  });
  loadEasyFuzzCommands();
}

async function reRunEasyFuzzCommand() {
  const target = document.getElementById('targetSelect').value;
  const select = document.getElementById('easyfuzzCmdSelect');
  const textarea = document.getElementById('easyfuzzCmdTextarea');
  const idx = parseInt(select.value);
  if (isNaN(idx) || !target || !textarea.value.trim()) {
    alert('Please select and edit a command first.');
    return;
  }
  if (!confirm('Re-run EasyFuzz Phase 1 with the modified command?')) return;

  // Save the modified command first
  await saveEasyFuzzCommand();

  // Start Phase 1 with EasyFuzz mode
  await startPipeline(1);
}

// ──────────────────────────────────────────────
// Issue Submission Functions
// ──────────────────────────────────────────────

async function loadIssueFiles() {
  const target = document.getElementById('targetSelect').value;
  const select = document.getElementById('issueFileSelect');
  if (!target) {
    select.innerHTML = '<option value="">-- Select target first --</option>';
    return;
  }
  const d = await api('/api/issues/list?target=' + encodeURIComponent(target));
  select.innerHTML = '<option value="">-- Select issue file --</option>';
  if (d && d.files && d.files.length) {
    d.files.forEach(function(f) {
      const opt = document.createElement('option');
      opt.value = f; opt.textContent = f;
      select.appendChild(opt);
    });
  } else {
    select.innerHTML = '<option value="">-- No issue files found --</option>';
  }
  document.getElementById('issueEditor').value = '';
}

async function onIssueFileSelect() {
  const target = document.getElementById('targetSelect').value;
  const file = document.getElementById('issueFileSelect').value;
  const editor = document.getElementById('issueEditor');
  if (!target || !file) {
    editor.value = '';
    editor.readOnly = true;
    return;
  }
  const d = await api('/api/issues/content?target=' + encodeURIComponent(target) + '&file=' + encodeURIComponent(file));
  if (d && d.content) {
    editor.value = d.content;
    editor.readOnly = false;
  } else {
    editor.value = '// Failed to load content';
    editor.readOnly = true;
  }
}

async function checkDuplicate() {
  const target = document.getElementById('targetSelect').value;
  const editor = document.getElementById('issueEditor');
  const btn = document.getElementById('btnCheckDup');

  if (!target) { alert('Please select a target first.'); return; }
  if (!editor.value.trim()) { alert('Issue editor is empty.'); return; }

  btn.disabled = true;
  btn.textContent = 'Checking...';

  const d = await api('/api/issues/check-duplicate', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({target: target, issue_content: editor.value})
  });

  btn.disabled = false;
  btn.textContent = '\uD83D\uDD0D Check Duplicate';

  function fmtMeta(d) {
    var parts = [];
    if (d.commit_since) parts.push('Commit: ' + d.commit_since.replace('T', ' ').replace(/\.\d+[+-].+$/, ''));
    if (d.issues_checked) parts.push('Checked: ' + d.issues_checked + ' issues');
    return parts.length ? '<span style="font-size:11px;opacity:0.7;display:block;margin:4px 0 2px 0;">' + parts.join(' &middot; ') + '</span>' : '';
  }

  if (d && d.duplicate) {
    const baseUrl = getRepoUrl();
    const link = baseUrl
      ? '<a href="' + baseUrl + '/issues/' + d.issue_number + '" target="_blank" style="color:#fbbf24;font-weight:700;text-decoration:underline;">#' + d.issue_number + '</a>'
      : '#' + d.issue_number;
    addNotification('fuzz-done', 'Potential Duplicate Found',
      link + (d.issue_title ? ' &mdash; ' + escHtml(d.issue_title) : '') +
      fmtMeta(d) +
      (d.reason ? '<span style="font-size:12px;display:block;margin-top:4px;">' + escHtml(d.reason) + '</span>' : '') +
      '<br><span style="font-size:11px;opacity:0.7;">' + target + '</span>',
      'checkdup-' + target + '-' + Date.now());
  } else if (d && !d.duplicate && !d.error) {
    addNotification('phase4-done', 'No Duplicate Found',
      'This issue appears to be unique for <strong>' + target + '</strong>.' +
      fmtMeta(d) +
      (d.reason ? '<br><span style="font-size:12px;display:block;margin-top:4px;">' + escHtml(d.reason) + '</span>' : ''),
      'checkdup-' + target + '-' + Date.now());
  } else {
    addNotification('stale', 'Duplicate Check Failed',
      (d ? d.error : 'Request failed') + ' &mdash; <strong>' + target + '</strong>',
      'checkdup-' + target + '-' + Date.now());
  }
}

async function copyIssueText() {
  const editor = document.getElementById('issueEditor');
  const status = document.getElementById('issueCopyStatus');
  if (!editor.value) return;
  try {
    await navigator.clipboard.writeText(editor.value);
    status.style.display = 'inline';
    setTimeout(function() { status.style.display = 'none'; }, 2000);
  } catch (e) {
    editor.select();
    document.execCommand('copy');
    status.style.display = 'inline';
    setTimeout(function() { status.style.display = 'none'; }, 2000);
  }
}

async function loadRepoUrl() {
  const target = document.getElementById('targetSelect').value;
  if (!target) return;
  const d = await api('/api/issues/repo-url?target=' + encodeURIComponent(target));
  if (d && d.repo_url) {
    _cachedRepoUrl = d.repo_url;
    return;
  }
  const detected = await api('/api/issues/detect-repo-url?target=' + encodeURIComponent(target));
  if (detected && detected.repo_url) {
    _cachedRepoUrl = detected.repo_url;
    await api('/api/issues/repo-url?target=' + encodeURIComponent(target), {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({repo_url: detected.repo_url})
    });
  }
}

let _cachedRepoUrl = '';

function getRepoUrl() {
  return _cachedRepoUrl.replace(/\/+$/, '');
}

async function loadGitHubIssues() {
  const target = document.getElementById('targetSelect').value;
  const container = document.getElementById('issuesListContainer');
  const placeholder = document.getElementById('issuesListPlaceholder');
  const repoLabel = document.getElementById('issuesRepoLabel');
  // Always clear repo label when loading — avoids stale project name
  if (repoLabel) repoLabel.textContent = '';
  if (!container) return;
  if (!target) {
    _cachedRepoUrl = '';
    container.innerHTML = '';
    if (placeholder) container.appendChild(placeholder);
    return;
  }

  // 清除旧数据，避免切换到新项目时还显示旧的 issue
  _cachedRepoUrl = '';
  container.innerHTML = '<div class="issue-loading"><span class="status-dot green pulsing"></span> Loading issues...</div>';

  await loadRepoUrl();
  const baseUrl = getRepoUrl();
  if (baseUrl) {
    if (placeholder) placeholder.style.display = 'none';
    container.innerHTML = '<div class="issue-loading"><span class="status-dot green pulsing"></span> Loading issues...</div>';

    const d = await api('/api/issues/github-list?target=' + encodeURIComponent(target));
    container.innerHTML = '';

    if (d && d.issues && d.issues.length) {
      if (repoLabel) repoLabel.textContent = d.repo || baseUrl.replace(/https?:\/\/github\.com\//, '');
      d.issues.forEach(function(issue) {
        var el = document.createElement('div');
        el.className = 'issue-item';
        el.onclick = function() { window.open(issue.url, '_blank'); };
        var created = issue.created_at ? new Date(issue.created_at).toLocaleDateString() : '';
        el.innerHTML =
          '<span class="issue-state ' + (issue.state === 'open' ? 'open' : 'closed') + '"></span>' +
          '<div style="flex:1;min-width:0;">' +
            '<div class="issue-title">' + escHtml(issue.title) + '</div>' +
            '<div class="issue-meta">#' + issue.number + ' ' + issue.state + ' \u00b7 ' + created + '</div>' +
          '</div>' +
          '<span class="issue-comments">' +
            (issue.comments > 0
              ? '<svg width="14" height="14" viewBox="0 0 16 16" fill="#656d76" style="vertical-align:middle;margin-right:2px;"><path d="M1 2.75C1 1.784 1.784 1 2.75 1h10.5c.966 0 1.75.784 1.75 1.75v7.5A1.75 1.75 0 0113.25 12H9.06l-2.573 2.573A1.458 1.458 0 014 13.543V12H2.75A1.75 1.75 0 011 10.25z"/></svg>'
              : '') +
            (issue.comments > 0 ? issue.comments : '') +
          '</span>';
        container.appendChild(el);
      });
    } else if (d && d.error) {
      container.innerHTML = '<div class="issue-error">API error: ' + escHtml(d.error) + '</div>';
    } else {
      container.innerHTML = '<div class="issue-error">No issues found or API rate limited.</div>';
    }
  } else {
    placeholder.style.display = 'flex';
    container.innerHTML = '';
    container.appendChild(placeholder);
  }
}

function escHtml(s) {
  if (!s) return '';
  var d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

async function saveRepoUrl() {
  const target = document.getElementById('targetSelect').value;
  const url = _cachedRepoUrl;
  if (!target) return;
  await api('/api/issues/repo-url?target=' + encodeURIComponent(target), {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({repo_url: url})
  });
}



function openGitHubIssue() {
  copyIssueText();
  doOpenGitHub('issues/new');
}

function openGitHubIssues() {
  doOpenGitHub('issues');
}

function openGitHubNewIssue() {
  doOpenGitHub('issues/new');
}

function doOpenGitHub(path) {
  const base = getRepoUrl();
  if (!base) {
    alert('Please configure the GitHub Repo URL first.');
    return;
  }
  window.open(base + '/' + path, '_blank');
}

// ──────────────────────────────────────────────
// Full EasyFuzz Pipeline Functions

async function startFullEasyFuzz() {
  const target = document.getElementById('targetSelect').value;
  if (!target) { alert('Please select a target project first.'); return; }
  const status = document.getElementById('pipelineStatus');

  // Check if already configured
  const cfg = await api('/api/easyfuzz/full-config?target=' + encodeURIComponent(target));
  if (!cfg || !cfg.configured) {
    // First time: show dialog
    showFullFuzzDialog();
    return;
  }

  // Already configured: start the full pipeline
  if (_fullFuzzStarted) {
    status.textContent = 'Full pipeline already started.';
    status.style.color = '#9a6700';
    return;
  }

  status.textContent = 'Starting full pipeline (' + cfg.duration_min + 'min fuzz)...';
  status.style.color = '#9a6700';

  const r = await api('/api/pipeline/start?target=' + encodeURIComponent(target) +
    '&phase=1&full_easyfuzz=1', {method:'POST'});
  if (r && r.status === 'started') {
    _fullFuzzStarted = true;
    status.textContent = 'Full pipeline running — fuzzing for ' + cfg.duration_min + 'min...';
    status.style.color = '#1a7f37';
    // 立即刷新右上角 badge 为 Running
    document.getElementById('globalStatus').innerHTML = '<span class="badge badge-green"><span class="status-dot green pulsing"></span>Running</span>';
  } else {
    status.textContent = r && r.error ? r.error : 'Failed to start';
    status.style.color = '#cf222e';
  }
}

function showFullFuzzDialog() {
  document.getElementById('fullFuzzDialog').style.display = 'flex';
  document.getElementById('fullFuzzSaveStatus').style.display = 'none';
  document.getElementById('fuzzDurationInput').value = 720;
}

function closeFullFuzzDialog() {
  document.getElementById('fullFuzzDialog').style.display = 'none';
}

async function saveFullFuzzConfig() {
  const target = document.getElementById('targetSelect').value;
  const duration = parseInt(document.getElementById('fuzzDurationInput').value) || 30;
  const r = await api('/api/easyfuzz/full-config?target=' + encodeURIComponent(target), {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({duration_min: duration})
  });
  if (r && r.status === 'saved') {
    const status = document.getElementById('fullFuzzSaveStatus');
    status.style.display = 'inline';
    status.textContent = '\u2713 \u5df2\u8bbe\u7f6e\u5b8c\u6bd5\uff08' + duration + '\u5206\u949f\uff09';
    setTimeout(() => {
      closeFullFuzzDialog();
    }, 1500);
  }
}

// 检测 easy-fuzz / full-pipeline fuzz 完成 → 通知（全局扫描，不依赖当前选中的项目）
async function checkFuzzCompletion() {
  const r = await api('/api/easyfuzz/full-result');
  if (!r || !r.has_result || !r.results) return;
  for (var i = 0; i < r.results.length; i++) {
    var item = r.results[i];
    var proj = item.project || '?';
    var dur = item.duration_min || 0;
    var timeStr = dur >= 60 ? Math.floor(dur/60)+'h '+dur%60+'m' : Math.round(dur)+'m';
    addNotification('fuzz-done', proj + ' Fuzzing Complete',
      proj + ' fuzz 了 ' + timeStr + '，发现了 <strong>' + (item.crashes||0) + '</strong> 个 crash',
      proj);  // keySuffix = project name, 保证每个项目最多一条
  }
}

// 普通模式 Phase 4 完成通知
async function checkPhase4Completion() {
  if (!_phase4Running) return;
  const target = document.getElementById('targetSelect').value;
  if (!target) return;
  const s = await api('/api/status?target=' + encodeURIComponent(target));
  if (!s || s.pipeline_running) return;
  _phase4Running = false;
  addNotification('phase4-done', 'Phase 4 Complete',
    target + ' Phase 4 运行完成', target);
}

// Patch updateDashboard to check both fuzz completion and phase 4 completion
const _origUpdateDashboard = updateDashboard;
updateDashboard = function() {
  _origUpdateDashboard();
  checkFuzzCompletion();
  checkPhase4Completion();
};

// Patch updateDashboard to handle EasyFuzz mode
const _origUpdateSelectedInfo = updateSelectedInfo;
updateSelectedInfo = function() {
  _origUpdateSelectedInfo();
  // If EasyFuzz enabled, load commands
  if (document.getElementById('easyfuzzToggle').checked) {
    loadEasyFuzzCommands();
  }
};

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('targetSelect').addEventListener('change', () => {
    document.querySelectorAll('.strategy-cb').forEach(cb => cb.checked = false);
    const selAll = document.getElementById('selectAll');
    if (selAll) selAll.checked = false;
    window._selectedNames = [];
    window._selectedRef = '';
    loadManifest();
    updateDashboard();
    loadRefContext();
    // Load issue data when target changes
    loadIssueFiles();
    loadGitHubIssues();
    // If EasyFuzz enabled, reload commands for the new project
    if (document.getElementById('easyfuzzToggle').checked) {
      loadEasyFuzzCommands();
    }
    // If on report page, reload summary
    const reportPage = document.querySelector('.page[data-page="report"]');
    if (reportPage && reportPage.classList.contains('active')) {
      loadSummary();
    }
  });
});

api('/api/projects').then(d => {
  if (d && d.projects) {
    const sel = document.getElementById('targetSelect');
    d.projects.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p; opt.textContent = p;
      sel.appendChild(opt);
    });
  }
});

setInterval(updateDashboard, 5000);
updateDashboard();
checkEngine();

const CODE_TOKENS = ['</>','{ }','0x00','afl','fuzz','/*..*/','for(;;)','while','if()','ptr->','++','!=','&&','||','SIGSEGV','ASAN','#include','[ ]','malloc','free','0xFF','{;}','==','!','main()','--','=>','::'];
document.addEventListener('click', e => {
  if (e.target.closest('button,select,input,a,option')) return;
  const count = 6 + Math.floor(Math.random() * 6);
  for (let i = 0; i < count; i++) {
    const el = document.createElement('span');
    el.className = 'code-burst';
    el.textContent = CODE_TOKENS[Math.floor(Math.random() * CODE_TOKENS.length)];
    const angle = Math.random() * Math.PI * 2;
    const dist = 60 + Math.random() * 100;
    const size = 12 + Math.random() * 14;
    const hue = 200 + Math.random() * 60;
    el.style.left = (e.clientX + (Math.random() - 0.5) * 20) + 'px';
    el.style.top = (e.clientY + (Math.random() - 0.5) * 20) + 'px';
    el.style.fontSize = size + 'px';
    el.style.color = 'hsla(' + hue + ',70%,50%,0.9)';
    el.style.setProperty('--dx', Math.cos(angle) * dist + 'px');
    el.style.setProperty('--dy', Math.sin(angle) * dist + 'px');
    el.style.setProperty('--r', (Math.random() - 0.5) * 720 + 'deg');
    el.style.animationDuration = (0.6 + Math.random() * 0.8) + 's';
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 1500);
  }
});

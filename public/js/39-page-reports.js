// ===== RECRUITING REPORTS / ANALYTICS PAGE (additive) =====
// A "Reports" page: headline totals, the pipeline funnel, an 8-week submission
// trend, per-recruiter productivity, time-to-fill and top clients. Built from the
// single org-scoped GET /reports/recruiting endpoint. Managers see the whole desk;
// recruiters see only their own numbers.

(function () {
  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function canUse(u){ return u && window.userHasAnyRole && userHasAnyRole(u,'admin','bd','bd_lead','ra_lead','recruiter'); }
  function money(n){ n = Number(n)||0; return '$'+n.toLocaleString('en-US'); }

  if (!STATE.reports) STATE.reports = { loading:false, data:null };

  function loadReport(){
    STATE.reports.loading = true; paint();
    apiGet('/reports/recruiting').then(function(d){ STATE.reports.data = d||null; STATE.reports.loading = false; paint(); })
      .catch(function(e){ STATE.reports.loading = false; showToast('Failed to load reports: '+e.message,'error'); paint(); });
  }
  window.reportsReload = loadReport;

  // ── nav + routing (wrap, like the job-board module) ──────────────────────────
  var _prevRender = window.render;
  window.render = function(){
    _prevRender.apply(this, arguments);
    injectNav();
    if (STATE.page === 'reports') paint();
  };
  function injectNav(){
    var u = STATE.user; if(!u || !canUse(u)) return;
    var navWrap = document.querySelector('.sb-nav'); if(!navWrap) return;
    var existing = navWrap.querySelector('[data-rptnav]');
    if (existing){ existing.classList.toggle('active', STATE.page==='reports'); return; }
    var d = document.createElement('div');
    d.className = 'nav-item' + (STATE.page==='reports' ? ' active' : '');
    d.setAttribute('data-rptnav','1');
    d.innerHTML = '<span class="nav-icon">'+icon('reports')+'</span>Reports';
    d.onclick = function(){ goPage('reports'); };
    navWrap.appendChild(d);
    if (STATE.page==='reports'){ var t=document.querySelector('.tb-title'); if(t) t.textContent='Reports'; }
  }
  var _prevGoPage = window.goPage;
  window.goPage = function(p){
    if (p === 'reports'){ STATE.page='reports'; STATE.modal=null; render(); loadReport(); return; }
    return _prevGoPage.apply(this, arguments);
  };
  function paint(){ if(STATE.page!=='reports') return; var c=document.getElementById('content'); if(!c) return; c.innerHTML = renderReports(); var t=document.querySelector('.tb-title'); if(t) t.textContent='Reports'; }

  function tile(label, value, sub){
    return '<div class="card" style="padding:14px 16px;flex:1;min-width:130px">'+
      '<div style="font-size:24px;font-weight:800;color:var(--text)">'+esc(value)+'</div>'+
      '<div style="font-size:12px;color:var(--text3);margin-top:2px">'+esc(label)+'</div>'+
      (sub?'<div style="font-size:11px;color:var(--text3);margin-top:2px">'+esc(sub)+'</div>':'')+
    '</div>';
  }

  function funnelCard(funnel, stages){
    var colors = window.ATS_STAGE_COLORS || {};
    var max = Math.max(1, Math.max.apply(null, stages.map(function(s){ return funnel[s]||0; })));
    var rows = stages.map(function(s){
      var n = funnel[s]||0; var w = Math.round((n/max)*100);
      return '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">'+
        '<div style="width:130px;font-size:12px;color:var(--text2);text-align:right;flex-shrink:0">'+esc(s)+'</div>'+
        '<div style="flex:1;background:var(--bg);border-radius:6px;height:20px;position:relative;overflow:hidden">'+
          '<div style="width:'+w+'%;height:100%;background:'+(colors[s]||'var(--accent)')+';border-radius:6px;min-width:'+(n?'2px':'0')+'"></div>'+
        '</div>'+
        '<div style="width:34px;font-size:12.5px;font-weight:700;color:'+(n?'var(--text)':'var(--text3)')+'">'+n+'</div>'+
      '</div>';
    }).join('');
    return '<div class="card" style="padding:16px"><div style="font-weight:600;font-size:14px;margin-bottom:12px">Pipeline funnel</div>'+rows+'</div>';
  }

  function trendCard(trend){
    var max = Math.max(1, Math.max.apply(null, trend.map(function(t){ return t.count; })));
    var bars = trend.map(function(t){
      var h = t.count ? Math.max(6, Math.round((t.count/max)*90)) : 2;
      return '<div style="flex:1;display:flex;flex-direction:column;justify-content:flex-end;align-items:center;height:110px">'+
        '<div style="font-size:11px;font-weight:700;color:'+(t.count?'var(--text)':'var(--text3)')+'">'+t.count+'</div>'+
        '<div style="width:60%;height:'+h+'px;background:var(--accent);border-radius:4px 4px 0 0;margin-top:3px"></div>'+
        '<div style="font-size:9.5px;color:var(--text3);margin-top:4px;white-space:nowrap">'+esc(t.week)+'</div>'+
      '</div>';
    }).join('');
    return '<div class="card" style="padding:16px"><div style="font-weight:600;font-size:14px;margin-bottom:10px">Submissions — last 8 weeks</div>'+
      '<div style="display:flex;align-items:flex-end;gap:6px">'+bars+'</div></div>';
  }

  function recruiterCard(rows){
    if (!rows.length) return '';
    var head = ['Recruiter','Total','Submitted','Interviews','Placements','Fill %','Revenue']
      .map(function(h){ return '<th style="text-align:left;padding:8px 10px;font-size:11px;color:var(--text3);font-weight:700;white-space:nowrap">'+h+'</th>'; }).join('');
    var body = rows.map(function(r){
      return '<tr style="border-top:1px solid var(--border)">'+
        '<td style="padding:8px 10px;font-size:12.5px;font-weight:600">'+esc(r.recruiter)+'</td>'+
        '<td style="padding:8px 10px;font-size:12.5px">'+r.total+'</td>'+
        '<td style="padding:8px 10px;font-size:12.5px">'+r.submitted+'</td>'+
        '<td style="padding:8px 10px;font-size:12.5px">'+r.interviews+'</td>'+
        '<td style="padding:8px 10px;font-size:12.5px;font-weight:700;color:var(--green)">'+r.placements+'</td>'+
        '<td style="padding:8px 10px;font-size:12.5px">'+r.fill_rate+'%</td>'+
        '<td style="padding:8px 10px;font-size:12.5px">'+money(r.revenue)+'</td>'+
      '</tr>';
    }).join('');
    return '<div class="card" style="padding:0;overflow-x:auto"><div style="padding:14px 16px;font-weight:600;font-size:14px;border-bottom:1px solid var(--border)">Recruiter productivity</div>'+
      '<table style="width:100%;border-collapse:collapse;min-width:620px"><thead><tr style="background:var(--bg)">'+head+'</tr></thead><tbody>'+body+'</tbody></table></div>';
  }

  function clientsCard(rows){
    if (!rows.length) return '';
    var max = Math.max(1, Math.max.apply(null, rows.map(function(r){ return r.count; })));
    var body = rows.map(function(r){
      var w = Math.round((r.count/max)*100);
      return '<div style="display:flex;align-items:center;gap:10px;margin-bottom:7px">'+
        '<div style="width:130px;font-size:12.5px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex-shrink:0">'+esc(r.client)+'</div>'+
        '<div style="flex:1;background:var(--bg);border-radius:6px;height:16px"><div style="width:'+w+'%;height:100%;background:var(--accent);border-radius:6px"></div></div>'+
        '<div style="width:26px;font-size:12px;font-weight:700">'+r.count+'</div>'+
      '</div>';
    }).join('');
    return '<div class="card" style="padding:16px"><div style="font-weight:600;font-size:14px;margin-bottom:12px">Top clients by submissions</div>'+body+'</div>';
  }

  window.renderReports = function(){
    var r = STATE.reports;
    if (r.loading || !r.data) return '<div class="page"><div style="font-size:18px;font-weight:700;margin-bottom:6px">Reports</div>'+
      '<div style="text-align:center;padding:50px;color:var(--text3)">'+(r.loading?'Loading reports…':'No data yet.')+'</div></div>';
    var d = r.data, t = d.totals || {};
    var ttf = d.avg_time_to_fill != null ? d.avg_time_to_fill + ' days' : '—';
    var header = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'+
      '<div><div style="font-size:18px;font-weight:700">Reports</div>'+
      '<div style="font-size:12.5px;color:var(--text3)">'+(d.role==='recruiter'?'Your recruiting numbers':'Whole-desk recruiting analytics')+'</div></div>'+
      '<button class="btn btn-sm btn-outline" onclick="reportsReload()">↻ Refresh</button></div>';
    var tiles = '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">'+
      tile('Candidates added', t.candidates_added||0)+
      tile('Submissions', t.submissions||0)+
      tile('Interviews', t.interviews||0)+
      tile('Placements', t.placements||0)+
      tile('Open jobs', t.open_jobs||0)+
      tile('Avg time-to-fill', ttf)+
      tile('Revenue', money(t.revenue))+
    '</div>';
    return '<div class="page">'+header+tiles+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">'+funnelCard(d.funnel,d.stages)+trendCard(d.trend)+'</div>'+
      '<div style="margin-bottom:14px">'+recruiterCard(d.by_recruiter||[])+'</div>'+
      clientsCard(d.top_clients||[])+
    '</div>';
  };
})();

// ===== MY TEAM PAGE (additive) =====
// For any user with at least one direct report on the flexible reporting
// hierarchy (users.manager_id) — the gate is DATA-DRIVEN (having reports), not
// role-based, matching the "flexible, not a fixed ladder" design. A BD Lead
// with reports sees it; a BD Lead with none doesn't; an RA given a report by an
// admin does. Shows the full reporting subtree rooted at the viewer plus their
// team's real, hierarchy-scoped recruiting snapshot (GET /recruiting-dashboard,
// which the backend already scopes to the caller's reporting chain).
//
// Reparenting stays admin-only (Admin → user → Reporting Hierarchy). This page
// is a read view of a manager's own team; it deliberately has no write action.

(function () {
  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  // Data-driven gate: does anyone report to this user?
  function leadsATeam(u){ return !!(u && window.directReportsOf && directReportsOf(u.id).length); }

  // ── nav + routing (wrap, like the reports/clients modules) ───────────────────
  var _prevRender = window.render;
  window.render = function(){
    _prevRender.apply(this, arguments);
    injectNav();
    if (STATE.page==='myteam'){ paint(); var t=document.querySelector('.tb-title'); if(t) t.textContent='My Team'; }
  };
  function injectNav(){
    var u=STATE.user; if(!u) return;
    var navWrap=document.querySelector('.sb-nav'); if(!navWrap) return;
    var existing=navWrap.querySelector('[data-myteamnav]');
    // Gate is data-driven and can change at runtime (an admin assigns a report),
    // so add/remove the nav item to match the live state rather than once.
    if (!leadsATeam(u)){ if(existing&&existing.parentNode) existing.parentNode.removeChild(existing); return; }
    if (existing){ existing.classList.toggle('active', STATE.page==='myteam'); return; }
    var d=document.createElement('div');
    d.className='nav-item'+(STATE.page==='myteam'?' active':'');
    d.setAttribute('data-myteamnav','1');
    d.innerHTML='<span class="nav-icon">'+icon('profile')+'</span>My Team';
    d.onclick=function(){ goPage('myteam'); };
    navWrap.appendChild(d);
  }
  var _prevGoPage = window.goPage;
  window.goPage = function(p){
    if (p==='myteam'){ STATE.page='myteam'; STATE.modal=null; render(); if(window.recDashboardLoad) recDashboardLoad(); return; }
    return _prevGoPage.apply(this, arguments);
  };
  function paint(){ if(STATE.page!=='myteam')return; var c=document.getElementById('content'); if(c) c.innerHTML=renderMyTeam(); }

  function snapshotCard(){
    var d=STATE._recDash||{};
    var bs=d.by_stage||{};
    var interviews=(bs['Interview Scheduled']||0)+(bs['Interview Completed']||0);
    var loading=!d._at&&!d.empty;
    function tile(label,value,color){
      return '<div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 14px;text-align:center;min-width:105px;flex:1">'+
        '<div style="font-size:24px;font-weight:700;color:'+(color||'var(--text)')+'">'+(value||0)+'</div>'+
        '<div style="font-size:11px;color:var(--text3);margin-top:2px;white-space:nowrap">'+esc(label)+'</div>'+
      '</div>';
    }
    var stagePills=Object.keys(bs).map(function(s){
      var cnt=bs[s]; if(!cnt)return'';
      var color=(window.recStageColor?recStageColor(s):'var(--text)');
      return '<div style="text-align:center;padding:10px 14px;background:var(--bg);border-radius:var(--r2);min-width:74px">'+
        '<div style="font-family:var(--display);font-size:20px;font-weight:700;color:'+color+'">'+cnt+'</div>'+
        '<div style="font-size:10.5px;color:var(--text3);margin-top:2px">'+esc(s)+'</div>'+
      '</div>';
    }).join('');
    return '<div class="card cp mb4">'+
      '<div class="flex jb aic mb3"><div><div class="fw6">Your team’s work</div>'+
        '<div class="f12 text3">Live recruiting numbers across everyone in your reporting line</div></div>'+
        '<button class="btn btn-outline btn-sm" onclick="goPage(\'reports\')">Full reports →</button></div>'+
      (loading?'<div style="text-align:center;color:var(--text3);font-size:13px;padding:8px 0">Loading…</div>':
        '<div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">'+
          tile('Subs this week',d.submissions_week,'var(--accent)')+
          tile('Subs this month',d.submissions_month,'var(--accent)')+
          tile('In interview',interviews,'#2563eb')+
          tile('Awaiting approval',d.awaiting_approval,'var(--amber)')+
          tile('Placements',bs['Placement'],'var(--green)')+
        '</div>'+
        '<div class="flex gap2 flex-wrap">'+(stagePills||'<div class="text3 f13">No submissions across your team yet.</div>')+'</div>')+
    '</div>';
  }

  window.renderMyTeam = function(){
    var u=STATE.user;
    if(!leadsATeam(u)) return '<div class="page"><div style="font-size:18px;font-weight:700;margin-bottom:6px">My Team</div>'+
      '<div style="text-align:center;padding:50px;color:var(--text3)">No one reports to you yet.</div></div>';
    var directCount=directReportsOf(u.id).length;
    var totalCount=reportingSubtree(u.id).length;
    var tree=renderOrgSubtree(u.id,{click:'none'});
    return '<div class="page">'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'+
        '<div><div style="font-size:18px;font-weight:700">My Team</div>'+
          '<div style="font-size:12.5px;color:var(--text3)">'+directCount+' direct report'+(directCount===1?'':'s')+' · '+totalCount+' in your reporting line</div></div>'+
      '</div>'+
      snapshotCard()+
      '<div class="card cp">'+
        '<div class="fw6" style="margin-bottom:2px">Reporting structure</div>'+
        '<div class="f12 text3 mb3">Everyone under you on the org chart. An admin sets reporting lines.</div>'+
        tree+
      '</div>'+
    '</div>';
  };
})();

// ===== ROLE-AWARE RECRUITING DASHBOARD (additive) =====
// Injects a "Recruiting" overview at the top of the dashboard, scoped by role
// via GET /recruiting-dashboard: a recruiter sees THEIR jobs / pipeline /
// interviews / offers / rejections and submissions this week & month; a BD
// manager sees the whole desk (jobs, awaiting approval, client submissions,
// placements). Other roles (RA…) are untouched.

(function () {

  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  // Pure recruiters now have their own native dashboard (renderRecruiterDashboard
  // in 05-page-dashboard.js), so the injected strip is managers-only.
  function involved(u){ return userHasAnyRole(u,'admin','bd','bd_lead'); }
  function fmtDT(s){ try{ var d=new Date(s); return (d.getMonth()+1)+'/'+d.getDate()+' '+String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0'); }catch(e){ return ''; } }

  var _prevRender = window.render;
  window.render = function(){
    _prevRender.apply(this, arguments);
    if (STATE.page === 'dashboard') injectRecruitingCards();
  };

  function loadDash(){
    if (STATE._recDashLoading) return;
    var fresh = STATE._recDash && (Date.now() - STATE._recDash._at < 60000);
    if (fresh) return;
    STATE._recDashLoading = true;
    apiGet('/recruiting-dashboard').then(function(d){
      d = d || {}; d._at = Date.now();
      STATE._recDash = d; STATE._recDashLoading = false;
      if (STATE.page==='dashboard') render();
    }).catch(function(){ STATE._recDashLoading = false; STATE._recDash = { _at: Date.now(), empty:true }; });
  }

  // Per-recruiter performance for the manager next in line: submissions,
  // interviews, offers, placements and the revenue those placements brought
  // in (job_orders.placement_fee), so a manager can see what's happening
  // with each recruiter assigned to them without opening every job.
  function loadRecruiterAnalytics(){
    if (STATE._recAnLoading) return;
    var fresh = STATE._recAn && (Date.now() - STATE._recAn._at < 60000);
    if (fresh) return;
    STATE._recAnLoading = true;
    apiGet('/bd-analytics/recruiters').then(function(d){
      STATE._recAn = { _at: Date.now(), rows: d || [] }; STATE._recAnLoading = false;
      if (STATE.page==='dashboard') render();
    }).catch(function(){ STATE._recAn = { _at: Date.now(), rows: [] }; STATE._recAnLoading = false; });
  }

  function money(n){
    n = n || 0;
    return '$' + n.toLocaleString('en-US', { maximumFractionDigits: 0 });
  }

  function recruiterTeamCard(){
    loadRecruiterAnalytics();
    var rows = (STATE._recAn && STATE._recAn.rows) || [];
    if (!rows.length) return '';
    var totalRevenue = rows.reduce(function(s,r){ return s + (r.revenue||0); }, 0);
    var body = rows.map(function(r){
      return '<div style="display:flex;align-items:center;gap:10px;padding:9px 2px;border-bottom:1px solid var(--border)">'+
        '<div style="flex:1;min-width:0">'+
          '<div style="font-size:13px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(r.name||'')+'</div>'+
          '<div style="font-size:11px;color:var(--text3)">'+esc(r.employee_id||'')+'</div>'+
        '</div>'+
        '<div style="text-align:center;width:56px"><div style="font-weight:700;font-size:14px">'+(r.total||0)+'</div><div style="font-size:9.5px;color:var(--text3)">subs</div></div>'+
        '<div style="text-align:center;width:56px"><div style="font-weight:700;font-size:14px;color:#2563eb">'+(r.interview||0)+'</div><div style="font-size:9.5px;color:var(--text3)">interview</div></div>'+
        '<div style="text-align:center;width:56px"><div style="font-weight:700;font-size:14px;color:#7c3aed">'+(r.offer||0)+'</div><div style="font-size:9.5px;color:var(--text3)">offers</div></div>'+
        '<div style="text-align:center;width:64px"><div style="font-weight:700;font-size:14px;color:var(--green)">'+(r.placed||0)+'</div><div style="font-size:9.5px;color:var(--text3)">placed</div></div>'+
        '<div style="text-align:right;width:84px"><div style="font-weight:700;font-size:13.5px;color:var(--green)">'+(r.revenue?money(r.revenue):'—')+'</div><div style="font-size:9.5px;color:var(--text3)">revenue</div></div>'+
      '</div>';
    }).join('');
    return '<div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin-top:10px">'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">'+
        '<div style="font-weight:600;font-size:12.5px">My recruiting team — performance</div>'+
        (totalRevenue?'<div style="font-size:11.5px;color:var(--text3)">Total revenue: <b style="color:var(--green)">'+money(totalRevenue)+'</b></div>':'')+
      '</div>'+body+'</div>';
  }

  function tile(label, value, color){
    return '<div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 14px;text-align:center;min-width:105px;flex:1">'+
      '<div style="font-size:24px;font-weight:700;color:'+(color||'var(--text)')+'">'+value+'</div>'+
      '<div style="font-size:11px;color:var(--text3);margin-top:2px;white-space:nowrap">'+esc(label)+'</div>'+
    '</div>';
  }

  function injectRecruitingCards(){
    var u = STATE.user; if (!u || !involved(u)) return;
    var content = document.getElementById('content'); if (!content) return;
    if (content.querySelector('[data-recdash]')) return;
    loadDash();
    var d = STATE._recDash;
    if (!d || d.empty) return;

    var isRecruiter = d.role === 'recruiter';
    var bs = d.by_stage || {};
    var interviews = (bs['Interview Scheduled']||0) + (bs['Interview Completed']||0);

    var tiles = isRecruiter ? [
      tile('My Jobs', (d.jobs&&d.jobs.total)||0, 'var(--accent)'),
      tile('In Interview', interviews, '#2563eb'),
      tile('Offers', bs['Offer']||0, '#7c3aed'),
      tile('Placements', bs['Placement']||0, 'var(--green)'),
      tile('Rejected', bs['Rejected']||0, 'var(--red)'),
      tile('Subs · Week', d.submissions_week||0),
      tile('Subs · Month', d.submissions_month||0)
    ] : [
      tile('Active Jobs', (d.jobs&&d.jobs.active)||0, 'var(--accent)'),
      tile('Awaiting Approval', d.awaiting_approval||0, 'var(--amber)'),
      tile('At Client', bs['Submitted to Client']||0, 'var(--accent)'),
      tile('In Interview', interviews, '#2563eb'),
      tile('Offers', bs['Offer']||0, '#7c3aed'),
      tile('Placements', bs['Placement']||0, 'var(--green)'),
      tile('Subs · Week', d.submissions_week||0),
      tile('Subs · Month', d.submissions_month||0)
    ];

    var upcoming = (d.upcoming_interviews||[]).map(function(iv){
      return '<div style="display:flex;justify-content:space-between;gap:10px;padding:6px 2px;border-bottom:1px solid var(--border);font-size:12.5px">'+
        '<span style="font-weight:600">'+esc(iv.candidate||'Candidate')+'</span>'+
        '<span style="color:var(--text3);white-space:nowrap">'+esc(fmtDT(iv.interview_at))+(iv.interview_location?' · '+esc(iv.interview_location):'')+'</span>'+
      '</div>';
    }).join('');

    var wrap = document.createElement('div');
    wrap.setAttribute('data-recdash','1');
    wrap.innerHTML =
      '<div style="margin:0 0 16px 0">'+
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:9px">'+
          '<div style="font-weight:700;font-size:14.5px">Recruiting — '+(isRecruiter?'my desk':'the desk')+'</div>'+
          '<span style="font-size:12px;color:var(--accent);cursor:pointer" onclick="goPage(\''+(isRecruiter?'bd_myjobs':'bd_joborders')+'\')">'+(isRecruiter?'My Jobs →':'Jobs →')+'</span>'+
        '</div>'+
        '<div style="display:flex;gap:10px;flex-wrap:wrap">'+tiles.join('')+'</div>'+
        (upcoming?'<div style="background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 14px;margin-top:10px">'+
          '<div style="font-weight:600;font-size:12.5px;margin-bottom:5px">Upcoming interviews</div>'+upcoming+'</div>':'')+
        (isRecruiter?'':recruiterTeamCard())+
      '</div>';
    var page = content.querySelector('.page') || content.firstElementChild;
    if (page) page.insertBefore(wrap, page.firstChild);
    else content.insertBefore(wrap, content.firstChild);
  }

})();

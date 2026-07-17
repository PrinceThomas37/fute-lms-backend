// ===== ROLE-AWARE RECRUITING DASHBOARD (additive) =====
// Injects a "Recruiting" overview at the top of the dashboard, scoped by role
// via GET /recruiting-dashboard: a recruiter sees THEIR jobs / pipeline /
// interviews / offers / rejections and submissions this week & month; a BD
// manager sees the whole desk (jobs, awaiting approval, client submissions,
// placements). Other roles (RA…) are untouched.

(function () {

  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function involved(u){ return userHasAnyRole(u,'admin','bd','bd_lead','recruiter'); }
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
      '</div>';
    var page = content.querySelector('.page') || content.firstElementChild;
    if (page) page.insertBefore(wrap, page.firstChild);
    else content.insertBefore(wrap, content.firstChild);
  }

})();

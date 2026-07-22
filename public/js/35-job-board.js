// ===== COMPANY-WIDE JOB BOARD =====
// Recruiters can see every job in the company (not just their desk): who's on
// it, how busy it is, and ask the BD team to be assigned. Candidate contact
// details stay locked until assignment — the backend masks them. BD managers
// get an "Assignment requests" card on their dashboard to approve/decline.

(function () {

  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function isBDM(u){ return userHasAnyRole(u,'admin','bd','bd_lead'); }
  function isRec(u){ return userHasRole(u,'recruiter'); }
  function agoTxt(s){
    try{
      var ms=Date.now()-new Date(s).getTime(), h=Math.floor(ms/3600000);
      if(h<1)return 'just now'; if(h<24)return h+'h ago';
      var d=Math.floor(h/24); return d+' day'+(d!==1?'s':'')+' ago';
    }catch(e){ return ''; }
  }

  STATE.jb = STATE.jb || { list:null, loading:false, q:'', modalJob:null, subs:null, subsMasked:false, subsLoading:false };

  // ── render / nav / routing hooks ───────────────────────────────────────────
  var _prevRender = window.render;
  window.render = function(){
    _prevRender.apply(this, arguments);
    injectNav();
    if (STATE.page === 'job_board') paint();
    if (STATE.page === 'dashboard') injectRequestsCard();
  };

  var _prevGoPage = window.goPage;
  window.goPage = function(p){
    if (p === 'job_board') {
      STATE.page = 'job_board'; STATE.modal = null; STATE.jb.modalJob = null;
      render(); load();
      return;
    }
    return _prevGoPage.apply(this, arguments);
  };

  function injectNav(){
    var u = STATE.user; if (!u || !isRec(u) || isBDM(u)) return;
    var navWrap = document.querySelector('.sb-nav'); if (!navWrap) return;
    var existing = navWrap.querySelector('[data-jbnav]');
    if (existing) { existing.classList.toggle('active', STATE.page==='job_board'); }
    else {
      var d = document.createElement('div');
      d.className = 'nav-item' + (STATE.page==='job_board' ? ' active' : '');
      d.setAttribute('data-jbnav','1');
      d.innerHTML = '<span class="nav-icon">'+icon('leads')+'</span>All Jobs';
      d.onclick = function(){ goPage('job_board'); };
      var anchor = navWrap.querySelector('[data-bdnav]');
      if (anchor && anchor.parentNode) anchor.parentNode.insertBefore(d, anchor.nextSibling);
      else navWrap.appendChild(d);
    }
    if (STATE.page==='job_board'){ var t=document.querySelector('.tb-title'); if (t) t.textContent='All Jobs'; }
  }

  function load(){
    if (STATE.jb.loading) return;
    STATE.jb.loading = true;
    apiGet('/job-orders/browse').then(function(d){
      STATE.jb.list = d || []; STATE.jb.loading = false;
      if (STATE.page==='job_board') paint();
    }).catch(function(){
      STATE.jb.list = []; STATE.jb.loading = false;
      if (STATE.page==='job_board') paint();
    });
  }

  // ── the board ──────────────────────────────────────────────────────────────
  function statusBadge(st){
    var c = st==='Active' ? 'var(--green)' : st==='On Hold' ? 'var(--amber)' : st==='Closed' ? 'var(--red)' : 'var(--text3)';
    return '<span style="font-size:10.5px;font-weight:700;color:'+c+';border:1px solid currentColor;border-radius:9px;padding:1px 8px;opacity:.85">'+esc(st||'')+'</span>';
  }

  function actionBtn(j){
    if (j.assigned_to_me)
      return '<button class="btn btn-sm btn-outline" style="color:var(--green);border-color:var(--green)" onclick="event.stopPropagation();bdOpenSubmissions(\''+j.id+'\')">✓ On your desk — open</button>';
    if (j.my_request && j.my_request.status==='pending')
      return '<button class="btn btn-sm btn-outline" disabled style="opacity:.6;cursor:default">Requested — waiting on BD</button>';
    return '<button class="btn btn-sm btn-primary" onclick="event.stopPropagation();jbRequest(\''+j.id+'\')">Request assignment</button>';
  }

  function paint(){
    var content = document.getElementById('content'); if (!content) return;
    var t = document.querySelector('.tb-title'); if (t) t.textContent = 'All Jobs';

    if (STATE.jb.loading || STATE.jb.list === null){
      content.innerHTML = '<div class="page"><div style="text-align:center;padding:60px;color:var(--text3)">Loading all jobs…</div></div>';
      if (STATE.jb.list === null) load();
      return;
    }

    var q = (STATE.jb.q||'').toLowerCase();
    var jobs = STATE.jb.list.filter(function(j){
      if (!q) return true;
      return [j.job_title,j.client,j.job_code,j.city,j.state,j.primary_skills,(j.company&&j.company.name)]
        .some(function(v){ return v && String(v).toLowerCase().indexOf(q) > -1; });
    });

    var cards = jobs.map(function(j){
      var loc = [j.city,j.state].filter(Boolean).join(', ');
      var recs = (j.recruiters||[]);
      var pr = j.priority && j.priority!=='Normal'
        ? '<span style="font-size:10px;font-weight:700;color:var(--red);background:var(--red-l);padding:2px 7px;border-radius:8px;margin-left:6px">'+esc(j.priority)+'</span>' : '';
      return '<div class="card" style="padding:16px;cursor:pointer" onclick="jbOpenJob(\''+j.id+'\')">'+
        '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px">'+
          '<span style="font-family:var(--mono);font-size:11px;color:var(--text3)">'+esc(j.job_code||'')+'</span>'+statusBadge(j.status)+
        '</div>'+
        '<div style="font-weight:600;font-size:15px;margin-bottom:3px">'+esc(j.job_title||'')+pr+'</div>'+
        '<div style="font-size:12.5px;color:var(--text3);margin-bottom:10px">'+esc(j.client||(j.company&&j.company.name)||'')+(loc?' · '+esc(loc):'')+'</div>'+
        (j.bd_manager&&j.bd_manager.name?'<div style="font-size:11.5px;color:var(--text3);margin-bottom:8px">BD Manager: <span style="color:var(--text2);font-weight:500">'+esc(j.bd_manager.name)+'</span></div>':'')+
        '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:12px;font-size:11.5px;color:var(--text3)">'+
          '<span>'+(recs.length?('👥 '+esc(recs.slice(0,3).join(', '))+(recs.length>3?' +'+(recs.length-3):'')):'No recruiters yet')+'</span>'+
          '<span style="white-space:nowrap">'+(j.submission_count||0)+' subs</span>'+
        '</div>'+
        actionBtn(j)+
      '</div>';
    }).join('');

    content.innerHTML = '<div class="page">'+
      '<div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">'+
        '<input id="jb-search" class="inp" style="max-width:340px" placeholder="Search title, client, skills, location…" value="'+esc(STATE.jb.q||'')+'" oninput="jbSearch(this.value)"/>'+
        '<span style="font-size:12.5px;color:var(--text3)">'+jobs.length+' of '+STATE.jb.list.length+' jobs · newest first</span>'+
      '</div>'+
      (jobs.length
        ? '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px">'+cards+'</div>'
        : '<div class="card" style="padding:40px;text-align:center;color:var(--text3)">'+(STATE.jb.list.length?'No jobs match your search.':'No jobs in the company yet — jobs appear here when the BD team opens them.')+'</div>')+
    '</div>' + modalHtml();
  }

  window.jbSearch = function(v){
    STATE.jb.q = v;
    var content = document.getElementById('content');
    paint();
    var inp = document.getElementById('jb-search');
    if (inp){ inp.focus(); inp.setSelectionRange(inp.value.length, inp.value.length); }
  };

  // ── job detail modal (candidates masked until assigned) ────────────────────
  window.jbOpenJob = function(id){
    STATE.jb.modalJob = id; STATE.jb.subs = null; STATE.jb.subsMasked = false; STATE.jb.subsLoading = true;
    paint();
    apiGet('/job-orders/'+id+'/submissions').then(function(d){
      if (d && d.masked){ STATE.jb.subs = d.submissions||[]; STATE.jb.subsMasked = true; }
      else { STATE.jb.subs = d||[]; STATE.jb.subsMasked = false; }
      STATE.jb.subsLoading = false; paint();
    }).catch(function(){ STATE.jb.subs = []; STATE.jb.subsLoading = false; paint(); });
  };
  window.jbCloseModal = function(){ STATE.jb.modalJob = null; paint(); };

  function modalHtml(){
    var id = STATE.jb.modalJob; if (!id) return '';
    var j = (STATE.jb.list||[]).find(function(x){ return x.id===id; }); if (!j) return '';
    var loc = [j.city,j.state,j.country].filter(Boolean).join(', ');

    function dr(lbl,val){ return val?'<div style="font-size:12.5px;margin-bottom:4px"><span style="color:var(--text3)">'+lbl+': </span>'+esc(val)+'</div>':''; }

    var subsRows;
    if (STATE.jb.subsLoading) subsRows = '<div style="padding:14px;text-align:center;color:var(--text3);font-size:13px">Loading candidates…</div>';
    else if (!(STATE.jb.subs||[]).length) subsRows = '<div style="padding:14px;text-align:center;color:var(--text3);font-size:13px">No candidates on this job yet.</div>';
    else subsRows = (STATE.jb.subs||[]).map(function(s){
      var c = s.candidate||{};
      var who = s.recruiter && s.recruiter.name ? ' · by '+esc(s.recruiter.name) : '';
      return '<div style="display:flex;align-items:center;gap:10px;padding:8px 2px;border-bottom:1px solid var(--border)">'+
        '<div style="flex:1;min-width:0">'+
          '<div style="font-size:13px;font-weight:600">'+esc(c.full_name||'Candidate')+' <span style="font-family:var(--mono);font-size:10.5px;color:var(--text3)">'+esc(c.candidate_code||'')+'</span></div>'+
          '<div style="font-size:11.5px;color:var(--text3)">'+esc(c.current_title||'')+([c.city,c.state].filter(Boolean).length?' · '+esc([c.city,c.state].filter(Boolean).join(', ')):'')+who+'</div>'+
        '</div>'+
        '<span style="font-size:11px;color:var(--accent);white-space:nowrap">'+esc(s.stage||'')+'</span>'+
      '</div>';
    }).join('');

    return '<div onclick="jbCloseModal()" style="position:fixed;inset:0;background:rgba(0,0,0,.35);z-index:90;display:flex;align-items:center;justify-content:center;padding:20px">'+
      '<div onclick="event.stopPropagation()" style="background:var(--card);border-radius:var(--r3);max-width:640px;width:100%;max-height:86vh;overflow:auto;padding:22px 24px">'+
        '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:4px">'+
          '<div>'+
            '<div style="display:flex;gap:8px;align-items:center;margin-bottom:4px"><span style="font-family:var(--mono);font-size:11px;color:var(--text3)">'+esc(j.job_code||'')+'</span>'+statusBadge(j.status)+'</div>'+
            '<div style="font-size:18px;font-weight:700">'+esc(j.job_title||'')+'</div>'+
            '<div style="font-size:13px;color:var(--text3);margin-top:2px">'+esc(j.client||(j.company&&j.company.name)||'')+(loc?' · '+esc(loc):'')+'</div>'+
          '</div>'+
          '<button class="btn btn-sm btn-outline" onclick="jbCloseModal()">✕</button>'+
        '</div>'+
        '<div style="margin:12px 0;padding-top:12px;border-top:1px solid var(--border);display:grid;grid-template-columns:1fr 1fr;gap:6px">'+
          dr('Job Type',j.job_type)+dr('Level',j.emp_level)+dr('Remote',j.remote)+dr('Positions',j.positions)+
          dr('Priority',j.priority)+dr('Skills',j.primary_skills)+
        '</div>'+
        '<div style="margin:6px 0 4px;font-weight:600;font-size:13.5px">Candidates on this job ('+((STATE.jb.subs||[]).length)+')</div>'+
        (STATE.jb.subsMasked?'<div style="font-size:11.5px;color:var(--amber);background:var(--amber-l);border-radius:8px;padding:6px 10px;margin-bottom:6px">🔒 Contact details are hidden — they unlock when you\'re assigned to this job.</div>':'')+
        subsRows+
        '<div style="margin-top:14px">'+actionBtn(j)+'</div>'+
      '</div>'+
    '</div>';
  }

  window.jbRequest = function(id){
    apiPost('/job-orders/'+id+'/request-assignment').then(function(r){
      var j = (STATE.jb.list||[]).find(function(x){ return x.id===id; });
      if (j) j.my_request = { id: r && r.id, status: 'pending' };
      showToast('Request sent — the BD team will review it', 'success');
      paint();
    }).catch(function(e){ showToast(e.message || 'Could not send request', 'error'); });
  };

  // ── BDM dashboard: assignment requests queue ───────────────────────────────
  function loadRequests(){
    if (STATE.jb._reqLoading) return;
    if (STATE.jb._reqs && Date.now() - STATE.jb._reqs._at < 60000) return;
    STATE.jb._reqLoading = true;
    apiGet('/assignment-requests?status=pending').then(function(d){
      STATE.jb._reqs = { _at: Date.now(), list: d || [] }; STATE.jb._reqLoading = false;
      if (STATE.page==='dashboard') render();
    }).catch(function(){ STATE.jb._reqs = { _at: Date.now(), list: [] }; STATE.jb._reqLoading = false; });
  }

  function injectRequestsCard(){
    var u = STATE.user; if (!u || !isBDM(u)) return;
    var content = document.getElementById('content'); if (!content) return;
    if (content.querySelector('[data-jbreq]')) return;
    loadRequests();
    var reqs = STATE.jb._reqs && STATE.jb._reqs.list || [];
    if (!reqs.length) return;

    var rows = reqs.map(function(r){
      var job = r.job||{}, rec = r.recruiter||{};
      return '<div style="display:flex;align-items:center;gap:10px;padding:8px 2px;border-bottom:1px solid var(--border)">'+
        '<div style="flex:1;min-width:0;font-size:13px">'+
          '<b>'+esc(rec.name||'Recruiter')+'</b> wants <b>'+esc(job.job_title||'')+'</b> '+
          '<span style="font-family:var(--mono);font-size:10.5px;color:var(--text3)">'+esc(job.job_code||'')+'</span>'+
          '<span style="font-size:11.5px;color:var(--text3)"> · '+agoTxt(r.created_at)+(r.note?' · “'+esc(r.note)+'”':'')+'</span>'+
        '</div>'+
        '<button class="btn btn-sm btn-primary" onclick="jbDecide(\''+r.id+'\',\'approve\')">Assign</button>'+
        '<button class="btn btn-sm btn-outline" onclick="jbDecide(\''+r.id+'\',\'decline\')">Decline</button>'+
      '</div>';
    }).join('');

    var wrap = document.createElement('div');
    wrap.setAttribute('data-jbreq','1');
    wrap.innerHTML = '<div class="card cp" style="margin:0 0 16px 0">'+
      '<div class="flex jb aic mb3">'+
        '<div><div class="fw6">Assignment requests</div><div class="f12 text3">'+reqs.length+' recruiter'+(reqs.length!==1?'s':'')+' waiting for a job</div></div>'+
      '</div>'+rows+'</div>';
    var page = content.querySelector('.page') || content.firstElementChild;
    var after = content.querySelector('[data-recdash]');
    if (after && after.parentNode) after.parentNode.insertBefore(wrap, after.nextSibling);
    else if (page) page.insertBefore(wrap, page.firstChild);
    else content.insertBefore(wrap, content.firstChild);
  }

  window.jbDecide = function(id, action){
    apiPost('/assignment-requests/'+id+'/decide', { action: action }).then(function(){
      showToast(action==='approve' ? 'Recruiter assigned to the job' : 'Request declined', 'success');
      STATE.jb._reqs = null;
      render();
    }).catch(function(e){ showToast(e.message || 'Could not update request', 'error'); });
  };

})();

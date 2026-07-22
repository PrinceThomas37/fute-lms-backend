// ===== APPLICANTS / CANDIDATE DATABASE MODULE (additive) =====
// The shared candidate pool as a Ceipal-style browsable database, usable by both
// BD managers and recruiters. Adds a top-nav "Applicants" page: search + filter +
// paginate, add a new candidate (individual CN- id) with duplicate detection
// (full name + email-or-phone, warn-and-offer), edit, delete, and add-to-job.
// Slice 1 of docs/ATS_RECRUITING_PLAN.md.

(function () {

  // ── taxonomies ──────────────────────────────────────────────────────────────
  var APPLICANT_STATUSES = ['New lead','Active','Submitted','Interviewing','Placed','Do Not Call','Blacklisted','Inactive'];
  var SOURCES = ['Monster','CareerBuilder','LinkedIn','Indeed','Dice','Naukri','ZipRecruiter','Referral','Career Site','Job Board','Vendor','Manual'];
  var WORK_AUTH = ['US Citizen','Green Card','GC EAD','H1B','H4 EAD','OPT EAD','CPT','TN','L2 EAD','E3','Canada Citizen','Canada PR','Other'];
  var PAY_TYPES = ['Hourly','Yearly'];
  var AVAILABILITY = ['Immediate','1 week','2 weeks','3 weeks','1 month','Notice period'];
  var US_STATES = ["Alabama","Alaska","Arizona","Arkansas","California","Colorado","Connecticut","Delaware","Florida","Georgia","Hawaii","Idaho","Illinois","Indiana","Iowa","Kansas","Kentucky","Louisiana","Maine","Maryland","Massachusetts","Michigan","Minnesota","Mississippi","Missouri","Montana","Nebraska","Nevada","New Hampshire","New Jersey","New Mexico","New York","North Carolina","North Dakota","Ohio","Oklahoma","Oregon","Pennsylvania","Rhode Island","South Carolina","South Dakota","Tennessee","Texas","Utah","Vermont","Virginia","Washington","West Virginia","Wisconsin","Wyoming"];

  if (!STATE.ats) {
    STATE.ats = {
      loading:false, rows:[], total:0, page:1, limit:25,
      q:'', filters:{ applicant_status:'', source:'', state:'', work_authorization:'',
        availability:'', experience_min:'', experience_max:'', created_from:'', created_to:'', has_resume:'' },
      advOpen:false, form:{}, editId:null, dupMatches:[], sel:{}, view:'grid'
    };
  }
  if (!STATE.ats.sel) STATE.ats.sel = {};

  // resolve a taxonomy from the managed lookups (Slice 6), falling back to the
  // built-in defaults if the lookups aren't loaded / are empty.
  function lk(cat, fb){ return (window.atsLookup ? window.atsLookup(cat, fb) : fb); }

  // Shared: attach a resume file to a candidate (used by every quick-create
  // modal). Resolves true/false, never rejects — creation must not fail on a
  // bad attachment.
  window.atsUploadResumeFile = function(candId, fileEl){
    return new Promise(function(resolve){
      var f = fileEl && fileEl.files && fileEl.files[0];
      if (!f || !candId){ resolve(false); return; }
      if (f.size > 4.5*1024*1024){ showToast('Resume too large (max ~4.5 MB) — not attached','error'); resolve(false); return; }
      var r = new FileReader();
      r.onload = function(){
        apiPost('/candidates/'+candId+'/documents', { filename:f.name, content_type:f.type||'application/octet-stream', doc_type:'resume', data_base64:String(r.result) })
          .then(function(){ resolve(true); })
          .catch(function(){ showToast('Resume upload failed','error'); resolve(false); });
      };
      r.onerror = function(){ resolve(false); };
      r.readAsDataURL(f);
    });
  };

  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function code(t){ return '<span style="font-family:var(--mono);font-size:10.5px;color:var(--text3);font-weight:600">'+esc(t)+'</span>'; }
  function canUse(u){ return userHasAnyRole(u,'admin','bd','bd_lead','recruiter'); }
  function isBDMlike(u){ return userHasAnyRole(u,'admin','bd','bd_lead'); }
  function fmtDate(s){ if(!s)return '—'; try{ var d=new Date(s); return (d.getMonth()+1)+'/'+d.getDate()+'/'+String(d.getFullYear()).slice(2); }catch(e){ return '—'; } }
  function loc(c){ return [c.city,c.state].filter(Boolean).join(', ') || c.current_location || '—'; }
  function jobTitle(c){ return c.headline || c.current_title || '—'; }
  function ownerName(c){ return (c.owner && c.owner.name) || '—'; }
  function creatorName(c){ return (c.creator && c.creator.name) || '—'; }

  // ── data ─────────────────────────────────────────────────────────────────────
  function loadApplicants(){
    STATE.ats.loading = true; paintATSPage();
    var a = STATE.ats, p = ['page='+a.page, 'limit='+a.limit];
    if (a.q) p.push('q='+encodeURIComponent(a.q));
    Object.keys(a.filters).forEach(function(k){ if(a.filters[k]) p.push(k+'='+encodeURIComponent(a.filters[k])); });
    return apiGet('/candidates?'+p.join('&')).then(function(r){
      STATE.ats.rows = (r&&r.data)||[]; STATE.ats.total = (r&&r.total)||0; STATE.ats.loading = false; paintATSPage();
    }).catch(function(e){ STATE.ats.loading=false; showToast('Failed to load candidates: '+e.message,'error'); paintATSPage(); });
  }

  // ── nav + routing (wrap, like the BD module) ─────────────────────────────────
  var _prevRender = window.render;
  window.render = function(){
    _prevRender.apply(this, arguments);
    injectATSNav();
    if (STATE.page === 'applicants') paintATSPage();
  };

  function injectATSNav(){
    var u = STATE.user; if(!u || !canUse(u)) return;
    var navWrap = document.querySelector('.sb-nav'); if(!navWrap) return;
    if (navWrap.querySelector('[data-atsnav]')) return;
    var d = document.createElement('div');
    d.className = 'nav-item' + (STATE.page==='applicants' ? ' active' : '');
    d.setAttribute('data-atsnav','1');
    d.innerHTML = '<span class="nav-icon">'+icon('profile')+'</span>Candidates';
    d.onclick = function(){ goPage('applicants'); };
    // place after any BD nav item, else at the end
    var bd = navWrap.querySelector('[data-bdnav]');
    if (bd && bd.parentNode) bd.parentNode.insertBefore(d, bd.nextSibling);
    else navWrap.appendChild(d);
    if (STATE.page==='applicants'){ var t=document.querySelector('.tb-title'); if(t) t.textContent='Candidates'; }
  }

  var _prevGoPage = window.goPage;
  window.goPage = function(p){
    if (p === 'applicants'){
      STATE.page = 'applicants'; STATE.modal = null;
      render();
      if (window.atsLoadLookups) atsLoadLookups();
      loadApplicants();
      return;
    }
    return _prevGoPage.apply(this, arguments);
  };

  function paintATSPage(){
    if (STATE.page !== 'applicants') return;
    var c = document.getElementById('content'); if(!c) return;
    c.innerHTML = (STATE.ats.view === 'sourcing' && window.renderSourcing) ? renderSourcing() : renderApplicants();
  }

  // Candidates / Sourcing sub-tabs — Sourcing used to be its own top-level nav
  // item; it now lives inside the Candidates tab since both work the same pool.
  window.atsSetView = function(v){
    STATE.ats.view = v;
    if (v === 'sourcing' && window.srcLoadForCandidatesTab) srcLoadForCandidatesTab();
    render();
  };
  window.atsTabBar = function(){
    var v = STATE.ats.view || 'grid';
    function tab(key, label){
      var active = v === key;
      return '<button onclick="atsSetView(\''+key+'\')" style="padding:7px 14px;border-radius:8px;font-size:12.5px;font-weight:600;cursor:pointer;border:1px solid '+(active?'var(--accent)':'var(--border)')+';background:'+(active?'var(--accent)':'var(--card)')+';color:'+(active?'#fff':'var(--text2)')+'">'+label+'</button>';
    }
    return '<div style="display:flex;gap:8px;margin-bottom:14px">'+tab('grid','All Candidates')+tab('sourcing','Sourcing')+'</div>';
  };

  // ── grid ──────────────────────────────────────────────────────────────────────
  function renderApplicants(){
    var a = STATE.ats;
    var fopt = function(key, all, list){
      return '<select class="sel" style="max-width:170px" onchange="atsSetFilter(\''+key+'\',this.value)">'+
        '<option value="">'+all+'</option>'+
        list.map(function(s){ return '<option value="'+esc(s)+'"'+(a.filters[key]===s?' selected':'')+'>'+esc(s)+'</option>'; }).join('')+
      '</select>';
    };
    var u = STATE.user, canManage = userHasAnyRole(u,'admin','bd_lead');
    var owners = (STATE.users||[]).filter(function(x){ return userHasAnyRole(x,'admin','bd','bd_lead','recruiter'); });
    var f = a.filters;
    var advActive = f.availability||f.experience_min||f.experience_max||f.created_from||f.created_to||f.has_resume||f.owner_id;
    var anyActive = a.q||f.applicant_status||f.source||f.work_authorization||f.state||advActive;
    var advPanel = a.advOpen ? (
      '<div class="card" style="padding:12px 14px;margin-bottom:12px;display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px">'+
        '<div><label style="font-size:11px;color:var(--text2)">Availability</label>'+
          '<select class="sel" onchange="atsSetFilter(\'availability\',this.value)"><option value="">Any</option>'+
          lk('availability',AVAILABILITY).map(function(s){ return '<option value="'+esc(s)+'"'+(f.availability===s?' selected':'')+'>'+esc(s)+'</option>'; }).join('')+'</select></div>'+
        '<div><label style="font-size:11px;color:var(--text2)">Ownership</label>'+
          '<select class="sel" onchange="atsSetFilter(\'owner_id\',this.value)"><option value="">Anyone</option>'+
          owners.map(function(o){ return '<option value="'+o.id+'"'+(f.owner_id===o.id?' selected':'')+'>'+esc(o.name)+'</option>'; }).join('')+'</select></div>'+
        '<div><label style="font-size:11px;color:var(--text2)">Experience (yrs)</label>'+
          '<div style="display:flex;gap:6px"><input class="sel" type="number" placeholder="min" value="'+esc(f.experience_min)+'" onchange="atsSetFilter(\'experience_min\',this.value)">'+
          '<input class="sel" type="number" placeholder="max" value="'+esc(f.experience_max)+'" onchange="atsSetFilter(\'experience_max\',this.value)"></div></div>'+
        '<div><label style="font-size:11px;color:var(--text2)">Created from</label><input class="sel" type="date" value="'+esc(f.created_from)+'" onchange="atsSetFilter(\'created_from\',this.value)"></div>'+
        '<div><label style="font-size:11px;color:var(--text2)">Created to</label><input class="sel" type="date" value="'+esc(f.created_to)+'" onchange="atsSetFilter(\'created_to\',this.value)"></div>'+
        '<div style="display:flex;align-items:end"><label style="font-size:12.5px;color:var(--text2);display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox"'+(f.has_resume==='1'?' checked':'')+' onchange="atsSetFilter(\'has_resume\',this.checked?\'1\':\'\')"> Has résumé</label></div>'+
      '</div>') : '';
    var toolbar =
      atsTabBar()+
      '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap">'+
        '<div><div style="font-size:18px;font-weight:700">Candidates</div>'+
        '<div style="font-size:12.5px;color:var(--text3)">'+(a.total||0)+' candidate'+(a.total===1?'':'s')+' in the database</div></div>'+
        '<div style="display:flex;gap:8px">'+
          (canManage?'<button class="btn btn-outline" onclick="atsOpenLookupsManager()">Manage lists</button>':'')+
          '<button class="btn btn-primary" onclick="atsOpenNew()">+ New Candidate</button>'+
        '</div>'+
      '</div>'+
      '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px">'+
        '<input class="sel" style="max-width:280px" placeholder="Search name, email, phone, CN- code…" value="'+esc(a.q)+'" '+
          'oninput="atsSetSearch(this.value)" onkeydown="if(event.key===\'Enter\')atsApplySearch()">'+
        '<button class="btn btn-sm btn-outline" onclick="atsApplySearch()">Search</button>'+
        fopt('applicant_status','All statuses',lk('applicant_status',APPLICANT_STATUSES))+
        fopt('source','All sources',lk('source',SOURCES))+
        fopt('work_authorization','All work auth',lk('work_authorization',WORK_AUTH))+
        fopt('state','All states',US_STATES)+
        '<button class="btn btn-sm '+(a.advOpen?'btn-primary':'btn-outline')+'" onclick="atsToggleAdvanced()">Advanced '+(a.advOpen?'▴':'▾')+(advActive?' •':'')+'</button>'+
        (anyActive?'<button class="btn btn-sm btn-outline" onclick="atsClearFilters()">Clear</button>':'')+
      '</div>'+advPanel;

    if (a.loading) return '<div class="page">'+toolbar+'<div style="text-align:center;padding:50px;color:var(--text3)">Loading candidates…</div></div>';

    var selIds = Object.keys(a.sel).filter(function(k){ return a.sel[k]; });
    var allOn = a.rows.length && a.rows.every(function(c){ return a.sel[c.id]; });
    var bulkBar = selIds.length ?
      '<div class="card" style="padding:9px 14px;margin-bottom:10px;display:flex;align-items:center;gap:12px">'+
        '<span style="font-size:12.5px;color:var(--text2)"><b>'+selIds.length+'</b> selected</span>'+
        '<button class="btn btn-sm btn-primary" onclick="atsSequenceSelected()">▶ Add to email sequence</button>'+
        '<button class="btn btn-sm btn-outline" onclick="atsClearSel()">Clear</button>'+
      '</div>' : '';

    var head = ['<input type="checkbox" '+(allOn?'checked':'')+' onclick="atsToggleSelAll()">','Candidate ID','Name','Email','Mobile','City','State','Source','Status','Job Title','Ownership','Work Auth','Created By','Created','']
      .map(function(h){ return '<th style="text-align:left;padding:9px 10px;font-size:11px;color:var(--text3);font-weight:700;white-space:nowrap">'+h+'</th>'; }).join('');

    var body = a.rows.map(function(c){
      return '<tr style="border-top:1px solid var(--border)">'+
        '<td style="padding:9px 10px"><input type="checkbox" '+(a.sel[c.id]?'checked':'')+' onclick="atsToggleSel(\''+c.id+'\')"></td>'+
        '<td style="padding:9px 10px;white-space:nowrap">'+code(c.candidate_code||'—')+'</td>'+
        '<td style="padding:9px 10px;white-space:nowrap"><span style="font-weight:600;font-size:13px;cursor:pointer;color:var(--accent)" onclick="bdOpenCandidate(\''+c.id+'\')">'+esc(c.full_name||'—')+'</span></td>'+
        '<td style="padding:9px 10px;font-size:12.5px">'+esc(c.email||'—')+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px;white-space:nowrap">'+esc(c.phone||'—')+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px">'+esc(c.city||'—')+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px;white-space:nowrap">'+esc(c.state||'—')+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px;white-space:nowrap">'+esc(c.source||'—')+'</td>'+
        '<td style="padding:9px 10px;font-size:12px;white-space:nowrap">'+statusBadge(c.applicant_status)+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px">'+esc(jobTitle(c))+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px;white-space:nowrap">'+esc(ownerName(c))+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px;white-space:nowrap">'+esc(c.work_authorization||'—')+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px;white-space:nowrap">'+esc(creatorName(c))+'</td>'+
        '<td style="padding:9px 10px;font-size:12px;color:var(--text3);white-space:nowrap">'+fmtDate(c.created_at)+'</td>'+
        '<td style="padding:9px 10px;white-space:nowrap">'+
          '<button class="btn btn-sm btn-outline" onclick="atsAddToJob(\''+c.id+'\')">Add to Job</button>'+
        '</td>'+
      '</tr>';
    }).join('');

    if (!a.rows.length) body = '<tr><td colspan="15" style="padding:40px;text-align:center;color:var(--text3)">No candidates match. '+
      '<span style="color:var(--accent);cursor:pointer" onclick="atsOpenNew()">Add the first one →</span></td></tr>';

    var totalPages = Math.max(1, Math.ceil((a.total||0)/a.limit));
    var fromN = a.total ? (a.page-1)*a.limit+1 : 0, toN = Math.min(a.page*a.limit, a.total);
    var pager =
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-top:12px;font-size:12.5px;color:var(--text3)">'+
        '<div>'+fromN+'–'+toN+' of '+(a.total||0)+'</div>'+
        '<div style="display:flex;gap:6px;align-items:center">'+
          '<button class="btn btn-sm btn-outline" '+(a.page<=1?'disabled style="opacity:.5"':'')+' onclick="atsGoPage('+(a.page-1)+')">‹ Prev</button>'+
          '<span>Page '+a.page+' / '+totalPages+'</span>'+
          '<button class="btn btn-sm btn-outline" '+(a.page>=totalPages?'disabled style="opacity:.5"':'')+' onclick="atsGoPage('+(a.page+1)+')">Next ›</button>'+
        '</div>'+
      '</div>';

    return '<div class="page">'+toolbar+bulkBar+
      '<div class="card" style="padding:0;overflow-x:auto"><table style="width:100%;border-collapse:collapse;min-width:1100px">'+
        '<thead><tr style="background:var(--bg)">'+head+'</tr></thead><tbody>'+body+'</tbody></table></div>'+
      pager+
    '</div>';
  }

  // ── multi-select → email sequence ───────────────────────────────────────────
  window.atsToggleSel = function(id){ STATE.ats.sel[id]=!STATE.ats.sel[id]; render(); };
  window.atsToggleSelAll = function(){
    var a=STATE.ats, allOn=a.rows.length&&a.rows.every(function(c){return a.sel[c.id];});
    a.rows.forEach(function(c){ a.sel[c.id]=!allOn; });
    render();
  };
  window.atsClearSel = function(){ STATE.ats.sel={}; render(); };
  window.atsSequenceSelected = function(){
    var a=STATE.ats;
    var items=a.rows.filter(function(c){return a.sel[c.id];})
      .map(function(c){ return { entity_id:c.id, label:c.full_name||'Candidate' }; });
    if(!items.length){ showToast('Select candidates first','error'); return; }
    if(typeof wfStartSequence!=='function'){ showToast('Sequencing module not loaded','error'); return; }
    wfStartSequence('candidate', items, { anyStage:true });
  };

  function statusBadge(s){
    var col = { 'New lead':'var(--text3)','Active':'var(--green)','Submitted':'var(--accent)','Interviewing':'#2563eb',
      'Placed':'var(--green)','Do Not Call':'var(--amber)','Blacklisted':'var(--red)','Inactive':'#9ca3af' }[s] || 'var(--text3)';
    return '<span style="font-weight:700;color:'+col+';background:rgba(0,0,0,.04);padding:2px 8px;border-radius:10px">'+esc(s||'—')+'</span>';
  }

  // ── search / filter / pagination handlers ────────────────────────────────────
  window.atsSetSearch = function(v){ STATE.ats.q = v; };
  window.atsApplySearch = function(){ STATE.ats.page = 1; loadApplicants(); };
  window.atsSetFilter = function(k,v){ STATE.ats.filters[k]=v; STATE.ats.page=1; loadApplicants(); };
  window.atsClearFilters = function(){ STATE.ats.q=''; STATE.ats.filters={ applicant_status:'', source:'', state:'', work_authorization:'', availability:'', experience_min:'', experience_max:'', created_from:'', created_to:'', has_resume:'', owner_id:'' }; STATE.ats.page=1; loadApplicants(); };
  window.atsToggleAdvanced = function(){ STATE.ats.advOpen = !STATE.ats.advOpen; render(); };
  window.atsGoPage = function(p){ if(p<1)return; STATE.ats.page=p; loadApplicants(); };

  // ── add / edit modal ─────────────────────────────────────────────────────────
  // The ONE add-candidate window used everywhere — the Candidates database AND
  // every job's "+ Add Candidate". Pass a jobCtx ({jobId,jobTitle,jobCode}) to
  // additionally tag the candidate to that job after creating (or to search an
  // existing candidate to add), so there is a single consistent form.
  window.atsOpenNew = function(jobCtx){
    STATE.ats.editId = null; STATE.ats.dupMatches = []; STATE.ats._resumeStash = null;
    STATE.ats._jobCtx = (jobCtx && jobCtx.jobId) ? jobCtx : null;
    STATE.ats._jobTagQ = ''; STATE.ats._jobTagPool = [];
    STATE.ats.form = { applicant_status:'New lead', source:'Manual', pay_currency:'USD' };
    showApplicantModal();
  };
  window.atsOpenEdit = function(id){
    STATE.ats._jobCtx = null; STATE.ats._jobTagQ = ''; STATE.ats._jobTagPool = [];
    var c = STATE.ats.rows.find(function(x){ return x.id===id; });
    if(!c){ apiGet('/candidates/'+id).then(function(d){ STATE.ats.editId=id; STATE.ats.dupMatches=[]; STATE.ats._resumeStash=null; STATE.ats.form=Object.assign({},d); showApplicantModal(); }).catch(function(e){ showToast('Failed: '+e.message,'error'); }); return; }
    STATE.ats.editId = id; STATE.ats.dupMatches = []; STATE.ats._resumeStash = null; STATE.ats.form = Object.assign({}, c);
    showApplicantModal();
  };

  window.atsFormSet = function(k,v){ STATE.ats.form[k]=v; };

  // ── job-context: search an existing candidate to add to this job ────────────
  window.atsJobTagSearch = function(q){
    STATE.ats._jobTagQ = q; q = (q||'').trim();
    if (q.length < 2){ STATE.ats._jobTagPool = []; showApplicantModal(); return; }
    apiGet('/candidates?q='+encodeURIComponent(q)).then(function(pool){ STATE.ats._jobTagPool = pool||[]; showApplicantModal(); })
      .catch(function(){ STATE.ats._jobTagPool = []; showApplicantModal(); });
  };
  window.atsJobTagPick = function(cid){
    var ctx = STATE.ats._jobCtx; if(!ctx) return;
    apiPost('/pipeline', { candidate_id:cid, job_order_id:ctx.jobId }).then(function(){ atsAfterJobAdd(ctx); })
      .catch(function(e){
        if (/already tagged/i.test(e.message)) showToast('Already on this job','error');
        else showToast('Failed: '+e.message,'error');
      });
  };
  function atsAfterJobAdd(ctx){
    STATE.ats._jobCtx = null; STATE.ats._jobTagPool = []; STATE.ats._jobTagQ = '';
    closeModal();
    showToast('Candidate added to '+((ctx && ctx.jobTitle) || 'the job'),'success');
    // Refresh whichever job view is open so the new candidate shows immediately.
    if (STATE.page==='bd_pipeline' && window.bdReloadPipeline) return bdReloadPipeline();
    if ((STATE.page==='bd_kanban' || STATE.page==='bd_jodetail') && window.bdOpenPipeline) return bdOpenPipeline(ctx.jobId);
  }

  // ── resume parsing: file → fields, prefilled into the form ─────────────────
  // The file is stashed so it still attaches on save even though the modal
  // re-render clears the file input.
  window.atsParseResume = function(){
    var fileEl = document.getElementById('ats_resume_file');
    var f = fileEl && fileEl.files && fileEl.files[0];
    if (!f && STATE.ats._resumeStash){ atsDoParse(STATE.ats._resumeStash); return; }
    if (!f){ showToast('Choose a resume file first','error'); return; }
    if (f.size > 4.5*1024*1024){ showToast('File too large (max ~4.5 MB)','error'); return; }
    var r = new FileReader();
    r.onload = function(){
      STATE.ats._resumeStash = { name:f.name, type:f.type||'application/octet-stream', data:String(r.result) };
      atsDoParse(STATE.ats._resumeStash);
    };
    r.onerror = function(){ showToast('Could not read file','error'); };
    r.readAsDataURL(f);
  };
  function atsDoParse(stash){
    showToast('Parsing resume…','info');
    apiPost('/candidates/parse-resume', { filename:stash.name, content_type:stash.type, data_base64:stash.data })
      .then(function(r){
        var flds = (r&&r.fields)||{};
        var form = STATE.ats.form;
        // fill only fields the user hasn't already typed; resume_text always
        Object.keys(flds).forEach(function(k){
          if (k==='summary') return;
          if (form[k]===undefined || form[k]===null || form[k]==='') form[k]=flds[k];
        });
        if (r.resume_text) form.resume_text = r.resume_text;
        showApplicantModal();
        showToast(r.used_ai?'Parsed with AI — review the filled fields':'Parsed (basic mode — no AI key). Review the filled fields','success');
      })
      .catch(function(e){ showToast('Parse failed: '+e.message,'error'); });
  }
  // upload from the live input, or from the stash if the input was cleared by a re-render
  function uploadResumeFor(candId){
    var fileEl = document.getElementById('ats_resume_file');
    if (fileEl && fileEl.files && fileEl.files[0]) return atsUploadResumeFile(candId, fileEl);
    var st = STATE.ats._resumeStash;
    if (st) return apiPost('/candidates/'+candId+'/documents', { filename:st.name, content_type:st.type, doc_type:'resume', data_base64:st.data }).catch(function(){ showToast('Resume upload failed','error'); });
    return Promise.resolve(false);
  }

  function fld(label, inner, req){
    return '<div><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">'+label+(req?' <span style="color:var(--red)">*</span>':'')+'</label>'+inner+'</div>';
  }
  function inp(key, ph){ return '<input class="sel" value="'+esc(STATE.ats.form[key]||'')+'" placeholder="'+(ph||'')+'" oninput="atsFormSet(\''+key+'\',this.value)">'; }
  function sel(key, opts, blank){
    var list = (blank?['']:[]).concat(opts);
    return '<select class="sel" onchange="atsFormSet(\''+key+'\',this.value)">'+
      list.map(function(o){ return '<option value="'+esc(o)+'"'+(STATE.ats.form[key]===o?' selected':'')+'>'+esc(o||'Select…')+'</option>'; }).join('')+'</select>';
  }

  function showApplicantModal(){
    var f = STATE.ats.form, editing = !!STATE.ats.editId;
    var u = STATE.user;
    var jobCtx = STATE.ats._jobCtx;

    // When adding from a job, offer to reuse an existing candidate (search-to-add)
    // before falling back to creating a brand-new one via the form below.
    var jobTag = '';
    if (jobCtx && !editing){
      var jq = (STATE.ats._jobTagQ||'').trim();
      var jpool = jq.length>=2 ? (STATE.ats._jobTagPool||[]) : [];
      var jpoolHtml = jq.length<2
        ? '<div style="color:var(--text3);font-size:12px;padding:4px 2px">Type a name, email or CN- code to add someone already in the system.</div>'
        : (jpool.map(function(c){
            return '<div style="display:flex;justify-content:space-between;align-items:center;border:1px solid var(--border);border-radius:8px;padding:7px 10px;margin-bottom:5px">'+
              '<div><div style="font-weight:600;font-size:12.5px">'+esc(c.full_name)+' '+code(c.candidate_code||'')+'</div>'+
              '<div style="font-size:11px;color:var(--text3)">'+esc(c.current_title||c.headline||'')+(c.email?' · '+esc(c.email):'')+'</div></div>'+
              '<button class="btn btn-sm btn-primary" onclick="atsJobTagPick(\''+c.id+'\')">Add</button>'+
            '</div>';
          }).join('') || '<div style="color:var(--text3);font-size:12px;padding:4px 2px">No matches — fill the form below to create a new candidate.</div>');
      jobTag =
        '<div style="border:1px solid var(--border);border-radius:8px;padding:11px 13px;margin-bottom:16px;background:var(--bg)">'+
          '<div style="font-size:11px;font-weight:700;color:var(--text3);margin-bottom:7px">ALREADY IN THE SYSTEM? SEARCH TO ADD TO THIS JOB</div>'+
          '<input class="sel" placeholder="Search name, email, CN- code…" value="'+esc(STATE.ats._jobTagQ||'')+'" oninput="atsJobTagSearch(this.value)">'+
          '<div style="max-height:22vh;overflow-y:auto;margin-top:8px">'+jpoolHtml+'</div>'+
          '<div style="font-size:11px;color:var(--text3);margin-top:7px;border-top:1px dashed var(--border);padding-top:7px">…or create a brand-new candidate below.</div>'+
        '</div>';
    }
    var modalTitle = editing ? ('Edit Candidate'+(f.candidate_code?' '+code(f.candidate_code):''))
      : (jobCtx ? ('Add Candidate'+(jobCtx.jobTitle?' — '+esc(jobCtx.jobTitle):'')) : 'New Candidate');
    var saveLabel = editing ? 'Save changes' : (jobCtx ? 'Create & add to job' : 'Create candidate');
    var ownerSel = '';
    if (isBDMlike(u)) {
      var owners = (STATE.users||[]).filter(function(x){ return userHasAnyRole(x,'admin','bd','bd_lead','recruiter'); });
      ownerSel = fld('Ownership',
        '<select class="sel" onchange="atsFormSet(\'owner_id\',this.value)">'+
          '<option value="">'+esc(u.name)+' (me)</option>'+
          owners.map(function(o){ return '<option value="'+o.id+'"'+(f.owner_id===o.id?' selected':'')+'>'+esc(o.name)+'</option>'; }).join('')+
        '</select>');
    }

    var dup = STATE.ats.dupMatches.length ? (
      '<div style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:12px;margin-bottom:14px">'+
        '<div style="font-weight:700;font-size:12.5px;color:#b45309;margin-bottom:8px">⚠ Possible existing candidate'+(STATE.ats.dupMatches.length>1?'s':'')+' — matched by name + email/phone</div>'+
        STATE.ats.dupMatches.map(function(m){
          return '<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;background:var(--card);border:1px solid var(--border);border-radius:7px;padding:8px 10px;margin-bottom:6px">'+
            '<div style="font-size:12.5px"><b>'+esc(m.full_name)+'</b> '+code(m.candidate_code||'')+
              '<div style="font-size:11px;color:var(--text3)">'+esc(m.email||'')+(m.phone?' · '+esc(m.phone):'')+(m.current_title?' · '+esc(m.current_title):'')+'</div></div>'+
            '<button class="btn btn-sm btn-outline" onclick="atsOpenEdit(\''+m.id+'\')">Open</button>'+
          '</div>';
        }).join('')+
        '<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:6px">'+
          '<button class="btn btn-sm btn-primary" onclick="atsSaveApplicant(true)">Create anyway</button>'+
        '</div>'+
      '</div>') : '';

    STATE.modal =
      '<div class="modal modal-w720" onclick="event.stopPropagation()">'+
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">'+
          '<div style="font-weight:700;font-size:16px">'+modalTitle+'</div>'+
          '<span style="cursor:pointer;color:var(--text3)" onclick="closeModal()">✕</span>'+
        '</div>'+
        '<div style="padding:18px 20px;max-height:66vh;overflow-y:auto">'+
          jobTag+
          dup+
          '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">'+
            fld('Full Name', inp('full_name','Jane Doe'), true)+
            fld('Email', inp('email','jane@example.com'))+
            fld('Mobile', inp('phone','(555) 123-4567'))+
            fld('Work Authorization', sel('work_authorization', lk('work_authorization',WORK_AUTH), true))+
            fld('Source', sel('source', lk('source',SOURCES), true))+
            fld('Candidate Status', sel('applicant_status', lk('applicant_status',APPLICANT_STATUSES)))+
            fld('City', inp('city'))+
            fld('State', sel('state', US_STATES, true))+
            fld('Country', inp('country','United States'))+
            fld('Zip', inp('zip'))+
            fld('Current Title', inp('current_title'))+
            fld('Desired / Headline Title', inp('headline'))+
            fld('Current Employer', inp('current_employer'))+
            fld('Experience (years)', inp('experience_years','e.g. 8'))+
            fld('LinkedIn', inp('linkedin_url'))+
            fld('Availability', sel('availability', lk('availability',AVAILABILITY), true))+
            fld('Notice Period', inp('notice_period'))+
            fld('Current CTC', inp('current_ctc'))+
            fld('Expected CTC', inp('expected_ctc'))+
            fld('Bill Rate', inp('bill_rate'))+
            fld('Pay Rate', inp('pay_rate'))+
            fld('Pay Type', sel('pay_type', lk('pay_type',PAY_TYPES), true))+
            fld('Resume URL', inp('resume_url'))+
            fld('Attach Resume', '<input type="file" id="ats_resume_file" accept=".pdf,.doc,.docx,.rtf,.txt" style="font-size:11.5px;width:100%">'+
              (STATE.ats._resumeStash?'<div style="font-size:10.5px;color:var(--green);margin-top:3px">✓ '+esc(STATE.ats._resumeStash.name)+' ready to attach</div>':''))+
            ownerSel+
          '</div>'+
          '<div style="margin-top:10px"><button class="btn btn-sm btn-outline" onclick="atsParseResume()">✨ Parse &amp; fill from resume</button>'+
            '<span style="font-size:11px;color:var(--text3);margin-left:8px">Choose a resume file above, then parse to auto-fill the form. Review before saving.</span></div>'+
          '<div style="margin-top:12px">'+fld('Skills', '<textarea class="sel" style="min-height:60px;resize:vertical" placeholder="Comma-separated skills" oninput="atsFormSet(\'skills\',this.value)">'+esc(f.skills||'')+'</textarea>')+'</div>'+
        '</div>'+
        '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:'+(editing?'space-between':'flex-end')+';gap:8px;align-items:center">'+
          (editing?'<button class="btn btn-sm btn-outline" style="color:var(--red)" onclick="atsDeleteApplicant(\''+STATE.ats.editId+'\')">Delete</button>':'')+
          '<div style="display:flex;gap:8px">'+
            '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
            '<button class="btn btn-primary" onclick="atsSaveApplicant(false)">'+saveLabel+'</button>'+
          '</div>'+
        '</div>'+
      '</div>';
    render();
  }

  window.atsSaveApplicant = function(force){
    var f = STATE.ats.form;
    if (!f.full_name || !f.full_name.trim()){ showToast('Full name is required','error'); return; }
    var payload = Object.assign({}, f); if (force) payload.force = true;

    if (STATE.ats.editId){
      var editId = STATE.ats.editId;
      apiPut('/candidates/'+editId, payload).then(function(){
        return uploadResumeFor(editId);
      }).then(function(){
        STATE.ats._resumeStash=null;
        showToast('Candidate updated','success'); closeModal();
        if (window.bdReloadCandidateProfile) window.bdReloadCandidateProfile();
        loadApplicants();
      }).catch(function(e){ showToast('Failed: '+e.message,'error'); });
      return;
    }
    var ctx = STATE.ats._jobCtx;
    apiPost('/candidates', payload).then(function(c){
      return uploadResumeFor(c.id).then(function(){ return c; });
    }).then(function(c){
      STATE.ats._resumeStash=null; STATE.ats.dupMatches=[];
      if (ctx){
        return apiPost('/pipeline', { candidate_id:c.id, job_order_id:ctx.jobId })
          .then(function(){ atsAfterJobAdd(ctx); })
          .catch(function(e){ showToast('Candidate created, but adding to the job failed: '+e.message,'error'); closeModal(); });
      }
      showToast('Candidate created','success'); closeModal(); STATE.ats.page=1; loadApplicants();
    }).catch(function(e){
      // 409 possible_duplicate → surface matches, keep the form open (warn-and-offer)
      if (/possible_duplicate/i.test(e.message)){
        apiGet('/candidates/check-duplicate?full_name='+encodeURIComponent(f.full_name||'')+'&email='+encodeURIComponent(f.email||'')+'&phone='+encodeURIComponent(f.phone||''))
          .then(function(r){ STATE.ats.dupMatches = (r&&r.duplicates)||[]; showApplicantModal(); showToast('Possible duplicate found — review below','info'); })
          .catch(function(){ STATE.ats.dupMatches=[{full_name:f.full_name,candidate_code:'',email:f.email,phone:f.phone}]; showApplicantModal(); });
      } else showToast('Failed: '+e.message,'error');
    });
  };

  window.atsDeleteApplicant = function(id){
    if (!confirm('Remove this candidate from the database?')) return;
    apiDelete('/candidates/'+id).then(function(){ showToast('Candidate removed','info'); closeModal(); loadApplicants(); })
      .catch(function(e){ showToast('Failed: '+e.message,'error'); });
  };

  // ── add a candidate to a job — type-to-search the job by id / title / client ─
  window.atsAddToJob = function(cid){
    var c = STATE.ats.rows.find(function(x){ return x.id===cid; }) || {};
    apiGet('/job-orders').then(function(jobs){
      STATE.ats._jobPick = { cid:cid, name:c.full_name||'candidate', jobs:jobs||[], q:'' };
      atsRenderJobPick();
    }).catch(function(e){ showToast('Failed to load jobs: '+e.message,'error'); });
  };
  window.atsJobPickSearch = function(q){ if(STATE.ats._jobPick){ STATE.ats._jobPick.q=q; atsRenderJobPick(); } };
  function atsRenderJobPick(){
    var jp = STATE.ats._jobPick; if(!jp) return;
    var q = (jp.q||'').toLowerCase();
    var list = jp.jobs.filter(function(j){
      if(!q) return true;
      return [j.job_code,j.job_title,j.client].some(function(v){ return String(v||'').toLowerCase().indexOf(q)>-1; });
    }).slice(0,30);
    var rows = list.map(function(j){
      return '<div style="display:flex;justify-content:space-between;align-items:center;border:1px solid var(--border);border-radius:8px;padding:8px 11px;margin-bottom:6px;cursor:pointer" onclick="atsDoAddToJob(\''+jp.cid+'\',\''+j.id+'\')">'+
        '<div><div style="font-weight:600;font-size:13px">'+esc(j.job_title||'')+' '+code(j.job_code||'')+'</div>'+
        '<div style="font-size:11px;color:var(--text3)">'+esc(j.client||'')+(j.status?' · '+esc(j.status):'')+'</div></div>'+
        '<span class="btn btn-sm btn-primary">Tag</span>'+
      '</div>';
    }).join('') || '<div style="color:var(--text3);font-size:12.5px;padding:8px">No jobs match.</div>';
    STATE.modal =
      '<div class="modal modal-w560" onclick="event.stopPropagation()">'+
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border);font-weight:700;font-size:16px">Add '+esc(jp.name)+' to a Job</div>'+
        '<div style="padding:18px 20px">'+
          '<input class="sel" placeholder="Search by job ID, title, or client…" value="'+esc(jp.q)+'" oninput="atsJobPickSearch(this.value)" style="margin-bottom:10px">'+
          '<div style="max-height:40vh;overflow-y:auto">'+rows+'</div>'+
          '<div style="font-size:11.5px;color:var(--text3);margin-top:8px">Tags the candidate into the job pipeline. Promote to a submission from the job\'s Pipeline tab.</div>'+
        '</div>'+
        '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end">'+
          '<button class="btn btn-outline" onclick="closeModal()">Close</button>'+
        '</div>'+
      '</div>';
    render();
  }
  window.atsDoAddToJob = function(cid, jid){
    if(!jid){ showToast('Pick a job','error'); return; }
    apiPost('/pipeline', { candidate_id:cid, job_order_id:jid }).then(function(){
      showToast('Tagged to job pipeline','success'); STATE.ats._jobPick=null; closeModal();
    }).catch(function(e){
      if (/already tagged/i.test(e.message)) showToast('Candidate already in that pipeline','error');
      else showToast('Failed: '+e.message,'error');
    });
  };

})();

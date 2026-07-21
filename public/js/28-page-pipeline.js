// ===== JOB PIPELINE (TAGGING) MODULE (additive) =====
// The Ceipal "Pipeline" tab for a job order: candidates TAGGED to the job (a
// lightweight sourcing bucket, PL- ids) before being promoted to a formal
// submission. Reached from the BD job detail and the recruiter board. Slice 2 of
// docs/ATS_RECRUITING_PLAN.md.

(function () {

  var PIPELINE_STATUSES = ['Tagged','Contacted','Interested','Screening','Shortlisted','Moved to Submission','Not Interested','Rejected'];
  var PSTATUS_COLORS = { 'Tagged':'var(--text3)','Contacted':'#6b7280','Interested':'#2563eb','Screening':'var(--amber)',
    'Shortlisted':'#7c3aed','Moved to Submission':'var(--green)','Not Interested':'#9ca3af','Rejected':'var(--red)' };

  if (STATE.bd) { STATE.bd.pipeline = STATE.bd.pipeline || []; STATE.bd.view = STATE.bd.view || {}; STATE.bd.plSel = STATE.bd.plSel || {}; }

  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function code(t){ return '<span style="font-family:var(--mono);font-size:10.5px;color:var(--text3);font-weight:600">'+esc(t)+'</span>'; }
  var SUBSTAGE_COLORS={"Sourced":"var(--text3)","Screening":"#6b7280","Submitted to BDM":"var(--amber)","Submitted to Client":"var(--accent)","Interview Scheduled":"#2563eb","Interview Completed":"#1d4ed8","Offer":"#7c3aed","Confirmation":"#0891b2","Placement":"var(--green)","Rejected":"var(--red)","Not Joined":"#b91c1c","On Hold":"#9ca3af"};
  function isBDM(u){ return userHasAnyRole(u,'admin','bd','bd_lead'); }
  function isRec(u){ return userHasRole(u,'recruiter'); }
  function joById(id){ return (STATE.bd.jobOrders||[]).find(function(j){ return j.id===id; }); }
  function fmtDate(s){ if(!s)return '—'; try{ var d=new Date(s); return (d.getMonth()+1)+'/'+d.getDate()+'/'+String(d.getFullYear()).slice(2); }catch(e){ return '—'; } }
  function candLoc(c){ return [c.city,c.state].filter(Boolean).join(', ') || c.current_location || '—'; }

  // What a recruiter (or anyone) needs to actually work a req: description,
  // pay, location, work auth, skills, experience — shown to EVERYONE, not
  // gated behind the BD-only "Job details" tab which also carries BD-only
  // controls (assign recruiter, approvals, posting JD).
  function renderJobSummaryCard(j){
    var loc = [j.city,j.state,j.country,j.zip].filter(Boolean).join(', ');
    var pay = (j.pay_min||j.pay_max) ? ((j.pay_cur||'USD')+' '+(j.pay_min||'?')+'–'+(j.pay_max||'?')) : '';
    var exp = (j.exp_min||j.exp_max) ? ((j.exp_min||'0')+'–'+(j.exp_max||'?')+' yrs') : '';
    function dr(lbl,val){ return val?'<div style="font-size:12.5px;margin-bottom:4px"><span style="color:var(--text3)">'+esc(lbl)+': </span>'+esc(val)+'</div>':''; }
    var grid = dr('Location',loc)+dr('Pay Rate',pay)+dr('Job Type',j.job_type)+
      dr('Employment Level',j.emp_level)+dr('Work Authorization',j.work_auth)+dr('Remote',j.remote)+
      dr('Priority',j.priority)+dr('Positions',j.positions)+dr('Experience',exp)+
      dr('Primary Skills',j.primary_skills)+dr('Secondary Skills',j.secondary_skills)+dr('Industry',j.industry);
    var descId = 'pl-jd-'+j.id;
    var longDesc = !!(j.job_description && j.job_description.length > 320);
    // Always show a Job Description block (placeholder if the BDM left it
    // empty) — recruiters kept landing on candidates with no req context, so
    // this section must never silently disappear.
    var descBody = j.job_description
      ? '<div id="'+descId+'" style="font-size:13px;line-height:1.5;white-space:pre-wrap;'+(longDesc?'max-height:110px;overflow:hidden':'')+'">'+esc(j.job_description)+'</div>'+
        (longDesc?'<button class="btn btn-sm btn-outline" style="margin-top:8px" onclick="var el=document.getElementById(\''+descId+'\');var open=el.style.maxHeight===\'none\';el.style.maxHeight=open?\'110px\':\'none\';el.style.overflow=open?\'hidden\':\'visible\';this.textContent=open?\'Show more\':\'Show less\'">Show more</button>':'')
      : '<div style="font-size:12.5px;color:var(--text3);font-style:italic">No job description was provided by the BD team yet.</div>';
    var desc =
      '<div style="margin-top:'+(grid?'12px':'0')+';padding-top:'+(grid?'12px':'0')+(grid?';border-top:1px solid var(--border)':'')+'">'+
        '<div style="font-size:11px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">Job Description</div>'+descBody+
      '</div>';
    return '<div class="card" style="padding:16px 18px;margin-bottom:14px">'+
      (grid?'<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:7px 18px">'+grid+'</div>':'')+
      desc+
    '</div>';
  }

  function loadPipeline(jid){
    return apiGet('/job-orders/'+jid+'/pipeline').then(function(d){
      STATE.bd.pipeline = d||[];
      // Seed STATE.bd.submissions from promoted rows so the shared stage modal
      // can resolve each candidate's current stage + name for its confirmation.
      STATE.bd.submissions = (d||[]).filter(function(p){ return p.submission; })
        .map(function(p){ return Object.assign({}, p.submission, { candidate: p.candidate }); });
    }).catch(function(e){ STATE.bd.pipeline = []; showToast('Failed to load pipeline: '+e.message,'error'); });
  }

  // joById() only searches STATE.bd.jobOrders, which is populated by the
  // My Jobs / Jobs list loader. Entry points that reach a job WITHOUT going
  // through that list first — the All Jobs board, the recruiter dashboard's
  // "My jobs" top-5 card — never populate it, so opening a job straight from
  // there showed "Job not found" even though the job is real and the caller
  // is assigned to it. Fetch the single job order directly whenever it's
  // missing, so Candidates always has what it needs regardless of entry point.
  function ensureJobOrder(jid){
    if (joById(jid)) return Promise.resolve();
    return apiGet('/job-orders/'+jid).then(function(j){
      if (j && j.id){
        STATE.bd.jobOrders = STATE.bd.jobOrders || [];
        if (!STATE.bd.jobOrders.some(function(x){ return x.id===j.id; })) STATE.bd.jobOrders.push(j);
      }
    }).catch(function(){ /* joById() will report "Job not found" if this fails */ });
  }

  // ── render + routing wrap (mirrors the applicants module) ────────────────────
  var _prevRender = window.render;
  window.render = function(){
    _prevRender.apply(this, arguments);
    if (STATE.page === 'bd_pipeline'){
      paintPipelinePage();
      var t = document.querySelector('.tb-title'); if (t) t.textContent = 'Candidates';
    }
  };
  var _prevGoPage = window.goPage;
  window.goPage = function(p){
    if (p === 'bd_pipeline'){ STATE.page='bd_pipeline'; STATE.modal=null; render(); return; }
    return _prevGoPage.apply(this, arguments);
  };

  window.bdOpenPipeline = function(jid){
    STATE.bd.view = STATE.bd.view || {}; STATE.bd.view.pipelineJoId = jid;
    Promise.all([ ensureJobOrder(jid), loadPipeline(jid) ]).then(function(){ goPage('bd_pipeline'); });
  };
  // The standalone "Submissions" tab (29-page-submissions.js) was merged into
  // this "Candidates" tab and removed. Kept as a thin alias so every existing
  // caller (dashboard top-jobs, job board, My Jobs cards, candidate profile,
  // board/job-detail buttons) keeps working unchanged.
  window.bdOpenSubmissions = function(jid){ bdOpenPipeline(jid); };
  window.bdReloadPipeline = function(){
    var jid = STATE.bd.view && STATE.bd.view.pipelineJoId; if(!jid) return;
    loadPipeline(jid).then(function(){ render(); });
  };

  function paintPipelinePage(){ var c=document.getElementById('content'); if(!c) return; c.innerHTML = renderPipelinePage(); }

  // ── the page ──────────────────────────────────────────────────────────────
  window.renderPipelinePage = function(){
    var u = STATE.user;
    var jid = STATE.bd.view && STATE.bd.view.pipelineJoId;
    var j = joById(jid);
    if (!j) return '<div class="page"><div style="padding:40px;text-align:center;color:var(--text3)">Job not found.</div></div>';
    var rows = (STATE.bd.pipeline||[]).filter(function(p){ return p.job_order_id===jid; });
    var back = isBDM(u) ? 'bd_joborders' : 'bd_myjobs';

    // Job details FIRST — what a recruiter needs to actually work the req:
    // description, pay, location, work auth, skills, experience. Visible to
    // everyone (not just BD), unlike the separate "Job details" tab which
    // also carries BD-only controls (assign recruiter, approvals, posting JD).
    var jobCard = renderJobSummaryCard(j);

    var tabs =
      '<div style="display:flex;gap:4px;border-bottom:1px solid var(--border);margin-bottom:14px">'+
        '<div style="padding:8px 16px;font-size:13px;font-weight:700;color:var(--accent);border-bottom:2px solid var(--accent)">Candidates ('+rows.length+')</div>'+
        '<div style="padding:8px 16px;font-size:13px;font-weight:600;color:var(--text3);cursor:pointer" onclick="bdOpenKanban(\''+j.id+'\')">Board</div>'+
        (isBDM(u)?'<div style="padding:8px 16px;font-size:13px;font-weight:600;color:var(--text3);cursor:pointer" onclick="bdOpenJobOrder(\''+j.id+'\')">Job details</div>':'')+
      '</div>';

    // multi-select bulk bar (ported from the old Submissions tab): sequence
    // the promoted candidates, or email the JD to the selected ones.
    var sel = STATE.bd.plSel || {};
    var selRows = rows.filter(function(p){ return sel[p.id]; });
    var bulkBar = selRows.length ?
      '<div class="card" style="padding:9px 14px;margin-bottom:10px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">'+
        '<span style="font-size:12.5px;color:var(--text2)"><b>'+selRows.length+'</b> selected</span>'+
        '<button class="btn btn-sm btn-primary" onclick="plSequenceSelected()">▶ Start sequence</button>'+
        '<button class="btn btn-sm btn-outline" onclick="plEmailJD()">✉ Email JD</button>'+
        '<button class="btn btn-sm btn-outline" onclick="plClearSel()">Clear</button>'+
      '</div>' : '';

    var allOn = rows.length && rows.every(function(p){ return sel[p.id]; });
    var head = '<th style="padding:8px 9px"><input type="checkbox" '+(allOn?'checked':'')+' onclick="plToggleSelAll()"></th>'+
      ['Pipeline ID','Candidate Name','Stage','Work Auth','Mobile','Location','Country','Exp','Source','Resume',
      'Bill Rate','Pay Rate','Employer','Availability','Notice','Current CTC','Tagged By','Tagged On','']
      .map(function(h){ return '<th style="text-align:left;padding:8px 9px;font-size:11px;color:var(--text3);font-weight:700;white-space:nowrap">'+h+'</th>'; }).join('');

    var body = rows.map(function(p){
      var c = p.candidate || {};
      // ONE stage control everywhere: the same submission-stage dropdown the
      // Submissions grid and Board use, routed through the shared stage modal.
      // Un-promoted rows show "Not submitted"; picking a stage promotes the
      // candidate (materializes the submission) and opens the notes modal.
      var promoted = !!p.submission_id;
      var curStage = p.submission ? (p.submission.stage||'') : '';
      var stageOpts = (window.ATS_STAGE_LIST||[]).map(function(x){
        return '<option value="'+esc(x)+'"'+(curStage===x?' selected':'')+'>'+esc(x)+'</option>'; }).join('');
      var statusSel =
        '<select class="sel" style="font-size:11px;padding:3px 6px;min-width:150px;color:'+(SUBSTAGE_COLORS[curStage]||'var(--text2)')+';font-weight:600" onchange="plMove(\''+p.id+'\',\''+(p.submission_id||'')+'\',this.value)">'+
          (promoted?'':'<option value="">Not submitted</option>')+
          stageOpts+
        '</select>'+
        (p.submission&&p.submission.sub_stage?'<div style="font-size:10px;color:var(--text3);margin-top:2px">'+esc(p.submission.sub_stage)+'</div>':'');
      var resume = c.resume_url ? '<a href="'+esc(c.resume_url)+'" target="_blank" rel="noopener" style="color:var(--accent)">↗</a>' : '—';
      return '<tr style="border-top:1px solid var(--border)">'+
        '<td style="padding:8px 9px"><input type="checkbox" '+(sel[p.id]?'checked':'')+' onclick="plToggleSel(\''+p.id+'\')"></td>'+
        '<td style="padding:8px 9px;white-space:nowrap">'+code(p.pipeline_code||'—')+'</td>'+
        '<td style="padding:8px 9px;white-space:nowrap;font-size:12.5px"><span style="font-weight:600;cursor:pointer;color:var(--accent)" onclick="bdOpenCandidate(\''+c.id+'\')">'+esc(c.full_name||'—')+'</span> '+(c.candidate_code?'<span style="font-size:10px;color:var(--text3)">'+esc(c.candidate_code)+'</span>':'')+'</td>'+
        '<td style="padding:8px 9px">'+statusSel+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(p.work_auth_snap||c.work_authorization||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(c.phone||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px">'+esc(candLoc(c))+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(c.country||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(c.experience_years!=null?c.experience_years:'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(p.source||c.source||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:14px;text-align:center">'+resume+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(p.bill_rate||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(p.pay_rate||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px">'+esc(p.employer_name||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(p.availability||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(p.notice_period||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(p.current_ctc||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc((p.tagger&&p.tagger.name)||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;color:var(--text3);white-space:nowrap">'+fmtDate(p.tagged_at)+'</td>'+
        '<td style="padding:8px 9px;white-space:nowrap">'+
          (promoted?'<span style="font-size:11px;color:var(--green);font-weight:700;margin-right:4px">✓ Submitted</span>':'')+
          '<button class="btn btn-sm btn-outline" onclick="plOpenEdit(\''+p.id+'\')">Edit</button>'+
          ' <button class="btn btn-sm btn-outline" style="color:var(--red)" onclick="plRemove(\''+p.id+'\')">✕</button>'+
        '</td>'+
      '</tr>';
    }).join('');
    if (!rows.length) body = '<tr><td colspan="20" style="padding:40px;text-align:center;color:var(--text3)">No candidates on this job yet. '+
      '<span style="color:var(--accent);cursor:pointer" onclick="plOpenAdd(\''+j.id+'\')">Add a candidate →</span></td></tr>';

    return '<div class="page">'+
      '<div style="margin-bottom:6px"><span onclick="goPage(\''+back+'\')" style="cursor:pointer;font-size:12.5px;color:var(--accent)">← Jobs</span></div>'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">'+
        '<div><div style="display:flex;gap:8px;align-items:center">'+code(j.job_code)+'<span style="font-weight:700;font-size:17px">'+esc(j.job_title||'')+'</span></div>'+
        '<div style="font-size:12.5px;color:var(--text3)">'+esc(j.client||'')+'</div></div>'+
        '<button class="btn btn-primary" onclick="plOpenAdd(\''+j.id+'\')">+ Add Candidate</button>'+
      '</div>'+
      jobCard+
      tabs+bulkBar+
      '<div class="card" style="padding:0;overflow-x:auto"><table style="width:100%;border-collapse:collapse;min-width:1500px">'+
        '<thead><tr style="background:var(--bg)">'+head+'</tr></thead><tbody>'+body+'</tbody></table></div>'+
    '</div>';
  };

  // ── unified stage move (the ONE way to change a candidate's stage) ──────────
  // Promoted rows go straight through the shared stage modal. Un-promoted rows
  // are materialized as a submission first (silent promote to the entry stage),
  // then the SAME modal captures the note and moves to the chosen stage — so
  // there's no separate "Promote" step and no divergent pipeline vocabulary.
  window.plMove = function(pipelineId, submissionId, stage){
    if (!stage) return;
    if (submissionId){
      openStageModal(submissionId, stage, function(){ bdReloadPipeline(); });
      return;
    }
    var u = STATE.user, recruiterScoped = isRec(u) && !isBDM(u);
    if (recruiterScoped && ['Sourced','Screening','Submitted to BDM'].indexOf(stage) < 0){
      showToast('You can take a candidate up to "Submitted to BDM" — the BD team owns the later stages','error'); render(); return;
    }
    apiPost('/pipeline/'+pipelineId+'/promote', { stage:'Sourced' }).then(function(r){
      var sub = r && r.submission; if(!sub){ showToast('Could not promote candidate','error'); return; }
      STATE.bd.submissions = STATE.bd.submissions || [];
      if(!STATE.bd.submissions.some(function(x){ return x.id===sub.id; })) STATE.bd.submissions.push(sub);
      if (stage === sub.stage){ showToast('Promoted to submission','success'); bdReloadPipeline(); return; }
      openStageModal(sub.id, stage, function(){ bdReloadPipeline(); });
    }).catch(function(e){ showToast('Failed: '+e.message,'error'); });
  };
  // ── multi-select + bulk actions (ported from the old Submissions tab) ───────
  function plCurrentRows(){
    var jid = STATE.bd.view && STATE.bd.view.pipelineJoId;
    return (STATE.bd.pipeline||[]).filter(function(p){ return p.job_order_id===jid; });
  }
  function plSelectedRows(){ var sel=STATE.bd.plSel||{}; return plCurrentRows().filter(function(p){ return sel[p.id]; }); }
  window.plToggleSel = function(id){ STATE.bd.plSel=STATE.bd.plSel||{}; STATE.bd.plSel[id]=!STATE.bd.plSel[id]; render(); };
  window.plToggleSelAll = function(){
    var rows=plCurrentRows(); var sel=STATE.bd.plSel||{};
    var allOn=rows.length && rows.every(function(p){ return sel[p.id]; });
    rows.forEach(function(p){ sel[p.id]=!allOn; }); STATE.bd.plSel=sel; render();
  };
  window.plClearSel = function(){ STATE.bd.plSel={}; render(); };
  window.plSequenceSelected = function(){
    // Sequencing enrolls a submitted candidate — only promoted rows qualify.
    var promoted = plSelectedRows().filter(function(p){ return p.submission_id; });
    var skipped = plSelectedRows().length - promoted.length;
    if(!promoted.length){ showToast('Sequencing needs submitted candidates — move a tagged candidate to a stage first','error'); return; }
    if(skipped) showToast(skipped+' tagged (un-submitted) candidate'+(skipped>1?'s':'')+' skipped','info');
    if(typeof wfStartSequence!=='function'){ showToast('Sequencing module not loaded','error'); return; }
    var items = promoted.map(function(p){ var c=p.candidate||{}; return { entity_id:p.submission_id, label:c.full_name||'Candidate' }; });
    wfStartSequence('submission', items, { anyStage:true });
  };
  window.plEmailJD = function(){
    var jid = STATE.bd.view && STATE.bd.view.pipelineJoId;
    var j = joById(jid) || {};
    var emails = plSelectedRows().map(function(p){ return (p.candidate||{}).email; }).filter(Boolean);
    if(!emails.length){ showToast('No email addresses on the selected candidates','error'); return; }
    var subject = 'Job opportunity: '+(j.job_title||'')+(j.client?' — '+j.client:'');
    var body = 'Hi,\n\nI would like to share this opportunity with you:\n\n'+
      (j.job_title||'')+(j.client?' at '+j.client:'')+'\n'+
      [j.city,j.state].filter(Boolean).join(', ')+'\n\n'+
      String(j.job_description||'').slice(0,1300)+
      '\n\nPlease reply if you are interested and we can discuss the details.\n';
    window.open('mailto:'+encodeURIComponent(emails.join(','))+'?subject='+encodeURIComponent(subject)+'&body='+encodeURIComponent(body), '_self');
  };

  window.plRemove = function(id){
    if (!confirm('Remove this candidate from the pipeline?')) return;
    apiDelete('/pipeline/'+id).then(function(){ showToast('Removed from pipeline','info'); bdReloadPipeline(); })
      .catch(function(e){ showToast('Failed: '+e.message,'error'); });
  };

  // ── edit snapshot fields ────────────────────────────────────────────────────
  window.plOpenEdit = function(id){
    var p = (STATE.bd.pipeline||[]).find(function(x){ return x.id===id; }); if(!p) return;
    STATE.bd._plEdit = Object.assign({}, p);
    var f = STATE.bd._plEdit;
    function row(label,key){ return '<div><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">'+label+'</label>'+
      '<input class="sel" value="'+esc(f[key]||'')+'" oninput="plEditSet(\''+key+'\',this.value)"></div>'; }
    STATE.modal =
      '<div class="modal modal-w560" onclick="event.stopPropagation()">'+
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border);font-weight:700;font-size:15px">Edit Pipeline Entry '+code(p.pipeline_code||'')+'</div>'+
        '<div style="padding:18px 20px"><div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">'+
          row('Work Authorization','work_auth_snap')+row('Employer','employer_name')+
          row('Bill Rate','bill_rate')+row('Pay Rate','pay_rate')+
          row('Availability','availability')+row('Notice Period','notice_period')+
          row('Current CTC','current_ctc')+row('Source','source')+
        '</div>'+
        '<div style="margin-top:12px"><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">Notes</label>'+
          '<textarea class="sel" style="min-height:56px;resize:vertical" oninput="plEditSet(\'notes\',this.value)">'+esc(f.notes||'')+'</textarea></div>'+
        '</div>'+
        '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px">'+
          '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
          '<button class="btn btn-primary" onclick="plSaveEdit(\''+id+'\')">Save</button>'+
        '</div>'+
      '</div>';
    render();
  };
  window.plEditSet = function(k,v){ STATE.bd._plEdit = STATE.bd._plEdit||{}; STATE.bd._plEdit[k]=v; };
  window.plSaveEdit = function(id){
    var f = STATE.bd._plEdit||{};
    apiPatch('/pipeline/'+id, {
      work_auth_snap:f.work_auth_snap, employer_name:f.employer_name, bill_rate:f.bill_rate, pay_rate:f.pay_rate,
      availability:f.availability, notice_period:f.notice_period, current_ctc:f.current_ctc, source:f.source, notes:f.notes
    }).then(function(p){
      STATE.bd.pipeline = (STATE.bd.pipeline||[]).map(function(x){ return x.id===id?p:x; });
      showToast('Updated','success'); closeModal();
    }).catch(function(e){ showToast('Failed: '+e.message,'error'); });
  };

  // ── add a candidate: create new (default), or search to reuse an existing one
  window.plOpenAdd = function(jid){
    // Do NOT pre-load the whole candidate pool — the modal opens straight on the
    // "create new" form. Existing candidates only surface if the recruiter
    // actively searches (which still guards against duplicates).
    STATE.bd._plAddJob = jid; STATE.bd._plSearchQ=''; STATE.bd._plDup=[]; STATE.bd._plPool=[];
    plShowAddModal(jid);
  };
  window.plSearch = function(jid, q){
    STATE.bd._plSearchQ = q;
    q = (q||'').trim();
    if (q.length < 2) { STATE.bd._plPool=[]; plShowAddModal(jid); return; }
    apiGet('/candidates?q='+encodeURIComponent(q)).then(function(pool){ STATE.bd._plPool=pool||[]; plShowAddModal(jid); })
      .catch(function(){ STATE.bd._plPool=[]; plShowAddModal(jid); });
  };
  function plShowAddModal(jid){
    var taggedCids = (STATE.bd.pipeline||[]).filter(function(p){ return p.job_order_id===jid; }).map(function(p){ return p.candidate_id; });
    var q = (STATE.bd._plSearchQ||'').trim();
    // Only show results when the recruiter is actively searching — no default
    // dump of every existing candidate.
    var pool = q.length>=2 ? (STATE.bd._plPool||[]).filter(function(c){ return taggedCids.indexOf(c.id)<0; }) : [];
    var poolHtml = q.length<2
      ? '<div style="color:var(--text3);font-size:12px;padding:6px 2px">Type a name or email to reuse an existing candidate, or just create a new one below.</div>'
      : (pool.map(function(c){
          return '<div style="display:flex;justify-content:space-between;align-items:center;border:1px solid var(--border);border-radius:8px;padding:8px 11px;margin-bottom:6px">'+
            '<div><div style="font-weight:600;font-size:13px">'+esc(c.full_name)+' '+code(c.candidate_code||'')+'</div>'+
            '<div style="font-size:11px;color:var(--text3)">'+esc(c.current_title||c.headline||'')+(c.email?' · '+esc(c.email):'')+'</div></div>'+
            '<button class="btn btn-sm btn-primary" onclick="plTag(\''+jid+'\',\''+c.id+'\')">Tag</button>'+
          '</div>';
        }).join('') || '<div style="color:var(--text3);font-size:12.5px;padding:8px">No matching candidates — create a new one below.</div>');

    var dup = (STATE.bd._plDup&&STATE.bd._plDup.length) ? (
      '<div style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:10px;margin-bottom:12px">'+
        '<div style="font-weight:700;font-size:12px;color:#b45309;margin-bottom:6px">⚠ Possible existing candidate — tag one instead of creating a copy</div>'+
        STATE.bd._plDup.map(function(m){ return '<div style="display:flex;justify-content:space-between;align-items:center;background:var(--card);border:1px solid var(--border);border-radius:7px;padding:7px 10px;margin-bottom:5px">'+
          '<div style="font-size:12.5px"><b>'+esc(m.full_name)+'</b> '+code(m.candidate_code||'')+'<div style="font-size:11px;color:var(--text3)">'+esc(m.email||'')+(m.phone?' · '+esc(m.phone):'')+'</div></div>'+
          '<button class="btn btn-sm btn-primary" onclick="plTag(\''+jid+'\',\''+m.id+'\')">Tag</button></div>'; }).join('')+
        '<div style="display:flex;justify-content:flex-end;margin-top:4px"><button class="btn btn-sm btn-outline" onclick="plQuickCreate(\''+jid+'\',true)">Create anyway</button></div>'+
      '</div>') : '';

    STATE.modal =
      '<div class="modal modal-w640" onclick="event.stopPropagation()">'+
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border);font-weight:700;font-size:16px">Add Candidate</div>'+
        '<div style="padding:18px 20px">'+
          dup+
          // Create-new is the primary action — no default candidate list.
          '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">'+
            '<input id="pl_name" class="sel" placeholder="Full name *">'+
            '<input id="pl_email" class="sel" placeholder="Email">'+
            '<input id="pl_phone" class="sel" placeholder="Phone number">'+
            '<input id="pl_title" class="sel" placeholder="Current title">'+
            '<input id="pl_city" class="sel" placeholder="City">'+
            '<input id="pl_state" class="sel" placeholder="State">'+
          '</div>'+
          '<div style="display:flex;align-items:center;gap:10px;margin-top:8px">'+
            '<label style="font-size:11.5px;color:var(--text2);white-space:nowrap">Resume:</label>'+
            '<input id="pl_resume" type="file" accept=".pdf,.doc,.docx,.rtf,.txt" style="font-size:11.5px">'+
          '</div>'+
          '<button class="btn btn-primary btn-sm" style="margin-top:10px" onclick="plQuickCreate(\''+jid+'\',false)">Create &amp; Add</button>'+
          // Reuse an existing candidate — secondary, only shows matches on search.
          '<div style="border-top:1px solid var(--border);margin-top:16px;padding-top:12px">'+
            '<div style="font-size:11px;font-weight:700;color:var(--text3);margin-bottom:8px">ALREADY IN THE SYSTEM? SEARCH TO REUSE</div>'+
            '<input class="sel" placeholder="Search name, email, CN- code…" value="'+esc(q)+'" oninput="plSearch(\''+jid+'\',this.value)" style="margin-bottom:10px">'+
            '<div style="max-height:26vh;overflow-y:auto">'+poolHtml+'</div>'+
          '</div>'+
        '</div>'+
        '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end">'+
          '<button class="btn btn-outline" onclick="closeModal()">Close</button>'+
        '</div>'+
      '</div>';
    render();
  }
  window.plTag = function(jid, cid){
    apiPost('/pipeline', { candidate_id:cid, job_order_id:jid }).then(function(){
      showToast('Tagged to pipeline','success'); STATE.bd._plDup=[]; closeModal(); bdReloadPipeline();
    }).catch(function(e){
      if (/already tagged/i.test(e.message)) showToast('Already in this pipeline','error');
      else showToast('Failed: '+e.message,'error');
    });
  };
  window.plQuickCreate = function(jid, force){
    var g=function(id){return (document.getElementById(id)||{}).value||'';};
    var name=g('pl_name')||STATE.bd._plNewName||'';
    var email=g('pl_email')||STATE.bd._plNewEmail||'';
    var phone=g('pl_phone')||STATE.bd._plNewPhone||'';
    var title=g('pl_title');
    if (!name.trim()){ showToast('Name required','error'); return; }
    STATE.bd._plNewName=name; STATE.bd._plNewEmail=email; STATE.bd._plNewPhone=phone;   // preserve across dup re-render
    var resumeEl=document.getElementById('pl_resume');
    var payload = { full_name:name, email:email, phone:phone, current_title:title,
      city:g('pl_city'), state:g('pl_state'), source:'Manual' };
    if (force) payload.force = true;
    apiPost('/candidates', payload).then(function(c){
      STATE.bd._plDup=[]; STATE.bd._plNewName=STATE.bd._plNewEmail=STATE.bd._plNewPhone='';
      var attach=(window.atsUploadResumeFile?atsUploadResumeFile(c.id,resumeEl):Promise.resolve(false));
      attach.then(function(){ plTag(jid, c.id); });
    }).catch(function(e){
      if (/possible_duplicate/i.test(e.message)){
        apiGet('/candidates/check-duplicate?full_name='+encodeURIComponent(name)+'&email='+encodeURIComponent(email)+'&phone='+encodeURIComponent(phone))
          .then(function(r){ STATE.bd._plDup=(r&&r.duplicates)||[]; plShowAddModal(jid); showToast('Possible duplicate — review','info'); })
          .catch(function(){ showToast('Duplicate check failed','error'); });
      } else showToast('Failed: '+e.message,'error');
    });
  };

})();

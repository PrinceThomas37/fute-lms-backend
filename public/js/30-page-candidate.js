// ===== CANDIDATE PROFILE MODULE (additive) =====
// The Ceipal candidate profile: header, the lifecycle progress bar (per job),
// the candidate's pipelines & submissions across every job, and the activity
// log. Read-only over the ATS tables (no new schema). Slice 4 of
// docs/ATS_RECRUITING_PLAN.md.

(function () {

  // submission stage ordering, for "milestone reached" comparisons
  var STAGE_ORDER = { 'Sourced':0,'Screening':1,'Submitted to BDM':2,'Submitted to Client':3,
    'Interview Scheduled':4,'Interview Completed':5,'Offer':6,'Confirmation':7,'Placement':8 };

  // the profile lifecycle bar (matches Ceipal): each milestone maps to the
  // submission stage that marks it reached.
  var MILESTONES = [
    { key:'pipeline',   label:'Pipeline' },
    { key:'submission', label:'Submission' },
    { key:'client',     label:'Client Submission', stage:'Submitted to Client' },
    { key:'interview',  label:'Interview',          stage:'Interview Scheduled' },
    { key:'confirm',    label:'Confirmation',       stage:'Confirmation' },
    { key:'placement',  label:'Placement',          stage:'Placement' },
    { key:'notjoined',  label:'Not Joined',         stage:'Not Joined' }
  ];

  if (STATE.bd) STATE.bd.profile = STATE.bd.profile || null;

  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function code(t){ return '<span style="font-family:var(--mono);font-size:11px;color:var(--accent);font-weight:700">'+esc(t)+'</span>'; }
  function fmtDT(s){ if(!s)return ''; try{ var d=new Date(s); return (d.getMonth()+1)+'/'+d.getDate()+'/'+String(d.getFullYear()).slice(2)+' '+String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0'); }catch(e){ return ''; } }
  function loc(c){ return [c.city,c.state,c.country].filter(Boolean).join(', ') || c.current_location || '—'; }

  // ── data ─────────────────────────────────────────────────────────────────────
  window.bdOpenCandidate = function(id){
    if(!id) return;
    Promise.all([ apiGet('/candidates/'+id), apiGet('/candidates/'+id+'/history') ]).then(function(r){
      var hist = r[1] || { pipeline:[], submissions:[], activity:[] };
      STATE.bd.profile = { id:id, candidate:r[0]||{}, history:hist, selJob:null };
      // make sure jobs referenced by the history are navigable
      STATE.bd = STATE.bd || {}; STATE.bd.jobOrders = STATE.bd.jobOrders || [];
      (hist.pipeline||[]).concat(hist.submissions||[]).forEach(function(x){
        if(x.job && !STATE.bd.jobOrders.some(function(j){return j.id===x.job.id;})) STATE.bd.jobOrders.push(x.job);
      });
      goPage('bd_candidate');
    }).catch(function(e){ showToast('Failed to load candidate: '+e.message,'error'); });
  };
  window.bdReloadCandidateProfile = function(){
    if(STATE.page!=='bd_candidate' || !STATE.bd.profile) return;
    var id = STATE.bd.profile.id;
    Promise.all([ apiGet('/candidates/'+id), apiGet('/candidates/'+id+'/history') ]).then(function(r){
      STATE.bd.profile.candidate = r[0]||STATE.bd.profile.candidate;
      STATE.bd.profile.history = r[1]||STATE.bd.profile.history;
      render();
    }).catch(function(){});
  };

  // ── routing wrap ──────────────────────────────────────────────────────────
  var _prevRender = window.render;
  window.render = function(){
    _prevRender.apply(this, arguments);
    if (STATE.page === 'bd_candidate'){ paintProfile(); var t=document.querySelector('.tb-title'); if(t) t.textContent='Candidate'; }
  };
  var _prevGoPage = window.goPage;
  window.goPage = function(p){
    if (p === 'bd_candidate'){ STATE.page='bd_candidate'; STATE.modal=null; render(); return; }
    return _prevGoPage.apply(this, arguments);
  };
  function paintProfile(){ var c=document.getElementById('content'); if(!c) return; c.innerHTML = renderProfile(); }

  window.bdProfileSelectJob = function(jid){ if(STATE.bd.profile) STATE.bd.profile.selJob = jid; render(); };

  // ── lifecycle computation ──────────────────────────────────────────────────
  function computeMilestones(jobId){
    var h = STATE.bd.profile.history;
    var pipe = (h.pipeline||[]).find(function(p){ return p.job_order_id===jobId; });
    var sub = (h.submissions||[]).find(function(s){ return s.job_order_id===jobId; });
    var acts = sub ? (h.activity||[]).filter(function(a){ return a.submission_id===sub.id; }) : [];
    function actTime(stage){ var a=acts.find(function(x){ return x.new_stage===stage; }); return a?a.created_at:null; }
    var maxOrder = -1;
    if (sub){
      maxOrder = STAGE_ORDER[sub.stage]!=null ? STAGE_ORDER[sub.stage] : 0;
      acts.forEach(function(a){ if(STAGE_ORDER[a.new_stage]!=null && STAGE_ORDER[a.new_stage]>maxOrder) maxOrder=STAGE_ORDER[a.new_stage]; });
    }
    var rejected = sub && sub.stage==='Rejected';
    var onHold = sub && sub.stage==='On Hold';
    return MILESTONES.map(function(m){
      var reached=false, at=null;
      if (m.key==='pipeline'){ reached = !!pipe || !!sub; at = pipe?pipe.tagged_at:(sub?sub.created_at:null); }
      else if (m.key==='submission'){ reached = !!sub; at = sub?(sub.submitted_at||sub.created_at):null; }
      else if (m.key==='client'){ reached = !!sub && (!!sub.bdm_approved_at || maxOrder>=STAGE_ORDER['Submitted to Client']); at = sub?(sub.bdm_approved_at||actTime('Submitted to Client')):null; }
      else if (m.key==='notjoined'){ reached = !!sub && sub.stage==='Not Joined'; at = actTime('Not Joined'); }
      else { reached = !!sub && maxOrder>=STAGE_ORDER[m.stage]; at = actTime(m.stage); }
      return { label:m.label, reached:reached, at:at };
    }).concat(rejected?[{label:'Rejected',reached:true,at:actTime('Rejected'),bad:true}]:[])
      .concat(onHold?[{label:'On Hold',reached:true,at:null,warn:true}]:[]);
  }

  function lifecycleBar(jobId){
    var steps = computeMilestones(jobId);
    var nodes = steps.map(function(s,i){
      var color = s.bad?'var(--red)':(s.warn?'var(--amber)':(s.reached?'var(--green)':'var(--border2)'));
      var txtcol = s.reached?'var(--text)':'var(--text3)';
      return '<div style="flex:1;text-align:center;position:relative;min-width:70px">'+
        (i>0?'<div style="position:absolute;left:-50%;right:50%;top:9px;height:2px;background:'+(s.reached?'var(--green)':'var(--border2)')+'"></div>':'')+
        '<div style="width:18px;height:18px;border-radius:50%;background:'+color+';margin:0 auto 6px;position:relative;z-index:1;display:flex;align-items:center;justify-content:center;color:#fff;font-size:11px">'+(s.reached?'✓':'')+'</div>'+
        '<div style="font-size:11px;font-weight:600;color:'+txtcol+'">'+esc(s.label)+'</div>'+
        '<div style="font-size:10px;color:var(--text3);margin-top:2px">'+(s.at?esc(fmtDT(s.at)):'')+'</div>'+
      '</div>';
    }).join('');
    return '<div style="display:flex;align-items:flex-start;overflow-x:auto;padding:6px 4px">'+nodes+'</div>';
  }

  // ── the page ──────────────────────────────────────────────────────────────
  window.renderProfile = function(){
    var pr = STATE.bd.profile; if(!pr) return '<div class="page"><div style="padding:40px;text-align:center;color:var(--text3)">No candidate loaded.</div></div>';
    var c = pr.candidate||{}, h = pr.history||{pipeline:[],submissions:[],activity:[]};

    // jobs this candidate touches (union of pipeline + submissions)
    var jobMap = {};
    (h.pipeline||[]).forEach(function(p){ jobMap[p.job_order_id] = jobMap[p.job_order_id]||{ job:p.job, pipe:null, sub:null }; jobMap[p.job_order_id].pipe=p; });
    (h.submissions||[]).forEach(function(s){ jobMap[s.job_order_id] = jobMap[s.job_order_id]||{ job:s.job, pipe:null, sub:null }; jobMap[s.job_order_id].sub=s; });
    var jobs = Object.keys(jobMap).map(function(k){ return jobMap[k]; });
    var selJob = pr.selJob || (jobs[0] && (jobs[0].job&&jobs[0].job.id || jobs[0].job_order_id));
    if (selJob && !jobMap[selJob]) selJob = jobs[0] && jobs[0].job && jobs[0].job.id;

    function field(lbl,val){ return '<div style="margin-bottom:8px"><div style="font-size:10.5px;color:var(--text3);text-transform:uppercase;letter-spacing:.3px">'+lbl+'</div><div style="font-size:13px;color:var(--text)">'+esc(val||'—')+'</div></div>'; }

    var header =
      '<div class="card" style="padding:18px 20px;margin-bottom:16px">'+
        '<div style="display:flex;justify-content:space-between;align-items:flex-start">'+
          '<div>'+
            '<div style="display:flex;gap:8px;align-items:center;margin-bottom:4px">'+code(c.candidate_code||'')+
              '<span style="font-size:20px;font-weight:700">'+esc(c.full_name||'')+'</span>'+
              (c.applicant_status?'<span style="font-size:11px;font-weight:700;color:var(--accent);background:rgba(0,0,0,.04);padding:2px 8px;border-radius:10px">'+esc(c.applicant_status)+'</span>':'')+
            '</div>'+
            '<div style="font-size:13px;color:var(--text3)">'+esc(c.headline||c.current_title||'')+(c.current_employer?' · '+esc(c.current_employer):'')+'</div>'+
          '</div>'+
          '<button class="btn btn-sm btn-outline" onclick="atsOpenEdit(\''+c.id+'\')">Edit</button>'+
        '</div>'+
        '<div style="margin-top:14px;padding-top:14px;border-top:1px solid var(--border);display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px">'+
          field('Email',c.email)+field('Mobile',c.phone)+field('Work Authorization',c.work_authorization)+
          field('Location',loc(c))+field('Experience',c.experience_years!=null?c.experience_years+' yrs':'')+field('Source',c.source)+
          field('Availability',c.availability)+field('Notice Period',c.notice_period)+field('Current CTC',c.current_ctc)+
          field('Bill Rate',c.bill_rate)+field('Pay Rate',c.pay_rate)+field('Ownership',(c.owner&&c.owner.name)||'')+
        '</div>'+
        (c.skills?'<div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);font-size:12.5px"><span style="color:var(--text3)">Skills: </span>'+esc(c.skills)+'</div>':'')+
      '</div>';

    // lifecycle bar with a job selector
    var jobSel = jobs.length>1 ?
      '<select class="sel" style="max-width:320px" onchange="bdProfileSelectJob(this.value)">'+
        jobs.map(function(x){ var j=x.job||{}; return '<option value="'+esc(j.id)+'"'+(selJob===j.id?' selected':'')+'>'+esc((j.job_code?j.job_code+' · ':'')+(j.job_title||'')+(j.client?' — '+j.client:''))+'</option>'; }).join('')+
      '</select>' : (jobs.length===1 ? '<div style="font-size:12.5px;color:var(--text3)">'+esc((jobs[0].job&&jobs[0].job.job_code?jobs[0].job.job_code+' · ':'')+((jobs[0].job&&jobs[0].job.job_title)||''))+'</div>' : '');
    var lifecycle = jobs.length ?
      '<div class="card" style="padding:16px;margin-bottom:16px">'+
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><div style="font-weight:600;font-size:14px">Lifecycle</div>'+jobSel+'</div>'+
        lifecycleBar(selJob)+
      '</div>' :
      '<div class="card" style="padding:16px;margin-bottom:16px;color:var(--text3);font-size:13px">Not yet on any job. Tag this candidate to a job’s pipeline to begin.</div>';

    // pipelines & submissions table
    var rows = jobs.map(function(x){
      var j=x.job||{}, p=x.pipe, s=x.sub;
      return '<tr style="border-top:1px solid var(--border)">'+
        '<td style="padding:9px 10px;font-size:12.5px"><span style="cursor:pointer;color:var(--accent);font-weight:600" onclick="bdOpenSubmissions(\''+j.id+'\')">'+esc((j.job_code?j.job_code+' · ':'')+(j.job_title||''))+'</span><div style="font-size:11px;color:var(--text3)">'+esc(j.client||'')+'</div></td>'+
        '<td style="padding:9px 10px;font-size:12px">'+(p?code(p.pipeline_code||'')+' <span style="color:var(--text3)">'+esc(p.pipeline_status||'')+'</span>':'<span style="color:var(--text3)">—</span>')+'</td>'+
        '<td style="padding:9px 10px;font-size:12px">'+(s?code(s.submission_code||'')+' <span style="color:var(--text3)">'+esc(s.stage||'')+'</span>':'<span style="color:var(--text3)">—</span>')+'</td>'+
        '<td style="padding:9px 10px;white-space:nowrap">'+
          '<button class="btn btn-sm btn-outline" onclick="bdOpenPipeline(\''+j.id+'\')">Pipeline</button> '+
          '<button class="btn btn-sm btn-outline" onclick="bdOpenSubmissions(\''+j.id+'\')">Submissions</button>'+
        '</td>'+
      '</tr>';
    }).join('') || '<tr><td colspan="4" style="padding:24px;text-align:center;color:var(--text3)">No jobs yet.</td></tr>';
    var jobsCard =
      '<div class="card" style="padding:0;margin-bottom:16px;overflow-x:auto">'+
        '<div style="padding:14px 16px;font-weight:600;font-size:14px;border-bottom:1px solid var(--border)">Jobs ('+jobs.length+')</div>'+
        '<table style="width:100%;border-collapse:collapse;min-width:640px"><thead><tr style="background:var(--bg)">'+
          ['Job','Pipeline','Submission',''].map(function(hh){ return '<th style="text-align:left;padding:8px 10px;font-size:11px;color:var(--text3);font-weight:700">'+hh+'</th>'; }).join('')+
        '</tr></thead><tbody>'+rows+'</tbody></table>'+
      '</div>';

    // activity log
    var acts = (h.activity||[]).slice().sort(function(a,b){ return new Date(b.created_at)-new Date(a.created_at); });
    var actHtml = acts.map(function(a){
      var label = a.action==='promoted'?'Promoted to submission':a.action==='bdm_approved'?'BDM approved → client':a.action==='created'?'Submission created':(a.old_stage&&a.new_stage?'Moved '+a.old_stage+' → '+a.new_stage:(a.new_stage||a.action));
      return '<div style="display:flex;gap:10px;padding:8px 4px;border-bottom:1px solid var(--border)">'+
        '<div style="font-size:11px;color:var(--text3);white-space:nowrap;min-width:96px">'+esc(fmtDT(a.created_at))+'</div>'+
        '<div style="font-size:12.5px">'+esc(label)+(a.note?' — <span style="color:var(--text3)">'+esc(a.note)+'</span>':'')+'</div>'+
      '</div>';
    }).join('') || '<div style="padding:12px 4px;color:var(--text3);font-size:12.5px">No activity yet.</div>';
    var actCard = '<div class="card" style="padding:16px"><div style="font-weight:600;font-size:14px;margin-bottom:8px">Activity</div>'+actHtml+'</div>';

    return '<div class="page">'+
      '<div style="margin-bottom:6px"><span onclick="goPage(\'applicants\')" style="cursor:pointer;font-size:12.5px;color:var(--accent)">← Applicants</span></div>'+
      header + lifecycle + jobsCard + actCard +
    '</div>';
  };

})();

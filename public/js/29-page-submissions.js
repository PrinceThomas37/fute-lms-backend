// ===== JOB SUBMISSIONS GRID MODULE (additive) =====
// The Ceipal "Submissions" tab for a job order: candidates formally submitted
// (SB- ids) with the application-status lifecycle and the BDM gate on
// "Submitted to Client". Reached from the job detail, the pipeline page, and the
// recruiter board. Slice 3 of docs/ATS_RECRUITING_PLAN.md.

(function () {

  var SUB_STATUSES = ['Sourced','Screening','Submitted to BDM','Submitted to Client','Interview Scheduled',
    'Interview Completed','Offer','Confirmation','Placement','Rejected','Not Joined','On Hold'];
  var SUB_GATED = 'Submitted to Client';
  var SUB_COLORS = { 'Sourced':'var(--text3)','Screening':'#6b7280','Submitted to BDM':'var(--amber)',
    'Submitted to Client':'var(--accent)','Interview Scheduled':'#2563eb','Interview Completed':'#1d4ed8',
    'Offer':'#7c3aed','Confirmation':'#0891b2','Placement':'var(--green)','Rejected':'var(--red)',
    'Not Joined':'#b91c1c','On Hold':'#9ca3af' };
  var REVISION_STATUSES = ['N/A','Revised','Reformatted','Rejected by BDM'];

  if (STATE.bd) { STATE.bd.submissions = STATE.bd.submissions || []; STATE.bd.view = STATE.bd.view || {}; }

  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function code(t){ return '<span style="font-family:var(--mono);font-size:11px;color:var(--accent);font-weight:700">'+esc(t)+'</span>'; }
  function isBDM(u){ return userHasAnyRole(u,'admin','bd','bd_lead'); }
  function isRec(u){ return userHasRole(u,'recruiter'); }
  function joById(id){ return (STATE.bd.jobOrders||[]).find(function(j){ return j.id===id; }); }
  function fmtDate(s){ if(!s)return '—'; try{ var d=new Date(s); return (d.getMonth()+1)+'/'+d.getDate()+'/'+String(d.getFullYear()).slice(2); }catch(e){ return '—'; } }
  function candLoc(c){ return [c.city,c.state].filter(Boolean).join(', ') || c.current_location || '—'; }

  function loadSubs(jid){
    return apiGet('/job-orders/'+jid+'/submissions').then(function(d){ STATE.bd.submissions = d||[]; })
      .catch(function(e){ STATE.bd.submissions = []; showToast('Failed to load submissions: '+e.message,'error'); });
  }

  var _prevRender = window.render;
  window.render = function(){
    _prevRender.apply(this, arguments);
    if (STATE.page === 'bd_submissions'){
      paintSubmissionsPage();
      var t = document.querySelector('.tb-title'); if (t) t.textContent = 'Submissions';
    }
  };
  var _prevGoPage = window.goPage;
  window.goPage = function(p){
    if (p === 'bd_submissions'){ STATE.page='bd_submissions'; STATE.modal=null; render(); return; }
    return _prevGoPage.apply(this, arguments);
  };

  window.bdOpenSubmissions = function(jid){
    STATE.bd.view = STATE.bd.view || {}; STATE.bd.view.submissionsJoId = jid;
    loadSubs(jid).then(function(){ goPage('bd_submissions'); });
  };
  window.bdReloadSubmissions = function(){
    var jid = STATE.bd.view && STATE.bd.view.submissionsJoId; if(!jid) return;
    loadSubs(jid).then(function(){ render(); });
  };

  function paintSubmissionsPage(){ var c=document.getElementById('content'); if(!c) return; c.innerHTML = renderSubmissionsPage(); }

  window.renderSubmissionsPage = function(){
    var u = STATE.user;
    var jid = STATE.bd.view && STATE.bd.view.submissionsJoId;
    var j = joById(jid);
    if (!j) return '<div class="page"><div style="padding:40px;text-align:center;color:var(--text3)">Job not found.</div></div>';
    var rows = (STATE.bd.submissions||[]).filter(function(s){ return s.job_order_id===jid; });
    var back = isBDM(u) ? 'bd_joborders' : 'bd_myjobs';
    var recruiterScoped = isRec(u) && !isBDM(u);

    var tabs =
      '<div style="display:flex;gap:4px;border-bottom:1px solid var(--border);margin-bottom:14px">'+
        '<div style="padding:8px 16px;font-size:13px;font-weight:600;color:var(--text3);cursor:pointer" onclick="bdOpenPipeline(\''+j.id+'\')">Pipeline</div>'+
        '<div style="padding:8px 16px;font-size:13px;font-weight:700;color:var(--accent);border-bottom:2px solid var(--accent)">Submissions ('+rows.length+')</div>'+
        '<div style="padding:8px 16px;font-size:13px;font-weight:600;color:var(--text3);cursor:pointer" onclick="bdOpenKanban(\''+j.id+'\')">Board</div>'+
        (isBDM(u)?'<div style="padding:8px 16px;font-size:13px;font-weight:600;color:var(--text3);cursor:pointer" onclick="bdOpenJobOrder(\''+j.id+'\')">Job details</div>':'')+
      '</div>';

    var head = ['Submission ID','Applicant Name','Work Auth','Mobile','Location','Country','Exp','Source','Resume',
      'Revision','Application Status','Bill Rate','Pay Rate','Employer','Availability','Notice','Submitted By','Submitted On','']
      .map(function(h){ return '<th style="text-align:left;padding:8px 9px;font-size:11px;color:var(--text3);font-weight:700;white-space:nowrap">'+h+'</th>'; }).join('');

    var body = rows.map(function(s){
      var c = s.candidate || {};
      var opts = SUB_STATUSES.filter(function(x){ return !(x===SUB_GATED && recruiterScoped && s.stage!==SUB_GATED); });
      var statusSel = '<select class="sel" style="font-size:11px;padding:3px 6px;min-width:150px;color:'+(SUB_COLORS[s.stage]||'var(--text2)')+';font-weight:600" onchange="sbSetStatus(\''+s.id+'\',this.value)">'+
        opts.map(function(x){ return '<option value="'+esc(x)+'"'+(s.stage===x?' selected':'')+'>'+esc(x)+'</option>'; }).join('')+'</select>';
      var resume = c.resume_url ? '<a href="'+esc(c.resume_url)+'" target="_blank" rel="noopener" style="color:var(--accent)">↗</a>' : '—';
      return '<tr style="border-top:1px solid var(--border)">'+
        '<td style="padding:8px 9px;white-space:nowrap">'+code(s.submission_code||'—')+'</td>'+
        '<td style="padding:8px 9px;white-space:nowrap;font-size:12.5px"><span style="font-weight:600;cursor:pointer;color:var(--accent)" onclick="bdOpenCandidate(\''+c.id+'\')">'+esc(c.full_name||'—')+'</span> '+(c.candidate_code?'<span style="font-size:10px;color:var(--text3)">'+esc(c.candidate_code)+'</span>':'')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(c.work_authorization||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(c.phone||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px">'+esc(candLoc(c))+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(c.country||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(c.experience_years!=null?c.experience_years:'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(c.source||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:14px;text-align:center">'+resume+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(s.revision_status||'N/A')+'</td>'+
        '<td style="padding:8px 9px">'+statusSel+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(s.bill_rate||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(s.pay_rate||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px">'+esc(s.employer_name||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(s.availability||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc(s.notice_period||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;white-space:nowrap">'+esc((s.submitter&&s.submitter.name)||(s.recruiter&&s.recruiter.name)||'—')+'</td>'+
        '<td style="padding:8px 9px;font-size:12px;color:var(--text3);white-space:nowrap">'+fmtDate(s.submitted_at||s.created_at)+'</td>'+
        '<td style="padding:8px 9px;white-space:nowrap">'+
          '<button class="btn btn-sm btn-outline" onclick="sbOpenEdit(\''+s.id+'\')">Edit</button>'+
          ' <button class="btn btn-sm btn-outline" style="color:var(--red)" onclick="sbRemove(\''+s.id+'\')">✕</button>'+
        '</td>'+
      '</tr>';
    }).join('');
    if (!rows.length) body = '<tr><td colspan="19" style="padding:40px;text-align:center;color:var(--text3)">No submissions yet. '+
      'Promote a candidate from the <span style="color:var(--accent);cursor:pointer" onclick="bdOpenPipeline(\''+j.id+'\')">Pipeline →</span></td></tr>';

    return '<div class="page">'+
      '<div style="margin-bottom:6px"><span onclick="goPage(\''+back+'\')" style="cursor:pointer;font-size:12.5px;color:var(--accent)">← Jobs</span></div>'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">'+
        '<div><div style="display:flex;gap:8px;align-items:center">'+code(j.job_code)+'<span style="font-weight:700;font-size:17px">'+esc(j.job_title||'')+'</span></div>'+
        '<div style="font-size:12.5px;color:var(--text3)">'+esc(j.client||'')+'</div></div>'+
      '</div>'+
      tabs+
      '<div class="card" style="padding:0;overflow-x:auto"><table style="width:100%;border-collapse:collapse;min-width:1600px">'+
        '<thead><tr style="background:var(--bg)">'+head+'</tr></thead><tbody>'+body+'</tbody></table></div>'+
    '</div>';
  };

  window.sbSetStatus = function(id, status){
    var u = STATE.user;
    if (status===SUB_GATED && isRec(u) && !isBDM(u)){ showToast('Only a BD Manager can submit to the client','error'); render(); return; }
    apiPatch('/submissions/'+id+'/stage', { stage:status }).then(function(s){
      STATE.bd.submissions = (STATE.bd.submissions||[]).map(function(x){ return x.id===id?s:x; });
      showToast('Status → '+status,'success'); render();
    }).catch(function(e){ showToast('Failed: '+e.message,'error'); render(); });
  };
  window.sbRemove = function(id){
    if (!confirm('Remove this submission?')) return;
    apiDelete('/submissions/'+id).then(function(){ showToast('Submission removed','info'); bdReloadSubmissions(); })
      .catch(function(e){ showToast('Failed: '+e.message,'error'); });
  };

  window.sbOpenEdit = function(id){
    var s = (STATE.bd.submissions||[]).find(function(x){ return x.id===id; }); if(!s) return;
    STATE.bd._sbEdit = Object.assign({}, s);
    var f = STATE.bd._sbEdit;
    function inp(label,key){ return '<div><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">'+label+'</label>'+
      '<input class="sel" value="'+esc(f[key]||'')+'" oninput="sbEditSet(\''+key+'\',this.value)"></div>'; }
    var revSel = '<div><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">Revision Status</label>'+
      '<select class="sel" onchange="sbEditSet(\'revision_status\',this.value)">'+
      REVISION_STATUSES.map(function(r){ return '<option value="'+esc(r)+'"'+((f.revision_status||'N/A')===r?' selected':'')+'>'+esc(r)+'</option>'; }).join('')+'</select></div>';
    STATE.modal =
      '<div class="modal modal-w560" onclick="event.stopPropagation()">'+
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border);font-weight:700;font-size:15px">Edit Submission '+code(s.submission_code||'')+'</div>'+
        '<div style="padding:18px 20px"><div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">'+
          revSel+inp('Employer','employer_name')+
          inp('Bill Rate','bill_rate')+inp('Pay Rate','pay_rate')+
          inp('Availability','availability')+inp('Notice Period','notice_period')+
        '</div>'+
        '<div style="margin-top:12px"><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">Notes</label>'+
          '<textarea class="sel" style="min-height:56px;resize:vertical" oninput="sbEditSet(\'notes\',this.value)">'+esc(f.notes||'')+'</textarea></div>'+
        '</div>'+
        '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px">'+
          '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
          '<button class="btn btn-primary" onclick="sbSaveEdit(\''+id+'\')">Save</button>'+
        '</div>'+
      '</div>';
    render();
  };
  window.sbEditSet = function(k,v){ STATE.bd._sbEdit = STATE.bd._sbEdit||{}; STATE.bd._sbEdit[k]=v; };
  window.sbSaveEdit = function(id){
    var f = STATE.bd._sbEdit||{};
    apiPatch('/submissions/'+id, {
      revision_status:f.revision_status, employer_name:f.employer_name, bill_rate:f.bill_rate,
      pay_rate:f.pay_rate, availability:f.availability, notice_period:f.notice_period, notes:f.notes
    }).then(function(s){
      STATE.bd.submissions = (STATE.bd.submissions||[]).map(function(x){ return x.id===id?s:x; });
      showToast('Updated','success'); closeModal();
    }).catch(function(e){ showToast('Failed: '+e.message,'error'); });
  };

})();

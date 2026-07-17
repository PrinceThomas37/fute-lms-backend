// ===== JOB PIPELINE (TAGGING) MODULE (additive) =====
// The Ceipal "Pipeline" tab for a job order: candidates TAGGED to the job (a
// lightweight sourcing bucket, PL- ids) before being promoted to a formal
// submission. Reached from the BD job detail and the recruiter board. Slice 2 of
// docs/ATS_RECRUITING_PLAN.md.

(function () {

  var PIPELINE_STATUSES = ['Tagged','Contacted','Interested','Screening','Shortlisted','Moved to Submission','Not Interested','Rejected'];
  var PSTATUS_COLORS = { 'Tagged':'var(--text3)','Contacted':'#6b7280','Interested':'#2563eb','Screening':'var(--amber)',
    'Shortlisted':'#7c3aed','Moved to Submission':'var(--green)','Not Interested':'#9ca3af','Rejected':'var(--red)' };

  if (STATE.bd) { STATE.bd.pipeline = STATE.bd.pipeline || []; STATE.bd.view = STATE.bd.view || {}; }

  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function code(t){ return '<span style="font-family:var(--mono);font-size:11px;color:var(--accent);font-weight:700">'+esc(t)+'</span>'; }
  function isBDM(u){ return userHasAnyRole(u,'admin','bd','bd_lead'); }
  function isRec(u){ return userHasRole(u,'recruiter'); }
  function joById(id){ return (STATE.bd.jobOrders||[]).find(function(j){ return j.id===id; }); }
  function fmtDate(s){ if(!s)return '—'; try{ var d=new Date(s); return (d.getMonth()+1)+'/'+d.getDate()+'/'+String(d.getFullYear()).slice(2); }catch(e){ return '—'; } }
  function candLoc(c){ return [c.city,c.state].filter(Boolean).join(', ') || c.current_location || '—'; }

  function loadPipeline(jid){
    return apiGet('/job-orders/'+jid+'/pipeline').then(function(d){ STATE.bd.pipeline = d||[]; })
      .catch(function(e){ STATE.bd.pipeline = []; showToast('Failed to load pipeline: '+e.message,'error'); });
  }

  // ── render + routing wrap (mirrors the applicants module) ────────────────────
  var _prevRender = window.render;
  window.render = function(){
    _prevRender.apply(this, arguments);
    if (STATE.page === 'bd_pipeline'){
      paintPipelinePage();
      var t = document.querySelector('.tb-title'); if (t) t.textContent = 'Pipeline';
    }
  };
  var _prevGoPage = window.goPage;
  window.goPage = function(p){
    if (p === 'bd_pipeline'){ STATE.page='bd_pipeline'; STATE.modal=null; render(); return; }
    return _prevGoPage.apply(this, arguments);
  };

  window.bdOpenPipeline = function(jid){
    STATE.bd.view = STATE.bd.view || {}; STATE.bd.view.pipelineJoId = jid;
    loadPipeline(jid).then(function(){ goPage('bd_pipeline'); });
  };
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

    var tabs =
      '<div style="display:flex;gap:4px;border-bottom:1px solid var(--border);margin-bottom:14px">'+
        '<div style="padding:8px 16px;font-size:13px;font-weight:700;color:var(--accent);border-bottom:2px solid var(--accent)">Pipeline ('+rows.length+')</div>'+
        '<div style="padding:8px 16px;font-size:13px;font-weight:600;color:var(--text3);cursor:pointer" onclick="bdOpenSubmissions(\''+j.id+'\')">Submissions</div>'+
        '<div style="padding:8px 16px;font-size:13px;font-weight:600;color:var(--text3);cursor:pointer" onclick="bdOpenKanban(\''+j.id+'\')">Board</div>'+
        (isBDM(u)?'<div style="padding:8px 16px;font-size:13px;font-weight:600;color:var(--text3);cursor:pointer" onclick="bdOpenJobOrder(\''+j.id+'\')">Job details</div>':'')+
      '</div>';

    var head = ['Pipeline ID','Applicant Name','Pipeline Status','Work Auth','Mobile','Location','Country','Exp','Source','Resume',
      'Bill Rate','Pay Rate','Employer','Availability','Notice','Current CTC','Tagged By','Tagged On','']
      .map(function(h){ return '<th style="text-align:left;padding:8px 9px;font-size:11px;color:var(--text3);font-weight:700;white-space:nowrap">'+h+'</th>'; }).join('');

    var body = rows.map(function(p){
      var c = p.candidate || {};
      var statusSel = '<select class="sel" style="font-size:11px;padding:3px 6px;min-width:120px;color:'+(PSTATUS_COLORS[p.pipeline_status]||'var(--text2)')+';font-weight:600" onchange="plSetStatus(\''+p.id+'\',this.value)">'+
        PIPELINE_STATUSES.map(function(s){ return '<option value="'+esc(s)+'"'+(p.pipeline_status===s?' selected':'')+'>'+esc(s)+'</option>'; }).join('')+'</select>';
      var resume = c.resume_url ? '<a href="'+esc(c.resume_url)+'" target="_blank" rel="noopener" style="color:var(--accent)">↗</a>' : '—';
      var promoted = !!p.submission_id;
      return '<tr style="border-top:1px solid var(--border)">'+
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
          (promoted
            ? '<span style="font-size:11px;color:var(--green);font-weight:700">✓ Submitted</span>'
            : '<button class="btn btn-sm btn-primary" onclick="plPromote(\''+p.id+'\')">Promote</button>')+
          ' <button class="btn btn-sm btn-outline" onclick="plOpenEdit(\''+p.id+'\')">Edit</button>'+
          ' <button class="btn btn-sm btn-outline" style="color:var(--red)" onclick="plRemove(\''+p.id+'\')">✕</button>'+
        '</td>'+
      '</tr>';
    }).join('');
    if (!rows.length) body = '<tr><td colspan="19" style="padding:40px;text-align:center;color:var(--text3)">No candidates tagged yet. '+
      '<span style="color:var(--accent);cursor:pointer" onclick="plOpenAdd(\''+j.id+'\')">Add to pipeline →</span></td></tr>';

    return '<div class="page">'+
      '<div style="margin-bottom:6px"><span onclick="goPage(\''+back+'\')" style="cursor:pointer;font-size:12.5px;color:var(--accent)">← Jobs</span></div>'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">'+
        '<div><div style="display:flex;gap:8px;align-items:center">'+code(j.job_code)+'<span style="font-weight:700;font-size:17px">'+esc(j.job_title||'')+'</span></div>'+
        '<div style="font-size:12.5px;color:var(--text3)">'+esc(j.client||'')+'</div></div>'+
        '<button class="btn btn-primary" onclick="plOpenAdd(\''+j.id+'\')">+ Add to Pipeline</button>'+
      '</div>'+
      tabs+
      '<div class="card" style="padding:0;overflow-x:auto"><table style="width:100%;border-collapse:collapse;min-width:1500px">'+
        '<thead><tr style="background:var(--bg)">'+head+'</tr></thead><tbody>'+body+'</tbody></table></div>'+
    '</div>';
  };

  // ── inline status / promote / remove ────────────────────────────────────────
  window.plSetStatus = function(id, status){
    apiPatch('/pipeline/'+id+'/status', { status:status }).then(function(p){
      STATE.bd.pipeline = (STATE.bd.pipeline||[]).map(function(x){ return x.id===id?p:x; });
      showToast('Status → '+status,'success'); render();
    }).catch(function(e){ showToast('Failed: '+e.message,'error'); render(); });
  };
  window.plPromote = function(id){
    apiPost('/pipeline/'+id+'/promote', {}).then(function(r){
      if (r && r.already) showToast('Already submitted','info'); else showToast('Promoted to submission','success');
      bdReloadPipeline();
    }).catch(function(e){ showToast('Failed: '+e.message,'error'); });
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

  // ── add to pipeline: search the pool or quick-create (with dedup) ────────────
  window.plOpenAdd = function(jid){
    STATE.bd._plAddJob = jid; STATE.bd._plSearchQ=''; STATE.bd._plDup=[];
    apiGet('/candidates').then(function(pool){ STATE.bd._plPool = pool||[]; plShowAddModal(jid); })
      .catch(function(){ STATE.bd._plPool=[]; plShowAddModal(jid); });
  };
  window.plSearch = function(jid, q){
    STATE.bd._plSearchQ = q;
    apiGet('/candidates'+(q?'?q='+encodeURIComponent(q):'')).then(function(pool){ STATE.bd._plPool=pool||[]; plShowAddModal(jid); })
      .catch(function(){ STATE.bd._plPool=[]; plShowAddModal(jid); });
  };
  function plShowAddModal(jid){
    var taggedCids = (STATE.bd.pipeline||[]).filter(function(p){ return p.job_order_id===jid; }).map(function(p){ return p.candidate_id; });
    var pool = (STATE.bd._plPool||[]).filter(function(c){ return taggedCids.indexOf(c.id)<0; });
    var q = STATE.bd._plSearchQ||'';
    var poolHtml = pool.map(function(c){
      return '<div style="display:flex;justify-content:space-between;align-items:center;border:1px solid var(--border);border-radius:8px;padding:8px 11px;margin-bottom:6px">'+
        '<div><div style="font-weight:600;font-size:13px">'+esc(c.full_name)+' '+code(c.candidate_code||'')+'</div>'+
        '<div style="font-size:11px;color:var(--text3)">'+esc(c.current_title||c.headline||'')+(c.email?' · '+esc(c.email):'')+'</div></div>'+
        '<button class="btn btn-sm btn-primary" onclick="plTag(\''+jid+'\',\''+c.id+'\')">Tag</button>'+
      '</div>';
    }).join('') || '<div style="color:var(--text3);font-size:12.5px;padding:8px">No matching candidates.</div>';

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
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border);font-weight:700;font-size:16px">Add to Pipeline</div>'+
        '<div style="padding:18px 20px">'+
          dup+
          '<input class="sel" placeholder="Search name, email, CN- code…" value="'+esc(q)+'" oninput="plSearch(\''+jid+'\',this.value)" style="margin-bottom:12px">'+
          '<div style="max-height:30vh;overflow-y:auto">'+poolHtml+'</div>'+
          '<div style="border-top:1px solid var(--border);margin-top:12px;padding-top:12px">'+
            '<div style="font-size:11px;font-weight:700;color:var(--text3);margin-bottom:8px">OR CREATE NEW</div>'+
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">'+
              '<input id="pl_name" class="sel" placeholder="Full name">'+
              '<input id="pl_email" class="sel" placeholder="Email">'+
              '<input id="pl_phone" class="sel" placeholder="Mobile">'+
              '<input id="pl_title" class="sel" placeholder="Current title">'+
            '</div>'+
            '<button class="btn btn-primary btn-sm" style="margin-top:9px" onclick="plQuickCreate(\''+jid+'\',false)">Create & Tag</button>'+
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
    var name=(document.getElementById('pl_name')||{}).value||STATE.bd._plNewName||'';
    var email=(document.getElementById('pl_email')||{}).value||STATE.bd._plNewEmail||'';
    var phone=(document.getElementById('pl_phone')||{}).value||STATE.bd._plNewPhone||'';
    var title=(document.getElementById('pl_title')||{}).value||'';
    if (!name.trim()){ showToast('Name required','error'); return; }
    STATE.bd._plNewName=name; STATE.bd._plNewEmail=email; STATE.bd._plNewPhone=phone;   // preserve across dup re-render
    var payload = { full_name:name, email:email, phone:phone, current_title:title, source:'Manual' };
    if (force) payload.force = true;
    apiPost('/candidates', payload).then(function(c){
      STATE.bd._plDup=[]; STATE.bd._plNewName=STATE.bd._plNewEmail=STATE.bd._plNewPhone='';
      plTag(jid, c.id);
    }).catch(function(e){
      if (/possible_duplicate/i.test(e.message)){
        apiGet('/candidates/check-duplicate?full_name='+encodeURIComponent(name)+'&email='+encodeURIComponent(email)+'&phone='+encodeURIComponent(phone))
          .then(function(r){ STATE.bd._plDup=(r&&r.duplicates)||[]; plShowAddModal(jid); showToast('Possible duplicate — review','info'); })
          .catch(function(){ showToast('Duplicate check failed','error'); });
      } else showToast('Failed: '+e.message,'error');
    });
  };

})();

// ===== STAGE-CHANGE MODAL (shared, additive) =====
// Every stage move (kanban, submissions grid, BD job detail, bulk) runs through
// this modal: pick a sub-stage (4–5 per stage), add a note, set the interview
// date/time + location for interview stages, and optionally drop a
// reminder-to-call into the existing reminders system.

(function () {

  var SUB_STAGES = {
    'Sourced':              ['New','Attempted Contact','Contacted','Left Message','Not Reachable'],
    'Screening':            ['Scheduled','In Progress','Passed','Failed','No Show'],
    'Submitted to BDM':     ['Under Review','Needs Revision','Approved','Sent Back'],
    'Submitted to Client':  ['Awaiting Feedback','Shortlisted','Feedback Received','Rejected by Client'],
    'Interview Scheduled':  ['Round 1','Round 2','Round 3','Final Round','Rescheduled'],
    'Interview Completed':  ['Awaiting Feedback','Positive','Negative','Next Round Planned'],
    'Offer':                ['Preparing','Extended','Negotiating','Accepted','Declined'],
    'Confirmation':         ['Docs Pending','BGV In Progress','Cleared','Start Date Confirmed'],
    'Placement':            ['Started','Active','Completed','Extended'],
    'Rejected':             ['By Client','By BDM','Candidate Withdrew','Position Closed'],
    'Not Joined':           ['No Show','Accepted Elsewhere','Personal Reasons','Counter-Offered'],
    'On Hold':              ['Client Hold','Candidate Hold','Position Hold']
  };
  window.ATS_SUB_STAGES = SUB_STAGES;

  // Full ordered stage list + colors — the single vocabulary every surface
  // (pipeline, submissions grid, board, job detail) now shares.
  var STAGE_LIST = ['Sourced','Screening','Submitted to BDM','Submitted to Client','Interview Scheduled','Interview Completed','Offer','Confirmation','Placement','Rejected','Not Joined','On Hold'];
  window.ATS_STAGE_LIST = STAGE_LIST;
  var STAGE_COLORS = {'Sourced':'var(--text3)','Screening':'#6b7280','Submitted to BDM':'var(--amber)','Submitted to Client':'var(--accent)','Interview Scheduled':'#2563eb','Interview Completed':'#1d4ed8','Offer':'#7c3aed','Confirmation':'#0891b2','Placement':'var(--green)','Rejected':'var(--red)','Not Joined':'#b91c1c','On Hold':'#9ca3af'};
  window.ATS_STAGE_COLORS = STAGE_COLORS;

  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function isInterviewStage(st){ return /^Interview/.test(st); }

  // openStageModal(idOrIds, newStage, onDone)
  //   idOrIds — one submission id or an array (bulk change)
  //   onDone  — called with the updated submission(s) after save
  window.openStageModal = function (idOrIds, newStage, onDone) {
    var ids = Array.isArray(idOrIds) ? idOrIds : [idOrIds];
    if (!ids.length || !newStage) return;
    var u = STATE.user;
    var recruiterScoped = userHasRole(u,'recruiter') && !userHasAnyRole(u,'admin','bd','bd_lead');
    var subs = (STATE.bd && STATE.bd.submissions) || [];

    // Recruiters own the stages up to "Submitted to BDM". Everything after —
    // client submission, interview scheduling, offer, placement, rejection —
    // is BD's; recruiters see those stages but can't change them.
    var RECRUITER_STAGES = ['Sourced','Screening','Submitted to BDM'];
    if (recruiterScoped) {
      if (RECRUITER_STAGES.indexOf(newStage) < 0) {
        showToast('You can move candidates up to "Submitted to BDM" — the BD team owns the stages after that','error'); render(); return;
      }
      var locked = ids.filter(function(id){
        var s = subs.find(function(x){ return x.id===id; });
        return s && RECRUITER_STAGES.indexOf(s.stage) < 0;
      });
      if (locked.length) {
        showToast('That candidate is with the BD team now — only a BD Manager can change this stage','error'); render(); return;
      }
      if (newStage === 'Submitted to BDM') {
        if (ids.length > 1) { showToast('Submit candidates to the BD Manager one at a time — each needs its own submission details','error'); render(); return; }
        openSubmitToBDMModal(ids[0], onDone); return;
      }
    }
    var names = ids.map(function(id){ var s=subs.find(function(x){return x.id===id;})||{}; return (s.candidate&&s.candidate.full_name)||''; }).filter(Boolean);
    var subStages = SUB_STAGES[newStage] || [];
    var showInterview = isInterviewStage(newStage);

    // Confirmation line: show exactly what's changing — [current] → [target] —
    // so a stage move never happens without the user seeing where it goes.
    var curStage = '';
    if (ids.length === 1) { var s0 = subs.find(function(x){ return x.id===ids[0]; }); curStage = (s0 && s0.stage) || ''; }
    var arrow = '<span style="color:var(--text3)">'+(curStage?esc(curStage):'—')+'</span>'+
      ' <span style="color:var(--text3)">→</span> '+
      '<span style="font-weight:700;color:'+(STAGE_COLORS[newStage]||'var(--text)')+'">'+esc(newStage)+'</span>';

    STATE._stageMove = { ids: ids, stage: newStage, onDone: onDone || null };
    STATE.modal =
      '<div class="modal modal-w480" onclick="event.stopPropagation()">'+
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border)">'+
          '<div style="font-weight:700;font-size:15px">'+
            (ids.length>1 ? 'Move '+ids.length+' candidates' : esc(names[0]||'Candidate'))+
          '</div>'+
          '<div style="font-size:13px;margin-top:3px">'+arrow+'</div>'+
        '</div>'+
        '<div style="padding:16px 20px">'+
          (subStages.length?
            '<div style="margin-bottom:12px"><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">Sub-stage</label>'+
            '<select id="stg-sub" class="sel"><option value="">— none —</option>'+
              subStages.map(function(s){ return '<option value="'+esc(s)+'">'+esc(s)+'</option>'; }).join('')+
            '</select></div>':'')+
          (showInterview?
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px">'+
              '<div><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">Interview date &amp; time</label>'+
                '<input id="stg-iv-at" type="datetime-local" class="sel"></div>'+
              '<div><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">Location / meeting link</label>'+
                '<input id="stg-iv-loc" class="sel" placeholder="Office, Zoom link, phone…"></div>'+
            '</div>':'')+
          (newStage==='Rejected'?
            '<div style="margin-bottom:12px"><label style="font-size:11px;color:var(--red);display:block;margin-bottom:3px;font-weight:700">Reason for rejection (required)</label>'+
            '<textarea id="stg-reject" class="sel" style="min-height:56px;resize:vertical" placeholder="Client feedback, BDM decision, position closed…"></textarea></div>':'')+
          '<div style="margin-bottom:12px"><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">Note <span style="color:var(--red)">*</span></label>'+
            '<textarea id="stg-note" class="sel" style="min-height:56px;resize:vertical" placeholder="Why is this candidate moving? (call summary, feedback, next step…)"></textarea></div>'+
          '<label style="font-size:12.5px;color:var(--text2);display:flex;align-items:center;gap:7px;cursor:pointer;margin-bottom:8px">'+
            '<input type="checkbox" id="stg-rem" onchange="document.getElementById(\'stg-rem-fields\').style.display=this.checked?\'grid\':\'none\'"> Set a reminder to call / follow up'+
          '</label>'+
          '<div id="stg-rem-fields" style="display:none;grid-template-columns:1fr 1fr;gap:10px">'+
            '<div><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">Remind on</label>'+
              '<input id="stg-rem-date" type="date" class="sel"></div>'+
            '<div><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">Reminder note</label>'+
              '<input id="stg-rem-note" class="sel" placeholder="Call about…"></div>'+
          '</div>'+
        '</div>'+
        '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px">'+
          '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
          '<button class="btn btn-primary" onclick="stgApply()">Move'+(ids.length>1?' ('+ids.length+')':'')+'</button>'+
        '</div>'+
      '</div>';
    render();
  };

  window.stgApply = function () {
    var mv = STATE._stageMove; if (!mv) return;
    var val = function(id){ var el=document.getElementById(id); return el?el.value:''; };
    var remOn = (document.getElementById('stg-rem')||{}).checked;
    // Notes are required on every stage change (product rule) — capture the
    // "why" behind each move so the candidate's history reads as a story.
    var note = val('stg-note').trim();
    if (!note) { showToast('Please add a note describing this stage change','error'); var nEl=document.getElementById('stg-note'); if(nEl)nEl.focus(); return; }
    var payload = { stage: mv.stage, sub_stage: val('stg-sub') || undefined, note: note };
    if (mv.stage === 'Rejected') {
      var rr = val('stg-reject');
      if (!rr.trim()) { showToast('Please add the reason for rejection','error'); return; }
      payload.rejection_reason = rr.trim();
    }
    if (document.getElementById('stg-iv-at')) {
      payload.interview_at = val('stg-iv-at') || undefined;
      payload.interview_location = val('stg-iv-loc') || undefined;
    }
    if (remOn && val('stg-rem-date')) { payload.reminder_date = val('stg-rem-date'); payload.reminder_note = val('stg-rem-note') || undefined; }

    var updated = [], failed = 0;
    var finish = function(){
      closeModal();
      if (failed) showToast('Moved '+updated.length+', failed '+failed,'error');
      else showToast('Moved to "'+mv.stage+'"'+(updated.length>1?' ('+updated.length+')':''),'success');
      // patch local state for whichever grid is open
      if (STATE.bd && STATE.bd.submissions) {
        STATE.bd.submissions = STATE.bd.submissions.map(function(s){
          var u = updated.find(function(x){ return x.id===s.id; }); return u || s;
        });
      }
      if (mv.onDone) mv.onDone(updated);
      STATE._stageMove = null;
      render();
    };
    Promise.all(mv.ids.map(function(id){
      return apiPatch('/submissions/'+id+'/stage', payload)
        .then(function(s){ updated.push(s); })
        .catch(function(){ failed++; });
    })).then(finish);
  };

  // ═══ SUBMIT TO BD MANAGER — the hand-off form ═══════════════════════════
  // Mirrors the client-facing submission template: applicant details,
  // relocation, availability, the (important) submission comment, and the
  // resume. On submit the stage moves to "Submitted to BDM" with the details
  // stored on the submission for the BDM to forward.
  window.openSubmitToBDMModal = function (subId, onDone) {
    var subs = (STATE.bd && STATE.bd.submissions) || [];
    var sub = subs.find(function(x){ return x.id===subId; }) || {};
    var candId = (sub.candidate && sub.candidate.id) || sub.candidate_id;
    if (!candId) { showToast('Candidate not found on this submission','error'); return; }

    apiGet('/candidates/'+candId).then(function(c){
      c = c || {};
      var names = String(c.full_name||'').trim().split(/\s+/);
      var first = c.first_name || names[0] || '';
      var last  = c.last_name || names.slice(1).join(' ') || '';
      var locFallback = [c.city,c.state].filter(Boolean).join(', ');

      function fld(id,label,valv,ph,req){
        return '<div><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">'+label+(req?' <span style="color:var(--red)">*</span>':'')+'</label>'+
          '<input id="'+id+'" class="sel" value="'+esc(valv||'')+'" placeholder="'+esc(ph||'')+'"></div>';
      }

      STATE._sbdm = { subId: subId, candId: candId, onDone: onDone||null, file: null };
      STATE.modal =
        '<div class="modal" style="width:600px;max-width:94vw" onclick="event.stopPropagation()">'+
          '<div style="padding:16px 20px;border-bottom:1px solid var(--border)">'+
            '<div style="font-weight:700;font-size:15px">Submit to BD Manager</div>'+
            '<div style="font-size:12px;color:var(--text3);margin-top:2px">'+esc(c.full_name||'Candidate')+' — these details go to the BDM with the profile</div>'+
          '</div>'+
          '<div style="padding:16px 20px;max-height:62vh;overflow:auto">'+
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">'+
              fld('sbdm-first','Applicant First Name',first,'',true)+
              fld('sbdm-last','Applicant Last Name',last,'',true)+
              fld('sbdm-email','Applicant Email Address',c.email,'',true)+
              fld('sbdm-mobile','Mobile Number',c.phone,'')+
              fld('sbdm-home','Home Phone',c.alt_phone,'N/A')+
              fld('sbdm-auth','Work Authorization',c.work_authorization,'N/A')+
              fld('sbdm-loc','Current Location',c.current_location||locFallback,'City, State')+
              fld('sbdm-reloc','Relocation','','Willing to relocate to…')+
              fld('sbdm-avail','Availability',c.availability,'asap / 2 weeks…')+
            '</div>'+
            '<div style="margin-bottom:12px"><label style="font-size:11px;color:var(--red);display:block;margin-bottom:3px;font-weight:700">Submission Comment (important) <span>*</span></label>'+
              '<textarea id="sbdm-comment" class="sel" style="min-height:64px;resize:vertical" placeholder="Why this candidate fits — rate, highlights, anything the BDM should know"></textarea></div>'+
            '<div style="background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:10px 12px">'+
              '<div style="font-size:12px;font-weight:600;margin-bottom:6px">Resume</div>'+
              (c.resume_filename?'<div style="font-size:12px;color:var(--green);margin-bottom:6px">✓ On file: '+esc(c.resume_filename)+'</div>'
                :'<div style="font-size:12px;color:var(--amber);margin-bottom:6px">No resume on file — attach one below.</div>')+
              '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">'+
                '<label class="btn btn-sm btn-outline" style="cursor:pointer;margin:0">Attach file<input type="file" accept=".pdf,.doc,.docx,.txt,.rtf" style="display:none" onchange="sbdmPickFile(this)"></label>'+
                '<span id="sbdm-file-name" style="font-size:12px;color:var(--text3)"></span>'+
                '<button class="btn btn-sm btn-outline" onclick="sbdmFormat()" title="Convert the attached resume to the company letterhead format">✨ Format resume</button>'+
              '</div>'+
              '<div id="sbdm-fmt-status" style="font-size:11.5px;color:var(--green);margin-top:7px"></div>'+
            '</div>'+
          '</div>'+
          '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px">'+
            '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
            '<button class="btn btn-primary" onclick="sbdmSubmit()">Submit to BD Manager</button>'+
          '</div>'+
        '</div>';
      render();
    }).catch(function(e){ showToast('Could not load candidate: '+e.message,'error'); });
  };

  window.sbdmPickFile = function(input){
    var st = STATE._sbdm; if (!st || !input.files || !input.files[0]) return;
    st.file = input.files[0];
    var el = document.getElementById('sbdm-file-name');
    if (el) el.textContent = st.file.name;
  };

  window.sbdmFormat = function(){
    var st = STATE._sbdm;
    if (!st || !st.file) { showToast('Attach a resume file first, then click Format','error'); return; }
    if (!window.atsFormatResumeFile) { showToast('Formatter not loaded','error'); return; }
    // Format → open the preview (with Word/PDF download) AND stash the formatted
    // doc so it's attached to the packet when the recruiter submits.
    window.atsFormatResumeFile(st.file, { onFormatted: function(html, name){
      st.formattedHtml = html; st.formattedName = name;
      var el = document.getElementById('sbdm-fmt-status');
      if (el) el.textContent = '✓ Formatted on the futé letterhead — it will be attached to this submission.';
    }});
  };

  window.sbdmSubmit = function(){
    var st = STATE._sbdm; if (!st) return;
    var val = function(id){ var el=document.getElementById(id); return el?el.value.trim():''; };
    var details = {
      first_name: val('sbdm-first'), last_name: val('sbdm-last'),
      email: val('sbdm-email'), mobile: val('sbdm-mobile'),
      home_phone: val('sbdm-home') || 'N/A', work_auth: val('sbdm-auth') || 'N/A',
      current_location: val('sbdm-loc'), relocation: val('sbdm-reloc'),
      availability: val('sbdm-avail'), comment: val('sbdm-comment')
    };
    if (!details.first_name || !details.email) { showToast('First name and email are required','error'); return; }
    if (!details.comment) { showToast('The submission comment is important — please add it','error'); return; }

    // Record which resume files ride along with the packet so the BDM's
    // submission view can point straight at them.
    if (st.formattedName) details.formatted_resume = st.formattedName + '_Submission.doc';
    if (st.file) details.original_resume = st.file.name;

    var patchStage = function(){
      apiPatch('/submissions/'+st.subId+'/stage', { stage:'Submitted to BDM', submission_details: details, note: details.comment })
        .then(function(s){
          closeModal();
          showToast('Submitted to the BD Manager','success');
          if (STATE.bd && STATE.bd.submissions) {
            STATE.bd.submissions = STATE.bd.submissions.map(function(x){ return x.id===s.id ? s : x; });
          }
          if (st.onDone) st.onDone([s]);
          STATE._sbdm = null;
          render();
        })
        .catch(function(e){ showToast(e.message||'Could not submit','error'); });
    };

    var uploadDoc = function(filename, contentType, dataUri){
      return apiPost('/candidates/'+st.candId+'/documents',
        { filename:filename, content_type:contentType, doc_type:'resume', data_base64:dataUri });
    };
    var readFile = function(f){ return new Promise(function(res,rej){
      var r=new FileReader(); r.onload=function(){res(String(r.result));}; r.onerror=function(){rej(new Error('Could not read the resume file'));}; r.readAsDataURL(f);
    }); };

    // Attach the resume(s) to the packet BEFORE moving the stage: the original
    // file (raw source) and the formatted futé-letterhead copy when present.
    var uploads = [];
    if (st.file) uploads.push(readFile(st.file).then(function(d){ return uploadDoc(st.file.name, st.file.type||'application/octet-stream', d); }));
    if (st.formattedHtml && window.atsFormattedDocDataUri) {
      var fName = (st.formattedName || details.first_name || 'candidate').replace(/[^A-Za-z0-9 _-]/g,'').trim().replace(/\s+/g,'_') || 'candidate';
      uploads.push(uploadDoc(fName + '_Submission.doc', 'application/msword', window.atsFormattedDocDataUri(st.formattedHtml)));
    }
    if (!uploads.length) { patchStage(); return; }
    Promise.all(uploads).then(patchStage).catch(function(e){ showToast('Resume upload failed: '+(e.message||e),'error'); });
  };

})();

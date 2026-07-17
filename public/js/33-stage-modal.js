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
    if (newStage === 'Submitted to Client' && recruiterScoped) {
      showToast('Only a BD Manager can send a candidate to the client','error'); render(); return;
    }
    var subs = (STATE.bd && STATE.bd.submissions) || [];
    var names = ids.map(function(id){ var s=subs.find(function(x){return x.id===id;})||{}; return (s.candidate&&s.candidate.full_name)||''; }).filter(Boolean);
    var subStages = SUB_STAGES[newStage] || [];
    var showInterview = isInterviewStage(newStage);

    STATE._stageMove = { ids: ids, stage: newStage, onDone: onDone || null };
    STATE.modal =
      '<div class="modal modal-w480" onclick="event.stopPropagation()">'+
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border)">'+
          '<div style="font-weight:700;font-size:15px">Move to “'+esc(newStage)+'”</div>'+
          '<div style="font-size:12px;color:var(--text3);margin-top:2px">'+
            (ids.length>1 ? ids.length+' candidates selected' : esc(names[0]||'Candidate'))+
          '</div>'+
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
          '<div style="margin-bottom:12px"><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">Note</label>'+
            '<textarea id="stg-note" class="sel" style="min-height:56px;resize:vertical" placeholder="What happened? (call summary, feedback…)"></textarea></div>'+
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
    var payload = { stage: mv.stage, sub_stage: val('stg-sub') || undefined, note: val('stg-note') || undefined };
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

})();

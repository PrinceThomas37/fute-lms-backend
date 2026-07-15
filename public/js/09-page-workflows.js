// ── WORKFLOWS (engine UI: definitions, builder, enrollments) ─────────────────
var WF_CHANNEL_LABELS={email:'Email',bd_touch:'BD touch',reminder:'Reminder',stage_move:'Stage move',candidate_email:'Email candidate',recruiter_task:'Recruiter task',submission_stage_move:'Move stage'};
// Entity types a sequence can target, with their pipeline stages for stage-move steps.
var WF_ENTITY_TYPES={contact:{label:'Leads (contacts)',domain:'sales',stages:['Unassigned','Assigned','Connected','Rejected','Future','In Discussion']},submission:{label:'Candidates (recruiting)',domain:'recruiting',stages:['Sourced','Screening','Submitted to BDM','Submitted to Client','Interview','Offer','Placed','Rejected']}};
var WF_STATUS_COLORS={active:'var(--green)',paused:'var(--amber)',completed:'var(--accent)',exited:'var(--text3)',failed:'var(--red)',draft:'var(--amber)',archived:'var(--text3)'};
function wfStatusBadge(s,extra){ var c=WF_STATUS_COLORS[s]||'var(--text3)'; return '<span style="font-size:10px;padding:2px 8px;border-radius:6px;font-weight:700;background:'+c+'22;color:'+c+'">'+htmlEsc(s+(extra?' · '+extra:''))+'</span>'; }
function wfStepLabel(s){ var lbl=WF_CHANNEL_LABELS[s.channel]||s.channel; if(s.channel==='email'&&s.config&&s.config.template_key)lbl+=' ('+s.config.template_key+')'; if((s.channel==='stage_move'||s.channel==='submission_stage_move')&&s.config&&s.config.to_stage)lbl+=' → '+s.config.to_stage; return lbl; }
function wfChain(steps){ return (steps||[]).map(function(s,i){ return (i>0?'<span style="color:var(--text3)"> → +'+s.delay_days+'d </span>':'')+'<span style="font-weight:600">'+htmlEsc(wfStepLabel(s))+'</span>'; }).join(''); }

function loadWorkflows(){
  STATE._wfLoading=true;
  Promise.all([
    apiGet('/wf/definitions').catch(function(){return [];}),
    apiGet('/wf/enrollments').catch(function(){return [];}),
    apiGet('/wf/stats').catch(function(){return {by_workflow:{},total:0};}),
    apiGet('/wf/channels').catch(function(){return {channels:['email','bd_touch','reminder','stage_move'],catalogue:[]};})
  ]).then(function(r){
    STATE.wf={defs:r[0]||[],enrollments:r[1]||[],stats:r[2]||{by_workflow:{}},channels:(r[3]&&r[3].channels)||[],catalogue:(r[3]&&r[3].catalogue)||[]};
    STATE.wfDefs=r[0]||[];
    STATE._wfLoading=false; scheduleRender();
  });
}
window.wfSetStatus=function(id,status){ apiPost('/wf/definitions/'+id+'/status',{status:status}).then(function(){ showToast('Workflow '+status,'success'); loadWorkflows(); }).catch(function(e){showToast('Failed: '+(e&&e.message||e),'error');}); };
window.wfRunTick=function(){ STATE.wfTickLog='running'; scheduleRender(); apiPost('/wf/tick',{}).then(function(r){ STATE.wfTickLog=r; loadWorkflows(); }).catch(function(e){ STATE.wfTickLog=null; showToast('Tick failed: '+(e&&e.message||e),'error'); scheduleRender(); }); };
window.wfEnrollmentAction=function(id,action){ apiPost('/wf/enrollments/'+id+'/'+action,{}).then(function(){ showToast('Enrollment '+action+(action==='exit'?'ed':'d'),'success'); loadWorkflows(); }).catch(function(e){showToast('Failed: '+(e&&e.message||e),'error');}); };
window.wfToggleRuns=function(id){
  STATE.wfRuns=STATE.wfRuns||{};
  if(STATE.wfRuns[id]){ delete STATE.wfRuns[id]; scheduleRender(); return; }
  STATE.wfRuns[id]='loading'; scheduleRender();
  apiGet('/wf/enrollments/'+id+'/runs').then(function(r){ STATE.wfRuns[id]=r||[]; scheduleRender(); }).catch(function(){ STATE.wfRuns[id]=[]; scheduleRender(); });
};
window.wfSetFilter=function(k,v){ STATE.wfFilter=STATE.wfFilter||{}; STATE.wfFilter[k]=v; scheduleRender(); };

// ── builder modal ──
function wfChannelsForEntity(et){
  var cat=(STATE.wf&&STATE.wf.catalogue)||[];
  var list=cat.filter(function(c){return !c.entity_types||c.entity_types.indexOf(et)>-1;}).map(function(c){return c.name;});
  if(!list.length)list=et==='submission'?['candidate_email','recruiter_task','submission_stage_move']:['email','bd_touch','reminder','stage_move'];
  return list;
}
function wfDefaultConfig(channel){
  if(channel==='email')return {template_key:'fu1',thread:true};
  if(channel==='candidate_email')return {subject:'',body:''};
  if(channel==='stage_move')return {to_stage:'Connected'};
  if(channel==='submission_stage_move')return {to_stage:'Screening'};
  return {note:'',message:''};
}
function wfDefaultStep(et){ return et==='submission'?{name:'Email the candidate',channel:'candidate_email',delay_days:0,config:{subject:'',body:''}}:{name:'Initial outreach email',channel:'email',delay_days:0,config:{template_key:'initial',thread:false}}; }
function wfBlankStep(){ var et=(STATE.wfBuilder&&STATE.wfBuilder.entity_type)||'contact'; var ch=wfChannelsForEntity(et)[0]||'email'; return {name:'',channel:ch,delay_days:2,config:wfDefaultConfig(ch)}; }
window.wfOpenBuilder=function(id,entityType,enrollAfter){
  var b;
  if(id){ var d=(STATE.wf&&STATE.wf.defs||[]).find(function(x){return x.id===id;}); if(!d)return;
    b={id:d.id,name:d.name,description:d.description||'',domain:d.domain||'sales',entity_type:d.entity_type||'contact',steps:(d.steps||[]).map(function(s){return {name:s.name,channel:s.channel,delay_days:s.delay_days,config:Object.assign({},s.config||{})};})};
  } else { var et=entityType||'contact'; b={id:null,name:'',description:'',domain:(WF_ENTITY_TYPES[et]&&WF_ENTITY_TYPES[et].domain)||'sales',entity_type:et,steps:[wfDefaultStep(et)]}; }
  if(enrollAfter)b._enrollAfter=enrollAfter;
  STATE.wfStart=null; STATE.wfBuilder=b; refreshWfBuilder();
};
window.wfBuilderField=function(k,v){ if(STATE.wfBuilder)STATE.wfBuilder[k]=v; };
window.wfSetEntityType=function(et){ var b=STATE.wfBuilder; if(!b)return; b.entity_type=et; b.domain=(WF_ENTITY_TYPES[et]&&WF_ENTITY_TYPES[et].domain)||'sales'; b.steps=[wfDefaultStep(et)]; refreshWfBuilder(); };
window.wfStepField=function(i,k,v){ var s=STATE.wfBuilder&&STATE.wfBuilder.steps[i]; if(!s)return; if(k==='delay_days')v=parseInt(v,10)||0; s[k]=v; if(k==='channel'){ s.config=wfDefaultConfig(v); refreshWfBuilder(); } };
window.wfStepCfg=function(i,k,v){ var s=STATE.wfBuilder&&STATE.wfBuilder.steps[i]; if(!s)return; if(k==='thread')v=!!v; s.config=s.config||{}; s.config[k]=v; };
window.wfAddStep=function(){ STATE.wfBuilder.steps.push(wfBlankStep()); refreshWfBuilder(); };
window.wfRemoveStep=function(i){ STATE.wfBuilder.steps.splice(i,1); refreshWfBuilder(); };
window.wfMoveStep=function(i,dir){ var st=STATE.wfBuilder.steps, j=i+dir; if(j<0||j>=st.length)return; var t=st[i]; st[i]=st[j]; st[j]=t; refreshWfBuilder(); };
window.wfSaveDefinition=function(){
  var b=STATE.wfBuilder; if(!b)return;
  if(!b.name){ showToast('Name is required','warning'); return; }
  if(!b.steps.length){ showToast('Add at least one step','warning'); return; }
  var payload={name:b.name,description:b.description,domain:b.domain,entity_type:b.entity_type||'contact',steps:b.steps};
  var isNew=!b.id, enrollAfter=b._enrollAfter;
  var req=b.id?apiPut('/wf/definitions/'+b.id,payload):apiPost('/wf/definitions',payload);
  req.then(function(res){
    STATE.wfBuilder=null; closeModal();
    if(isNew&&enrollAfter&&res&&res.id){
      // Created from "Start sequence": activate it, then enroll the selection.
      apiPost('/wf/definitions/'+res.id+'/status',{status:'active'})
        .then(function(){ wfEnrollSelectionInto(res.id,enrollAfter.entity_type,enrollAfter.items); })
        .catch(function(e){ showToast('Created, but activate failed: '+(e&&e.message||e),'error'); loadWorkflows(); });
    } else {
      showToast(b.id?'Sequence updated':'Sequence created (draft — activate it to enroll)','success'); loadWorkflows();
    }
  }).catch(function(e){ showToast('Save failed: '+(e&&e.message||e),'error'); });
};
// ── "Start sequence" on a selection (bulk enroll) ──
// opts.anyStage = enrol leads regardless of their pipeline stage (used when the
// selection was hand-picked across groups on the Leads page).
window.wfStartSequence=function(entityType,items,opts){
  if(!items||!items.length){ showToast('Select at least one '+(entityType==='submission'?'candidate':'lead'),'warning'); return; }
  opts=opts||{};
  STATE.wfStart={entity_type:entityType,items:items,anyStage:!!opts.anyStage,fromMailboxIds:[]};
  if(STATE.wf===undefined&&!STATE._wfLoading)loadWorkflows();
  wfLoadMailboxes();
  renderWfStartModal();
};
// Connected/active sending mailboxes for the "from" picker (cached).
function wfLoadMailboxes(){
  if(STATE.wfMailboxes!==undefined&&STATE.wfMailboxes!=='loading')return;
  if(STATE.wfMailboxes==='loading')return;
  STATE.wfMailboxes='loading';
  apiGet('/wf/sending-mailboxes').then(function(r){ STATE.wfMailboxes=r||[]; if(STATE.wfStart)renderWfStartModal(); }).catch(function(){ STATE.wfMailboxes=[]; if(STATE.wfStart)renderWfStartModal(); });
}
window.wfToggleMailbox=function(id){
  var st=STATE.wfStart; if(!st)return;
  st.fromMailboxIds=st.fromMailboxIds||[];
  var i=st.fromMailboxIds.indexOf(id);
  if(i>-1)st.fromMailboxIds.splice(i,1); else st.fromMailboxIds.push(id);
  renderWfStartModal();
};
window.wfToggleAnyStage=function(v){ if(STATE.wfStart)STATE.wfStart.anyStage=!!v; renderWfStartModal(); };
window.wfStartBuildNew=function(){ var st=STATE.wfStart; if(!st)return; wfOpenBuilder(null,st.entity_type,{entity_type:st.entity_type,items:st.items}); };
window.wfEnrollSelectionInto=function(workflowId,entityType,items){
  var st=STATE.wfStart||{};
  var et=entityType||st.entity_type||'contact';
  var its=items||st.items||[];
  if(!its.length)return;
  apiPost('/wf/enroll-bulk',{
    workflow_id:workflowId, entity_type:et,
    from_mailbox_ids:st.fromMailboxIds||[],
    any_stage:!!st.anyStage,
    items:its.map(function(x){return {entity_id:x.entity_id,job_id:x.job_id||null,contact_id:x.contact_id||null};})
  })
    .then(function(r){
      var msg='Enrolled '+(r.enrolled||0)+(r.skipped?', '+r.skipped+' already in it':'')+(r.errors&&r.errors.length?', '+r.errors.length+' failed':'');
      if(r.rotation&&r.rotation.length)msg+=' · rotating across '+r.rotation.length+' mailbox'+(r.rotation.length>1?'es':'');
      showToast(msg,(r.enrolled?'success':'warning'));
      STATE.wfStart=null; if(STATE.bd)STATE.bd.seqSel=[]; if(STATE.leadSeqSel)STATE.leadSeqSel={}; closeModal(); loadWorkflows();
    })
    .catch(function(e){ showToast('Enroll failed: '+(e&&e.message||e),'error'); });
};
function wfMailboxPicker(st){
  var mb=STATE.wfMailboxes;
  var sel=st.fromMailboxIds||[];
  var body;
  if(mb===undefined||mb==='loading')body='<div style="font-size:12px;color:var(--text3);padding:6px 2px">Loading mailboxes…</div>';
  else if(!mb.length)body='<div style="font-size:12px;color:var(--text3);padding:6px 2px">No active sending mailboxes found.</div>';
  else body=mb.map(function(m){
    var on=sel.indexOf(m.id)>-1;
    var conn=m.connected?'<span style="font-size:10px;color:var(--green);font-weight:600">✓ connected</span>':'<span style="font-size:10px;color:var(--amber);font-weight:600" title="Not connected — this mailbox can\'t send until it\'s connected under the user\'s Email IDs">⚠ not connected</span>';
    return '<label style="display:flex;align-items:center;gap:9px;padding:7px 9px;border:1px solid '+(on?'var(--accent)':'var(--border)')+';border-radius:7px;margin-bottom:5px;cursor:pointer;background:'+(on?'var(--accent-l)':'transparent')+'">'+
      '<input type="checkbox" '+(on?'checked':'')+' onchange="wfToggleMailbox(\''+m.id+'\')" style="width:14px;height:14px;flex-shrink:0"/>'+
      '<div style="flex:1;min-width:0"><div style="font-size:12.5px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+htmlEsc(m.email)+(m.is_primary?' <span style="font-size:9px;color:var(--amber)">★</span>':'')+'</div>'+
        '<div style="font-size:10.5px;color:var(--text3)">'+(m.owner?htmlEsc(m.owner)+' · ':'')+htmlEsc(m.platform||'')+'</div></div>'+
      conn+
    '</label>';
  }).join('');
  var summary=sel.length
    ?'<div style="font-size:11.5px;color:var(--accent);margin-top:2px">▶ Rotating across '+sel.length+' mailbox'+(sel.length>1?'es':'')+' (round-robin across the selection).</div>'
    :'<div style="font-size:11.5px;color:var(--text3);margin-top:2px">None selected — each lead sends from its job\'s default mailbox.</div>';
  return '<div style="margin:4px 0 12px">'+
    '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px">Send from (rotate across selected)</div>'+
    '<div style="max-height:180px;overflow-y:auto">'+body+'</div>'+summary+
  '</div>';
}
function renderWfStartModal(){
  var st=STATE.wfStart; if(!st)return;
  var defs=((STATE.wf&&STATE.wf.defs)||[]).filter(function(d){return (d.entity_type||'contact')===st.entity_type&&d.status==='active';});
  var rows=defs.map(function(d){
    return '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;border:1px solid var(--border);border-radius:8px;padding:10px 12px;margin-bottom:7px">'+
      '<div style="min-width:0"><div style="font-weight:600;font-size:13px">'+htmlEsc(d.name)+'</div><div style="font-size:11.5px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+wfChain(d.steps)+'</div></div>'+
      '<button class="btn btn-sm btn-primary" onclick="wfEnrollSelectionInto(\''+d.id+'\')">Start</button>'+
    '</div>';
  }).join('')||'<div style="font-size:12.5px;color:var(--text3);padding:6px 2px 12px">No active '+(st.entity_type==='submission'?'recruiting':'sales')+' sequences yet — build one below.</div>';
  var stageToggle=st.entity_type==='contact'
    ?'<label style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text2);margin:2px 0 12px;cursor:pointer"><input type="checkbox" '+(st.anyStage?'checked':'')+' onchange="wfToggleAnyStage(this.checked)" style="width:14px;height:14px"/> Send regardless of lead stage <span style="color:var(--text3)">(needed for Connected / Future / Rejected leads)</span></label>'
    :'';
  STATE.modal='<div class="modal modal-w480" style="max-height:88vh;overflow-y:auto">'+
    '<div class="mh"><div class="mt">Start sequence · '+st.items.length+' '+(st.entity_type==='submission'?'candidate(s)':'lead(s)')+'</div></div>'+
    '<div class="mb_">'+
      '<div style="font-size:12px;color:var(--text3);margin-bottom:10px">Pick an existing sequence to enroll the selection, or build and name a new one.</div>'+
      wfMailboxPicker(st)+
      stageToggle+
      '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px">Sequence</div>'+
      rows+
      '<button onclick="wfStartBuildNew()" class="btn btn-outline btn-sm" style="width:100%;margin-top:4px">+ Build a new sequence</button>'+
    '</div>'+
    '<div class="mf"><button class="btn btn-outline" onclick="STATE.wfStart=null;closeModal()">Cancel</button></div>'+
  '</div>';
  render();
}
function refreshWfBuilder(){
  var b=STATE.wfBuilder; if(!b)return;
  if(!b.entity_type)b.entity_type='contact';
  var channels=wfChannelsForEntity(b.entity_type);
  var stages=(WF_ENTITY_TYPES[b.entity_type]&&WF_ENTITY_TYPES[b.entity_type].stages)||['Unassigned','Assigned','Connected','Rejected','Future','In Discussion'];
  var stepRows=b.steps.map(function(s,i){
    var chanOpts=channels.map(function(c){return '<option value="'+c+'"'+(s.channel===c?' selected':'')+'>'+(WF_CHANNEL_LABELS[c]||c)+'</option>';}).join('');
    var cfg='';
    if(s.channel==='email'){
      cfg='<select onchange="wfStepCfg('+i+',\'template_key\',this.value)" style="font-size:12px;padding:5px;border:1px solid var(--border);border-radius:6px;background:var(--bg)">'+['initial','fu1','fu2'].map(function(k){return '<option value="'+k+'"'+((s.config&&s.config.template_key)===k?' selected':'')+'>'+k+'</option>';}).join('')+'</select>'+
        '<label style="font-size:12px;color:var(--text2);display:flex;align-items:center;gap:4px"><input type="checkbox" '+(s.config&&s.config.thread?'checked':'')+' onchange="wfStepCfg('+i+',\'thread\',this.checked)">thread</label>';
    } else if(s.channel==='candidate_email'){
      cfg='<div style="display:flex;flex-direction:column;gap:5px;width:100%">'+
        '<input placeholder="Subject (leave blank for default; vars: {{first_name}} {{position}} {{client}})" value="'+htmlEsc(s.config&&s.config.subject||'')+'" oninput="wfStepCfg('+i+',\'subject\',this.value)" style="font-size:12px;padding:5px 7px;border:1px solid var(--border);border-radius:6px;background:var(--bg)">'+
        '<textarea placeholder="Email body (blank = default; vars ok, HTML)" oninput="wfStepCfg('+i+',\'body\',this.value)" style="font-size:12px;padding:5px 7px;border:1px solid var(--border);border-radius:6px;background:var(--bg);min-height:56px;font-family:inherit">'+htmlEsc(s.config&&s.config.body||'')+'</textarea></div>';
    } else if(s.channel==='stage_move'||s.channel==='submission_stage_move'){
      cfg='<select onchange="wfStepCfg('+i+',\'to_stage\',this.value)" style="font-size:12px;padding:5px;border:1px solid var(--border);border-radius:6px;background:var(--bg)">'+stages.map(function(st){return '<option value="'+st+'"'+((s.config&&s.config.to_stage)===st?' selected':'')+'>'+st+'</option>';}).join('')+'</select>';
    } else if(s.channel==='recruiter_task'){
      cfg='<input placeholder="Task note (e.g. Call the candidate, collect docs)" value="'+htmlEsc(s.config&&s.config.note||'')+'" oninput="wfStepCfg('+i+',\'note\',this.value)" style="font-size:12px;padding:5px 7px;border:1px solid var(--border);border-radius:6px;background:var(--bg);flex:1;min-width:160px">';
    } else {
      cfg='<input placeholder="Task note" value="'+htmlEsc(s.config&&s.config.note||'')+'" oninput="wfStepCfg('+i+',\'note\',this.value)" style="font-size:12px;padding:5px 7px;border:1px solid var(--border);border-radius:6px;background:var(--bg);flex:1;min-width:120px">'+
        '<input placeholder="Suggested message (vars ok)" value="'+htmlEsc(s.config&&s.config.message||'')+'" oninput="wfStepCfg('+i+',\'message\',this.value)" style="font-size:12px;padding:5px 7px;border:1px solid var(--border);border-radius:6px;background:var(--bg);flex:1;min-width:120px">';
    }
    return '<div style="border:1px solid var(--border2);border-radius:8px;padding:9px 10px;margin-bottom:7px;background:var(--bg3)">'+
      '<div style="display:flex;gap:6px;align-items:center;margin-bottom:6px">'+
        '<span style="font-size:11px;font-weight:700;color:var(--text3);min-width:16px">'+(i+1)+'.</span>'+
        '<input placeholder="Step name" value="'+htmlEsc(s.name||'')+'" oninput="wfStepField('+i+',\'name\',this.value)" style="flex:1;font-size:12.5px;padding:5px 7px;border:1px solid var(--border);border-radius:6px;background:var(--bg)">'+
        '<button onclick="wfMoveStep('+i+',-1)" style="border:1px solid var(--border);background:transparent;border-radius:6px;cursor:pointer;color:var(--text2)">↑</button>'+
        '<button onclick="wfMoveStep('+i+',1)" style="border:1px solid var(--border);background:transparent;border-radius:6px;cursor:pointer;color:var(--text2)">↓</button>'+
        '<button onclick="wfRemoveStep('+i+')" style="border:1px solid #ef4444;color:#ef4444;background:transparent;border-radius:6px;cursor:pointer">×</button>'+
      '</div>'+
      '<div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap">'+
        '<select onchange="wfStepField('+i+',\'channel\',this.value)" style="font-size:12px;padding:5px;border:1px solid var(--border);border-radius:6px;background:var(--bg)">'+chanOpts+'</select>'+
        '<label style="font-size:12px;color:var(--text2)">after <input type="number" min="0" max="90" value="'+(s.delay_days||0)+'" onchange="wfStepField('+i+',\'delay_days\',this.value)" style="width:48px;font-size:12px;padding:4px;border:1px solid var(--border);border-radius:6px;background:var(--bg)"> day(s)</label>'+
        cfg+
      '</div>'+
    '</div>';
  }).join('');
  var entityPicker=b.id
    ? '<div style="font-size:12px;color:var(--text3);margin-bottom:12px">Applies to: <b style="color:var(--text2)">'+((WF_ENTITY_TYPES[b.entity_type]||{}).label||b.entity_type)+'</b></div>'
    : '<select onchange="wfSetEntityType(this.value)" class="inp" style="margin-bottom:12px">'+Object.keys(WF_ENTITY_TYPES).map(function(et){return '<option value="'+et+'"'+(b.entity_type===et?' selected':'')+'>'+WF_ENTITY_TYPES[et].label+'</option>';}).join('')+'</select>';
  STATE.modal='<div class="modal modal-w480" style="max-height:88vh;overflow-y:auto">'+
    '<div class="mh"><div class="mt">'+(b.id?'Edit sequence':'New sequence')+'</div></div>'+
    '<div class="mb_">'+
      '<input placeholder="Sequence name (e.g. Java Dev – Client X pipeline)" value="'+htmlEsc(b.name)+'" oninput="wfBuilderField(\'name\',this.value)" class="inp" style="margin-bottom:8px">'+
      '<input placeholder="Description" value="'+htmlEsc(b.description)+'" oninput="wfBuilderField(\'description\',this.value)" class="inp" style="margin-bottom:8px">'+
      entityPicker+
      '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.04em;margin-bottom:6px">Steps (delay counts from the previous step)</div>'+
      stepRows+
      '<button onclick="wfAddStep()" style="border:1px dashed var(--border2);background:transparent;color:var(--text2);border-radius:8px;padding:7px;width:100%;cursor:pointer;font-size:12px">+ Add step</button>'+
      (b.id?'<div style="font-size:11.5px;color:var(--text3);margin-top:8px">Editing steps is blocked while this workflow has active enrollments.</div>':'')+
    '</div>'+
    '<div class="mf"><button class="btn btn-outline" onclick="STATE.wfBuilder=null;closeModal()">Cancel</button><button class="btn" onclick="wfSaveDefinition()">Save</button></div>'+
  '</div>';
  render();
}

// ── per-job enrollment helpers (job detail modal) ──
function loadJobEnrollments(jobId){
  apiGet('/wf/enrollments?job_id='+jobId).then(function(r){ STATE.wfByJob=STATE.wfByJob||{}; STATE.wfByJob[jobId]=r||[]; scheduleRender(); }).catch(function(){});
  if(!STATE.wfDefs)apiGet('/wf/definitions').then(function(r){ STATE.wfDefs=r||[]; scheduleRender(); }).catch(function(){ STATE.wfDefs=[]; });
}
function wfContactEnrollment(jobId,contactId){
  var list=(STATE.wfByJob&&STATE.wfByJob[jobId])||[];
  return list.find(function(e){return e.contact_id===contactId&&(e.status==='active'||e.status==='paused');})||null;
}
function wfContactChip(jobId,c){
  var e=wfContactEnrollment(jobId,c.id); if(!e)return '';
  var def=(STATE.wfDefs||[]).find(function(d){return d.id===e.workflow_id;});
  var total=def&&def.steps?def.steps.length:'?';
  var links=e.status==='active'
    ?'<a onclick="wfJobEnrollmentAction(\''+e.id+'\',\'pause\',\''+jobId+'\')" style="cursor:pointer;color:var(--amber)">pause</a> · <a onclick="wfJobEnrollmentAction(\''+e.id+'\',\'exit\',\''+jobId+'\')" style="cursor:pointer;color:var(--red)">exit</a>'
    :'<a onclick="wfJobEnrollmentAction(\''+e.id+'\',\'resume\',\''+jobId+'\')" style="cursor:pointer;color:var(--green)">resume</a> · <a onclick="wfJobEnrollmentAction(\''+e.id+'\',\'exit\',\''+jobId+'\')" style="cursor:pointer;color:var(--red)">exit</a>';
  return '<div style="font-size:11.5px;margin-top:6px;display:flex;align-items:center;gap:6px;flex-wrap:wrap">⚙ <span style="font-weight:600">'+htmlEsc((e.workflow&&e.workflow.name)||'Workflow')+'</span> · step '+e.current_step_order+'/'+total+' '+wfStatusBadge(e.status)+' <span style="color:var(--text3)">'+links+'</span></div>';
}
window.wfJobEnrollmentAction=function(id,action,jobId){ apiPost('/wf/enrollments/'+id+'/'+action,{}).then(function(){ showToast('Enrollment '+action+(action==='exit'?'ed':'d'),'success'); loadJobEnrollments(jobId); }).catch(function(e){showToast('Failed: '+(e&&e.message||e),'error');}); };
window.wfEnrollContact=function(contactId,jobId){
  var defs=(STATE.wfDefs||[]).filter(function(d){return d.status==='active'&&d.entity_type==='contact';});
  if(!defs.length){ showToast('No active sequence — create and activate one in Email → Sequence first','warning'); return; }
  if(defs.length===1){ wfDoEnroll(defs[0].id,contactId,jobId); return; }
  STATE.modal='<div class="modal modal-w480"><div class="mh"><div class="mt">Enroll in workflow</div></div><div class="mb_">'+
    defs.map(function(d){ return '<button onclick="wfDoEnroll(\''+d.id+'\',\''+contactId+'\',\''+jobId+'\')" style="display:block;width:100%;text-align:left;background:var(--bg3);border:1px solid var(--border2);border-radius:8px;padding:10px 12px;margin-bottom:7px;cursor:pointer"><div style="font-weight:600;font-size:13px;color:var(--text)">'+htmlEsc(d.name)+'</div><div style="font-size:11.5px;color:var(--text3);margin-top:3px">'+wfChain(d.steps)+'</div></button>'; }).join('')+
    '</div><div class="mf"><button class="btn btn-outline" onclick="openJob(\''+jobId+'\')">Cancel</button></div></div>';
  render();
};
window.wfDoEnroll=function(workflowId,contactId,jobId){
  apiPost('/wf/enroll',{workflow_id:workflowId,contact_id:contactId,job_id:jobId})
    .then(function(){ showToast('Enrolled — the engine takes it from here','success'); openJob(jobId); loadJobEnrollments(jobId); })
    .catch(function(e){ showToast('Enroll failed: '+(e&&e.message||e),'error'); openJob(jobId); });
};

function renderSequenceBody(){
  var u=STATE.user;
  if(!userHasAnyRole(u,'admin','bd_lead','ra_lead','bd'))return '<div style="padding:14px;color:var(--text3)">Forbidden</div>';
  if(STATE.wf===undefined&&!STATE._wfLoading){loadWorkflows();}
  var canDesign=userHasAnyRole(u,'admin','ra_lead','bd_lead');
  var canTick=userHasAnyRole(u,'admin','bd_lead');
  var wf=STATE.wf;
  if(!wf)return '<div style="padding:14px;color:var(--text3)">Loading sequence…</div>';
  var tick=STATE.wfTickLog;
  var tickHtml=tick?(tick==='running'?'<span style="font-size:12px;color:var(--text3)">Running…</span>':'<span style="font-size:12px;color:var(--text2)">Last run: checked '+(tick.checked||0)+' · done '+(tick.done||0)+' · deferred '+(tick.deferred||0)+' · completed '+(tick.completed||0)+' · exited '+(tick.exited||0)+(tick.off?' · <b style="color:var(--red)">engine off — migration 007 not applied</b>':'')+'</span>'):'';
  var defCards=(wf.defs||[]).map(function(d){
    var st=(wf.stats.by_workflow||{})[d.id]||{};
    var stats='<span style="font-size:11.5px;color:var(--text3)">'+(st.active||0)+' active · '+(st.completed||0)+' completed · '+(st.exited||0)+' exited</span>';
    var btns=canDesign?('<button onclick="wfOpenBuilder(\''+d.id+'\')" style="font-size:11px;border:1px solid var(--border2);background:transparent;color:var(--accent);padding:4px 10px;border-radius:6px;cursor:pointer">Edit</button>'+
      (d.status==='draft'?'<button onclick="wfSetStatus(\''+d.id+'\',\'active\')" style="font-size:11px;border:0;background:var(--green);color:#fff;padding:4px 10px;border-radius:6px;cursor:pointer">Activate</button>':'')+
      (d.status==='active'?'<button onclick="wfSetStatus(\''+d.id+'\',\'archived\')" style="font-size:11px;border:1px solid var(--border2);background:transparent;color:var(--text2);padding:4px 10px;border-radius:6px;cursor:pointer">Archive</button>':'')+
      (d.status==='archived'?'<button onclick="wfSetStatus(\''+d.id+'\',\'active\')" style="font-size:11px;border:1px solid var(--border2);background:transparent;color:var(--green);padding:4px 10px;border-radius:6px;cursor:pointer">Reactivate</button>':'')):'';
    return '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px 16px;margin-bottom:10px">'+
      '<div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">'+
        '<div style="display:flex;align-items:center;gap:8px"><span style="font-weight:700;font-size:14px">'+htmlEsc(d.name)+'</span><span style="font-size:10px;padding:2px 7px;border-radius:6px;background:var(--bg3);color:var(--text2);font-weight:600">'+htmlEsc(d.domain||'sales')+'</span>'+wfStatusBadge(d.status)+'</div>'+
        '<div style="display:flex;gap:6px;align-items:center">'+stats+btns+'</div>'+
      '</div>'+
      (d.description?'<div style="font-size:12px;color:var(--text3);margin-top:5px">'+htmlEsc(d.description)+'</div>':'')+
      '<div style="font-size:12.5px;margin-top:8px">'+wfChain(d.steps)+'</div>'+
    '</div>';
  }).join('')||'<div style="color:var(--text3);font-size:13px;padding:10px">No sequences yet'+(canDesign?' — create one.':'.')+'</div>';

  var f=STATE.wfFilter||{};
  var enr=(wf.enrollments||[]).filter(function(e){ return (!f.status||e.status===f.status)&&(!f.workflow||e.workflow_id===f.workflow); });
  var wfOpts='<option value="">All workflows</option>'+(wf.defs||[]).map(function(d){return '<option value="'+d.id+'"'+(f.workflow===d.id?' selected':'')+'>'+htmlEsc(d.name)+'</option>';}).join('');
  var stOpts='<option value="">All statuses</option>'+['active','paused','completed','exited','failed'].map(function(s){return '<option value="'+s+'"'+(f.status===s?' selected':'')+'>'+s+'</option>';}).join('');
  var enrRows=enr.map(function(e){
    var def=(wf.defs||[]).find(function(d){return d.id===e.workflow_id;});
    var total=def&&def.steps?def.steps.length:'?';
    var name=e.contact?((e.contact.first_name||'')+' '+(e.contact.last_name||'')).trim()||e.contact.email:e.entity_id.slice(0,8);
    var fromMb=(e.metadata&&e.metadata.from_mailbox_email)?' · ✉ '+htmlEsc(e.metadata.from_mailbox_email):'';
    var jobLbl=(e.job?htmlEsc((e.job.position||'')+((e.job.company&&e.job.company.name)?' · '+e.job.company.name:'')):'—')+fromMb;
    var acts='';
    if(e.status==='active')acts='<a onclick="wfEnrollmentAction(\''+e.id+'\',\'pause\')" style="cursor:pointer;color:var(--amber);font-size:11px">Pause</a> <a onclick="wfEnrollmentAction(\''+e.id+'\',\'exit\')" style="cursor:pointer;color:var(--red);font-size:11px">Exit</a>';
    else if(e.status==='paused')acts='<a onclick="wfEnrollmentAction(\''+e.id+'\',\'resume\')" style="cursor:pointer;color:var(--green);font-size:11px">Resume</a> <a onclick="wfEnrollmentAction(\''+e.id+'\',\'exit\')" style="cursor:pointer;color:var(--red);font-size:11px">Exit</a>';
    var runs=STATE.wfRuns&&STATE.wfRuns[e.id];
    var runsHtml='';
    if(runs==='loading')runsHtml='<div style="padding:8px 14px;font-size:12px;color:var(--text3)">Loading history…</div>';
    else if(runs)runsHtml='<div style="padding:6px 14px 10px;background:var(--bg3)">'+(runs.length?runs.map(function(r){
      var oc=r.outcome==='done'?'var(--green)':r.outcome==='failed'?'var(--red)':'var(--text3)';
      var why=r.detail&&(r.detail.reason||r.detail.error)?' — '+htmlEsc(r.detail.reason||r.detail.error):'';
      return '<div style="font-size:12px;padding:3px 0;color:var(--text2)">step '+r.step_order+' · '+(WF_CHANNEL_LABELS[r.channel]||r.channel)+' · <b style="color:'+oc+'">'+r.outcome+'</b>'+why+' <span style="color:var(--text3)">· '+String(r.run_at||'').slice(0,16).replace('T',' ')+'</span></div>';
    }).join(''):'<div style="font-size:12px;color:var(--text3)">No steps executed yet.</div>')+'</div>';
    return '<div style="border-bottom:1px solid var(--border)">'+
      '<div style="display:flex;align-items:center;gap:10px;padding:9px 14px">'+
        '<div style="flex:1.2;min-width:0"><div style="font-size:13px;font-weight:600">'+htmlEsc(name)+'</div><div style="font-size:11px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+jobLbl+'</div></div>'+
        '<div style="flex:1;font-size:12px;color:var(--text2)">'+htmlEsc((e.workflow&&e.workflow.name)||'—')+'</div>'+
        '<div style="font-size:12px;color:var(--text2);min-width:56px">step '+e.current_step_order+'/'+total+'</div>'+
        '<div style="font-size:12px;color:var(--text3);min-width:78px">'+(e.next_step_due_date||'—')+'</div>'+
        '<div style="min-width:90px">'+wfStatusBadge(e.status,e.exit_reason)+'</div>'+
        '<div style="min-width:86px;display:flex;gap:8px">'+acts+'</div>'+
        '<a onclick="wfToggleRuns(\''+e.id+'\')" style="cursor:pointer;font-size:11px;color:var(--accent)">'+(runs?'Hide':'History')+'</a>'+
      '</div>'+runsHtml+
    '</div>';
  }).join('')||'<div style="padding:14px;color:var(--text3);font-size:13px">No enrollments'+((f.status||f.workflow)?' match the filter.':' yet — open a lead and enroll a contact.')+'</div>';

  return '<div>'+
    '<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;flex-wrap:wrap;margin-bottom:14px">'+
      '<div style="font-size:12.5px;color:var(--text3);max-width:600px;line-height:1.5">This is your outreach sequence — the steps every enrolled lead moves through (initial email → follow-ups → LinkedIn touch). Edit the steps, timing and templates here; no code changes. Enroll a contact from a lead\'s detail view.</div>'+
      '<div style="display:flex;gap:8px;align-items:center">'+tickHtml+
        (canTick?'<button onclick="wfRunTick()" style="background:transparent;border:1px solid var(--border2);color:var(--text2);padding:7px 14px;border-radius:8px;font-size:12px;cursor:pointer">▶ Run sequence now</button>':'')+
        (canDesign?'<button onclick="wfOpenBuilder()" style="background:var(--accent);color:#fff;border:0;padding:7px 16px;border-radius:8px;font-size:13px;cursor:pointer">+ New sequence</button>':'')+
      '</div>'+
    '</div>'+
    '<div style="font-weight:600;font-size:13px;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Sequences</div>'+
    defCards+
    '<div style="display:flex;justify-content:space-between;align-items:center;margin:20px 0 8px"><div style="font-weight:600;font-size:13px;color:var(--text2);text-transform:uppercase;letter-spacing:.05em">Enrolled leads ('+enr.length+')</div>'+
      '<div style="display:flex;gap:6px"><select onchange="wfSetFilter(\'status\',this.value)" style="font-size:12px;padding:5px 8px;border:1px solid var(--border);border-radius:7px;background:var(--bg);color:var(--text)">'+stOpts+'</select>'+
      '<select onchange="wfSetFilter(\'workflow\',this.value)" style="font-size:12px;padding:5px 8px;border:1px solid var(--border);border-radius:7px;background:var(--bg);color:var(--text)">'+wfOpts+'</select></div>'+
    '</div>'+
    '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden">'+enrRows+'</div>'+
  '</div>';
}

function renderAdmin(){
  var u=STATE.user;
  if(STATE.sendingPaused===undefined){loadSendingStatus();}
  if(STATE.raModes===undefined){loadManagerRaModes();}
  var selectedUserId=STATE.adminSelectedUser||null;
  if(selectedUserId){return renderAdminUserDetail(selectedUserId);}

  var tab=STATE.adminTab||'bd';
  var q=(STATE.adminSearch||'').toLowerCase().trim();

  var tabs=[
    {id:'bd',        lbl:'BD'},
    {id:'ra',        lbl:'RA'},
    {id:'recruiter', lbl:'Recruiter'},
    {id:'admin',     lbl:'Admin'}
  ];

  var assignments=STATE.teamAssignments||[];
  var allUsers=STATE.users||[];

  function usersForTab(t){
    if(t==='bd')        return allUsers.filter(function(x){return userHasAnyRole(x,'bd','bd_lead')&&!userHasRole(x,'admin');});
    if(t==='ra')        return allUsers.filter(function(x){return userHasAnyRole(x,'ra','ra_lead')&&!userHasAnyRole(x,'bd','bd_lead','admin');});
    if(t==='recruiter') return allUsers.filter(function(x){return userHasRole(x,'recruiter')&&!userHasAnyRole(x,'bd','bd_lead','ra','ra_lead','admin');});
    if(t==='admin')     return allUsers.filter(function(x){return userHasRole(x,'admin');});
    return allUsers;
  }

  var tabUsers=usersForTab(tab);
  if(q){
    tabUsers=tabUsers.filter(function(x){
      return (x.name||'').toLowerCase().indexOf(q)>-1||
             (x.email||'').toLowerCase().indexOf(q)>-1||
             (x.empId||'').toLowerCase().indexOf(q)>-1||
             (x.desig||'').toLowerCase().indexOf(q)>-1;
    });
  }

  var tabBar=tabs.map(function(t){
    var count=usersForTab(t.id).length;
    var on=tab===t.id;
    return '<button onclick="STATE.adminTab=\''+t.id+'\';render()" style="padding:8px 16px;border:0;border-bottom:2px solid '+(on?'var(--accent)':'transparent')+';background:none;cursor:pointer;font-size:13px;font-weight:'+(on?'700':'500')+';color:'+(on?'var(--accent)':'var(--text2)')+'">'+t.lbl+' <span style="font-size:11px;color:'+(on?'var(--accent)':'var(--text3)')+'">'+count+'</span></button>';
  }).join('');

  var rows=tabUsers.map(function(usr){
    var emailCount=(STATE.userEmailsCache&&STATE.userEmailsCache[usr.id]||[]).length||
                   (STATE.emailAccounts||[]).filter(function(a){return a.assigned_to===usr.id;}).length;
    var teamCount=assignments.filter(function(a){return a.manager_id===usr.id;}).length;
    // Per-BD RA mode toggle (BD tab only) — auto = leads auto-send, manual = BD sends by hand.
    var raChip='';
    if(tab==='bd'){
      var mode=(STATE.raModes&&STATE.raModes[usr.id])||'auto';
      var isAuto=mode!=='manual';
      raChip='<span onclick="toggleManagerRaMode(event,\''+usr.id+'\')" title="Click to switch between Automatic and Manual outreach for this BD" style="font-size:11px;padding:3px 9px;border-radius:8px;font-weight:600;cursor:pointer;background:'+(isAuto?'var(--accent-l)':'var(--amber-l,#fef3c7)')+';color:'+(isAuto?'var(--accent)':'var(--amber,#b45309)')+'">'+(isAuto?'⚙ Auto RA':'✋ Manual RA')+'</span>';
    }
    return '<div onclick="STATE.adminSelectedUser=\''+usr.id+'\';loadUserEmails(\''+usr.id+'\');render()" style="display:flex;align-items:center;gap:14px;padding:12px 16px;border-bottom:1px solid var(--border);cursor:pointer">'+
      av(usr,'36')+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-weight:600;font-size:13.5px">'+htmlEsc(usr.name)+'</div>'+
        '<div style="font-size:11.5px;color:var(--text3)">'+htmlEsc(usr.email)+(usr.empId?' · '+htmlEsc(usr.empId):'')+'</div>'+
      '</div>'+
      raChip+
      (roleLabel(usr.role)?'<span style="font-size:11px;padding:2px 8px;background:var(--bg);border:1px solid var(--border);color:var(--text2);border-radius:8px">'+htmlEsc(roleLabel(usr.role))+'</span>':'')+
      (emailCount?'<span style="font-size:11px;padding:2px 8px;background:var(--accent-l);color:var(--accent);border-radius:8px">'+emailCount+' email'+(emailCount>1?'s':'')+'</span>':'')+
      (teamCount?'<span style="font-size:11px;padding:2px 8px;background:var(--green-l);color:var(--green);border-radius:8px">'+teamCount+' member'+(teamCount>1?'s':'')+'</span>':'')+
      '<span style="font-size:11px;padding:3px 9px;background:'+(usr.is_active!==false?'var(--green-l)':'var(--red-l)')+';color:'+(usr.is_active!==false?'var(--green)':'var(--red)')+';border-radius:8px;font-weight:600">'+(usr.is_active!==false?'Active':'Inactive')+'</span>'+
      '<div style="color:var(--text3);font-size:18px;margin-left:4px">›</div>'+
    '</div>';
  }).join('');

  var canSeeEngine=userHasAnyRole(u,'admin','ra_lead');
  var isAdmin=userHasRole(u,'admin');
  var engineBtn='<button onclick="openEmailEngineModal()" style="display:flex;align-items:center;gap:7px;padding:7px 14px;background:var(--card);border:1px solid var(--border2);border-radius:8px;font-size:13px;color:var(--text2);cursor:pointer">'+
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>'+
    'Email Engine Schedule'+
  '</button>';
  var sysSettingsBtn='<button onclick="openSystemSettingsModal()" style="display:flex;align-items:center;gap:7px;padding:7px 14px;background:var(--card);border:1px solid var(--border2);border-radius:8px;font-size:13px;color:var(--text2);cursor:pointer">'+
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 21v-7"/><path d="M4 10V3"/><path d="M12 21v-9"/><path d="M12 8V3"/><path d="M20 21v-5"/><path d="M20 12V3"/><path d="M1 14h6"/><path d="M9 8h6"/><path d="M17 16h6"/></svg>'+
    'System Settings'+
  '</button>';
  var integrationsBtn='<button onclick="openIntegrationsModal()" style="display:flex;align-items:center;gap:7px;padding:7px 14px;background:var(--card);border:1px solid var(--border2);border-radius:8px;font-size:13px;color:var(--text2);cursor:pointer">'+
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>'+
    'Integrations'+
  '</button>';

  var paused=STATE.sendingPaused;
  var stopCard='<div style="background:'+(paused?'#fef2f2':'var(--card)')+';border:1px solid '+(paused?'#fca5a5':'var(--border)')+';border-radius:var(--r2);padding:14px 16px;margin-bottom:16px;display:flex;align-items:center;gap:14px;flex-wrap:wrap">'+
    '<div style="flex:1;min-width:200px">'+
      '<div style="font-weight:700;font-size:14px;color:'+(paused?'#b91c1c':'var(--text)')+';display:flex;align-items:center;gap:8px">'+
        '<span style="width:9px;height:9px;border-radius:50%;background:'+(paused?'#dc2626':'var(--green)')+';display:inline-block"></span>'+
        'Email sending: '+(paused?'PAUSED':'Active')+'</div>'+
      '<div style="font-size:12px;color:var(--text3);margin-top:3px">'+(paused?'All outbound email is stopped. Queued emails stay pending until you resume.':'Emergency stop halts all outbound email immediately. Already-sent emails cannot be recalled.')+'</div>'+
    '</div>'+
    (paused
      ?'<button onclick="toggleSending(false)" style="padding:9px 18px;background:var(--green);color:#fff;border:0;border-radius:8px;font-weight:700;font-size:13px;cursor:pointer">Resume sending</button>'
      :'<button onclick="toggleSending(true)" style="padding:9px 18px;background:#dc2626;color:#fff;border:0;border-radius:8px;font-weight:700;font-size:13px;cursor:pointer">⏸ Emergency stop</button>')+
  '</div>';

  return '<div class="page">'+
    '<div class="ph"><div class="flex jb aic">'+
      '<div><div class="ptitle">Admin</div><div class="psub">'+allUsers.length+' users · Fute Global LLC</div></div>'+
      '<div style="display:flex;gap:8px;align-items:center">'+
        (canSeeEngine?engineBtn:'')+
        (isAdmin?integrationsBtn:'')+
        (isAdmin?sysSettingsBtn:'')+
        (isAdmin?'<button class="btn btn-sm" onclick="openPurgePending(\'all\')" style="background:transparent;color:var(--red);border:1px solid #fca5a5">Delete pending (all managers)…</button>':'')+
        '<button class="btn btn-primary btn-sm" onclick="openAddUser()">'+ico('plus',13)+'Add user</button>'+
      '</div>'+
    '</div></div>'+
    stopCard+
    '<div style="margin-bottom:14px">'+
      '<input class="inp" placeholder="Search by name, email, employee ID…" value="'+htmlEsc(STATE.adminSearch||'')+'" oninput="STATE.adminSearch=this.value;render()" style="max-width:360px">'+
    '</div>'+
    '<div style="display:flex;gap:2px;border-bottom:2px solid var(--border);margin-bottom:16px">'+tabBar+'</div>'+
    '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden">'+
      (rows||'<div style="padding:40px;text-align:center;color:var(--text3);font-size:13px">'+(q?'No users match "'+htmlEsc(q)+'"':'No users in this group yet.')+'</div>')+
    '</div>'+
  '</div>';
}

// ── Control Center — per-user pending-queue counts (lazy, cached per user) ──
function loadUserQueueCounts(userId){
  STATE._ccQueue=STATE._ccQueue||{};
  if(STATE._ccQueue[userId]!==undefined)return;
  STATE._ccQueue[userId]='loading';
  apiPost('/admin/emails/purge-pending',{manager_id:userId,types:['outreach','fu1','fu2'],dry_run:true})
    .then(function(r){STATE._ccQueue[userId]=r;scheduleRender();})
    .catch(function(){STATE._ccQueue[userId]=null;scheduleRender();});
}
window.refreshUserControlCenter=function(userId){
  STATE._ccQueue=STATE._ccQueue||{};
  delete STATE._ccQueue[userId];
  loadUserQueueCounts(userId);
  loadWorkflows();
};

function renderAdminUserDetail(userId){
  var usr=STATE.users.find(function(x){return x.id===userId;});
  if(!usr)return'';

  // trigger email load if not already cached
  if(!(STATE.userEmailsCache&&STATE.userEmailsCache[userId])){
    loadUserEmails(userId);
  }

  var userEmails=STATE.userEmailsCache&&STATE.userEmailsCache[userId]||[];
  var assignments=STATE.teamAssignments||[];
  var myManagers=assignments.filter(function(a){return a.member_id===userId;});
  var myMembers=assignments.filter(function(a){return a.manager_id===userId;});

  // ── Control Center — sending status, RA mode, pending queue, active
  // sequence enrollments, all in one place instead of hunting across pages.
  // BD / BD Lead only (these are the users who send outreach).
  var isBDish=userHasAnyRole(usr,'bd','bd_lead');
  var ccCard='';
  if(isBDish){
    loadUserQueueCounts(userId);
    if(STATE.wf===undefined&&!STATE._wfLoading)loadWorkflows();

    var mgrPaused=(STATE.pausedManagers||[]).indexOf(userId)>-1;
    var raMode=(STATE.raModes&&STATE.raModes[userId])||'auto';
    var q=STATE._ccQueue&&STATE._ccQueue[userId];
    var qLoading=(q===undefined||q==='loading');
    var qFailed=(q===null);

    // Cross-reference this manager's job ids against the org-wide enrollment
    // list (already loaded for the Workflows page) — avoids a new backend
    // query. NOTE: /wf/enrollments caps at 500 rows org-wide, so a very large
    // backlog could clip older enrollments from this view (same cap the
    // Workflows page itself has today).
    var myJobIds={};
    (STATE.jobs||[]).forEach(function(j){if(j.assigned_to_bd===userId)myJobIds[j.id]=true;});
    var myEnrollments=((STATE.wf&&STATE.wf.enrollments)||[]).filter(function(e){return e.job&&myJobIds[e.job.id];});
    var activeEnrollments=myEnrollments.filter(function(e){return e.status==='active'||e.status==='paused';});

    var enrollRows=activeEnrollments.length?activeEnrollments.map(function(e){
      var cName=e.contact?((e.contact.first_name||'')+' '+(e.contact.last_name||'')).trim():'—';
      var seqName=(e.workflow&&e.workflow.name)||'—';
      var acts=e.status==='active'
        ?'<a onclick="wfEnrollmentAction(\''+e.id+'\',\'pause\')" style="cursor:pointer;color:var(--amber);font-size:11px">Pause</a> <a onclick="wfEnrollmentAction(\''+e.id+'\',\'exit\')" style="cursor:pointer;color:var(--red);font-size:11px;margin-left:10px">Stop</a>'
        :'<a onclick="wfEnrollmentAction(\''+e.id+'\',\'resume\')" style="cursor:pointer;color:var(--green);font-size:11px">Resume</a> <a onclick="wfEnrollmentAction(\''+e.id+'\',\'exit\')" style="cursor:pointer;color:var(--red);font-size:11px;margin-left:10px">Stop</a>';
      return '<div style="display:flex;align-items:center;gap:10px;padding:9px 14px;border-bottom:1px solid var(--border2)">'+
        '<div style="flex:1;min-width:0"><div style="font-size:13px;font-weight:500">'+htmlEsc(seqName)+'</div><div style="font-size:11px;color:var(--text3)">'+htmlEsc(cName)+'</div></div>'+
        wfStatusBadge(e.status)+'<span style="white-space:nowrap">'+acts+'</span>'+
      '</div>';
    }).join(''):'<div style="padding:14px;color:var(--text3);font-size:12.5px">No active or paused sequence enrollments for this manager\'s leads.</div>';

    ccCard='<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:18px;margin-bottom:16px">'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'+
        '<div style="font-weight:700;font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em">Control Center</div>'+
        '<button onclick="refreshUserControlCenter(\''+userId+'\')" style="font-size:11px;color:var(--text3);background:transparent;border:0;cursor:pointer">↻ Refresh</button>'+
      '</div>'+
      '<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px">'+
        '<div style="flex:1;min-width:180px;padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:8px">'+
          '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px">Sending</div>'+
          '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px">'+
            '<span style="font-weight:700;font-size:13px;color:'+(mgrPaused?'var(--red)':'var(--green)')+'">'+(mgrPaused?'Paused':'Active')+'</span>'+
            (mgrPaused
              ?'<button onclick="toggleManagerSending(\''+userId+'\',false)" style="font-size:11px;padding:4px 10px;background:var(--green);color:#fff;border:0;border-radius:6px;cursor:pointer">Resume</button>'
              :'<button onclick="toggleManagerSending(\''+userId+'\',true)" style="font-size:11px;padding:4px 10px;background:transparent;color:var(--red);border:1px solid #fca5a5;border-radius:6px;cursor:pointer">Pause</button>')+
          '</div></div>'+
        '<div style="flex:1;min-width:180px;padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:8px">'+
          '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.04em;margin-bottom:4px">RA Mode</div>'+
          '<div style="display:flex;align-items:center;justify-content:space-between;gap:8px">'+
            '<span style="font-weight:700;font-size:13px">'+(raMode==='manual'?'Manual':'Automatic')+'</span>'+
            '<button onclick="toggleManagerRaMode(event,\''+userId+'\')" style="font-size:11px;padding:4px 10px;background:transparent;color:var(--text2);border:1px solid var(--border2);border-radius:6px;cursor:pointer">Switch</button>'+
          '</div></div>'+
      '</div>'+
      '<div style="padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:8px;margin-bottom:14px">'+
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'+
          '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.04em">Pending queue</div>'+
          '<button onclick="openPurgePending(\''+userId+'\')" style="font-size:11px;color:var(--red);background:transparent;border:0;cursor:pointer">Delete pending…</button>'+
        '</div>'+
        (qLoading?'<div style="font-size:12.5px;color:var(--text3)">Loading…</div>':
         qFailed?'<div style="font-size:12.5px;color:var(--text3)">Could not load queue counts.</div>':
          '<div style="display:flex;gap:16px;font-size:13px;flex-wrap:wrap">'+
            '<div><strong>'+q.count+'</strong> total pending</div>'+
            '<div style="color:var(--text3)">Outreach: '+((q.by_type&&q.by_type.outreach)||0)+'</div>'+
            '<div style="color:var(--text3)">FU1: '+((q.by_type&&q.by_type.fu1)||0)+'</div>'+
            '<div style="color:var(--text3)">FU2: '+((q.by_type&&q.by_type.fu2)||0)+'</div>'+
          '</div>')+
      '</div>'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">'+
        '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.04em">Active sequence enrollments'+(activeEnrollments.length?' ('+activeEnrollments.length+')':'')+'</div>'+
        '<button onclick="openAdminEnrollPicker(\''+userId+'\')" style="font-size:11px;color:var(--accent);background:transparent;border:0;cursor:pointer">+ Enroll leads…</button>'+
      '</div>'+
      '<div style="border:1px solid var(--border);border-radius:8px;overflow:hidden">'+enrollRows+'</div>'+
    '</div>';
  }

  // role dropdown only — this IS the designation
  var roleOpts=['ra','ra_lead','bd','bd_lead','admin','recruiter'].map(function(r){
    var labels={ra:'Research Analyst',ra_lead:'RA Team Lead',bd:'BD Manager',bd_lead:'BD Team Lead',admin:'Admin',recruiter:'Recruiter'};
    return '<option value="'+r+'"'+(usr.role===r?' selected':'')+'>'+labels[r]+'</option>';
  }).join('');

  // show outreach emails only for BD users and admins
  var showEmails=!userHasRole(usr,'ra')||userHasAnyRole(usr,'ra_lead','bd','bd_lead','admin','recruiter');

  // email rows
  var emailRows=userEmails.map(function(e){
    var msConn=e.ms_connected;
    var platBadge='<span style="font-size:10px;padding:2px 7px;border-radius:6px;font-weight:600;background:'+(e.platform==='Microsoft'?'#e0f2fe':'#f0fdf4')+';color:'+(e.platform==='Microsoft'?'#0369a1':'#166534')+'">'+htmlEsc(e.platform)+'</span>';
    var connBtn='';
    if(e.platform==='Microsoft'){
      connBtn=!msConn?'<button onclick="connectMicrosoftUserEmail(\''+userId+'\',\''+e.id+'\')" style="font-size:10px;padding:2px 8px;background:#0078d4;color:#fff;border:0;border-radius:6px;cursor:pointer">Connect</button>':'<span style="font-size:10px;color:var(--green)">✓ Connected</span>';
    } else if(e.platform==='Gmail'){
      connBtn=!e.gmail_connected?'<button onclick="connectGmailUserEmail(\''+userId+'\',\''+e.id+'\')" style="font-size:10px;padding:2px 8px;background:#16a34a;color:#fff;border:0;border-radius:6px;cursor:pointer">Connect</button>':'<span style="font-size:10px;color:var(--green)">✓ Connected</span>';
    }
    return '<div style="display:flex;align-items:center;gap:8px;padding:10px 14px;border-bottom:1px solid var(--border);flex-wrap:wrap">'+
      '<div style="flex:1;min-width:160px"><div style="font-weight:500;font-size:13px">'+htmlEsc(e.display_name||e.email_address)+'</div>'+
        '<div style="font-size:11px;color:var(--text3)">'+htmlEsc(e.email_address)+'</div></div>'+
      platBadge+
      (e.is_primary?'<span style="font-size:10px;padding:2px 7px;background:var(--amber-l);color:var(--amber);border-radius:6px;font-weight:600">Primary</span>':'')+
      '<span style="font-size:10px;padding:2px 7px;border-radius:6px;font-weight:600;background:'+(e.is_active?'var(--green-l)':'var(--red-l)')+';color:'+(e.is_active?'var(--green)':'var(--red)')+'">'+( e.is_active?'Active':'Inactive')+'</span>'+
      connBtn+
      '<button onclick="toggleUserEmailActive(\''+userId+'\',\''+e.id+'\','+(e.is_active?'false':'true')+')" style="font-size:11px;color:'+(e.is_active?'var(--red)':'var(--green)')+';background:transparent;border:0;cursor:pointer">'+(e.is_active?'Deactivate':'Activate')+'</button>'+
      (e.is_primary?'':'<button onclick="setPrimaryEmail(\''+userId+'\',\''+e.id+'\')" style="font-size:11px;color:var(--text3);background:transparent;border:0;cursor:pointer">Set Primary</button>')+
      '<button onclick="deleteUserEmail(\''+userId+'\',\''+e.id+'\')" style="font-size:11px;color:var(--red);background:transparent;border:0;cursor:pointer">✕</button>'+
    '</div>';
  }).join('');

  // team assignment
  var teamHtml=
    (myManagers.length?'<div style="font-size:13px;margin-bottom:8px">Reports to: '+myManagers.map(function(a){return '<strong>'+htmlEsc((a.manager&&a.manager.name)||'')+'</strong>';}).join(', ')+'</div>':'')+
    (myMembers.length?'<div style="font-size:13px">Members: '+myMembers.map(function(a){return htmlEsc((a.member&&a.member.name)||'');}).filter(Boolean).join(', ')+'</div>':'<div style="font-size:13px;color:var(--text3)">No team members assigned.</div>');

  return '<div class="page">'+
    '<div class="ph"><div class="flex aic gap3">'+
      '<button onclick="STATE.adminSelectedUser=null;render()" style="background:transparent;border:0;color:var(--text3);font-size:22px;cursor:pointer;line-height:1">←</button>'+
      av(usr,'40')+
      '<div><div class="ptitle" style="margin:0">'+htmlEsc(usr.name)+'</div>'+
        '<div class="psub" style="margin:0">'+roleLabel(usr.role)+(usr.empId?' · '+htmlEsc(usr.empId):'')+'</div></div>'+
    '</div></div>'+
    '<div style="max-width:620px">'+

      // Profile — role dropdown IS the designation, no separate designation field
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:18px;margin-bottom:16px">'+
        '<div style="font-weight:700;font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:14px">Profile</div>'+
        '<div class="g2 mb3">'+
          '<div class="fgrp"><label class="flbl">Full name</label><input class="inp" id="ud-name" value="'+htmlEsc(usr.name)+'"/></div>'+
          '<div class="fgrp"><label class="flbl">Work email</label><input class="inp" id="ud-email" value="'+htmlEsc(usr.email)+'"/></div>'+
        '</div>'+
        '<div class="g2 mb3">'+
          '<div class="fgrp"><label class="flbl">Employee ID</label><input class="inp" id="ud-eid" value="'+htmlEsc(usr.empId||'')+'"/></div>'+
          '<div class="fgrp"><label class="flbl">Role</label><select class="sel" id="ud-role">'+roleOpts+'</select></div>'+
        '</div>'+
        '<div class="g2 mb3">'+
          '<div class="fgrp"><label class="flbl">Platform</label><select class="sel" id="ud-plt"><option'+(usr.plt==='Gmail'?' selected':'')+'>Gmail</option><option'+(usr.plt==='Outlook'?' selected':'')+'>Outlook</option></select></div>'+
        '</div>'+
        '<div style="display:flex;justify-content:space-between;align-items:center;padding-top:12px;border-top:1px solid var(--border)">'+
          '<button onclick="submitUserDetailSave(\''+userId+'\')" class="btn btn-primary">Save changes</button>'+
          (usr.id!==STATE.user.id?'<button onclick="removeUser(\''+userId+'\',true)" style="background:transparent;color:var(--red);border:1px solid var(--red);padding:7px 14px;border-radius:7px;font-size:12px;cursor:pointer">Deactivate</button>':'<span style="font-size:12px;color:var(--text3)">Cannot deactivate yourself</span>')+
        '</div>'+
      '</div>'+

      ccCard+

      // Outreach Email IDs — BD and Admin only
      (showEmails?
        '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden;margin-bottom:16px">'+
          '<div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">'+
            '<div style="font-weight:700;font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em">Outreach Email IDs <span style="font-weight:400">('+userEmails.length+' · max 4)</span></div>'+
            '<div style="display:flex;gap:6px">'+
              '<button onclick="openAddUserEmail(\''+userId+'\',\'Microsoft\')" style="font-size:12px;padding:5px 10px;background:#0078d4;color:#fff;border:0;border-radius:7px;cursor:pointer">+ Microsoft</button>'+
              '<button onclick="openAddUserEmail(\''+userId+'\',\'Gmail\')" style="font-size:12px;padding:5px 10px;background:#16a34a;color:#fff;border:0;border-radius:7px;cursor:pointer">+ Gmail</button>'+
            '</div>'+
          '</div>'+
          (emailRows||'<div style="padding:20px;text-align:center;font-size:13px;color:var(--text3)">No outreach email IDs added yet.</div>')+
        '</div>':'')+

      // Team Assignment
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:18px;margin-bottom:16px">'+
        '<div style="font-weight:700;font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px">Team Assignment</div>'+
        teamHtml+
      '</div>'+

    '</div>'+
  '</div>';
}

// ── Admin: enroll another manager's leads into a sequence on their behalf ───
// (Control Center → "+ Enroll leads…") Reuses the existing "Start sequence"
// picker and POST /wf/enroll-bulk exactly as the manager's own Leads/Email
// pages do — this only adds the missing step of choosing WHICH of another
// user's leads to enroll, since normally that selection happens on a page the
// manager themselves is viewing.
window.openAdminEnrollPicker=function(userId){
  var usr=STATE.users.find(function(x){return x.id===userId;});
  if(!usr)return;

  // A job is eligible if it belongs to this manager, has at least one contact,
  // and has no ACTIVE or PAUSED enrollment already (re-enrolling a completed/
  // exited/failed one is fine — the backend's own uniqueness rule already
  // guards against double-enrolling an active one, this is just so the admin
  // isn't offered leads that are already mid-sequence).
  var busyJobIds={};
  ((STATE.wf&&STATE.wf.enrollments)||[]).forEach(function(e){
    if((e.status==='active'||e.status==='paused')&&e.job)busyJobIds[e.job.id]=true;
  });
  var myJobs=(STATE.jobs||[]).filter(function(j){return j.assigned_to_bd===userId;});
  var eligible=myJobs.map(function(j){
    var contacts=(STATE.contacts||[]).filter(function(c){return c.job_id===j.id;});
    var primary=contacts.find(function(c){return c.is_primary;})||contacts[0];
    return primary?{job:j,contact:primary}:null;
  }).filter(function(x){return x&&!busyJobIds[x.job.id];});

  STATE._adminEnrollSel={};
  STATE._adminEnrollPool=eligible;
  renderAdminEnrollPicker(userId);
};
function renderAdminEnrollPicker(userId){
  var usr=STATE.users.find(function(x){return x.id===userId;});
  var pool=STATE._adminEnrollPool||[];
  var sel=STATE._adminEnrollSel||{};
  var selCount=Object.keys(sel).filter(function(k){return sel[k];}).length;
  var rows=pool.length?pool.map(function(x){
    var cName=((x.contact.first_name||'')+' '+(x.contact.last_name||'')).trim()||'Contact';
    var statusOk=x.contact.email_status==='valid'||!x.contact.email_status;
    return '<label style="display:flex;align-items:center;gap:10px;padding:9px 14px;border-bottom:1px solid var(--border);cursor:pointer">'+
      '<input type="checkbox" '+(sel[x.job.id]?'checked':'')+' onchange="adminEnrollToggle(\''+x.job.id+'\',this.checked)" style="width:15px;height:15px;flex-shrink:0"/>'+
      '<div style="flex:1;min-width:0"><div style="font-size:13px;font-weight:500">'+htmlEsc(x.job.position||'—')+' · '+htmlEsc(x.job.company_name||'')+'</div>'+
        '<div style="font-size:11.5px;color:var(--text3)">'+htmlEsc(cName)+(x.contact.email?' · '+htmlEsc(x.contact.email):'')+'</div></div>'+
      (statusOk?'':'<span style="font-size:10px;padding:2px 7px;background:var(--red-l);color:var(--red);border-radius:6px;font-weight:600">'+htmlEsc(x.contact.email_status)+'</span>')+
    '</label>';
  }).join(''):'<div style="padding:24px;text-align:center;color:var(--text3);font-size:13px">No eligible leads — every lead is either already in an active sequence or has no contact on file.</div>';

  STATE.modal='<div class="modal modal-w480" style="max-height:88vh;overflow-y:auto">'+
    '<div class="mh"><div><div class="mt">Enroll leads · '+htmlEsc(usr?usr.name:'')+'</div>'+
      '<div style="font-size:12px;color:var(--text3);margin-top:2px">Pick which of their leads to enroll, then choose or build a sequence. This does not require '+htmlEsc(usr?usr.name:'them')+' to do anything.</div></div>'+
      '<button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'+
    '<div class="mb_">'+
      (pool.length?'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><label style="display:flex;align-items:center;gap:8px;font-size:12.5px;cursor:pointer"><input type="checkbox" '+(selCount===pool.length?'checked':'')+' onchange="adminEnrollToggleAll(this.checked)" style="width:15px;height:15px"/> Select all ('+pool.length+')</label><span style="font-size:12px;color:var(--text3)">'+selCount+' selected</span></div>':'')+
      '<div style="border:1px solid var(--border);border-radius:8px;overflow:hidden;max-height:320px;overflow-y:auto">'+rows+'</div>'+
    '</div>'+
    '<div class="mf"><button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" '+(selCount?'':'disabled')+' onclick="adminEnrollContinue(\''+userId+'\')">Continue ('+selCount+')</button></div>'+
  '</div>';
  render();
}
window.adminEnrollToggle=function(jobId,checked){
  STATE._adminEnrollSel=STATE._adminEnrollSel||{};
  STATE._adminEnrollSel[jobId]=checked;
  renderAdminEnrollPicker(STATE.adminSelectedUser);
};
window.adminEnrollToggleAll=function(checked){
  var sel={};
  (STATE._adminEnrollPool||[]).forEach(function(x){sel[x.job.id]=checked;});
  STATE._adminEnrollSel=sel;
  renderAdminEnrollPicker(STATE.adminSelectedUser);
};
window.adminEnrollContinue=function(userId){
  var sel=STATE._adminEnrollSel||{};
  var pool=STATE._adminEnrollPool||[];
  var items=pool.filter(function(x){return sel[x.job.id];}).map(function(x){
    return {entity_id:x.contact.id,job_id:x.job.id,contact_id:x.contact.id,
      label:((x.contact.first_name||'')+' '+(x.contact.last_name||'')).trim()||'Contact'};
  });
  if(!items.length)return;
  // Hands off to the existing "Start sequence" flow (pick/build + POST
  // /wf/enroll-bulk) — identical to how a manager enrolls their own leads.
  wfStartSequence('contact',items);
};


// ── ADMIN ──────────────────────────────────────
// ── System Settings — admin-editable operational numbers (config/settings.js) ──
window.openSystemSettingsModal=function(){
  STATE._sysSettingsErrors={};
  if(STATE.sysSettings){renderSystemSettingsModal();return;}
  STATE.modal='<div class="modal modal-w480"><div class="mh"><div class="mt">System Settings</div></div><div class="mb_" style="padding:24px;text-align:center;color:var(--text3)">Loading…</div></div>';
  render();
  apiGet('/admin/settings/numbers').then(function(r){
    STATE.sysSettings=r||[];
    renderSystemSettingsModal();
  }).catch(function(e){
    closeModal();
    showToast('Failed to load settings: '+(e&&e.message||e),'error');
  });
};
function sysSettingsGrouped(){
  var list=STATE.sysSettings||[];
  var groups={};
  var order=[];
  list.forEach(function(s){
    if(!groups[s.group]){groups[s.group]=[];order.push(s.group);}
    groups[s.group].push(s);
  });
  return order.map(function(g){return {group:g,items:groups[g]};});
}
function renderSystemSettingsModal(){
  var errors=STATE._sysSettingsErrors||{};
  var groups=sysSettingsGrouped();
  var body=groups.map(function(g){
    var rows=g.items.map(function(s){
      var err=errors[s.key];
      return '<div style="margin-bottom:14px">'+
        '<label class="flbl" style="display:flex;justify-content:space-between;align-items:baseline">'+
          '<span>'+htmlEsc(s.label)+'</span>'+
          '<span style="font-size:11px;color:var(--text3);font-weight:400">'+s.min+'–'+s.max+' '+htmlEsc(s.unit||'')+'</span>'+
        '</label>'+
        '<input class="inp" type="number" id="sys-'+s.key+'" value="'+htmlEsc(String(s.value))+'" min="'+s.min+'" max="'+s.max+'" step="any" data-key="'+s.key+'" style="'+(err?'border-color:var(--red)':'')+'"/>'+
        '<div style="font-size:11.5px;color:'+(err?'var(--red)':'var(--text3)')+';margin-top:3px">'+htmlEsc(err||s.description)+'</div>'+
      '</div>';
    }).join('');
    return '<div style="margin-bottom:18px">'+
      '<div style="font-weight:700;font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">'+htmlEsc(g.group)+'</div>'+
      rows+
    '</div>';
  }).join('');
  STATE.modal='<div class="modal modal-w480" style="max-height:88vh;overflow-y:auto">'+
    '<div class="mh"><div><div class="mt">System Settings</div><div style="font-size:12px;color:var(--text3);margin-top:2px">Operational numbers used across the platform. Changes apply the next time each check runs (within about a minute).</div></div>'+
      '<button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'+
    '<div class="mb_">'+body+'</div>'+
    '<div class="mf"><button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" id="sys-settings-save" onclick="saveSystemSettings()">Save changes</button></div>'+
  '</div>';
  render();
}
window.saveSystemSettings=function(){
  var list=STATE.sysSettings||[];
  var values={};
  var clientErrors={};
  list.forEach(function(s){
    var el=document.getElementById('sys-'+s.key);
    if(!el)return;
    var raw=el.value;
    var num=parseFloat(raw);
    if(raw===''||isNaN(num)){clientErrors[s.key]='"'+s.label+'" must be a number';return;}
    if(num<s.min||num>s.max){clientErrors[s.key]='"'+s.label+'" must be between '+s.min+' and '+s.max;return;}
    if(num!==s.value)values[s.key]=num;
  });
  if(Object.keys(clientErrors).length){
    STATE._sysSettingsErrors=clientErrors;
    renderSystemSettingsModal();
    showToast('Fix the highlighted field(s) before saving','warning');
    return;
  }
  if(!Object.keys(values).length){
    showToast('No changes to save','info');
    return;
  }
  var btn=document.getElementById('sys-settings-save'); if(btn){btn.disabled=true;btn.textContent='Saving…';}
  apiPost('/admin/settings/numbers',{values:values}).then(function(r){
    STATE.sysSettings=r.settings||STATE.sysSettings;
    STATE._sysSettingsErrors={};
    closeModal();
    showToast('Settings saved','success');
  }).catch(function(e){
    var btn2=document.getElementById('sys-settings-save'); if(btn2){btn2.disabled=false;btn2.textContent='Save changes';}
    showToast('Save failed: '+(e&&e.message||e),'error');
  });
};

function loadSendingStatus(){
  apiGet('/admin/sending/status').then(function(s){
    STATE.sendingPaused=!!(s&&s.paused);
    STATE.pausedManagers=(s&&s.pausedManagers)||[];
    scheduleRender();
  }).catch(function(){
    if(STATE.sendingPaused===undefined)STATE.sendingPaused=false;
    if(STATE.pausedManagers===undefined)STATE.pausedManagers=[];
  });
}
function loadManagerRaModes(){
  if(STATE._raModesLoading)return;
  STATE._raModesLoading=true;
  apiGet('/admin/manager-ra-modes').then(function(r){
    STATE.raModes=(r&&r.modes)||{};
    STATE._raModesLoading=false;
    scheduleRender();
  }).catch(function(){ STATE._raModesLoading=false; if(STATE.raModes===undefined)STATE.raModes={}; });
}
window.toggleManagerRaMode=function(ev,bdId){
  if(ev&&ev.stopPropagation)ev.stopPropagation();
  var cur=(STATE.raModes&&STATE.raModes[bdId])||'auto';
  var next=cur==='auto'?'manual':'auto';
  var m=(STATE.users||[]).find(function(x){return x.id===bdId;})||{name:'this manager'};
  if(next==='manual'&&!confirm('Switch '+m.name+' to MANUAL outreach?\n\nNew leads assigned to them will NOT auto-send. They generate and send outreach themselves. (Auto follow-ups are also skipped for new assignments.)'))return;
  STATE.raModes=STATE.raModes||{};
  STATE.raModes[bdId]=next; // optimistic
  render();
  apiPost('/admin/manager-ra-mode',{bd_id:bdId,mode:next}).then(function(){
    showToast(m.name+' set to '+(next==='auto'?'Automatic':'Manual')+' RA','success');
  }).catch(function(e){
    STATE.raModes[bdId]=cur; render();
    showToast('Failed: '+(e&&e.message||e),'error');
  });
};
window.toggleSending=function(pause){
  if(pause&&!confirm('EMERGENCY STOP\n\nPause ALL outbound email sending right now?\n\nAny run in progress stops before the next email (already-sent mail cannot be recalled). Queued emails stay pending until you resume.'))return;
  apiPost(pause?'/admin/sending/pause':'/admin/sending/resume',{}).then(function(r){
    STATE.sendingPaused=!!(r&&r.paused);
    showToast(STATE.sendingPaused?'Sending PAUSED — all outbound email stopped':'Sending resumed','success');
    render();
  }).catch(function(e){showToast('Failed: '+(e&&e.message||e),'error');});
};
window.toggleManagerSending=function(managerId,pause){
  var m=(STATE.users||[]).find(function(x){return x.id===managerId;})||{name:'this manager'};
  if(pause&&!confirm('Stop all outbound emailing for '+m.name+'?\n\nAny send in progress for them stops before the next email; their queued emails stay pending until you resume. Other managers are unaffected.'))return;
  apiPost(pause?'/admin/sending/pause':'/admin/sending/resume',{manager_id:managerId}).then(function(){
    STATE.pausedManagers=STATE.pausedManagers||[];
    var i=STATE.pausedManagers.indexOf(managerId);
    if(pause&&i<0)STATE.pausedManagers.push(managerId);
    if(!pause&&i>-1)STATE.pausedManagers.splice(i,1);
    showToast(pause?('Emailing paused for '+m.name):('Emailing resumed for '+m.name),'success');
    render();
  }).catch(function(e){showToast('Failed: '+(e&&e.message||e),'error');});
};

// ── DELIVERABILITY DASHBOARD ───────────────────────────────────
// Note: the suppression (opt-out) list still runs in the background — anyone
// who replies "unsubscribe" is auto-removed from future sends, protecting
// sender reputation. There's just no browsing UI for it here anymore; the
// suppressed count still shows as a stat.
function loadDeliverability(){
  STATE._delivLoading=true;
  var days=STATE.delivDays||30;
  Promise.all([
    apiGet('/admin/deliverability?days='+days).catch(function(){return null;}),
    apiGet('/analytics/templates?days='+days).catch(function(){return [];})
  ]).then(function(r){
    STATE.deliv=r[0]; STATE.delivTemplates=r[1]||[];
    STATE._delivLoading=false; scheduleRender();
  });
}
window.openDeliverability=function(){ STATE.page='deliverability'; STATE.deliv=undefined; render(); loadDeliverability(); };
window.setDelivDays=function(days){ STATE.delivDays=days; STATE.deliv=undefined; render(); loadDeliverability(); };
window.resumeMailbox=function(id){ apiPost('/admin/mailbox/'+id+'/resume',{}).then(function(){ showToast('Mailbox resumed','success'); loadDeliverability(); }).catch(function(e){showToast('Failed: '+(e&&e.message||e),'error');}); };
window.runSpamCheck=function(){ apiPost('/emails/spam-check',{subject:STATE.spamSubj||'',body:STATE.spamBody||''}).then(function(r){ STATE.spamResult=r; scheduleRender(); }).catch(function(e){showToast('Failed: '+(e&&e.message||e),'error');}); };
window.previewTemplateSample=function(variant){
  var t=(STATE.delivTemplates||[]).find(function(x){return x.variant===variant;});
  if(!t||!t.sample){showToast('No sample available for this template','warning');return;}
  STATE.modal='<div class="modal modal-w480">'+
    '<div class="mh"><div class="mt">'+htmlEsc(t.label||t.variant)+' — sample sent</div></div>'+
    '<div class="mb_">'+
      '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.04em;margin-bottom:3px">Subject</div>'+
      '<div style="font-size:13.5px;font-weight:600;margin-bottom:12px">'+htmlEsc(t.sample.subject||'')+'</div>'+
      '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.04em;margin-bottom:3px">Body</div>'+
      '<div style="font-size:13px;white-space:pre-wrap;line-height:1.5;max-height:320px;overflow-y:auto;border:1px solid var(--border);border-radius:8px;padding:10px 12px">'+htmlEsc(t.sample.body||'')+'</div>'+
    '</div>'+
    '<div class="mf"><button class="btn btn-outline" onclick="closeModal()">Close</button></div>'+
  '</div>';
  render();
};

function renderDeliverability(){
  var u=STATE.user;
  if(!userHasAnyRole(u,'admin','bd_lead','ra_lead'))return '<div class="page">Forbidden</div>';
  if(STATE.deliv===undefined&&!STATE._delivLoading){loadDeliverability();}
  var days=STATE.delivDays||30;
  var d=STATE.deliv, tpls=STATE.delivTemplates||[], sr=STATE.spamResult;
  function stat(label,val,color){ return '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px 16px;min-width:118px"><div style="font-size:22px;font-weight:700;color:'+(color||'var(--text)')+'">'+(val==null?'—':val)+'</div><div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.04em;margin-top:2px">'+label+'</div></div>'; }
  var statsRow=d?'<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px">'+stat('Sent ('+days+'d)',d.sent,'var(--accent)')+stat('Failed ('+days+'d)',d.failed,'var(--amber)')+stat('Bounced',d.bounced_contacts,'var(--red)')+stat('Replied',d.replied_contacts,'var(--green)')+stat('Opted out',d.suppression_count,'var(--text2)')+'</div>':'<div style="color:var(--text3);margin-bottom:20px">Loading…</div>';
  var dayFilter='<div style="display:flex;gap:4px;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:3px">'+[7,30,90].map(function(n){
    var on=days===n;
    return '<button onclick="setDelivDays('+n+')" style="padding:5px 12px;border:0;border-radius:6px;background:'+(on?'var(--accent)':'transparent')+';color:'+(on?'#fff':'var(--text2)')+';font-size:12px;font-weight:600;cursor:pointer">'+n+'d</button>';
  }).join('')+'</div>';
  var mbRows=(d&&d.mailboxes||[]).map(function(m){
    var status=m.auto_paused?'<span style="font-size:11px;padding:2px 8px;background:#fee2e2;color:#b91c1c;border-radius:6px;font-weight:700">Auto-paused</span> <button onclick="resumeMailbox(\''+m.id+'\')" style="font-size:11px;color:var(--green);background:transparent;border:0;cursor:pointer">Resume</button>':(m.warmup?'<span style="font-size:11px;padding:2px 8px;background:var(--amber-l);color:var(--amber);border-radius:6px;font-weight:600">Warm-up · cap '+m.warmup.today_cap+'/day</span>':'<span style="font-size:11px;padding:2px 8px;background:var(--green-l);color:var(--green);border-radius:6px;font-weight:600">Healthy</span>');
    return '<div style="display:flex;align-items:center;gap:10px;padding:9px 14px;border-bottom:1px solid var(--border)"><div style="flex:1;min-width:0"><div style="font-size:13px;font-weight:500">'+htmlEsc(m.name||m.email)+'</div><div style="font-size:11px;color:var(--text3)">'+htmlEsc(m.email)+' · '+m.daily_limit+'/day cap</div></div>'+status+'</div>';
  }).join('');
  var tplRows=tpls.length?tpls.map(function(t){
    var hasSample=t.sample&&t.sample.subject;
    return '<div style="display:flex;align-items:center;gap:10px;padding:8px 14px;border-bottom:1px solid var(--border)">'+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-size:13px;font-weight:600">'+htmlEsc(t.label||t.variant)+'</div>'+
        (hasSample?'<div style="font-size:11.5px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:340px">'+htmlEsc(t.sample.subject)+'</div>':'')+
      '</div>'+
      (hasSample?'<button onclick="previewTemplateSample(\''+t.variant+'\')" style="font-size:11px;color:var(--accent);background:transparent;border:1px solid var(--border2);padding:4px 10px;border-radius:6px;cursor:pointer;white-space:nowrap">Preview</button>':'')+
      '<div style="font-size:12px;color:var(--text3);white-space:nowrap">'+t.sent+' sent · '+t.replied+' replied</div>'+
      '<div style="font-size:14px;font-weight:700;color:'+(t.reply_rate>=5?'var(--green)':t.reply_rate>0?'var(--accent)':'var(--text3)')+';min-width:54px;text-align:right">'+t.reply_rate+'%</div>'+
    '</div>';
  }).join(''):'<div style="padding:14px;color:var(--text3);font-size:13px">No sent emails with variants yet in this window.</div>';
  var spamHtml='';
  if(sr){ var col=sr.level==='risk'?'var(--red)':sr.level==='warn'?'var(--amber)':'var(--green)'; spamHtml='<div style="margin-top:10px;padding:10px 12px;border:1px solid '+col+';border-radius:8px">'+'<div style="font-weight:700;color:'+col+';font-size:13px">Spam score: '+sr.score+'/100 ('+sr.level+')</div>'+(sr.warnings&&sr.warnings.length?'<ul style="margin:6px 0 0 16px;font-size:12px;color:var(--text2)">'+sr.warnings.map(function(w){return '<li>'+htmlEsc(w)+'</li>';}).join('')+'</ul>':'<div style="font-size:12px;color:var(--text3);margin-top:4px">Looks clean.</div>')+'</div>'; }
  function card(title,inner,extra){ return '<div style="margin-bottom:20px"><div style="font-weight:600;font-size:13px;color:var(--text2);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center">'+title+(extra||'')+'</div><div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden">'+inner+'</div></div>'; }
  return '<div class="page">'+
    '<div class="ph"><div class="flex jb aic">'+
      '<div><div class="ptitle">Deliverability & Replies</div><div class="psub">Reputation, reply rate & content health</div></div>'+
      dayFilter+
    '</div></div>'+
    statsRow+
    card('Mailbox health (warm-up & auto-pause)', mbRows||'<div style="padding:14px;color:var(--text3);font-size:13px">No active mailboxes.</div>')+
    card('Reply rate by template', tplRows)+
    card('Spam-content checker',
      '<div style="padding:14px">'+
        '<div style="font-size:12.5px;color:var(--text3);margin-bottom:10px">Paste a subject + body to check it for things that hurt deliverability before you send: spam-trigger words, too many links/images, ALL-CAPS, excess exclamation marks, subject/body length, and a missing opt-out line.</div>'+
        '<input id="spamSubj" class="inp" placeholder="Subject" value="'+htmlEsc(STATE.spamSubj||'')+'" oninput="STATE.spamSubj=this.value" style="margin-bottom:8px">'+
        '<textarea id="spamBody" class="inp" placeholder="Paste an email body to score it" oninput="STATE.spamBody=this.value" style="width:100%;min-height:90px;font-family:inherit">'+htmlEsc(STATE.spamBody||'')+'</textarea>'+
        '<button onclick="runSpamCheck()" style="margin-top:8px;background:var(--accent);color:#fff;border:0;padding:7px 16px;border-radius:8px;font-size:13px;cursor:pointer">Check</button>'+spamHtml+
      '</div>')+
  '</div>';
}


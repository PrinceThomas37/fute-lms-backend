// ════════════════════════════════════════════════
// RENDER PAGES
// ════════════════════════════════════════════════
function renderPage(){
  if(STATE.page==="dashboard")return renderDashboard();
  if(STATE.page==="leads"){var html=renderJobs();setTimeout(bindJobsControls,0);return html;}
  if(STATE.page==="assign"){return renderAssignLeads();}
  if(STATE.page==="emailaccounts"||STATE.page==="managerusers"){return renderManagerUsers();}
  if(STATE.page==="insights"){if(STATE.user&&STATE.user.role==='ra'&&!STATE.insightsData){loadMyInsights();}return renderInsights();}
  if(STATE.page==="bdinsights"){if(STATE.user&&!STATE.bdInsightsData){loadBDInsights();}return renderBDInsights();}
  if(STATE.page==="bdleadinsights"){return renderBDLeadInsights();}
  if(STATE.page==="email")return renderEmail();
  if(STATE.page==="reminders")return renderReminders();
  if(STATE.page==="admin")return renderAdmin();
  if(STATE.page==="deliverability")return renderDeliverability();
  if(STATE.page==="workflows"){STATE.page="email";STATE.emailTab="sequence";return renderEmail();}
  if(STATE.page==="profile")return renderProfile();
  return "<div class='page'>Page not found</div>";
}

// ── DASHBOARD ──────────────────────────────────
function renderDashboard(){
  // Support "view as" — admin/BD can click a team member to see their dashboard
  var u=STATE.viewingUser||STATE.user;
  var isViewingOther=STATE.viewingUser&&STATE.viewingUser.id!==STATE.user.id;
  var pl=periodLeads(u);
  var total=pl.length;
  var emailed=pl.filter(function(l){return l.sent}).length;
  var pos=pl.filter(function(l){return l.stage==="Positive"||l.stage==="Connected"}).length;
  var pend=pl.filter(function(l){return l.stage==="Active"}).length;
  var rr=total?Math.round(emailed/total*100):0;

  var hour=new Date().getHours();
  var greet=hour<12?"Good morning":hour<17?"Good afternoon":"Good evening";

  // period picker
  var periods=["daily","weekly","monthly","quarterly"];
  var pickers=periods.map(function(p){
    return '<button class="fc'+(STATE.period===p?" on":"") + '" onclick="setPeriod(\''+p+'\')" style="text-transform:capitalize">'+p+'</button>';
  }).join("");

  // team card — only show for actual logged-in user (not when viewing someone else)
  var team=isViewingOther?[]:getTeam(u);
  var canClickTeam=(STATE.user.role==="admin"||STATE.user.role==="bd");
  var teamRows=team.map(function(t){
    var tl=getMyLeads(t);
    var tlp=filterPeriod(tl,STATE.period);
    var pos_=tlp.filter(function(l){return l.stage==="Positive"||l.stage==="Connected"}).length;
    var neg_=tlp.filter(function(l){return l.stage==="Negative"}).length;
    var resp_=tlp.filter(function(l){return l.sent}).length;
    var rr_=tlp.length?Math.round(resp_/tlp.length*100):0;
    var rrColor=rr_>50?"var(--green)":rr_>25?"var(--amber)":"var(--text3)";
    var clickStyle=canClickTeam?'cursor:pointer':'cursor:default';
    var hoverStyle=canClickTeam?' onmouseenter="this.style.background=\'var(--accent-l)\'" onmouseleave="this.style.background=\'transparent\'"':"";
    var clickAttr=canClickTeam?' onclick="viewAs(\''+t.id+'\')"':"";
    return '<div'+clickAttr+hoverStyle+' style="'+clickStyle+';display:flex;flex-direction:row;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border);transition:background .1s;background:transparent">'+
      '<div class="av av-36 '+t.avc+'" style="flex-shrink:0">'+t.av+'</div>'+
      '<div style="flex:1;min-width:0;overflow:hidden">'+
        '<div style="font-weight:500;font-size:13.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--text)">'+t.name+'</div>'+
        '<div style="font-size:11.5px;color:var(--text3);white-space:nowrap">'+roleLabel(t.role)+(t.empId?' · '+t.empId:'')+'</div>'+
      '</div>'+
      '<div style="display:flex;flex-direction:row;gap:0;align-items:center;flex-shrink:0">'+
        '<div style="text-align:center;width:72px">'+
          '<div style="font-family:var(--display);font-weight:700;font-size:17px;color:var(--accent);line-height:1.2">'+tlp.length+'</div>'+
          '<div style="font-size:10px;color:var(--text3)">leads</div>'+
        '</div>'+
        '<div style="text-align:center;width:80px">'+
          '<div style="font-family:var(--display);font-weight:700;font-size:17px;color:'+rrColor+';line-height:1.2">'+rr_+'%</div>'+
          '<div style="font-size:10px;color:var(--text3)">response</div>'+
        '</div>'+
        '<div style="text-align:center;width:60px">'+
          '<div style="font-family:var(--display);font-weight:700;font-size:17px;color:var(--green);line-height:1.2">'+pos_+'</div>'+
          '<div style="font-size:10px;color:var(--text3)">positive</div>'+
        '</div>'+
        '<div style="text-align:center;width:60px">'+
          '<div style="font-family:var(--display);font-weight:700;font-size:17px;color:var(--red);line-height:1.2">'+neg_+'</div>'+
          '<div style="font-size:10px;color:var(--text3)">negative</div>'+
        '</div>'+
        (canClickTeam?'<div style="width:20px;text-align:center;color:var(--text3);font-size:13px">›</div>':'')+
      '</div>'+
    '</div>';
  }).join("");

  // industry breakdown
  var indMap={};
  var allMy=getMyLeads(u);
  allMy.forEach(function(l){var co=STATE.companies.find(function(c){return c.id===l.coid});if(co)indMap[co.ind]=(indMap[co.ind]||0)+1;});
  var indArr=Object.entries(indMap).sort(function(a,b){return b[1]-a[1]}).slice(0,7);
  var maxI=indArr.length?indArr[0][1]:1;
  var indRows=indArr.map(function(e){
    var pct=Math.round(e[1]/maxI*100);
    return '<div class="ind-row">'+
      '<div style="font-size:13px;min-width:110px">'+e[0]+'</div>'+
      '<div class="ind-bg"><div class="ind-fill" style="width:'+pct+'%;background:var(--accent)"></div></div>'+
      '<div style="font-size:12px;font-family:var(--mono);color:var(--text3);min-width:22px;text-align:right">'+e[1]+'</div>'+
    '</div>';
  }).join("");

  // response rate bars (last 4 weeks)
  var bars=[3,2,1,0].map(function(w){
    var wEnd=new Date();wEnd.setDate(wEnd.getDate()-w*7);
    var wStart=new Date(wEnd);wStart.setDate(wStart.getDate()-7);
    var wl=allMy.filter(function(l){var d=new Date(l.date);return d>=wStart&&d<=wEnd;});
    var we=wl.filter(function(l){return l.sent}).length;
    var rate=wl.length?Math.round(we/wl.length*100):0;
    var bg=rate>60?"var(--green)":rate>30?"var(--amber)":"var(--accent)";
    return '<div class="bar-col"><div class="bar-fill" style="height:'+Math.max(4,rate)+'%;background:'+bg+'"></div><div class="bar-lbl">W'+(4-w)+'</div></div>';
  }).join("");

  // stage pills
  var stagePills=STAGES.map(function(s){
    var cnt=pl.filter(function(l){return l.stage===s}).length;
    if(!cnt)return"";
    var c=s==="Positive"?"var(--green)":s==="Negative"?"var(--red)":s==="Connected"?"var(--accent)":"var(--text)";
    return '<div style="text-align:center;padding:12px 16px;background:var(--bg);border-radius:var(--r2);min-width:76px">'+
      '<div style="font-family:var(--display);font-size:22px;font-weight:700;color:'+c+'">'+cnt+'</div>'+
      '<div style="font-size:11px;color:var(--text3);margin-top:2px">'+s+'</div>'+
    '</div>';
  }).join("");

  return '<div class="page">'+
    (isViewingOther?
      '<div style="display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--amber-l);border:1px solid rgba(217,119,6,.25);border-radius:var(--r2);margin-bottom:14px;font-size:13px">'+
        '<span style="font-size:16px">👁</span>'+
        '<span>You are viewing <strong>'+u.name+'</strong>\'s dashboard as an observer.</span>'+
        '<button class="btn btn-outline btn-sm" style="margin-left:auto;font-size:12px" onclick="stopViewing()">← Back to mine</button>'+
      '</div>'
    :"")+
    '<div class="banner">'+
      '<div style="position:absolute;top:16px;right:20px;background:rgba(255,255,255,.18);backdrop-filter:blur(8px);border:1px solid rgba(255,255,255,.3);border-radius:var(--r2);padding:10px 16px;text-align:right">'+
        '<div id="dash-clock-time" style="font-family:var(--display);font-size:13px;font-weight:500;letter-spacing:.01em;line-height:1;color:rgba(255,255,255,.85)">'+new Date().toLocaleTimeString("en-IN",{hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:true})+'</div>'+
        '<div id="dash-clock-date" style="font-size:22px;font-weight:700;margin-top:5px;color:#fff;font-family:var(--display)">'+new Date().toLocaleDateString("en-IN",{weekday:"short",day:"numeric",month:"short"})+'</div>'+
      '</div>'+
      '<div class="banner-name">'+(isViewingOther?u.name+"'s Dashboard":greet+', '+u.name.split(" ")[0]+' 👋')+'</div>'+
      '<div class="banner-sub">'+roleLabel(u.role)+'</div>'+
      '<div class="banner-stats">'+
        '<div><div class="bstat-val">'+total+'</div><div class="bstat-lbl">Leads this period</div></div>'+
        '<div style="width:1px;background:rgba(255,255,255,.25);align-self:stretch"></div>'+
        '<div><div class="bstat-val">'+emailed+'</div><div class="bstat-lbl">Emails sent</div></div>'+
        '<div style="width:1px;background:rgba(255,255,255,.25);align-self:stretch"></div>'+
        '<div><div class="bstat-val">'+rr+'%</div><div class="bstat-lbl">Response rate</div></div>'+
        '<div style="width:1px;background:rgba(255,255,255,.25);align-self:stretch"></div>'+
        '<div><div class="bstat-val">'+pos+'</div><div class="bstat-lbl">Positive</div></div>'+
      '</div>'+
    '</div>'+

    '<div class="flex gap2 mb4 flex-wrap">'+pickers+'</div>'+

    (team.length?
      '<div class="card mb4">'+
        '<div style="padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between">'+
          '<div>'+
            '<div class="fw6">'+(u.role==="ra"?"Your BD Manager":"Your Team")+'</div>'+
            (canClickTeam&&!isViewingOther?'<div style="font-size:11px;color:var(--text3);margin-top:2px">Click any member to view their dashboard</div>':'')+
          '</div>'+
          '<div style="display:flex;flex-direction:row;align-items:center;flex-shrink:0">'+
            '<div style="text-align:center;width:72px;font-size:10px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em">Leads</div>'+
            '<div style="text-align:center;width:80px;font-size:10px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em">Response</div>'+
            '<div style="text-align:center;width:60px;font-size:10px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em">Pos</div>'+
            '<div style="text-align:center;width:60px;font-size:10px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em">Neg</div>'+
            (canClickTeam?'<div style="width:20px"></div>':'')+
          '</div>'+
        '</div>'+
        '<div>'+teamRows+'</div>'+
        '<div style="padding:8px 14px;background:var(--bg);border-top:1px solid var(--border);border-radius:0 0 var(--r3) var(--r3);font-size:11.5px;color:var(--text3)">Showing stats for: <strong style="color:var(--text)">'+STATE.period+'</strong></div>'+
      '</div>'
    :"")+

    '<div class="g2 mb4">'+
      '<div class="card cp"><div class="flex jb aic mb3"><div><div class="fw6">Response rate trend</div><div class="f12 text3">Last 4 weeks</div></div><span class="bdg bdg-blue">'+rr+'% avg</span></div><div class="bar-chart">'+bars+'</div></div>'+
      '<div class="card cp"><div class="fw6 mb3">Industry breakdown</div>'+(indRows||'<div class="text3 f13">No leads yet</div>')+'</div>'+
    '</div>'+

    '<div class="card cp"><div class="flex jb aic mb3"><div class="fw6">Pipeline overview</div><div class="f12 text3">'+STATE.period+'</div></div><div class="flex gap2 flex-wrap">'+stagePills+'</div></div>'+

    // ── REMINDERS WIDGET ─────────────────────────
    (function(){
      var today=todayIST();
      var myR=STATE.reminders.filter(function(r){return r.user_id===STATE.user.id&&r.status==="pending";});
      var due=myR.filter(function(r){return r.return_date<=today;});
      var upcoming=myR.filter(function(r){return r.return_date>today;}).slice(0,4);
      if(!myR.length)return '<div class="card cp mt4">'+
        '<div class="flex jb aic mb3">'+
          '<div><div class="fw6">Reminders</div><div class="f12 text3">No reminders set</div></div>'+
          '<button class="btn btn-outline btn-sm" onclick="goPage(\'reminders\')">Go to Reminders</button>'+
        '</div>'+
        '<div style="padding:16px 0;text-align:center;font-size:13px;color:var(--text3)">Set reminders to follow up with contacts at the right time.</div>'+
      '</div>';

      var dueRows=due.map(function(r){
        return '<div style="display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid var(--border)">'+
          '<div style="width:7px;height:7px;border-radius:50%;background:var(--amber);flex-shrink:0"></div>'+
          '<div style="flex:1;min-width:0">'+
            '<div style="font-size:13.5px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+htmlEsc(r.name)+'</div>'+
            '<div class="f12 text3">'+htmlEsc(r.company||r.email||"")+'</div>'+
          '</div>'+
          '<span style="font-size:11px;padding:2px 7px;background:var(--amber);color:#fff;border-radius:10px;white-space:nowrap">Due today</span>'+
          '<button class="btn btn-sm" style="background:var(--amber);color:#fff;white-space:nowrap" onclick="sendReminderEmail(\''+r.id+'\')">'+ico("send",12)+' Send</button>'+
        '</div>';
      }).join("");

      var upcomingRows=upcoming.map(function(r){
        var days=Math.ceil((new Date(r.return_date)-new Date(today))/86400000);
        return '<div style="display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid var(--border)">'+
          '<div style="width:7px;height:7px;border-radius:50%;background:var(--accent);flex-shrink:0"></div>'+
          '<div style="flex:1;min-width:0">'+
            '<div style="font-size:13.5px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+htmlEsc(r.name)+'</div>'+
            '<div class="f12 text3">'+htmlEsc(r.return_date||'')+(r.reminder_time?' · '+r.reminder_time+' IST':'')+(r.note?' · '+htmlEsc(r.note):'')+'</div>'+
          '</div>'+
          '<span style="font-size:11px;padding:2px 8px;background:'+(days<=3?"var(--red-l)":"var(--accent-l)")+';color:'+(days<=3?"var(--red)":"var(--accent)")+';border-radius:10px;white-space:nowrap">'+days+' day'+(days!==1?"s":"")+'</span>'+
        '</div>';
      }).join("");

      return '<div class="card cp mt4">'+
        '<div class="flex jb aic mb3">'+
          '<div>'+
            '<div class="fw6">Reminders</div>'+
            '<div class="f12 text3">'+due.length+' due · '+upcoming.length+' upcoming</div>'+
          '</div>'+
          '<div class="flex gap2">'+
            (due.length?'<button class="btn btn-sm" style="background:var(--amber);color:#fff" onclick="sendAllDue()">Send all due ('+due.length+')</button>':"")+
            '<button class="btn btn-outline btn-sm" onclick="goPage(\'reminders\')">View all</button>'+
          '</div>'+
        '</div>'+
        (due.length?'<div style="margin-bottom:8px;font-size:12px;font-weight:600;color:var(--amber);text-transform:uppercase;letter-spacing:.05em">⏰ Due now</div>':"")+
        dueRows+
        (upcoming.length?'<div style="margin:'+(due.length?"12px":"0")+'px 0 8px;font-size:12px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.05em">Upcoming</div>':"")+
        upcomingRows+
        (myR.length>5?'<div style="padding-top:10px;text-align:center"><button class="btn btn-outline btn-sm" onclick="goPage(\'reminders\')">View all '+myR.length+' reminders</button></div>':"")+
      '</div>';
    })()+

  '</div>';
}

function filterPeriod(leads,p){
  var now=new Date();
  return leads.filter(function(l){
    var d=new Date(l.date);
    if(p==="daily")return l.date===todayIST();
    if(p==="weekly"){var w=new Date(now);w.setDate(w.getDate()-7);return d>=w;}
    if(p==="monthly")return d.getMonth()===now.getMonth()&&d.getFullYear()===now.getFullYear();
    if(p==="quarterly"){var q=new Date(now);q.setMonth(q.getMonth()-3);return d>=q;}
    return true;
  });
}


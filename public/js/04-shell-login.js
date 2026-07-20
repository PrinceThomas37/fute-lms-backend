// ════════════════════════════════════════════════
// RENDER LOGIN
// ════════════════════════════════════════════════
function renderLogin(){
  var picks=STATE.users.map(function(u){
    return '<button class="fc" onclick="loginAs(\''+u.id+'\')" style="font-size:11.5px">'+u.name+'</button>';
  }).join("");
  return '<div class="login-wrap">'+
    '<canvas id="login-canvas" style="position:fixed;inset:0;width:100%;height:100%;z-index:0"></canvas>'+
    '<div class="login-card" style="position:relative;z-index:2">'+
      '<div class="login-top">'+
        '<div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">'+
          '<div style="line-height:1;flex-shrink:0"><span style="font-family:var(--display);font-weight:700;font-size:36px;color:#fff;letter-spacing:-.5px">fut</span><span style="font-family:var(--display);font-weight:700;font-size:36px;color:#F5C23B;letter-spacing:-.5px">é</span></div>'+
          '<div><div style="font-family:var(--display);font-weight:700;font-size:20px;color:#fff;line-height:1.2">Fute Global LLC</div><div style="font-size:12px;color:rgba(255,255,255,.82);margin-top:2px">Lead Management Software</div></div>'+
        '</div>'+
        '<div style="font-size:11.5px;color:rgba(255,255,255,.65);border-top:1px solid rgba(255,255,255,.2);padding-top:10px">Internal platform · Authorized personnel only</div>'+
      '</div>'+
      '<div class="login-body">'+
        '<div style="font-family:var(--display);font-weight:600;font-size:17px;margin-bottom:5px">Welcome back</div>'+
        '<div style="font-size:13px;color:var(--text3);margin-bottom:20px">Sign in with your Fute Global account</div>'+
        '<button class="google-btn" onclick="showToast(\'Google Workspace login coming soon. Use email and password for now.\',\'info\')">'+
          '<span style="width:20px;height:20px;display:inline-flex">'+icon("google")+'</span>'+
          'Continue with Google Workspace'+
        '</button>'+
        '<button onclick="doGuestLogin()" style="display:flex;align-items:center;justify-content:center;gap:9px;width:100%;padding:10px;border:1.5px dashed rgba(30,122,60,.35);border-radius:8px;background:rgba(30,122,60,0.05);font-size:13.5px;font-weight:500;cursor:pointer;margin-bottom:14px;font-family:inherit;color:#1E7A3C">'+
          '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#1E7A3C" stroke-width="1.8"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>'+
          'Continue as Guest &nbsp;<span style="font-size:11px;color:#9ca3af;font-weight:400">· Portfolio preview</span>'+
        '</button>'+
        '<div class="or-div">or sign in with email</div>'+
        '<div class="fgrp"><label class="flbl">Work email</label><input class="inp" id="login-email" type="email" placeholder="you@futeglobal.com"/></div>'+
        '<div class="fgrp"><label class="flbl">Password</label><div style="position:relative"><input class="inp" id="login-pass" type="password" placeholder="••••••••" style="padding-right:40px"/><button type="button" onclick="var i=document.getElementById(\'login-pass\');i.type=i.type===\'password\'?\'text\':\'password\';this.innerHTML=i.type===\'password\'?\'<svg viewBox=&quot;0 0 24 24&quot; fill=&quot;none&quot; stroke=&quot;currentColor&quot; stroke-width=&quot;1.8&quot; width=&quot;16&quot; height=&quot;16&quot;><path d=&quot;M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z&quot;/><circle cx=&quot;12&quot; cy=&quot;12&quot; r=&quot;3&quot;/></svg>\':\' <svg viewBox=&quot;0 0 24 24&quot; fill=&quot;none&quot; stroke=&quot;currentColor&quot; stroke-width=&quot;1.8&quot; width=&quot;16&quot; height=&quot;16&quot;><path d=&quot;M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94&quot;/><path d=&quot;M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19&quot;/><line x1=&quot;1&quot; y1=&quot;1&quot; x2=&quot;23&quot; y2=&quot;23&quot;/></svg>\'" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:0;cursor:pointer;color:var(--text3);padding:0;display:flex;align-items:center"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button></div></div>'+
        '<div id="login-err" style="display:none;color:var(--red);font-size:12px;background:var(--red-l);padding:8px 10px;border-radius:var(--r);margin-bottom:10px"></div>'+
        '<button class="btn btn-primary w100" style="justify-content:center" onclick="doLogin()">Sign in</button>'+
      '</div>'+
    '</div>'+
  '</div>'+renderToasts();
}

// ════════════════════════════════════════════════
// RENDER APP SHELL
// ════════════════════════════════════════════════
function renderApp(){
  var u=STATE.user;
  var today=todayIST();
  var myLeads=getMyLeads(u);
  var todayCnt=myLeads.filter(function(l){return l.date===today}).length;

  var navItems=[
    {id:"dashboard",lbl:"Dashboard",ic:"dashboard"},
    // Lead-gen is BD/RA territory — a pure recruiter's desk is jobs + candidates,
    // so Leads stays out of their menu.
    ...(isPureRecruiter(u)?[]:[{id:"leads",lbl:"Leads",ic:"leads",badge:todayCnt}]),
    ...(!userHasRole(u,'ra')||userHasAnyRole(u,'bd','bd_lead','admin','ra_lead')?[{id:"email",lbl:"Email",ic:"email"}]:[]),
    ...(userHasRole(u,'ra')&&!userHasAnyRole(u,'admin','bd','bd_lead','ra_lead')?[{id:"insights",lbl:"Insights",ic:"dashboard"}]:[{id:"reminders",lbl:"Reminders",ic:"star",badge:STATE.reminders.filter(function(r){return r.user_id===u.id&&r.status==="pending"}).length||null}]),
    {id:"profile",lbl:"My Profile",ic:"profile"}
  ];
  // Admin only: Admin panel
  if(userHasRole(u,'admin'))navItems.splice(4,0,{id:"admin",lbl:"Admin",ic:"admin"});
  // Admin + leads: Deliverability dashboard
  if(userHasAnyRole(u,'admin','bd_lead','ra_lead'))navItems.splice(navItems.length-1,0,{id:"deliverability",lbl:"Deliverability",ic:"dashboard"});
  // Sequence now lives inside the Email page as a tab (see renderEmail) — no
  // standalone nav item, so it reads as part of outreach, not a separate module.
  // RA Lead + Admin: Assign Leads + Insights (RA team view)
  if(userHasAnyRole(u,'ra_lead','admin'))navItems.splice(2,0,{id:"assign",lbl:"Assign Leads",ic:"leads"});
  if(userHasAnyRole(u,'ra_lead','admin'))navItems.splice(navItems.length-1,0,{id:"insights",lbl:"Insights",ic:"dashboard"});
  // BD Lead (not admin): Team Insights + My Insights
  if(userHasRole(u,'bd_lead')&&!userHasRole(u,'admin')){
    navItems.splice(navItems.length-1,0,{id:"bdleadinsights",lbl:"Team Insights",ic:"dashboard"});
    navItems.splice(navItems.length-1,0,{id:"bdinsights",lbl:"My Insights",ic:"dashboard"});
  }
  // BD Manager (not bd_lead/admin): own performance Insights
  if(userHasRole(u,'bd')&&!userHasAnyRole(u,'bd_lead','admin'))navItems.splice(navItems.length-1,0,{id:"bdinsights",lbl:"My Insights",ic:"dashboard"});

  var nav=navItems.map(function(n){
    var active=STATE.page===n.id?" active":"";
    var badge=n.badge&&n.badge>0?'<span class="nav-badge">'+n.badge+'</span>':"";
    return '<div class="nav-item'+active+'" onclick="goPage(\''+n.id+'\')"><span class="nav-icon">'+icon(n.ic)+'</span>'+n.lbl+badge+'</div>';
  }).join("");

  var switchers=""; // removed — use team list to switch views

  var pageTitles={dashboard:"Dashboard",leads:"Leads",assign:"Assign Leads",email:"Email",admin:"Admin",deliverability:"Deliverability & Replies",emailaccounts:"Email Accounts",managerusers:"Manager Users",insights:"Insights",bdinsights:"My Insights",bdleadinsights:"Team Insights",profile:"My Profile",reminders:"Reminders"};
  var viewingName=STATE.viewingUser&&STATE.viewingUser.id!==u.id?" · Viewing: "+STATE.viewingUser.name:"";

  return '<div id="sidebar">'+
    '<div class="sb-brand"><div class="sb-logo">'+
      '<div style="line-height:1;flex-shrink:0"><span style="font-family:var(--display);font-weight:700;font-size:22px;color:var(--accent);letter-spacing:-.5px">fut</span><span style="font-family:var(--display);font-weight:700;font-size:22px;color:#F5C23B;letter-spacing:-.5px">é</span></div>'+
      '<div><div class="sb-name">Global</div><div class="sb-sub">Lead Management</div></div>'+
    '</div></div>'+
    '<div class="sb-nav"><div class="sb-lbl">Menu</div>'+nav+'</div>'+
    '<div class="sb-footer">'+
      (u.isGuest?
        '<div style="background:var(--accent-l);border:1px solid rgba(30,122,60,.2);border-radius:8px;padding:8px 10px;margin-bottom:8px">'+
          '<div style="font-size:11px;font-weight:700;color:var(--accent);margin-bottom:4px">GUEST MODE · Portfolio Preview</div>'+
          '<div style="font-size:10.5px;color:var(--text3);margin-bottom:7px">Switch view to explore different roles:</div>'+
          '<div style="display:flex;gap:5px;flex-wrap:wrap">'+
            '<button onclick="guestSwitchRole(\'bd\')" style="font-size:10.5px;padding:3px 8px;border-radius:5px;border:1px solid var(--border);background:'+(u.role==='bd'?'var(--accent)':'var(--card)')+';color:'+(u.role==='bd'?'#fff':'var(--text2)')+';cursor:pointer;font-weight:600">BD Manager</button>'+
            '<button onclick="guestSwitchRole(\'ra\')" style="font-size:10.5px;padding:3px 8px;border-radius:5px;border:1px solid var(--border);background:'+(u.role==='ra'?'var(--accent)':'var(--card)')+';color:'+(u.role==='ra'?'#fff':'var(--text2)')+';cursor:pointer;font-weight:600">RA</button>'+
            '<button onclick="guestSwitchRole(\'ra_lead\')" style="font-size:10.5px;padding:3px 8px;border-radius:5px;border:1px solid var(--border);background:'+(u.role==='ra_lead'?'var(--accent)':'var(--card)')+';color:'+(u.role==='ra_lead'?'#fff':'var(--text2)')+';cursor:pointer;font-weight:600">RA Lead</button>'+
          '</div>'+
        '</div>':'')  +
      '<div class="user-row" onclick="goPage(\'profile\')">'+av(u,"32")+'<div style="flex:1;min-width:0"><div class="u-name">'+u.name+(u.isGuest?'<span style="font-size:9px;background:#F5C23B;color:#78350f;padding:1px 5px;border-radius:4px;font-weight:700;margin-left:5px">GUEST</span>':'')+'</div><div class="u-role">'+roleLabel(u.role)+'</div></div></div>'+
      '<div class="signout" onclick="signOut()">Sign out</div>'+
    '</div>'+
  '</div>'+
  '<div id="main">'+
    '<div id="topbar">'+
      '<div>'+
        '<div class="tb-title">'+pageTitles[STATE.page]+viewingName+'</div>'+
      '</div>'+
      '<div class="tb-right">'+
        (STATE.viewingUser&&STATE.viewingUser.id!==u.id?
          '<button class="btn btn-outline btn-sm" onclick="stopViewing()" style="font-size:12px">← Back to my dashboard</button>'
        :"")+
      '</div>'+
    '</div>'+
    '<div id="content">'+renderPage()+'</div>'+
  '</div>'+
  renderToasts()+renderModal();
}

function roleLabel(r){return{ra:"Research Analyst",bd:"BD Manager",admin:"Admin",ra_lead:"RA Team Lead",bd_lead:"BD Team Lead",recruiter:"Recruiter"}[r]||r;}


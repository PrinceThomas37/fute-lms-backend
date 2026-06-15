// ════════════════════════════════════════════════
// SEED DATA
// ════════════════════════════════════════════════
var USERS = [
  // BD Team
  {id:"u1",name:"Prince Thomas",  email:"prince@futeglobal.com", role:"admin",empId:"FG-001",desig:"Business Development Manager",bdm:null,av:"PT",avc:"av-admin",plt:"Gmail"},
  {id:"u2",name:"Ash Sayyad",     email:"ash@futeglobal.com",    role:"bd",   empId:"FG-002",desig:"Business Development Manager",bdm:null,av:"AS",avc:"av-bd",  plt:"Gmail"},
  {id:"u3",name:"Pranay Narayan", email:"pranay@futeglobal.com", role:"bd",   empId:"FG-003",desig:"Business Development Manager",bdm:null,av:"PN",avc:"av-bd",  plt:"Gmail"},
  {id:"u4",name:"Sarah Smith",    email:"sarah@futeglobal.com",  role:"bd",   empId:"FG-004",desig:"Business Development Manager",bdm:null,av:"SS",avc:"av-bd",  plt:"Gmail"},
  {id:"u5",name:"Patrick Wilson", email:"patrick@futeglobal.com",role:"bd",   empId:"FG-005",desig:"Business Development Manager",bdm:null,av:"PW",avc:"av-bd",  plt:"Gmail"},
  {id:"u6",name:"Michael Smith",  email:"michael@futeglobal.com",role:"bd",   empId:"FG-006",desig:"Business Development Manager",bdm:null,av:"MS",avc:"av-bd",  plt:"Gmail"},
  {id:"u7",name:"Gregg Daniels",  email:"gregg@futeglobal.com",  role:"bd",   empId:"FG-007",desig:"Business Development Manager",bdm:null,av:"GD",avc:"av-bd",  plt:"Gmail"},
  // RA Team (unassigned — assign via Admin tab)
  {id:"u8", name:"Steven Parker",  email:"steven@futeglobal.com",  role:"ra",empId:"FG-008",desig:"Research Analyst",bdm:null,av:"SP",avc:"av-ra",plt:"Gmail"},
  {id:"u9", name:"Mick Thompson",  email:"mick@futeglobal.com",    role:"ra",empId:"FG-009",desig:"Research Analyst",bdm:null,av:"MT",avc:"av-ra",plt:"Gmail"},
  {id:"u10",name:"Dan Johnson",    email:"dan@futeglobal.com",     role:"ra",empId:"FG-010",desig:"Research Analyst",bdm:null,av:"DJ",avc:"av-ra",plt:"Gmail"},
  {id:"u11",name:"Amy Hernandez",  email:"amy@futeglobal.com",     role:"ra",empId:"FG-011",desig:"Research Analyst",bdm:null,av:"AH",avc:"av-ra",plt:"Gmail"},
  {id:"u12",name:"Jessica Davis",  email:"jessica@futeglobal.com", role:"ra",empId:"FG-012",desig:"Research Analyst",bdm:null,av:"JD",avc:"av-ra",plt:"Gmail"},
  {id:"u13",name:"Nancy Parker",   email:"nancy@futeglobal.com",   role:"ra",empId:"FG-013",desig:"Research Analyst",bdm:null,av:"NP",avc:"av-ra",plt:"Gmail"},
  {id:"u14",name:"Julia Jens",     email:"julia@futeglobal.com",   role:"ra",empId:"FG-014",desig:"Research Analyst",bdm:null,av:"JJ",avc:"av-ra",plt:"Gmail"},
  {id:"u15",name:"Diana Davis",    email:"diana@futeglobal.com",   role:"ra",empId:"FG-015",desig:"Research Analyst",bdm:null,av:"DD",avc:"av-ra",plt:"Gmail"},
  {id:"u16",name:"Anna Harper",    email:"anna@futeglobal.com",    role:"ra",empId:"FG-016",desig:"Research Analyst",bdm:null,av:"AH",avc:"av-ra",plt:"Gmail"},
  {id:"u17",name:"Justin Clark",   email:"justin@futeglobal.com",  role:"ra",empId:"FG-017",desig:"Research Analyst",bdm:null,av:"JC",avc:"av-ra",plt:"Gmail"},
  {id:"u18",name:"Lisa Anderson",  email:"lisa@futeglobal.com",    role:"ra",empId:"FG-018",desig:"Research Analyst",bdm:null,av:"LA",avc:"av-ra",plt:"Gmail"},
  {id:"u19",name:"Kristy Scott",   email:"kristy@futeglobal.com",  role:"ra",empId:"FG-019",desig:"Research Analyst",bdm:null,av:"KS",avc:"av-ra",plt:"Gmail"},
  {id:"u20",name:"Stephan Hunter", email:"stephan@futeglobal.com", role:"ra",empId:"FG-020",desig:"Research Analyst",bdm:null,av:"SH",avc:"av-ra",plt:"Gmail"},
  {id:"u21",name:"Melissa White",  email:"melissa@futeglobal.com", role:"ra",empId:"FG-021",desig:"Research Analyst",bdm:null,av:"MW",avc:"av-ra",plt:"Gmail"},
  {id:"u22",name:"David Miller",   email:"david@futeglobal.com",   role:"ra",empId:"FG-022",desig:"Research Analyst",bdm:null,av:"DM",avc:"av-ra",plt:"Gmail"},
  {id:"u23",name:"Daniel James",   email:"daniel@futeglobal.com",  role:"ra",empId:"FG-023",desig:"Research Analyst",bdm:null,av:"DJ",avc:"av-ra",plt:"Gmail"},
  {id:"u24",name:"Sharon Moss",    email:"sharon@futeglobal.com",  role:"ra",empId:"FG-024",desig:"Research Analyst",bdm:null,av:"SM",avc:"av-ra",plt:"Gmail"},
  {id:"u25",name:"Neal Patrick",   email:"neal@futeglobal.com",    role:"ra",empId:"FG-025",desig:"Research Analyst",bdm:null,av:"NP",avc:"av-ra",plt:"Gmail"}
];

var COMPANIES = [
  {id:"c1",name:"TechNova Solutions",web:"technova.io",ind:"Technology",loc:"Bangalore"},
  {id:"c2",name:"FinEdge Capital",web:"finedge.com",ind:"Finance",loc:"Mumbai"},
  {id:"c3",name:"HealthFirst Clinics",web:"healthfirst.in",ind:"Healthcare",loc:"Hyderabad"},
  {id:"c4",name:"BuildMax Infra",web:"buildmax.co.in",ind:"Manufacturing",loc:"Delhi"},
  {id:"c5",name:"RetailPro India",web:"retailpro.in",ind:"Retail",loc:"Chennai"},
  {id:"c6",name:"EduSpark",web:"eduspark.io",ind:"Education",loc:"Pune"},
  {id:"c7",name:"Nexus Consulting",web:"nexusconsult.com",ind:"Consulting",loc:"Bangalore"},
  {id:"c8",name:"MediaFlow",web:"mediaflow.in",ind:"Media",loc:"Mumbai"},
  {id:"c9",name:"LogiTrans",web:"logitrans.co.in",ind:"Logistics",loc:"Delhi"},
  {id:"c10",name:"LegalEdge",web:"legaledge.in",ind:"Legal",loc:"Hyderabad"},
  {id:"c11",name:"PropVault Realty",web:"propvault.in",ind:"Real Estate",loc:"Noida"},
  {id:"c12",name:"DataSense AI",web:"datasense.ai",ind:"Technology",loc:"Bangalore"}
];

var STAGES = ["Active","No Response","Negative","Positive","Connected","Future","Out of Office","Deactivated","Referred"];
var INDUSTRIES = ["Technology","Finance","Healthcare","Manufacturing","Retail","Education","Consulting","Media","Logistics","Legal","Real Estate"];
var SOURCES = ["LinkedIn","Indeed","Naukri","Company Website","Glassdoor","AngelList","Referral","Other"];
var POSITIONS = ["CTO","VP of Engineering","Head of Product","Procurement Director","Head of Digital","CFO","Director HR","VP Sales","Head of Operations","CMO","CHRO"];
var FIRSTNAMES = ["Arjun","Sunita","Vikram","Pooja","Rahul","Priya","Aditya","Sneha","Rohan","Meera","Karan","Divya","Amit","Neha"];
var LASTNAMES = ["Kapoor","Rao","Nair","Desai","Sharma","Singh","Mehta","Patel","Gupta","Kumar","Joshi","Verma"];
var RA_IDS = ["u8","u9","u10","u11","u12","u13","u14","u15","u16","u17","u18","u19","u20","u21","u22","u23","u24","u25"];
var RA_BD = {"u8":"u1","u9":"u1","u10":"u2","u11":"u2","u12":"u3","u13":"u3","u14":"u4","u15":"u4","u16":"u5","u17":"u5","u18":"u6","u19":"u6","u20":"u7","u21":"u7","u22":"u1","u23":"u2","u24":"u3","u25":"u4"};

function rp(arr){return arr[Math.floor(Math.random()*arr.length)]}
function rd(days){var d=new Date();d.setDate(d.getDate()-Math.floor(Math.random()*days));return d.toISOString().split("T")[0]}
function todayIST(){var n=new Date();return new Date(n.getTime()+5.5*3600000).toISOString().split("T")[0]}
function fmtDate(d){if(!d)return"—";var p=d.split("-");return p[2]+"/"+p[1]+"/"+p[0]}
function uname(id,users){var u=users.find(function(x){return x.id===id});return u?u.name:"—"}
function stageClass(s){return"st-"+s.replace(/ /g,"_")}

function genLeads(){
  var leads=[];var lid=1;
  COMPANIES.forEach(function(co){
    var n=Math.floor(Math.random()*4)+2;
    for(var j=0;j<n;j++){
      var aid=rp(RA_IDS);var bid=RA_BD[aid];
      var st=rp(STAGES);var dt=rd(30);
      var fn=rp(FIRSTNAMES);var ln=rp(LASTNAMES);
      leads.push({
        id:"l"+lid++,coid:co.id,pos:rp(POSITIONS),
        fn:fn,ln:ln,desig:rp(["CTO","VP Ops","Head of Digital","Director","CFO","CHRO"]),
        email:fn.toLowerCase()+"."+ln.toLowerCase()+"@"+co.web,
        phone:"+91 9"+Math.floor(Math.random()*8+1)+String(Math.random()).slice(2,10),
        li:"https://linkedin.com/in/"+fn.toLowerCase()+ln.toLowerCase(),
        src:rp(SOURCES),aid:aid,bid:bid,stage:st,date:dt,
        sent:st!=="Active"&&Math.random()>.3?dt:null,
        plt:rp(["Gmail","Outlook",null]),notes:"",del:null
      });
    }
  });
  return leads;
}

function genActs(leads){
  var acts=[];
  leads.forEach(function(l){
    acts.push({id:"a"+acts.length,lid:l.id,uid:l.aid,type:"created",txt:"Lead created",dt:l.date});
    if(l.sent)acts.push({id:"a"+acts.length,lid:l.id,uid:l.aid,type:"email",txt:"Email sent via "+(l.plt||"Gmail"),dt:l.sent});
    if(l.stage!=="Active")acts.push({id:"a"+acts.length,lid:l.id,uid:l.bid,type:"stage",txt:'Stage → "'+l.stage+'"',dt:l.date});
  });
  return acts;
}

// ════════════════════════════════════════════════
// STATE
// ════════════════════════════════════════════════

// ════════════════════════════════════════════════
// JOBS / CONTACTS MODEL  (matches backend index.js)
// ════════════════════════════════════════════════
function genJobs(seedLeads, companies){
  // Group seedLeads by (company + position) -> 1 job + N contacts
  var jobs = [], contacts = [], jmap = {};
  var stages = ["Active","In Progress","Interview","Closed","Lost"];
  for (var i=0;i<seedLeads.length;i++){
    var l = seedLeads[i];
    var key = l.coid + "||" + l.pos;
    var jid = jmap[key];
    if (!jid){
      jid = "j" + (jobs.length+1);
      jmap[key] = jid;
      var co = companies.find(function(c){return c.id===l.coid;}) || {};
      jobs.push({
        id: jid,
        company_id: l.coid,
        company_name: co.name || "",
        company_ind: co.ind || "",
        company_web: co.web || "",
        position: l.pos,
        location: l.loc || "",
        source: l.src || "LinkedIn",
        job_url: "",
        stage: stages[Math.floor(Math.random()*3)],
        notes: "",
        created_by: l.aid,
        assigned_to: l.aid,
        created_date: l.created || new Date().toISOString().slice(0,10),
        created_at: new Date().toISOString()
      });
    }
    contacts.push({
      id: "c" + (contacts.length+1),
      job_id: jid,
      first_name: l.fn,
      last_name: l.ln || "",
      designation: l.desig || "",
      email: l.email || "",
      phone: l.phone || "",
      linkedin: "",
      is_primary: contacts.filter(function(c){return c.job_id===jid;}).length===0,
      email_sent_at: l.sent || null
    });
  }
  return { jobs: jobs, contacts: contacts };
}
function getMyJobs(u){
  if (!u) return [];
  if (userHasAnyRole(u,'admin','ra_lead')) return STATE.jobs.slice();
  if (userHasRole(u,'bd_lead')) return STATE.jobs.filter(function(j){return j.assigned_to_bd!==null;});
  if (userHasRole(u,'bd')) return STATE.jobs.filter(function(j){return j.assigned_to_bd===u.id;});
  // ra: only jobs they created
  return STATE.jobs.filter(function(j){return j.created_by===u.id;});
}
function jobContacts(jid){
  return STATE.contacts.filter(function(c){return c.job_id===jid;})
    .sort(function(a,b){return (b.is_primary?1:0)-(a.is_primary?1:0);});
}
function jobById(id){ return STATE.jobs.find(function(j){return j.id===id;}); }
function escAttr(v){ return String(v==null?"":v).replace(/"/g,"&quot;").replace(/</g,"&lt;"); }
function escHtml(v){ return String(v==null?"":v).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); }
function getIndustriesList(){
  return (STATE.industriesList&&STATE.industriesList.length)?STATE.industriesList:[];
}
function buildIndustrySelectOptions(selected){
  var list=getIndustriesList().slice();
  if(selected&&list.indexOf(selected)===-1)list.unshift(selected);
  return [''].concat(list).map(function(v){
    return '<option value="'+escAttr(v)+'"'+(selected===v?' selected':'')+'>'+(v||'— Select Industry —')+'</option>';
  }).join('');
}

var STATE = {

  user: null,
  page: "dashboard",
  users: JSON.parse(JSON.stringify(USERS)),
  leads: genLeads(),
  companies: JSON.parse(JSON.stringify(COMPANIES)),
  activities: [],
  emails: [],
  toasts: [],
  modal: null,
  detailLead: null,
  leadsFilter: {search:"",stage:"all",date:"today",ind:"all"},
  leadsSelected: {},
  leadsPage: 0,
  leadsPageSize: 20,
  mailMerge: null,
  period: "monthly",
  emailTab: "compose",
  sendProgress: null,
  pendingSummary: null,
  _pendingSummaryTimer: null,
  _progressPollTimer: null,
  previewEmail: null,
  showEmailPreview: false,
  mergeLeadId: null,
  emailSearch: null,
  manualEmail: null,
  manualEmailName: null,
  aiPrompt: null,
  aiPromptDefault: "Write a concise, professional cold outreach email (3-4 short paragraphs). Open with a personalised hook referencing their company or role. Briefly introduce Fute Global as a specialist staffing firm. Include a soft CTA asking for a 15-min call. Be warm but direct — no fluff.",
  emailSubj: "Candidates for your {{pos}} role in {{loc}}",
  emailBody: "Hi {{fn}},\n\nI'm {{sender}} with Fute Global LLC. I came across your {{pos}} opening in {{loc}} and read through the requirements, and we have several people with {{job_resp}} experience on {{company_service}} work who look like a strong fit. They're open to direct hire and haven't been screened for your role yet.\n\nWould you like to review their resumes?\n\nLooking forward to your thoughts.",
  fu1Subj: "Re: Candidates for your {{pos}} role in {{loc}}",
  fu1Body: "Hi {{fn}},\n\nCircling back on your {{pos}} role in {{loc}}. Those candidates with {{job_resp}} experience on {{company_service}} projects are still available.\n\nWant me to send their resumes over?\n\nLooking forward to your thoughts.",
  fu2Subj: "Re: Candidates for your {{pos}} role in {{loc}}",
  fu2Body: "Hi {{fn}},\n\nI'll keep this short. Still holding a few screened-ready candidates with {{job_resp}} backgrounds for your {{pos}} opening in {{loc}} whenever the timing suits.\n\nShall I share their resumes?\n\nLooking forward to your thoughts.",
  appSettings: {},
  teamAssignments: [],
  userEmailsCache: {},      // userId -> array of user_emails
  managerUsersTab: 'bd',    // 'ra' | 'bd' | 'rateam' | 'bdteam'
  selectedManagerUser: null,
  genEmail: null,
  aiGenerating: false,
  adminTab: "all",
  adminSearch: "",
  adminView: "bd",
  adminSelectedUser: null,
  addUserForm: null,
  reminders: [],
  reminderTab: "ooo",
  reminderSearch: null,
  viewingUser: null,
  importPreview: null,
  importWB: null,
  importSheet: null,
  jobs: [],
  contacts: [],
  detailJob: null,
  industriesList: [],
  jobsFilter: {search:"",stages:[],industries:[],dateRange:"all",dateFrom:"",dateTo:""},
  openDrop: null,
  assignSel: {},
  assignTargetBD: "",
  distributePoolStats: null,
  _assignManagerId: null,
  _assignRatio: null,
  todaySummary: null,
  insightsData: null,
  insightsSelectedRA: null,
  bdInsightsData: null,
  bdLeadSelectedBD: null,
  bdInsightsData: null,
  assignFilter: {ra:"",dup:"all"},
  pendingEmails: [],
  previewPendingId: null,
  emailAccounts: [],
  composeContactId: null,
  composeCompanyId: null,
  composeFromEmailId: null,
  composeSubj: '',
  composeBody: '',
  composeContext: null,
  composeReminderId: null,
  showAIPanel: false,
  signatureHtml: '',
  sigEmailId: null,
  emailSignaturesCache: {},
  planFromEmailId: null,
  outreachStylePreset: 'v1',
  composeStylePreset: null,
  randomTemplateMode: false,
  varInsertTarget: 'body',
  showMoreVarChips: false,
  sigEditing: false,
  sigLayout: 'simple',
  raForm: {
    coName:'',coId:null,coInfo:null,website:'',industry:'',location:'',zipCode:'',
    position:'',jobUrl:'',jobCreatedDate:'',salaryRange:'',source:'',editJobId:null,
    contacts:[{firstName:'',lastName:'',designation:'',email:'',phone:'',linkedin:'',emailStatus:'',emailDupInfo:null}],
    research:{jd_raw:'',suggested_skills:[],company:{expertise:'',notes:'',headcount:'',hiring_volume:''},outreach:{angle:'',avoid:''},requirements:{skill_1:'',skill_2:'',skill_3:'',salary_min:null,salary_max:null,salary_period:'year',salary_display:'',location:'',local_hint:'',travel:''},contacts:[]}
  },
  raFormCoSuggestions:[],
  raFormZipSuggestions:[],
  raFormSubmitting:false,
};

// No pre-seeded reminders — users set them manually from the OOO list
STATE.activities = genActs(STATE.leads);
var _seed = genJobs(STATE.leads, STATE.companies);
STATE.jobs = _seed.jobs;
STATE.contacts = _seed.contacts;
STATE.emails = STATE.leads.filter(function(l){return l.sent}).slice(0,6).map(function(l,i){
  var co=STATE.companies.find(function(c){return c.id===l.coid})||{};
  var body="Hi "+l.fn+",\n\nI came across "+co.name+" and was really impressed by what you're building in the "+(co.ind||"")+" space.\n\nAt Fute Global, we specialize in connecting organizations with top-tier talent. Given your role as "+l.desig+", I believe we could be genuinely helpful with your "+l.pos+" search.\n\nWould you be open to a quick 15-minute call this week?\n\nWarm regards,\nFute Global LLC";
  return{id:"e"+i,lid:l.id,by:l.aid,to:l.email,subj:"Connecting re: "+l.pos+" at "+(co?co.name:""),body:body,plt:l.plt||"Gmail",dt:l.sent,status:"sent"};
});

// ════════════════════════════════════════════════
// RENDER ENGINE
// ════════════════════════════════════════════════
var toastTimer={};
// Patch only the toast container instead of rebuilding the whole page —
// a full render() here would wipe unsaved inputs in any open modal.
function updateToastsDOM(){
  var html=renderToasts();
  var w=document.querySelector('.toast-wrap');
  if(w){w.outerHTML=html;}
  else if(html){
    var app=document.getElementById('app');
    if(app){var d=document.createElement('div');d.innerHTML=html;if(d.firstChild)app.appendChild(d.firstChild);}
  }
}
function showToast(msg,type){
  type=type||"info";
  var id=Date.now();
  STATE.toasts.push({id:id,msg:msg,type:type});
  toastTimer[id]=setTimeout(function(){
    STATE.toasts=STATE.toasts.filter(function(t){return t.id!==id});
    updateToastsDOM();
  },3000);
  updateToastsDOM();
}

var clockTimer=null;
function startClock(){
  if(clockTimer)clearInterval(clockTimer);
  clockTimer=setInterval(function(){
    var n=new Date();
    var dt=document.getElementById("dash-clock-time");
    var dd=document.getElementById("dash-clock-date");
    if(dt)dt.textContent=n.toLocaleTimeString("en-IN",{hour:"2-digit",minute:"2-digit",second:"2-digit",hour12:true});
    if(dd)dd.textContent=n.toLocaleDateString("en-IN",{weekday:"short",day:"numeric",month:"short"});
  },1000);
}

function render(){
  var root=document.getElementById("app");
  if(!root)return;
  if(!STATE.user){root.innerHTML=renderLogin();bindLogin();return;}
  if(STATE.loading){
    root.innerHTML='<div style="display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column;gap:14px;background:var(--bg)">'+
      '<div style="width:36px;height:36px;border:3px solid var(--border2);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite"></div>'+
      '<div style="font-size:13.5px;color:var(--text3)">Loading your data...</div>'+
      '<style>@keyframes spin{to{transform:rotate(360deg)}}</style>'+
    '</div>';
    return;
  }
  // Save focus/cursor state so we can restore it after DOM rebuild
  var _ae=document.activeElement;
  var _focusId=_ae&&_ae.id||'';
  var _focusPh=_ae&&_ae.placeholder||'';
  var _focusTag=_ae&&_ae.tagName||'';
  var _selStart=_ae&&typeof _ae.selectionStart==='number'?_ae.selectionStart:-1;
  var _selEnd=_ae&&typeof _ae.selectionEnd==='number'?_ae.selectionEnd:-1;
  // Save all scroll positions before re-render
  var content=document.getElementById("content");
  var scrollTop=content?content.scrollTop:0;
  var pageEl=content?content.querySelector(".page"):null;
  var pageScroll=pageEl?pageEl.scrollTop:0;
  var winScroll=window.scrollY||0;
  // Signal to blur handlers that this blur is from a DOM rebuild, not user action
  STATE._rendering=true;
  root.innerHTML=renderApp();
  STATE._rendering=false;
  bindApp();
  startClock();
  // Restore scroll positions after re-render
  var newContent=document.getElementById("content");
  if(newContent){
    if(scrollTop)newContent.scrollTop=scrollTop;
    var newPage=newContent.querySelector(".page");
    if(newPage&&pageScroll)newPage.scrollTop=pageScroll;
  }
  if(winScroll)window.scrollTo(0,winScroll);
  // Restore focus and cursor position so typing isn't interrupted by DOM rebuild
  var _restored=null;
  if(_focusId)_restored=document.getElementById(_focusId);
  if(!_restored&&_focusPh&&_focusTag){
    var _els=document.querySelectorAll(_focusTag.toLowerCase()+'[placeholder]');
    for(var _i=0;_i<_els.length;_i++){if(_els[_i].placeholder===_focusPh){_restored=_els[_i];break;}}
  }
  if(_restored&&document.body.contains(_restored)){
    _restored.focus();
    if(_selStart>=0&&_restored.setSelectionRange){try{_restored.setSelectionRange(_selStart,_selEnd);}catch(e){}}
  }
}

// Debounced render — collapses multiple rapid async render() calls into one.
// Use scheduleRender() in background/API callbacks; use render() for direct user interactions.
var _scheduleRenderTimer=null;
function scheduleRender(){
  if(_scheduleRenderTimer)return;
  _scheduleRenderTimer=setTimeout(function(){
    _scheduleRenderTimer=null;
    // Skip background DOM rebuild whenever a modal or detail panel is open.
    // A full render replaces root.innerHTML which destroys all open forms and
    // wipes any unsaved input — even if the user has just switched windows and
    // the input has temporarily lost focus.
    var modalOpen=!!(STATE.modal||(document.getElementById('modal-overlay')&&document.getElementById('modal-overlay').style.display!=='none'));
    if(modalOpen||STATE.detailLead)return;
    render();
  },16);
}

// ════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════
function av(user,size){
  var nm=user.name||'';var parts=nm.trim().split(/\s+/);
  var initials=user.av||(((parts[0]||'')[0]||'')+((parts[1]||'')[0]||'')).toUpperCase()||'?';
  var roleMap={admin:'av-admin',bd:'av-bd',ra:'av-ra',ra_lead:'av-admin',bd_lead:'av-bd'};
  var cls=user.avc||(roleMap[user.role]||'av-ra');
  return '<div class="av av-'+size+' '+cls+'">'+initials+'</div>';
}
function avById(id,size){
  var u=STATE.users.find(function(x){return x.id===id});
  return u?av(u,size):'<div class="av av-'+size+' av-ra">?</div>';
}
function icon(name){
  var icons={
    dashboard:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/></svg>',
    leads:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
    email:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>',
    admin:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
    profile:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>',
    plus:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>',
    search:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
    dl:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>',
    eye:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>',
    edit:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>',
    trash:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>',
    send:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>',
    x:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>',
    google:'<svg viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>',
    star:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>',
    clock:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>',
    copy:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>'
  };
  return icons[name]||'<svg viewBox="0 0 24 24"></svg>';
}
function ico(name,size){
  size=size||15;
  return '<span style="width:'+size+'px;height:'+size+'px;display:inline-flex;flex-shrink:0">'+icon(name)+'</span>';
}

function getMyLeads(user){
  return STATE.leads.filter(function(l){
    if(l.del)return false;
    if(user.role==="ra")return l.aid===user.id;
    if(user.role==="bd")return l.bid===user.id;
    return true;
  });
}
function getTeam(user){
  if(user.role==="ra")return STATE.users.filter(function(u){return u.id===user.bdm});
  if(user.role==="bd")return STATE.users.filter(function(u){return u.bdm===user.id});
  return STATE.users.filter(function(u){return u.id!==user.id});
}
function filterLeads(leads){
  var f=STATE.leadsFilter;
  var today=todayIST();
  return leads.filter(function(l){
    if(f.date==="today"&&l.date!==today)return false;
    if(f.date==="week"){var w=new Date();w.setDate(w.getDate()-7);if(new Date(l.date)<w)return false;}
    if(f.date==="month"){var n=new Date();if(new Date(l.date).getMonth()!==n.getMonth())return false;}
    if(f.stage!=="all"&&l.stage!==f.stage)return false;
    if(f.ind!=="all"){var co=STATE.companies.find(function(c){return c.id===l.coid});if(!co||co.ind!==f.ind)return false;}
    if(f.search){
      var q=f.search.toLowerCase();
      var co2=STATE.companies.find(function(c){return c.id===l.coid});
      var vals=[l.email,l.fn,l.ln,co2?co2.name:"",l.pos,l.desig];
      if(!vals.some(function(v){return(v||"").toLowerCase().includes(q)}))return false;
    }
    return true;
  });
}
function periodLeads(user){
  var all=getMyLeads(user);
  var p=STATE.period;
  var now=new Date();
  return all.filter(function(l){
    var d=new Date(l.date);
    if(p==="daily")return l.date===todayIST();
    if(p==="weekly"){var w=new Date(now);w.setDate(w.getDate()-7);return d>=w;}
    if(p==="monthly")return d.getMonth()===now.getMonth()&&d.getFullYear()===now.getFullYear();
    if(p==="quarterly"){var q=new Date(now);q.setMonth(q.getMonth()-3);return d>=q;}
    return true;
  });
}
function formatSkillsLineClient(skills){
  var list=(skills||[]).filter(Boolean).slice(0,3);
  if(!list.length)return"";
  if(list.length===1)return" with experience in "+list[0];
  if(list.length===2)return" with experience in "+list[0]+" and "+list[1];
  return" with experience in "+list.slice(0,-1).join(", ")+", and "+list[list.length-1];
}
function formatJobRespClient(skills){
  var list=(skills||[]).filter(Boolean).slice(0,3);
  if(!list.length)return"the key requirements";
  if(list.length===1)return list[0];
  if(list.length===2)return list[0]+" and "+list[1];
  return list.slice(0,-1).join(", ")+", and "+list[list.length-1];
}
function formatCompanyServiceClient(industry){
  var val=String(industry||"").trim();
  return val||"relevant";
}
function findJobForLead(l,co){
  if(!l||!STATE.jobs)return null;
  if(l.job_id)return STATE.jobs.find(function(j){return j.id===l.job_id;})||null;
  return STATE.jobs.find(function(j){
    return (j.position===l.pos||j.position===l.position)&&
      ((j.company&&j.company.name)===(co&&co.name)||j.company_name===(co&&co.name));
  })||null;
}
function buildClientEmailVars(l,co,sender){
  var job=findJobForLead(l,co);
  var req=(job&&job.research&&job.research.requirements)||{};
  var skills=Array.isArray(req.skills)?req.skills:[];
  if(req.skill_1)skills[0]=req.skill_1;
  if(req.skill_2)skills[1]=req.skill_2;
  if(req.skill_3)skills[2]=req.skill_3;
  skills=skills.filter(Boolean).slice(0,3);
  var companyExpertise=(job&&job.research&&job.research.company&&job.research.company.expertise)||"";
  var loc=(job&&job.location)||(co?co.loc:"")||req.location||"";
  var city=req.city||(loc.indexOf(",")>-1?loc.split(",")[0].trim():loc);
  var salary=req.salary_display||(job&&job.salary_range)||"";
  var localHint=req.local_hint||"";
  var localLine=localHint?(" Must be local to "+localHint+"."):(req.local_required&&city?(" Local to "+city+" preferred."):"");
  return{
    fn:l.fn,ln:l.ln,company:co?co.name:"",ind:co?co.ind:"",pos:l.pos||l.position,desig:l.desig,
    loc:loc,sender:sender||STATE.user.name,
    skill_1:skills[0]||"",skill_2:skills[1]||"",skill_3:skills[2]||"",
    skills_line:formatSkillsLineClient(skills),
    job_resp:formatJobRespClient(skills),
    company_service:formatCompanyServiceClient(companyExpertise||(co&&co.ind)||(job&&job.industry)||""),
    salary_range:salary,salary_line:salary?(" ("+salary+")"):"",
    local_line:localLine,city:city
  };
}
function fillEmail(tmpl,l,co,sender){
  var map=buildClientEmailVars(l,co,sender);
  return normalizeSenderTitle(tmpl.replace(/{{(\w+)}}/g,function(m,k){
    return map[k]!==undefined?map[k]:m;
  }));
}

// Reminder (OOO-return) follow-up templates — only offered when composing from a reminder.
var REMINDER_TEMPLATES=[
  {name:'Welcome back',subject:"Following up on {{pos}} now that you're back",body:"Hi {{fn}},\n\nHope you had a good time away. I wanted to circle back on the {{pos}} opening at {{company}}. We have candidates ready whenever you'd like to take a look.\n\nWould a quick call this week work?\n\nBest,\n{{sender}}"},
  {name:'Quick check-in',subject:"Re-connecting on {{pos}} at {{company}}",body:"Hi {{fn}},\n\nWelcome back! I wanted to pick up where we left off on your {{pos}} search. Happy to share a few profiles that fit the key requirements.\n\nShould I send them over?\n\nThanks,\n{{sender}}"},
  {name:'Candidates ready',subject:"Candidates ready for your {{pos}} role",body:"Hi {{fn}},\n\nNow that you're back in the office, I'd love to help move your {{pos}} search forward at {{company}}. We've shortlisted strong candidates experienced in {{ind}}.\n\nOpen to a 15-minute call?\n\nWarm regards,\n{{sender}}"}
];
window.composeReminderEmail=function(reminderId,cid){
  var rem=(STATE.reminders||[]).find(function(r){return r.id===reminderId;});
  STATE.composeContext='reminder';
  STATE.composeReminderId=reminderId;
  STATE.manualEmail=null;STATE.genEmail=null;STATE.emailTab='compose';STATE.showAIPanel=false;
  STATE.composeSubj='';STATE.composeBody='';
  var c=cid?STATE.contacts.find(function(x){return x.id===cid;}):null;
  var contactId=cid||(rem&&rem.contact_id)||'';
  var jobId=(c&&c.job_id)||(rem&&(rem.job_id||(rem.job&&rem.job.id)))||'';
  STATE.composeContactId=contactId?(contactId+'|'+jobId):null;
  STATE.composeCompanyId=(c?(jobById(c.job_id)||{}).company_id:null)||null;
  STATE.page='email';STATE.modal=null;
  showToast('Pick a reminder template, then Send','info');render();
};
window.applyReminderTemplate=function(i){
  var t=REMINDER_TEMPLATES[i];if(!t)return;
  var recip=resolveComposeRecipient();
  var lead=recip&&recip.lead,co=recip&&recip.co;
  var fromEm=STATE.composeFromEmailId?((STATE.userEmailsCache[STATE.user.id]||[]).find(function(e){return e.id===STATE.composeFromEmailId;})):null;
  var senderName=(fromEm&&fromEm.display_name)||STATE.user.name||'';
  STATE.composeSubj=lead?fillEmail(t.subject,lead,co,senderName):t.subject;
  STATE.composeBody=lead?fillEmail(t.body,lead,co,senderName):t.body;
  render();
};
window.sendReminderViaEngine=function(){
  var subjEl=document.getElementById('email-subj'),bodyEl=document.getElementById('email-body');
  var subject=(subjEl&&subjEl.value)||STATE.composeSubj||'';
  var body=(bodyEl&&bodyEl.value)||STATE.composeBody||'';
  if(!subject.trim()){showToast('Add a subject line','warning');return;}
  if(!body.trim()){showToast('Write a message','warning');return;}
  var rem=STATE.composeReminderId?((STATE.reminders||[]).find(function(r){return r.id===STATE.composeReminderId;})):null;
  var parts=(STATE.composeContactId||'').split('|');
  var contactId=parts[0]||(rem&&rem.contact_id)||null;
  var jobId=parts[1]||(rem&&(rem.job_id||(rem.job&&rem.job.id)))||null;
  var c=contactId?STATE.contacts.find(function(x){return x.id===contactId;}):null;
  var to=(c&&c.email)||(rem&&rem.email)||null;
  if(!to){showToast('No recipient email on record','warning');return;}
  if(!jobId){showToast('This reminder is not linked to a job, so it cannot send through the engine','warning');return;}
  apiPost('/emails/reminder-send',{reminder_id:STATE.composeReminderId,contact_id:contactId,job_id:jobId,to_email:to,subject:subject,body:body}).then(function(){
    showToast('Reminder queued — the engine will send it shortly','success');
    var rid=STATE.composeReminderId;
    if(rid)STATE.reminders=(STATE.reminders||[]).map(function(r){return r.id===rid?Object.assign({},r,{status:'sent'}):r;});
    STATE.composeContext=null;STATE.composeReminderId=null;STATE.composeSubj='';STATE.composeBody='';STATE.composeContactId=null;STATE.composeCompanyId=null;STATE.genEmail=null;
    STATE.page='reminders';render();
  }).catch(function(e){showToast('Send failed: '+(e&&e.message||e),'error');});
};

// Five matched outreach styles — each with its own O1, FU1, and FU2 (keep in sync with email-vars.js)
var OUTREACH_STYLE_PRESETS={
  v1:{
    label:'Introduction',
    hint:'Classic introduction, candidates + fit',
    o1:{subj:'Candidates for your {{pos}} role in {{loc}}',body:"Hi {{fn}},\n\nI'm {{sender}} with Fute Global LLC. I came across your {{pos}} opening in {{loc}} and read through the requirements, and we have several people with {{job_resp}} experience on {{company_service}} work who look like a strong fit. They're open to direct hire and haven't been screened for your role yet.\n\nWould you like to review their resumes?\n\nLooking forward to your thoughts."},
    fu1:{subj:'Re: Candidates for your {{pos}} role in {{loc}}',body:"Hi {{fn}},\n\nCircling back on your {{pos}} role in {{loc}}. Those candidates with {{job_resp}} experience on {{company_service}} projects are still available.\n\nWant me to send their resumes over?\n\nLooking forward to your thoughts."},
    fu2:{subj:'Re: Candidates for your {{pos}} role in {{loc}}',body:"Hi {{fn}},\n\nI'll keep this short. Still holding a few screened-ready candidates with {{job_resp}} backgrounds for your {{pos}} opening in {{loc}} whenever the timing suits.\n\nShall I share their resumes?\n\nLooking forward to your thoughts."}
  },
  v2:{
    label:'Candidates first',
    hint:'Leads with the candidates, short and direct',
    o1:{subj:'{{pos}} in {{loc}}: a few resumes worth a look',body:"Hi {{fn}},\n\nA few direct-hire candidates with strong {{job_resp}} experience on {{company_service}} projects just became available, and they line up well with your {{pos}} opening in {{loc}}.\n\nShould I send their resumes across?\n\nHappy to share whenever you're ready."},
    fu1:{subj:'Re: {{pos}} in {{loc}}: a few resumes worth a look',body:"Hi {{fn}},\n\nQuick nudge on this. The {{job_resp}} candidates I mentioned for your {{pos}} role in {{loc}} are still on the market.\n\nShould I pass along their resumes?\n\nHappy to share whenever you're ready."},
    fu2:{subj:'Re: {{pos}} in {{loc}}: a few resumes worth a look',body:"Hi {{fn}},\n\nLast note from me on the {{pos}} opening in {{loc}}. Happy to forward those {{company_service}} candidates' resumes if it's useful.\n\nHappy to share whenever you're ready."}
  },
  v3:{
    label:'Question opener',
    hint:'Opens with a question about the role',
    o1:{subj:'A question about your {{pos}} opening in {{loc}}',body:"Hi {{fn}},\n\nIs your {{pos}} role in {{loc}} still open? I ask because I'm {{sender}} at Fute Global LLC, and after reading the job description I have a shortlist of people with {{job_resp}} experience on {{company_service}} projects who fit it well. They're direct-hire ready and haven't been put in front of you yet.\n\nOpen to a quick look at a couple of profiles?\n\nNo rush at all. Just let me know."},
    fu1:{subj:'Re: A question about your {{pos}} opening in {{loc}}',body:"Hi {{fn}},\n\nFollowing up in case my earlier note slipped by. I still have those {{job_resp}} candidates lined up for your {{pos}} role in {{loc}}.\n\nWorth a quick look at a couple of profiles?\n\nNo rush at all. Just let me know."},
    fu2:{subj:'Re: A question about your {{pos}} opening in {{loc}}',body:"Hi {{fn}},\n\nOne final check-in on the {{pos}} role in {{loc}}. If it's still active, I'd be glad to share a couple of {{company_service}} profiles for your review.\n\nNo rush at all. Just let me know."}
  },
  v4:{
    label:'Concise',
    hint:'Shortest version, straight to the point',
    o1:{subj:'{{pos}} ({{loc}}): direct-hire candidates available',body:"Hi {{fn}},\n\nSaw your {{pos}} opening in {{loc}}. We've got candidates with hands-on {{job_resp}} experience on {{company_service}} work, ready for direct hire and your screening, no obligation to proceed.\n\nWant me to forward a few resumes?\n\nAppreciate you taking a look."},
    fu1:{subj:'Re: {{pos}} ({{loc}}): direct-hire candidates available',body:"Hi {{fn}},\n\nFollowing up. The {{job_resp}} candidates for your {{pos}} role in {{loc}} are still available for review.\n\nWant me to forward a few resumes?\n\nAppreciate you taking a look."},
    fu2:{subj:'Re: {{pos}} ({{loc}}): direct-hire candidates available',body:"Hi {{fn}},\n\nFinal follow-up on {{pos}} in {{loc}}. Happy to forward those resumes whenever you'd like to take a look.\n\nAppreciate you taking a look."}
  },
  v5:{
    label:'Direct value',
    hint:'Direct-hire focus, clear value proposition',
    o1:{subj:'Direct-hire talent for your {{pos}} need in {{loc}}',body:"Hi {{fn}},\n\nI'm {{sender}}, and at Fute Global LLC we place direct-hire talent. Your {{pos}} opening in {{loc}} stood out, and we currently have candidates with solid {{job_resp}} experience on {{company_service}} projects who match what the role calls for, available for your screening at no cost or commitment.\n\nIs it worth sharing their resumes with you?\n\nI'll keep an eye out for your reply."},
    fu1:{subj:'Re: Direct-hire talent for your {{pos}} need in {{loc}}',body:"Hi {{fn}},\n\nWanted to resurface this. The candidates with {{job_resp}} experience on {{company_service}} work are still available for your {{pos}} role in {{loc}}.\n\nIs it worth sharing their resumes?\n\nI'll keep an eye out for your reply."},
    fu2:{subj:'Re: Direct-hire talent for your {{pos}} need in {{loc}}',body:"Hi {{fn}},\n\nI'll leave it here for now, but the {{job_resp}} candidates remain ready whenever your {{pos}} search in {{loc}} calls for them.\n\nGlad to share resumes at any point."}
  }
};
var MERGE_VAR_GROUPS=[
  {label:'Contact',chips:[
    ['{{fn}}','First name','Contact\'s first name'],
    ['{{ln}}','Last name','Contact\'s last name'],
    ['{{desig}}','Their job title','Contact\'s designation']
  ]},
  {label:'Job & company',chips:[
    ['{{pos}}','Job title','Open role you\'re hiring for'],
    ['{{company}}','Company name','Company name'],
    ['{{loc}}','Location','Job location'],
    ['{{city}}','City','City from job location'],
    ['{{ind}}','Industry','Company industry'],
    ['{{skills_line}}','Skills phrase','Auto phrase from job skills, e.g. " with experience in HVAC"'],
    ['{{job_resp}}','Job responsibility','Top skills from the JD, e.g. "Sage and communication"'],
    ['{{company_service}}','Project / industry','Company industry for project context, e.g. "Healthcare"'],
    ['{{local_line}}','Local requirement','Local/on-site requirement if set']
  ]},
  {label:'Compensation',chips:[
    ['{{salary_line}}','Salary','Salary in parentheses if available'],
    ['{{salary_range}}','Salary range','Raw salary range text']
  ]},
  {label:'Your details',chips:[
    ['{{sender}}','Your name','Your display name on the sending email']
  ]}
];
var MERGE_VAR_MORE=[
  ['{{skill_1}}','Skill 1','First matched skill'],
  ['{{skill_2}}','Skill 2','Second matched skill'],
  ['{{skill_3}}','Skill 3','Third matched skill']
];
function outreachTmplApiKey(tabKey){return tabKey==='outreach'?'o1':tabKey;}
function renderSendingEmailCard(userId,myEmails,selectedId,onSelectFn){
  if(!myEmails.length){
    return '<div class="card cp mb3"><div class="fw6 mb2" style="font-size:13px">Sending from</div>'+
      '<div style="font-size:12px;color:var(--amber);padding:4px 0">No active email IDs yet. Ask your admin to add one under your profile.</div></div>';
  }
  var selId=selectedId||(myEmails.find(function(e){return e.is_primary;})||myEmails[0]).id;
  var opts=myEmails.map(function(e){
    return '<option value="'+e.id+'"'+(e.id===selId?' selected':'')+'>'+htmlEsc(e.display_name||e.email_address)+' &lt;'+htmlEsc(e.email_address)+'&gt;</option>';
  }).join('');
  return '<div class="card cp mb3">'+
    '<div class="fw6 mb1" style="font-size:13px">Sending from</div>'+
    '<div style="font-size:11.5px;color:var(--text3);margin-bottom:8px">Emails go out from this address. Signature uses this ID too.</div>'+
    '<select class="sel" onchange="'+onSelectFn+'(this.value)">'+opts+'</select>'+
  '</div>';
}
function mergeVarFriendlyLabel(token){
  var i,g,c;
  for(i=0;i<MERGE_VAR_GROUPS.length;i++){
    for(c=0;c<MERGE_VAR_GROUPS[i].chips.length;c++){
      if(MERGE_VAR_GROUPS[i].chips[c][0]===token)return MERGE_VAR_GROUPS[i].chips[c][1];
    }
  }
  for(i=0;i<MERGE_VAR_MORE.length;i++){
    if(MERGE_VAR_MORE[i][0]===token)return MERGE_VAR_MORE[i][1];
  }
  return 'Field';
}
function renderVarChipBtn(token,label,hint,subjId,bodyId){
  return '<button type="button" title="'+htmlEsc(hint||label)+'" onclick="insertVarChip(\''+token+'\',\''+subjId+'\',\''+bodyId+'\')" '+
    'style="font-size:12px;padding:6px 12px;border-radius:20px;border:1px solid var(--border2);background:#fff;color:var(--text);cursor:pointer;white-space:nowrap;font-weight:500" '+
    'onmouseover="this.style.borderColor=\'var(--accent)\';this.style.background=\'var(--accent-l)\';this.style.color=\'var(--accent)\'" '+
    'onmouseout="this.style.borderColor=\'var(--border2)\';this.style.background=\'#fff\';this.style.color=\'var(--text)\'">'+htmlEsc(label)+'</button>';
}
function renderVarChipBar(subjId,bodyId){
  var target=STATE.varInsertTarget||'body';
  var groupHtml=MERGE_VAR_GROUPS.map(function(g){
    var chips=g.chips.map(function(v){return renderVarChipBtn(v[0],v[1],v[2],subjId,bodyId);}).join('');
    return '<div style="margin-bottom:10px"><div style="font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">'+htmlEsc(g.label)+'</div>'+
      '<div style="display:flex;flex-wrap:wrap;gap:6px">'+chips+'</div></div>';
  }).join('');
  var moreHtml='';
  if(STATE.showMoreVarChips){
    moreHtml='<div style="margin-bottom:10px"><div style="font-size:10px;font-weight:700;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Individual skills</div>'+
      '<div style="display:flex;flex-wrap:wrap;gap:6px">'+
      MERGE_VAR_MORE.map(function(v){return renderVarChipBtn(v[0],v[1],v[2],subjId,bodyId);}).join('')+
      '</div></div>';
  }
  return '<div style="padding:14px;background:var(--bg);border:1px solid var(--border);border-radius:var(--r2);margin-top:8px">'+
    '<div style="font-weight:600;font-size:13px;color:var(--text);margin-bottom:4px">Personalize your message</div>'+
    '<div style="font-size:12px;color:var(--text3);margin-bottom:12px">Step 1 — choose where to add &nbsp;·&nbsp; Step 2 — click a field below</div>'+
    '<div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap">'+
      '<button type="button" onclick="setVarInsertTarget(\'subject\')" style="padding:7px 16px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;border:2px solid '+(target==='subject'?'var(--accent)':'var(--border)')+';background:'+(target==='subject'?'var(--accent)':'#fff')+';color:'+(target==='subject'?'#fff':'var(--text2)')+'">① Subject line</button>'+
      '<button type="button" onclick="setVarInsertTarget(\'body\')" style="padding:7px 16px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;border:2px solid '+(target==='body'?'var(--accent)':'var(--border)')+';background:'+(target==='body'?'var(--accent)':'#fff')+';color:'+(target==='body'?'#fff':'var(--text2)')+'">② Email body</button>'+
      '<span style="font-size:11px;color:var(--text3);align-self:center">Adding to: <strong style="color:var(--accent)">'+(target==='subject'?'Subject line':'Email body')+'</strong></span>'+
    '</div>'+
    groupHtml+moreHtml+
    '<button type="button" onclick="STATE.showMoreVarChips=!STATE.showMoreVarChips;render()" style="font-size:11px;padding:4px 0;border:0;background:transparent;color:var(--accent);cursor:pointer;font-weight:600">'+
      (STATE.showMoreVarChips?'▲ Hide individual skills':'▼ Show individual skills (Skill 1, 2, 3)')+
    '</button>'+
  '</div>';
}

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
    {id:"leads",lbl:"Leads",ic:"leads",badge:todayCnt},
    ...(!userHasRole(u,'ra')||userHasAnyRole(u,'bd','bd_lead','admin','ra_lead')?[{id:"email",lbl:"Email",ic:"email"}]:[]),
    ...(userHasRole(u,'ra')&&!userHasAnyRole(u,'admin','bd','bd_lead','ra_lead')?[{id:"insights",lbl:"Insights",ic:"dashboard"}]:[{id:"reminders",lbl:"Reminders",ic:"star",badge:STATE.reminders.filter(function(r){return r.user_id===u.id&&r.status==="pending"}).length||null}]),
    {id:"profile",lbl:"My Profile",ic:"profile"}
  ];
  // Admin only: Admin panel
  if(userHasRole(u,'admin'))navItems.splice(4,0,{id:"admin",lbl:"Admin",ic:"admin"});
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

  var pageTitles={dashboard:"Dashboard",leads:"Leads",assign:"Assign Leads",email:"Email",admin:"Admin",emailaccounts:"Email Accounts",managerusers:"Manager Users",insights:"Insights",bdinsights:"My Insights",bdleadinsights:"Team Insights",profile:"My Profile",reminders:"Reminders"};
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

// ── LEADS ──────────────────────────────────────
function renderJobs(){
  var u=STATE.user;
  var jobs=getMyJobs(u);
  var f=STATE.jobsFilter;
  if(f.search){
    var q=f.search.toLowerCase();
    jobs=jobs.filter(function(j){
      if((j.position||"").toLowerCase().indexOf(q)>-1)return true;
      if((j.company_name||"").toLowerCase().indexOf(q)>-1)return true;
      if((j.location||"").toLowerCase().indexOf(q)>-1)return true;
      var cs=jobContacts(j.id);
      for(var i=0;i<cs.length;i++){
        var c=cs[i];
        if(((c.first_name||"")+" "+(c.last_name||"")).toLowerCase().indexOf(q)>-1)return true;
        if((c.email||"").toLowerCase().indexOf(q)>-1)return true;
      }
      return false;
    });
  }
  if(f.stages&&f.stages.length)jobs=jobs.filter(function(j){return f.stages.indexOf(j.stage)>-1;});
  if(f.industries&&f.industries.length)jobs=jobs.filter(function(j){return f.industries.indexOf(j.industry||j.company_ind||"")>-1;});
  if(f.dateRange&&f.dateRange!=="all"&&f.dateRange!=="custom"){var _now=new Date();var _today=todayIST();var _cut=null;if(f.dateRange==="today")_cut=_today;else if(f.dateRange==="yesterday"){var _yy=new Date(_now);_yy.setDate(_yy.getDate()-1);_cut=_yy.toISOString().slice(0,10);}else if(f.dateRange==="week"){var _ww=new Date(_now);_ww.setDate(_ww.getDate()-7);_cut=_ww.toISOString().slice(0,10);}if(_cut){if(f.dateRange==="today"||f.dateRange==="yesterday")jobs=jobs.filter(function(j){return (j.created_at||"").slice(0,10)===_cut;});else jobs=jobs.filter(function(j){return (j.created_at||"").slice(0,10)>=_cut;});}}
  if(f.dateRange==="custom"){if(f.dateFrom)jobs=jobs.filter(function(j){return (j.created_at||"").slice(0,10)>=f.dateFrom;});if(f.dateTo)jobs=jobs.filter(function(j){return (j.created_at||"").slice(0,10)<=f.dateTo;});}

  var stages=["Unassigned","Assigned","Connected","Rejected","Future","Qualified"];
  var stageOpts=stages.map(function(st){return '<option value="'+st+'"'+(f.stage===st?" selected":"")+'>'+st+'</option>';}).join("");

  var canChangeStageInline=userHasAnyRole(u,'admin','bd','bd_lead');
  var _tp=Math.max(1,Math.ceil(jobs.length/20));
  var _pg=Math.min(STATE.leadsPage||0,_tp-1);
  var rows=jobs.slice(_pg*20,(_pg+1)*20).map(function(j){
    var cs=jobContacts(j.id);
    var primary=cs[0]||{};
    var stageColor={Unassigned:"#94a3b8",Assigned:"#3b82f6",Connected:"#8b5cf6",Rejected:"#ef4444",Future:"#f59e0b",Qualified:"#10b981"}[j.stage]||"#64748b";
    return '<tr style="border-bottom:1px solid var(--border2);cursor:pointer" onclick="openJob(\''+j.id+'\')">'+
      '<td style="padding:12px"><div style="font-weight:600;color:var(--text)">'+escHtml(j.company_name)+(j.is_duplicate?'<span style="margin-left:6px;background:#fef9c3;color:#b45309;font-size:10px;padding:1px 6px;border-radius:6px;font-weight:600">DUP</span>':'')+(j.freshness==='Old'?'<span style="margin-left:6px;background:#fef2f2;color:#dc2626;font-size:10px;padding:1px 6px;border-radius:6px;font-weight:600">OLD</span>':'')+(j.freshness==='New'?'<span style="margin-left:6px;background:#f0fdf4;color:#16a34a;font-size:10px;padding:1px 6px;border-radius:6px;font-weight:600">NEW</span>':'')+'</div></td>'+
      '<td style="padding:12px"><div style="font-weight:500">'+escHtml(j.position)+'</div><div style="font-size:11px;color:var(--text3)">'+escHtml(j.location||"—")+'</div></td>'+
      '<td style="padding:12px"><div>'+escHtml((primary.first_name||"")+" "+(primary.last_name||""))+'</div><div style="font-size:11px;color:var(--text3)">'+escHtml(primary.email||"—")+'</div></td>'+
      '<td style="padding:12px;text-align:center"><span style="background:rgba(99,102,241,.1);color:var(--accent);padding:3px 9px;border-radius:10px;font-size:11px;font-weight:600">'+cs.length+'</span></td>'+
      (canChangeStageInline?'<td style="padding:12px"><select onchange="changeJobStage(\''+j.id+'\',this.value);event.stopPropagation()" onclick="event.stopPropagation()" style="font-size:11px;padding:4px 8px;border:1.5px solid '+stageColor+';border-radius:8px;background:'+stageColor+'1a;color:'+stageColor+';font-weight:600;cursor:pointer">'+['Unassigned','Assigned','Connected','Rejected','Future','In Discussion'].map(function(s){return'<option value="'+s+'"'+(j.stage===s?' selected':'')+'>'+s+'</option>';}).join('')+'</select></td>':'<td style="padding:12px"><span style="background:'+stageColor+'1a;color:'+stageColor+';padding:4px 10px;border-radius:10px;font-size:11px;font-weight:600">'+j.stage+'</span></td>')+
      '<td style="padding:12px;font-size:12px;color:var(--text2)">'+(j.assigned_bd_name?'<div style="font-weight:500">'+escHtml(j.assigned_bd_name)+'</div><div style="font-size:10px;color:var(--text3)">'+( j.assigned_at?(new Date(j.assigned_at)).toLocaleDateString("en-GB",{day:"2-digit",month:"short",hour:"2-digit",minute:"2-digit"}):"")+'</div>':'<span style="color:var(--text3)">—</span>')+'</td>'+
      '<td style="padding:12px;font-size:11px;color:var(--text3)">'+
        (j.created_at?'<div>'+escHtml(j.created_date||new Date(j.created_at).toISOString().slice(0,10))+'</div><div style="font-size:10px;margin-top:1px">'+new Date(new Date(j.created_at).getTime()+5.5*3600000).toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit',hour12:true})+'</div>':escHtml(j.created_date||''))+
      '</td>'+
    '</tr>';
  }).join("");

  if(!rows)rows='<tr><td colspan="8" style="padding:40px;text-align:center;color:var(--text3)">No leads found yet.</td></tr>';

  // RA sees form at top + their leads below; others see search/filter + table
  var isRA=(u.role==='ra');

  // Build RA-specific rows with 24hr edit button
  var now24=new Date();
  var raRows=jobs.map(function(j){
    var cs=jobContacts(j.id);
    var primary=cs[0]||{};
    var stageColor={Unassigned:'#94a3b8',Assigned:'#3b82f6',Connected:'#8b5cf6',Rejected:'#ef4444',Future:'#f59e0b','In Discussion':'#f59e0b',Qualified:'#10b981'}[j.stage]||'#64748b';
    var hoursOld=(now24-new Date(j.created_at))/3600000;
    var canRAEdit=hoursOld<=24;
    var editBtn=canRAEdit?
      '<button onclick="raFormEdit(\''+j.id+'\')" style="font-size:11px;padding:4px 10px;background:var(--accent-l);color:var(--accent);border:1px solid rgba(37,99,235,.2);border-radius:6px;cursor:pointer;font-weight:600">✏ Edit</button>':
      '<span style="font-size:10px;color:var(--text3)">Locked</span>';
    return '<tr style="border-bottom:1px solid var(--border2);cursor:pointer" onclick="openJob(\''+j.id+'\')">'+
      '<td style="padding:12px"><div style="font-weight:600;color:var(--text)">'+escHtml(j.company_name)+'</div><div style="font-size:11px;color:var(--text3)">'+escHtml(j.company_ind||j.industry||'')+'</div></td>'+
      '<td style="padding:12px;font-weight:500">'+escHtml(j.position)+'</td>'+
      '<td style="padding:12px"><div>'+escHtml((primary.first_name||'')+(primary.last_name?' '+primary.last_name:''))+'</div><div style="font-size:11px;color:var(--text3)">'+escHtml(primary.email||'\u2014')+'</div></td>'+
      '<td style="padding:12px;text-align:center"><span style="background:rgba(99,102,241,.1);color:var(--accent);padding:3px 9px;border-radius:10px;font-size:11px;font-weight:600">'+cs.length+'</span></td>'+
      '<td style="padding:12px"><span style="background:'+stageColor+'1a;color:'+stageColor+';padding:4px 10px;border-radius:10px;font-size:11px;font-weight:600">'+j.stage+'</span></td>'+
      '<td style="padding:12px;font-size:11px;color:var(--text3)">'+
        (j.created_at?'<div>'+escHtml(j.created_date||new Date(j.created_at).toISOString().slice(0,10))+'</div><div style="font-size:10px;margin-top:1px">'+new Date(new Date(j.created_at).getTime()+5.5*3600000).toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit',hour12:true})+'</div>':escHtml(j.created_date||''))+
      '</td>'+
      '<td style="padding:12px" onclick="event.stopPropagation()">'+editBtn+'</td>'+
    '</tr>';
  }).join('');
  if(!raRows)raRows='<tr><td colspan="7" style="padding:40px;text-align:center;color:var(--text3)">No leads submitted yet. Use the form above to add your first lead.</td></tr>';


  if(isRA){
    return '<div style="padding:24px">'+
      renderRALeadForm()+
      '<div style="margin:24px 0 12px;font-weight:700;font-size:13px;color:var(--text2);text-transform:uppercase;letter-spacing:.05em">Your submitted leads ('+jobs.length+')</div>'+
      '<div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;overflow:hidden">'+
        '<table style="width:100%;border-collapse:collapse;font-size:13px">'+
          '<thead style="background:var(--bg3);color:var(--text3);font-size:11px;text-transform:uppercase;letter-spacing:.5px">'+
            '<tr><th style="padding:12px;text-align:left">Company</th><th style="padding:12px;text-align:left">Position</th><th style="padding:12px;text-align:left">Primary Contact</th><th style="padding:12px;text-align:center">Contacts</th><th style="padding:12px;text-align:left">Stage</th><th style="padding:12px;text-align:left">Created</th><th style="padding:12px"></th></tr>'+
          '</thead>'+
          '<tbody>'+raRows+'</tbody>'+
        '</table>'+
      '</div>'+
      '<div style="margin-top:10px;font-size:12px;color:var(--text3)">'+jobs.length+' lead'+(jobs.length===1?'':'s')+' submitted by you</div>'+
    '</div>';
  }

  var allStagesList=['Unassigned','Assigned','Connected','Rejected','Future','In Discussion'];
  var allIndustriesList=getIndustriesList();
  var stageActive=f.stages&&f.stages.length>0;
  var indActive=f.industries&&f.industries.length>0;
  var dateActive=f.dateRange&&f.dateRange!=='all';
  var anyActive=stageActive||indActive||dateActive;
  function mkChkDrop(name,key,items,selected,active){
    var btn='<button onclick="event.stopPropagation();STATE.openDrop=STATE.openDrop===\''+name+'\' ?null:\''+name+'\';render()" style="padding:9px 13px;border:'+(active?'1.5px solid var(--accent)':'1px solid var(--border)')+';border-radius:8px;background:'+(active?'var(--accent-l)':'var(--bg2)')+';color:'+(active?'var(--accent)':'var(--text)')+';font-size:13px;font-weight:'+(active?'600':'400')+';cursor:pointer;display:flex;align-items:center;gap:6px;white-space:nowrap">'+(active?name+' ('+selected.length+')':name)+' <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M6 9l6 6 6-6"/></svg></button>';
    var panel='';
    if(STATE.openDrop===name){
      panel='<div style="position:absolute;top:calc(100% + 4px);left:0;z-index:9000;background:var(--card);border:1px solid var(--border2);border-radius:var(--r2);box-shadow:var(--sh2);min-width:190px;padding:6px 0" onclick="event.stopPropagation()">'+
        items.map(function(v){var on=selected.indexOf(v)>-1;return '<label style="display:flex;align-items:center;gap:9px;padding:7px 14px;cursor:pointer;font-size:13px;background:'+(on?'var(--accent-l)':'transparent')+';color:'+(on?'var(--accent)':'var(--text)')+'"><input type="checkbox" '+(on?'checked':'')+' onchange="toggleJobFilter(\''+key+'\',\''+v+'\',this.checked)" style="width:14px;height:14px;accent-color:var(--accent);cursor:pointer"/>'+v+'</label>';}).join('')+
        (selected.length?'<div style="border-top:1px solid var(--border);padding:6px 14px;margin-top:2px"><button onclick="STATE.jobsFilter.'+key+'=[];STATE.leadsPage=0;render()" style="font-size:11.5px;color:var(--red);background:none;border:none;cursor:pointer;padding:0">Clear</button></div>':'')+
      '</div>';
    }
    return '<div style="position:relative">'+btn+panel+'</div>';
  }
  var dateLabel=f.dateRange==='today'?'Today':f.dateRange==='yesterday'?'Yesterday':f.dateRange==='week'?'This week':f.dateRange==='custom'&&(f.dateFrom||f.dateTo)?((f.dateFrom||'…')+' → '+(f.dateTo||'…')):'Date';
  var dateBtn='<div style="position:relative">'+
    '<button onclick="event.stopPropagation();STATE.openDrop=STATE.openDrop===\'date\' ?null:\'date\';render()" style="padding:9px 13px;border:'+(dateActive?'1.5px solid var(--accent)':'1px solid var(--border)')+';border-radius:8px;background:'+(dateActive?'var(--accent-l)':'var(--bg2)')+';color:'+(dateActive?'var(--accent)':'var(--text)')+';font-size:13px;font-weight:'+(dateActive?'600':'400')+';cursor:pointer;display:flex;align-items:center;gap:6px;white-space:nowrap">'+dateLabel+' <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M6 9l6 6 6-6"/></svg></button>'+
    (STATE.openDrop==='date'?
      '<div style="position:absolute;top:calc(100% + 4px);left:0;z-index:9000;background:var(--card);border:1px solid var(--border2);border-radius:var(--r2);box-shadow:var(--sh2);padding:12px 14px;min-width:240px" onclick="event.stopPropagation()">'+
        // Preset chips
        '<div style="display:flex;flex-direction:column;gap:2px;margin-bottom:8px">'+
          ['today','yesterday','week'].map(function(val){var lbl=val==='today'?'Today':val==='yesterday'?'Yesterday':'This week';var on=f.dateRange===val;return '<button onclick="STATE.jobsFilter.dateRange=STATE.jobsFilter.dateRange===\''+val+'\' ?\'all\':\''+val+'\';STATE.jobsFilter.dateFrom=\'\';STATE.jobsFilter.dateTo=\'\';STATE.leadsPage=0;render()" style="padding:7px 12px;border-radius:7px;font-size:13px;cursor:pointer;text-align:left;border:1px solid '+(on?'var(--accent)':'var(--border)')+';background:'+(on?'var(--accent-l)':'transparent')+';color:'+(on?'var(--accent)':'var(--text)')+';font-weight:'+(on?'600':'400')+'">'+lbl+'</button>';}).join('')+
        '</div>'+
        // Custom separator
        '<div style="border-top:1px solid var(--border);margin:8px 0 10px"></div>'+
        '<div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Custom range</div>'+
        '<div style="display:flex;flex-direction:column;gap:8px">'+
          '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:12px;color:var(--text2);width:28px">From</span><input type="date" value="'+escAttr(f.dateFrom||'')+'" onchange="STATE.jobsFilter.dateRange=\'custom\';STATE.jobsFilter.dateFrom=this.value;STATE.leadsPage=0;render()" style="flex:1;padding:6px 10px;border:1px solid var(--border2);border-radius:7px;font-size:13px;background:var(--card);color:var(--text)"/></div>'+
          '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:12px;color:var(--text2);width:28px">To</span><input type="date" value="'+escAttr(f.dateTo||'')+'" onchange="STATE.jobsFilter.dateRange=\'custom\';STATE.jobsFilter.dateTo=this.value;STATE.leadsPage=0;render()" style="flex:1;padding:6px 10px;border:1px solid var(--border2);border-radius:7px;font-size:13px;background:var(--card);color:var(--text)"/></div>'+
        '</div>'+
        (dateActive?'<button onclick="STATE.jobsFilter.dateRange=\'all\';STATE.jobsFilter.dateFrom=\'\';STATE.jobsFilter.dateTo=\'\';STATE.leadsPage=0;render()" style="margin-top:10px;font-size:11.5px;color:var(--red);background:none;border:none;cursor:pointer;padding:0">Clear</button>':'')+
      '</div>':'')  +
  '</div>';

  // Stage summary counts from ALL jobs (not filtered)
  var allJobs=getMyJobs(u);
  var stageCounts={};
  var stageList=['Unassigned','Assigned','Connected','In Discussion','Future','Rejected'];
  stageList.forEach(function(s){stageCounts[s]=allJobs.filter(function(j){return j.stage===s;}).length;});
  var stageColors={Unassigned:'var(--text3)',Assigned:'var(--accent)',Connected:'var(--green)',['In Discussion']:'#8b5cf6',Future:'var(--amber)',Rejected:'var(--red)'};
  var stageBg={Unassigned:'var(--bg)',Assigned:'var(--accent-l)',Connected:'var(--green-l)',['In Discussion']:'#f5f3ff',Future:'var(--amber-l)',Rejected:'var(--red-l)'};
  var stageSummary='<div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap">'+
    stageList.filter(function(s){return stageCounts[s]>0;}).map(function(s){
      return '<div onclick="STATE.jobsFilter.stages=[\''+s+'\'];STATE.leadsPage=0;render()" style="display:flex;align-items:center;gap:6px;padding:6px 12px;background:'+stageBg[s]+';border:1px solid '+stageColors[s]+'33;border-radius:20px;cursor:pointer;transition:opacity .15s" title="Filter by '+s+'">'+
        '<div style="width:7px;height:7px;border-radius:50%;background:'+stageColors[s]+';flex-shrink:0"></div>'+
        '<span style="font-size:12px;font-weight:600;color:'+stageColors[s]+'">'+s+'</span>'+
        '<span style="font-size:12px;font-weight:700;color:'+stageColors[s]+'">'+stageCounts[s]+'</span>'+
      '</div>';
    }).join('')+
    '<div style="display:flex;align-items:center;gap:6px;padding:6px 12px;background:var(--card);border:1px solid var(--border);border-radius:20px;margin-left:auto">'+
      '<span style="font-size:12px;color:var(--text3)">Total</span>'+
      '<span style="font-size:12px;font-weight:700;color:var(--text)">'+allJobs.length+'</span>'+
    '</div>'+
  '</div>';

  return '<div style="padding:24px">'+
    stageSummary+
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;gap:12px;flex-wrap:wrap">'+
      '<div style="display:flex;gap:10px;align-items:center;flex:1;min-width:280px;flex-wrap:wrap">'+
        '<input id="jobs-search" placeholder="Search jobs, companies, contacts..." value="'+escAttr(f.search)+'" style="flex:1;max-width:340px;padding:9px 13px;border:1px solid var(--border);border-radius:8px;background:var(--bg2);color:var(--text);font-size:13px"/>'+
        mkChkDrop('Stage','stages',allStagesList,f.stages||[],stageActive)+
        mkChkDrop('Industry','industries',allIndustriesList,f.industries||[],indActive)+
        dateBtn+
        (anyActive?'<button onclick="STATE.jobsFilter.stages=[];STATE.jobsFilter.industries=[];STATE.jobsFilter.dateRange=\'all\';STATE.jobsFilter.dateFrom=\'\';STATE.jobsFilter.dateTo=\'\';STATE.openDrop=null;STATE.leadsPage=0;render()" style="padding:7px 12px;border:1.5px solid var(--red);border-radius:8px;background:var(--red-l);color:var(--red);font-size:12px;font-weight:600;cursor:pointer;white-space:nowrap">&#10005; Clear</button>':'')+
      '</div>'+
      '<div style="display:flex;gap:8px;align-items:center">'+
        (u.role==='ra_lead'||u.role==='admin'?'<button onclick="openExportLeads()" style="background:var(--card);color:var(--text);border:1.5px solid var(--border);padding:9px 15px;border-radius:8px;font-weight:600;cursor:pointer;font-size:13px;display:flex;align-items:center;gap:6px">'+ico("dl",13)+' Export</button>':'')+
        '<button onclick="triggerImport()" style="background:var(--card);color:var(--text);border:1.5px solid var(--border);padding:9px 15px;border-radius:8px;font-weight:600;cursor:pointer;font-size:13px;display:flex;align-items:center;gap:6px">'+ico("upload",13)+' Import Excel</button>'+
        (u.role!=='ra'?'<button onclick="openAddJob()" style="background:var(--accent);color:#fff;border:0;padding:10px 18px;border-radius:8px;font-weight:600;cursor:pointer;font-size:13px">+ Add Lead</button>':'')+
        '<input type="file" id="xl-import" accept=".xlsx,.xls" style="display:none" onchange="importXL(this)"/>'+
      '</div>'+
    '</div>'+
    '<div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;overflow:hidden">'+
      '<table style="width:100%;border-collapse:collapse;font-size:13px">'+
        '<thead style="background:var(--bg3);color:var(--text3);font-size:11px;text-transform:uppercase;letter-spacing:.5px">'+
          '<tr><th style="padding:12px;text-align:left">Company</th><th style="padding:12px;text-align:left">Position</th><th style="padding:12px;text-align:left">Primary Contact</th><th style="padding:12px;text-align:center">Contacts</th><th style="padding:12px;text-align:left">Stage</th><th style="padding:12px;text-align:left">Assigned BD</th><th style="padding:12px;text-align:left">Created</th></tr>'+
        '</thead>'+
        '<tbody>'+rows+'</tbody>'+
      '</table>'+
    '</div>'+
    '<div style="margin-top:14px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">'+
      '<div style="font-size:12px;color:var(--text3)">'+jobs.length+' lead'+(jobs.length===1?'':'s')+' · page '+(_pg+1)+' of '+_tp+'</div>'+
      (_tp>1?'<div style="display:flex;gap:5px">'+
        '<button onclick="setLeadsPage('+(_pg-1)+')" style="padding:5px 12px;border:1px solid var(--border2);border-radius:7px;background:var(--card);font-size:12px;cursor:pointer" '+(_pg===0?'disabled':'')+'>&#8592; Prev</button>'+
        '<span style="padding:5px 10px;font-size:12px;font-weight:600">'+(_pg+1)+' / '+_tp+'</span>'+
        '<button onclick="setLeadsPage('+(_pg+1)+')" style="padding:5px 12px;border:1px solid var(--border2);border-radius:7px;background:var(--card);font-size:12px;cursor:pointer" '+(_pg>=_tp-1?'disabled':'')+'>Next &#8594;</button>'+
      '</div>':'')+
    '</div>'+
  '</div>';
}

// Bind search/filter inputs (called from render() after DOM replace)
function bindJobsControls(){
  var s=document.getElementById("jobs-search");
  if(s)s.oninput=function(){STATE.jobsFilter.search=this.value;render();var x=document.getElementById("jobs-search");if(x){x.focus();x.setSelectionRange(x.value.length,x.value.length);}};
  var st=document.getElementById("jobs-stage");
  if(st)st.onchange=function(){STATE.jobsFilter.stage=this.value;render();};
}

function openJob(id){ STATE.detailJob=id; STATE.modal={type:"jobDetail",id:id}; render(); }
// From the send-results panel: open the failed lead's detail.
function closeAndOpenLead(jobId){ if(jobId){ openJob(jobId); } }
// Manually dismiss the send-results panel (stays put until dismissed when there are failures).
function dismissSendProgress(){ STATE._progressDismissed=true; STATE.sendProgress=null; scheduleRender(); }
function openAddJob(){ STATE.modal={type:"addJob"}; render(); }

// ── JOB DETAIL MODAL ──────────────────────────────
function renderJobDetailModal(){
  var j=jobById(STATE.modal.id); if(!j) return "";
  var u=STATE.user;
  var canChangeStage=userHasAnyRole(u,'admin','bd','bd_lead');
  var canEdit=userHasRole(u,'admin')||j.created_by===u.id||j.assigned_to===u.id||j.assigned_to_bd===u.id;
  var bdStages=['Connected','Rejected','Future','In Discussion'];
  var allStages=['Unassigned','Assigned','Connected','Rejected','Future','In Discussion'];
  var cs=jobContacts(j.id);
  var stageOpts=allStages.map(function(st){return '<option value="'+st+'"'+(j.stage===st?" selected":"")+'>'+st+'</option>';}).join("");

  var emailStatusColors={valid:'var(--green)',invalid:'var(--red)',deactivated:'var(--text3)',out_of_office:'var(--amber)'};
  var emailStatusLabels={valid:'Valid',invalid:'Invalid',deactivated:'Deactivated',out_of_office:'Out of Office'};
  var canChangeEmailStatus=userHasAnyRole(u,'admin','bd','bd_lead');

  var contactRows=cs.map(function(c){
    var es=c.email_status||'valid';
    var esColor=emailStatusColors[es]||'var(--text3)';
    var esLabel=emailStatusLabels[es]||es;
    var emailStatusBadge='<span style="font-size:10px;padding:2px 7px;border-radius:6px;font-weight:600;background:'+esColor+'22;color:'+esColor+'">'+esLabel+'</span>';
    var emailStatusSel=canChangeEmailStatus?
      '<select onchange="changeEmailStatus(\''+c.id+'\',this.value,\''+escHtml(c.email||'')+'\',\''+escHtml((c.first_name||'')+' '+(c.last_name||''))+'\')" style="font-size:11px;padding:3px 7px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--text);margin-top:4px">'+
        ['valid','invalid','deactivated','out_of_office'].map(function(s){
          return '<option value="'+s+'"'+(es===s?' selected':'')+'>'+emailStatusLabels[s]+'</option>';
        }).join('')+
      '</select>':'';
    return '<div style="background:var(--bg3);border:1px solid var(--border2);border-radius:8px;padding:12px;margin-bottom:8px">'+
      '<div style="display:flex;justify-content:space-between;align-items:start;gap:8px">'+
        '<div style="flex:1">'+
          '<div style="font-weight:600;color:var(--text)">'+escHtml((c.first_name||"")+" "+(c.last_name||""))+(c.is_primary?' <span style="background:rgba(16,185,129,.15);color:#10b981;padding:2px 7px;border-radius:8px;font-size:10px;margin-left:4px">PRIMARY</span>':'')+'</div>'+
          '<div style="font-size:12px;color:var(--text3);margin-top:2px">'+escHtml(c.designation||"—")+'</div>'+
          '<div style="font-size:12px;color:var(--text2);margin-top:6px;display:flex;align-items:center;gap:8px;flex-wrap:wrap">'+
            '\ud83d\udce7 '+escHtml(c.email||"—")+' '+emailStatusBadge+
          '</div>'+
          (canChangeEmailStatus?'<div style="margin-top:5px">'+emailStatusSel+(c.ooo_until&&es==='out_of_office'?'<span style="font-size:11px;color:var(--amber);margin-left:8px">until '+escHtml(c.ooo_until)+'</span>':'')+'</div>':'')+
          (c.phone?'<div style="font-size:12px;color:var(--text2);margin-top:4px">\ud83d\udcde '+escHtml(c.phone)+'</div>':'')+
          (c.linkedin?'<div style="font-size:12px;color:var(--text2);margin-top:2px">\ud83d\udd17 '+escHtml(c.linkedin)+'</div>':'')+
        '</div>'+
        '<div style="display:flex;flex-direction:column;gap:4px">'+
          (c.email?'<button onclick="sendEmailToContact(\''+c.id+'\')" style="background:var(--accent);color:#fff;border:0;padding:5px 10px;border-radius:6px;font-size:11px;cursor:pointer">Email</button>':'')+
          (canEdit?'<button onclick="deleteContact(\''+c.id+'\')" style="background:transparent;color:#ef4444;border:1px solid #ef4444;padding:5px 10px;border-radius:6px;font-size:11px;cursor:pointer">Delete</button>':'')+
        '</div>'+
      '</div>'+
    '</div>';
  }).join("");
  if(!contactRows)contactRows='<div style="color:var(--text3);font-size:12px;padding:12px;text-align:center">No contacts yet.</div>';

  return '<div style="background:var(--bg2);border-radius:14px;width:min(720px,94vw);max-height:90vh;overflow-y:auto;border:1px solid var(--border)">'+
    '<div style="padding:20px 24px;border-bottom:1px solid var(--border2);display:flex;justify-content:space-between;align-items:start;gap:12px">'+
      '<div><div style="font-size:18px;font-weight:700;color:var(--text)">'+escHtml(j.position)+'</div><div style="font-size:13px;color:var(--text3);margin-top:3px">'+escHtml(j.company_name)+(j.location?" · "+escHtml(j.location):"")+'</div></div>'+
      '<button onclick="closeModal()" style="background:transparent;border:0;color:var(--text3);font-size:22px;cursor:pointer;line-height:1">×</button>'+
    '</div>'+
    '<div style="padding:20px 24px">'+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:18px">'+
        '<div><label style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px">Stage</label>'+
          (canChangeStage?'<select id="job-stage-sel" onchange="changeJobStage(\''+j.id+'\',this.value)" style="width:100%;margin-top:5px;padding:8px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px">'+stageOpts+'</select>':'<div style="margin-top:5px;font-size:13px;color:var(--text)">'+j.stage+'</div>')+
        '</div>'+
        '<div><label style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px">Source</label><div style="margin-top:5px;font-size:13px;color:var(--text)">'+escHtml(j.source||"—")+'</div></div>'+
      '</div>'+
      '<div style="margin-bottom:18px"><label style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.5px">Notes</label>'+
        (canEdit?'<textarea id="job-notes" onblur="saveJobNotes(\''+j.id+'\',this.value)" style="width:100%;margin-top:5px;padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px;min-height:64px;resize:vertical;font-family:inherit">'+escHtml(j.notes||"")+'</textarea>':'<div style="margin-top:5px;font-size:13px;color:var(--text)">'+escHtml(j.notes||"—")+'</div>')+
      '</div>'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><div style="font-size:13px;font-weight:600;color:var(--text)">Contacts ('+cs.length+')</div>'+
        (canEdit?'<button onclick="openAddContact(\''+j.id+'\')" style="background:var(--accent);color:#fff;border:0;padding:6px 12px;border-radius:7px;font-size:11px;font-weight:600;cursor:pointer">+ Add Contact</button>':'')+
      '</div>'+
      contactRows+
      renderResearchSection(j, canEditResearch(u,j))+
      (canEdit?'<div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--border2);display:flex;justify-content:flex-end;gap:8px"><button onclick="deleteJob(\''+j.id+'\')" style="background:transparent;color:#ef4444;border:1px solid #ef4444;padding:7px 14px;border-radius:7px;font-size:12px;cursor:pointer">Delete Job</button></div>':'')+
    '</div>'+
  '</div>';
}

// ── ADD JOB MODAL ─────────────────────────────────
function renderAddJobModal(){
  var u=STATE.user;
  var coOpts=STATE.companies.map(function(c){return '<option value="'+c.id+'">'+escHtml(c.name)+'</option>';}).join("");
  return '<div style="background:var(--bg2);border-radius:14px;width:min(560px,94vw);max-height:90vh;overflow-y:auto;border:1px solid var(--border)">'+
    '<div style="padding:18px 22px;border-bottom:1px solid var(--border2);display:flex;justify-content:space-between"><div style="font-size:16px;font-weight:700;color:var(--text)">Add Lead</div><button onclick="closeModal()" style="background:transparent;border:0;color:var(--text3);font-size:22px;cursor:pointer;line-height:1">×</button></div>'+
    '<div style="padding:20px 22px">'+
      '<div style="margin-bottom:12px"><label style="font-size:11px;color:var(--text3)">Company</label><select id="aj-co" style="width:100%;margin-top:4px;padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px">'+coOpts+'</select></div>'+
      '<div style="margin-bottom:12px"><label style="font-size:11px;color:var(--text3)">Position</label><input id="aj-pos" placeholder="e.g. Senior Software Engineer" style="width:100%;margin-top:4px;padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px"/></div>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px">'+
        '<div><label style="font-size:11px;color:var(--text3)">Location</label><input id="aj-loc" style="width:100%;margin-top:4px;padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px"/></div>'+
        '<div><label style="font-size:11px;color:var(--text3)">Source</label><input id="aj-src" placeholder="LinkedIn, Indeed..." style="width:100%;margin-top:4px;padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px"/></div>'+
      '</div>'+
      '<div style="margin-bottom:14px"><label style="font-size:11px;color:var(--text3)">Job URL (optional)</label><input id="aj-url" style="width:100%;margin-top:4px;padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px"/></div>'+
      '<div style="font-size:12px;color:var(--text3);margin-bottom:8px;padding-top:6px;border-top:1px solid var(--border2);padding-top:12px">First contact (you can add more after creating)</div>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">'+
        '<input id="aj-fn" placeholder="First name *" style="padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px"/>'+
        '<input id="aj-ln" placeholder="Last name" style="padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px"/>'+
      '</div>'+
      '<input id="aj-desig" placeholder="Designation" style="width:100%;padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px;margin-bottom:10px"/>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px">'+
        '<input id="aj-email" placeholder="Email" style="padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px"/>'+
        '<input id="aj-phone" placeholder="Phone" style="padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px"/>'+
      '</div>'+
      '<div style="display:flex;justify-content:flex-end;gap:8px"><button onclick="closeModal()" style="background:transparent;color:var(--text3);border:1px solid var(--border);padding:9px 16px;border-radius:7px;cursor:pointer;font-size:13px">Cancel</button><button onclick="submitAddJob()" style="background:var(--accent);color:#fff;border:0;padding:9px 18px;border-radius:7px;cursor:pointer;font-size:13px;font-weight:600">Add Lead</button></div>'+
    '</div>'+
  '</div>';
}

// ── ADD CONTACT MODAL ─────────────────────────────
function renderAddContactModal(){
  var jid=STATE.modal.job_id;
  return '<div style="background:var(--bg2);border-radius:14px;width:min(480px,94vw);border:1px solid var(--border)">'+
    '<div style="padding:18px 22px;border-bottom:1px solid var(--border2);display:flex;justify-content:space-between"><div style="font-size:16px;font-weight:700;color:var(--text)">Add Contact</div><button onclick="backToJob(\''+jid+'\')" style="background:transparent;border:0;color:var(--text3);font-size:22px;cursor:pointer;line-height:1">×</button></div>'+
    '<div style="padding:20px 22px">'+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">'+
        '<input id="ac-fn" placeholder="First name *" style="padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px"/>'+
        '<input id="ac-ln" placeholder="Last name" style="padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px"/>'+
      '</div>'+
      '<input id="ac-desig" placeholder="Designation" style="width:100%;padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px;margin-bottom:10px"/>'+
      '<input id="ac-email" placeholder="Email" style="width:100%;padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px;margin-bottom:10px"/>'+
      '<input id="ac-phone" placeholder="Phone" style="width:100%;padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px;margin-bottom:10px"/>'+
      '<input id="ac-linkedin" placeholder="LinkedIn URL" style="width:100%;padding:9px;background:var(--bg3);border:1px solid var(--border);border-radius:7px;color:var(--text);font-size:13px;margin-bottom:14px"/>'+
      '<div style="display:flex;justify-content:flex-end;gap:8px"><button onclick="backToJob(\''+jid+'\')" style="background:transparent;color:var(--text3);border:1px solid var(--border);padding:9px 16px;border-radius:7px;cursor:pointer;font-size:13px">Cancel</button><button onclick="submitAddContact(\''+jid+'\')" style="background:var(--accent);color:#fff;border:0;padding:9px 18px;border-radius:7px;cursor:pointer;font-size:13px;font-weight:600">Add Contact</button></div>'+
    '</div>'+
  '</div>';
}

// ── JOB/CONTACT ACTIONS ──
function saveJobNotes(jid, val){
  var j=jobById(jid); if(!j) return;
  if (j.notes===val) return;
  j.notes=val; showToast("Notes saved","success");
}
function deleteJob(jid){
  if(!confirm("Delete this job and all its contacts?")) return;
  STATE.jobs=STATE.jobs.filter(function(j){return j.id!==jid;});
  STATE.contacts=STATE.contacts.filter(function(c){return c.job_id!==jid;});
  STATE.modal=null; STATE.detailJob=null;
  showToast("Job deleted","success"); render();
}
function submitAddJob(){
  var co=document.getElementById("aj-co").value;
  var pos=document.getElementById("aj-pos").value.trim();
  var fn=document.getElementById("aj-fn").value.trim();
  if(!pos){showToast("Position is required","error");return;}
  if(!fn){showToast("First contact name is required","error");return;}
  apiPost('/jobs',{
    company_id:co,
    position:pos,
    location:document.getElementById("aj-loc").value.trim()||null,
    source:document.getElementById("aj-src").value.trim()||"LinkedIn",
    job_url:document.getElementById("aj-url").value.trim()||null,
    contacts:[{
      first_name:fn,
      last_name:document.getElementById("aj-ln").value.trim(),
      designation:document.getElementById("aj-desig").value.trim()||null,
      email:document.getElementById("aj-email").value.trim()||null,
      phone:document.getElementById("aj-phone").value.trim()||null
    }]
  }).then(function(){
    STATE.modal=null;
    showToast("Lead created","success");
    return refreshJobs();
  }).catch(function(e){
    showToast("Failed to create lead: "+e.message,"error");
  });
}
function openAddContact(jid){ STATE.modal={type:"addContact",job_id:jid}; render(); }
function backToJob(jid){ STATE.modal={type:"jobDetail",id:jid}; render(); }
function submitAddContact(jid){
  var fn=document.getElementById("ac-fn").value.trim();
  if(!fn){showToast("First name is required","error");return;}
  var existing=jobContacts(jid);
  apiPost('/contacts',{
    job_id:jid,
    first_name:fn,
    last_name:document.getElementById("ac-ln").value.trim(),
    designation:document.getElementById("ac-desig").value.trim()||null,
    email:document.getElementById("ac-email").value.trim()||null,
    phone:document.getElementById("ac-phone").value.trim()||null,
    linkedin:document.getElementById("ac-linkedin").value.trim()||null,
    is_primary:existing.length===0
  }).then(function(){
    showToast("Contact added","success");
    return refreshJobs();
  }).then(function(){
    STATE.modal={type:"jobDetail",id:jid}; render();
  }).catch(function(e){
    showToast("Failed to add contact: "+e.message,"error");
  });
}
function deleteContact(cid){
  if(!confirm("Delete this contact?")) return;
  var c=STATE.contacts.find(function(x){return x.id===cid;}); if(!c) return;
  apiDelete('/contacts/'+cid).then(function(){
    showToast("Contact deleted","success");
    return refreshJobs();
  }).catch(function(e){
    showToast("Failed to delete contact: "+e.message,"error");
  });
}
function sendEmailToContact(cid){
  var c=STATE.contacts.find(function(x){return x.id===cid;}); if(!c) return;
  var j=jobById(c.job_id)||{};
  STATE.composeContactId=cid+'|'+(j.id||'');
  STATE.composeCompanyId=j.company_id||null;
  STATE.composeContext=null;STATE.composeReminderId=null;
  STATE.manualEmail=null;STATE.genEmail=null;STATE.emailTab='compose';STATE.showAIPanel=false;
  STATE.page="email"; STATE.modal=null; showToast("Compose email to "+c.first_name,"info"); render();
}
function closeModal(){ STATE.modal=null; render(); }

// ── EMAIL ──────────────────────────────────────
function renderEmail(){
  var u=STATE.user;
  // BD sees pending+queued+sent; others see sent only
  var isBD=userHasAnyRole(u,'bd','bd_lead','admin','ra_lead');
  var pending=STATE.pendingEmails||[];
  var sentEmails=STATE.sentEmails||[];
  var tabs=isBD?['pending','compose','sent','outreachplan']:['compose','sent','outreachplan'];
  if(!STATE.emailTab)STATE.emailTab=isBD?'pending':'compose';

  // ── Send progress bar ──
  var sp=STATE.sendProgress;
  var progressBar='';
  if(sp&&(sp.active||sp.done)){
    var pct=sp.total>0?Math.round((sp.sent+sp.failed)/sp.total*100):0;
    var barColor=sp.done?(sp.failed>0?'var(--amber)':'var(--green)'):'var(--accent)';
    var fails=sp.failDetails||[];
    // Stat chip
    var statChip=function(val,label,color){
      return '<div style="flex:1;min-width:70px;padding:8px 12px;border-radius:8px;background:var(--bg);border:1px solid var(--border2)">'+
        '<div style="font-size:20px;font-weight:700;line-height:1;color:'+color+'">'+val+'</div>'+
        '<div style="font-size:10.5px;color:var(--text3);text-transform:uppercase;letter-spacing:.05em;margin-top:3px">'+label+'</div>'+
      '</div>';
    };
    var waitingTotal=sp.deferred||0;
    var chips='<div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap">'+
      statChip(sp.sent,'Sent','var(--green)')+
      statChip(sp.failed,'Failed',sp.failed>0?'#ef4444':'var(--text2)')+
      (waitingTotal?statChip(waitingTotal,'Waiting','var(--amber)'):'')+
      statChip(sp.total,'Total','var(--text)')+
    '</div>';
    // Failed rows — each links back to its lead
    var failRows=fails.map(function(f){
      var cur=f.job_id?'cursor:pointer;':'';
      var click=f.job_id?(' onclick="closeAndOpenLead(\''+f.job_id+'\')" title="Open this lead"'):'';
      return '<div class="fail-row"'+click+' style="'+cur+'display:flex;align-items:center;justify-content:space-between;gap:10px;padding:9px 12px;border-bottom:1px solid var(--border2)">'+
        '<div style="min-width:0;flex:1">'+
          '<div style="font-size:12.5px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+htmlEsc(f.to||'(no address)')+'</div>'+
          '<div style="font-size:11.5px;color:var(--text3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+htmlEsc(f.error||'Send failed')+'</div>'+
        '</div>'+
        (f.job_id?'<div style="font-size:11.5px;color:var(--accent);white-space:nowrap;font-weight:600">View lead →</div>':'<div style="font-size:11px;color:var(--text3);white-space:nowrap">no lead link</div>')+
      '</div>';
    }).join('');
    var failPanel=fails.length?
      '<div style="margin-top:12px;border:1px solid var(--border2);border-radius:8px;overflow:hidden">'+
        '<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--amber-l)">'+
          '<div style="font-size:12px;font-weight:700;color:var(--amber)">Failed deliveries ('+fails.length+')</div>'+
          '<div style="font-size:11px;color:var(--amber)">click a row to open the lead</div>'+
        '</div>'+
        '<div style="max-height:240px;overflow-y:auto">'+failRows+'</div>'+
      '</div>':'';
    var dismissBtn=sp.done?'<button onclick="dismissSendProgress()" title="Dismiss" style="background:transparent;border:0;color:var(--text3);font-size:18px;line-height:1;cursor:pointer;padding:0 2px">×</button>':'';
    progressBar='<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px 18px;margin-bottom:16px">'+
      '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">'+
        '<div style="font-weight:700;font-size:14px">'+(sp.done?(sp.failed>0?'Send complete — '+sp.failed+' need attention':'Send complete'):'Sending emails…')+'</div>'+
        '<div style="display:flex;align-items:center;gap:10px"><div style="font-size:12px;font-weight:700;color:'+barColor+'">'+pct+'%</div>'+dismissBtn+'</div>'+
      '</div>'+
      chips+
      '<div style="background:var(--border);border-radius:99px;height:8px;overflow:hidden;margin-bottom:8px">'+
        '<div style="height:100%;border-radius:99px;background:'+barColor+';width:'+pct+'%;transition:width .3s ease"></div>'+
      '</div>'+
      '<div style="font-size:12px;color:var(--text3)">'+(sp.active&&sp.current?'Currently sending to: '+htmlEsc(sp.current):(sp.done?'Completed at '+(sp.completedAt?new Date(sp.completedAt).toLocaleTimeString('en-IN',{hour:'2-digit',minute:'2-digit'}):''):''))+'</div>'+
      failPanel+
      (sp.deferredNote?'<div style="margin-top:8px;font-size:12px;color:#b45309">'+htmlEsc(sp.deferredNote)+'</div>':'')+
    '</div>';
  }

  var tabBar=tabs.map(function(t){
    var lbl;
    if(t==='pending'){
      var ps=STATE.pendingSummary;
      if(ps&&ps.total_pending){
        lbl='Pending ('+ps.total_pending+(ps.ready_now?': '+ps.ready_now+' now':'')+(ps.waiting_window?(', '+ps.waiting_window+' waiting'):'')+')';
      }else{
        lbl='Pending'+(pending.length?' ('+pending.length+')':'');
      }
    }else if(t==='outreachplan'){lbl='Outreach Plan';}else{lbl=t.charAt(0).toUpperCase()+t.slice(1);}
    return '<div class="tab'+(STATE.emailTab===t?' active':'')+'" onclick="setEmailTab(\''+t+'\')">'+lbl+'</div>';
  }).join('');

  // ── PENDING TAB ──
  var pendingHtml='';
  if(STATE.emailTab==='pending'){
    var scheduleBanner=renderPendingScheduleBanner();
    var isRaLead=userHasRole(u,'ra_lead');

    // ── RA LEAD: BD user picker ──────────────────────────────────────
    if(isRaLead && !STATE.raLeadSelectedBD){
      // Group ALL emails (pending + sent + failed) by BD user for the picker
      var bdGroups={};
      (STATE.allBDEmails||STATE.pendingEmails||[]).forEach(function(e){
        var sid=e.sender&&e.sender.id?e.sender.id:(e.sent_by||'unknown');
        var sname=e.sender&&e.sender.name?e.sender.name:'Unknown';
        if(!bdGroups[sid])bdGroups[sid]={id:sid,name:sname,pending:0,sent:0,failed:0};
        if(e.status==='pending')bdGroups[sid].pending++;
        else if(e.status==='sent')bdGroups[sid].sent++;
        else if(e.status==='failed')bdGroups[sid].failed++;
      });
      // Always show all BD/BD_Lead users even if they have no emails yet
      (STATE.users||[]).filter(function(usr){return userHasRole(usr,'bd')||userHasRole(usr,'bd_lead');}).forEach(function(usr){
        if(!bdGroups[usr.id])bdGroups[usr.id]={id:usr.id,name:usr.name,pending:0,sent:0,failed:0};
        else if(!bdGroups[usr.id].name)bdGroups[usr.id].name=usr.name; // fill name if missing
      });
      var bdCards=Object.values(bdGroups).sort(function(a,b){return (b.pending+b.sent+b.failed)-(a.pending+a.sent+a.failed);}).map(function(bd){
        var initials=bd.name.split(' ').map(function(w){return w[0]||'';}).slice(0,2).join('').toUpperCase();
        var total=bd.pending+bd.sent+bd.failed;
        var statusLine=total===0?'<span style="color:var(--text3)">No emails yet</span>':(
          (bd.pending?'<span style="color:var(--amber);font-weight:600">'+bd.pending+' pending</span>':'')+
          (bd.pending&&(bd.sent||bd.failed)?' · ':'')+
          (bd.sent?'<span style="color:var(--green);font-weight:600">'+bd.sent+' sent</span>':'')+
          (bd.sent&&bd.failed?' · ':'')+
          (bd.failed?'<span style="color:var(--red,#dc2626);font-weight:600">'+bd.failed+' failed (all runs)</span>':'')
        );
        return '<div onclick="STATE.raLeadSelectedBD=\''+bd.id+'\';STATE.pendingEmailPage=0;loadPendingSummary();render()" style="display:flex;align-items:center;gap:14px;padding:14px 18px;border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s" onmouseover="this.style.background=\'var(--accent-l)\'" onmouseout="this.style.background=\'\'" >'+
          '<div style="width:38px;height:38px;border-radius:50%;background:var(--accent);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;flex-shrink:0">'+htmlEsc(initials)+'</div>'+
          '<div style="flex:1">'+
            '<div style="font-weight:600;font-size:13.5px">'+htmlEsc(bd.name)+'</div>'+
            '<div style="font-size:12px;margin-top:2px">'+statusLine+'</div>'+
          '</div>'+
          '<div style="color:var(--text3);font-size:16px">→</div>'+
        '</div>';
      }).join('');
      if(!bdCards)bdCards='<div style="padding:40px;text-align:center;color:var(--text3)">No BD users found.</div>';
      pendingHtml=scheduleBanner+'<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden">'+
        '<div style="padding:12px 18px;border-bottom:1px solid var(--border);font-size:12px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.05em">BD Managers — click to view emails</div>'+
        bdCards+
      '</div>';

    // ── RA LEAD: viewing a specific BD's emails ──────────────────────
    } else {
      var viewingBD=isRaLead&&STATE.raLeadSelectedBD;
      var displayPending=viewingBD
        ? (STATE.allBDEmails||STATE.pendingEmails||[]).filter(function(e){return (e.sender&&e.sender.id?e.sender.id:e.sent_by)===STATE.raLeadSelectedBD;})
        : pending;
      var bdName=viewingBD?(function(){var bd=(STATE.users||[]).find(function(u){return u.id===STATE.raLeadSelectedBD;});return bd?bd.name:'BD Manager';})():'';

      var totalRecipients=displayPending.length;
      var _pPg=Math.min(STATE.pendingEmailPage||0,Math.max(0,Math.ceil(totalRecipients/20)-1));
      var _pTp=Math.max(1,Math.ceil(totalRecipients/20));
      var pendingPaged=displayPending.slice(_pPg*20,(_pPg+1)*20);
      var sendAllBtn=isRaLead?'':('<button onclick="openSendAllConfirm()" style="background:var(--accent);color:#fff;border:0;padding:9px 18px;border-radius:8px;font-weight:600;font-size:13px;cursor:pointer'+(totalRecipients?'':';opacity:.4;cursor:not-allowed')+'"'+(totalRecipients?'':'disabled')+'>Send all pending ('+totalRecipients+')</button>');

      var pendingRows=pendingPaged.map(function(e){
        var isSelected=STATE.previewPendingId===e.id;
        var jname=(e.job&&e.job.position?e.job.position:'')+(e.job&&e.job.company?(' · '+e.job.company.name):'');
        var fu=e.followup_type;
        var rowBg=isSelected?'var(--accent-l)':fu==='fu2'?'#fff8f0':fu==='fu1'?'#fffdf0':'';
        var fuBadge=fu==='fu1'?'<span style="font-size:10px;padding:2px 7px;background:#fef9c3;color:#92400e;border-radius:6px;font-weight:700;margin-left:6px">FU1</span>':fu==='fu2'?'<span style="font-size:10px;padding:2px 7px;background:#ffedd5;color:#9a3412;border-radius:6px;font-weight:700;margin-left:6px">FU2</span>':'';
        var leadTz=(e.job&&e.job.timezone)||'EST';
        var tzRow2=(STATE.pendingSummary&&STATE.pendingSummary.by_timezone||[]).find(function(t){return t.timezone===leadTz;});
        var winBadge=(tzRow2&&tzRow2.waiting_window>0&&!(tzRow2.ready_now>0))?'<span style="font-size:10px;padding:2px 7px;background:#fef3c7;color:#92400e;border-radius:6px;font-weight:600;margin-left:6px">Waiting · '+htmlEsc(leadTz)+'</span>':'<span style="font-size:10px;padding:2px 7px;background:var(--green-l);color:var(--green);border-radius:6px;font-weight:600;margin-left:6px">Ready now</span>';
        return '<tr style="border-bottom:1px solid var(--border2);cursor:pointer;background:'+rowBg+'" onclick="previewPendingEmail(\''+e.id+'\')">'+'<td style="padding:10px 12px;font-size:13px"><div style="font-weight:500">'+htmlEsc(e.to_email)+fuBadge+winBadge+'</div>'+'<div style="font-size:11px;color:var(--text3)">'+htmlEsc((e.contact&&e.contact.first_name?e.contact.first_name+' '+(e.contact.last_name||''):''))+'</div></td>'+'<td style="padding:10px 12px;font-size:12px;color:var(--text2)">'+htmlEsc(jname)+'</td>'+'<td style="padding:10px 12px;font-size:12px;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+htmlEsc(e.subject||'')+'</td>'+'<td style="padding:10px 12px;white-space:nowrap">'+(function(){var sc=e.status==='sent'?'background:var(--green-l);color:var(--green)':e.status==='failed'?'background:#fee2e2;color:#dc2626':'background:var(--amber-l);color:var(--amber)';return '<span style="font-size:11px;padding:2px 8px;'+sc+';border-radius:8px;font-weight:600">'+htmlEsc(e.status)+'</span>';})() +'</td>'+'</tr>';
      }).join('');
      if(!pendingRows)pendingRows='<tr><td colspan="4" style="padding:40px;text-align:center;color:var(--text3)">No pending emails yet.</td></tr>';

    // Preview panel
    var previewPanel='';
    if(STATE.previewPendingId){
      var pe=displayPending.find(function(e){return e.id===STATE.previewPendingId;});
      if(pe){
        previewPanel='<div style="width:380px;flex-shrink:0;background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden">'+
          '<div style="padding:12px 14px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">'+
            '<div style="font-weight:600;font-size:13px">Email Preview</div>'+
            '<button class="btn-icon" onclick="STATE.previewPendingId=null;render()">'+ico('x',13)+'</button>'+
          '</div>'+
          '<div style="padding:12px 14px;border-bottom:1px solid var(--border);font-size:12px;color:var(--text2)">'+
            '<div><strong>To:</strong> '+htmlEsc(pe.to_email)+'</div>'+
            '<div class="mt1"><strong>Subject:</strong> '+htmlEsc(pe.subject||'')+'</div>'+
          '</div>'+
          '<div style="padding:14px;font-size:13px;line-height:1.7;white-space:pre-wrap;max-height:360px;overflow-y:auto">'+htmlEsc(pe.body||'')+'</div>'+
          '<div style="padding:10px 14px;border-top:1px solid var(--border);display:flex;justify-content:flex-end">'+
            '<button class="btn btn-outline btn-sm" onclick="openEditPendingEmail(\''+pe.id+'\')">✒ Edit email</button>'+
          '</div>'+
          '</div>'+
        '</div>';
      }
    }

    // Back button for RA Lead drill-down view
    var backBtn=viewingBD?('<div style="margin-bottom:14px"><button onclick="STATE.raLeadSelectedBD=null;STATE.previewPendingId=null;loadPendingSummary();render()" style="background:none;border:1px solid var(--border2);padding:6px 14px;border-radius:7px;font-size:13px;cursor:pointer;color:var(--text2)">← Back to all BD Managers</button><span style="margin-left:12px;font-weight:600;font-size:14px">'+htmlEsc(bdName)+'</span></div>'):'';

    pendingHtml='<div>'+scheduleBanner+
      backBtn+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'+
        '<div style="font-size:13px;color:var(--text2)">'+totalRecipients+' email'+(totalRecipients!==1?'s':'')+' ready · page '+(_pPg+1)+' of '+_pTp+'</div>'+
        sendAllBtn+
      '</div>'+
      '<div style="display:flex;gap:14px;align-items:flex-start">'+
        '<div style="flex:1;background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden">'+
          '<table style="width:100%;border-collapse:collapse;font-size:13px">'+
            '<thead style="background:var(--bg);color:var(--text3);font-size:11px;text-transform:uppercase;letter-spacing:.5px">'+
              '<tr><th style="padding:10px 12px;text-align:left">Recipient</th><th style="padding:10px 12px;text-align:left">Job</th><th style="padding:10px 12px;text-align:left">Subject</th><th style="padding:10px 12px;text-align:left">Status</th></tr>'+
            '</thead>'+
            '<tbody>'+pendingRows+'</tbody>'+
          '</table>'+
          (_pTp>1?'<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-top:1px solid var(--border)">'+
            '<div style="font-size:12px;color:var(--text3)">'+totalRecipients+' total · page '+(_pPg+1)+' of '+_pTp+'</div>'+
            '<div style="display:flex;gap:5px">'+
              '<button onclick="STATE.pendingEmailPage=Math.max(0,'+_pPg+'-1);render()" style="padding:5px 12px;border:1px solid var(--border2);border-radius:7px;background:var(--card);font-size:12px;cursor:pointer" '+(_pPg===0?'disabled':'')+'>← Prev</button>'+
              '<span style="padding:5px 10px;font-size:12px;font-weight:600">'+(_pPg+1)+' / '+_pTp+'</span>'+
              '<button onclick="STATE.pendingEmailPage=Math.min('+(_pTp-1)+','+_pPg+'+1);render()" style="padding:5px 12px;border:1px solid var(--border2);border-radius:7px;background:var(--card);font-size:12px;cursor:pointer" '+(_pPg>=_pTp-1?'disabled':'')+'>Next →</button>'+
            '</div>'+
          '</div>':'')  +
        '</div>'+
        previewPanel+
      '</div>'+
    '</div>';
    } // end else (BD table view)
  }

  // ── SENT TAB ──
  var sentHtml='';
  if(STATE.emailTab==='sent'){
    var _sPg=Math.min(STATE.sentEmailPage||0,Math.max(0,Math.ceil(sentEmails.length/20)-1));
    var _sTp=Math.max(1,Math.ceil(sentEmails.length/20));
    var sentPaged=sentEmails.slice(_sPg*20,(_sPg+1)*20);
    var sentRows=sentPaged.map(function(e){
      var jname=(e.job&&e.job.position?e.job.position:'')+(e.job&&e.job.company?(' · '+e.job.company.name):'');
      return '<tr style="border-bottom:1px solid var(--border2)">'+
        '<td style="padding:10px 12px;font-size:13px">'+htmlEsc(e.to_email||'')+'</td>'+
        '<td style="padding:10px 12px;font-size:12px;color:var(--text2)">'+htmlEsc(jname)+'</td>'+
        '<td style="padding:10px 12px;font-size:12px;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+htmlEsc(e.subject||'')+'</td>'+
        '<td style="padding:10px 12px"><span style="font-size:11px;padding:2px 8px;background:var(--green-l);color:var(--green);border-radius:8px;font-weight:600">'+htmlEsc(e.status||'sent')+'</span></td>'+
        '<td style="padding:10px 12px;font-size:11px;color:var(--text3)">'+htmlEsc(e.sent_at||'')+'</td>'+
      '</tr>';
    }).join('');
    if(!sentRows)sentRows='<tr><td colspan="5" style="padding:40px;text-align:center;color:var(--text3)">No sent emails yet.</td></tr>';
    sentHtml='<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden">'+
      '<table style="width:100%;border-collapse:collapse;font-size:13px">'+
        '<thead style="background:var(--bg);color:var(--text3);font-size:11px;text-transform:uppercase;letter-spacing:.5px">'+
          '<tr><th style="padding:10px 12px;text-align:left">To</th><th style="padding:10px 12px;text-align:left">Job</th><th style="padding:10px 12px;text-align:left">Subject</th><th style="padding:10px 12px;text-align:left">Status</th><th style="padding:10px 12px;text-align:left">Date</th></tr>'+
        '</thead>'+
        '<tbody>'+sentRows+'</tbody>'+
      '</table>'+
      (_sTp>1?'<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-top:1px solid var(--border)">'+
        '<div style="font-size:12px;color:var(--text3)">'+sentEmails.length+' total · page '+(_sPg+1)+' of '+_sTp+'</div>'+
        '<div style="display:flex;gap:5px">'+
          '<button onclick="STATE.sentEmailPage=Math.max(0,'+_sPg+'-1);render()" style="padding:5px 12px;border:1px solid var(--border2);border-radius:7px;background:var(--card);font-size:12px;cursor:pointer" '+(_sPg===0?'disabled':'')+'>← Prev</button>'+
          '<span style="padding:5px 10px;font-size:12px;font-weight:600">'+(_sPg+1)+' / '+_sTp+'</span>'+
          '<button onclick="STATE.sentEmailPage=Math.min('+(_sTp-1)+','+_sPg+'+1);render()" style="padding:5px 12px;border:1px solid var(--border2);border-radius:7px;background:var(--card);font-size:12px;cursor:pointer" '+(_sPg>=_sTp-1?'disabled':'')+'>Next →</button>'+
        '</div>'+
      '</div>':'')  +
    '</div>';
  }

  // ── OUTREACH PLAN TAB ──
  if(!STATE.activeTmpl)STATE.activeTmpl='outreach';
  var myPlan=STATE.myOutreachPlan||{};
  var fu1Day=parseInt(myPlan['fu1_day']||'3',10);
  var fu2Day=parseInt(myPlan['fu2_day']||'7',10);
  function dayOpts(selected,minDay){
    var opts='';
    for(var d=1;d<=10;d++){
      if(d<=minDay)continue;
      opts+='<option value="'+d+'"'+(d===selected?' selected':'')+'>Day '+d+'</option>';
    }
    return opts;
  }
  var tmplDefs=[
    {key:'outreach',label:'Outreach 1',sublabel:'Sent immediately on assignment',color:'var(--accent)',subjVal:myPlan['tmpl_o1_subject']||STATE.emailSubj,bodyVal:myPlan['tmpl_o1_body']||STATE.emailBody,subjId:'tmpl-o1-subj',bodyId:'tmpl-o1-body'},
    {key:'fu1',label:'Follow-up 1',sublabel:'Day '+fu1Day+' after outreach',color:'#ca8a04',subjVal:myPlan['tmpl_fu1_subject']||STATE.fu1Subj,bodyVal:myPlan['tmpl_fu1_body']||STATE.fu1Body,subjId:'tmpl-fu1-subj',bodyId:'tmpl-fu1-body'},
    {key:'fu2',label:'Follow-up 2',sublabel:'Day '+fu2Day+' after outreach',color:'#ea580c',subjVal:myPlan['tmpl_fu2_subject']||STATE.fu2Subj,bodyVal:myPlan['tmpl_fu2_body']||STATE.fu2Body,subjId:'tmpl-fu2-subj',bodyId:'tmpl-fu2-body'}
  ];
  var activeTmpl=tmplDefs.find(function(t){return t.key===STATE.activeTmpl;})||tmplDefs[0];
  var planEmails=(STATE.userEmailsCache&&STATE.userEmailsCache[u.id]||[]).filter(function(e){return e.is_active;});
  var planFromId=STATE.planFromEmailId||(planEmails.find(function(e){return e.is_primary;})||planEmails[0]||{}).id;
  if(planFromId&&!STATE.planFromEmailId)STATE.planFromEmailId=planFromId;
  if(planFromId&&STATE.sigEmailId!==planFromId)STATE.sigEmailId=planFromId;
  var styleBtns=Object.keys(OUTREACH_STYLE_PRESETS).map(function(pk){
    var p=OUTREACH_STYLE_PRESETS[pk];
    var on=STATE.outreachStylePreset===pk;
    return '<button type="button" onclick="applyOutreachStylePreset(\''+pk+'\')" style="text-align:left;padding:10px 14px;border-radius:10px;cursor:pointer;border:2px solid '+(on?'var(--accent)':'var(--border)')+';background:'+(on?'var(--accent-l)':'var(--card)')+';min-width:140px;flex:1">'+
      '<div style="font-weight:700;font-size:13px;color:'+(on?'var(--accent)':'var(--text)')+'">'+htmlEsc(p.label)+'</div>'+
      '<div style="font-size:11px;color:var(--text3);margin-top:3px">'+htmlEsc(p.hint)+'</div></button>';
  }).join('');
  var tmplTabBtns=tmplDefs.map(function(t){
    var isActive=STATE.activeTmpl===t.key;
    return '<button onclick="STATE.activeTmpl=\''+t.key+'\';render()" style="padding:8px 18px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border:2px solid '+(isActive?t.color:'var(--border)')+';background:'+(isActive?t.color:'var(--card)')+';color:'+(isActive?'#fff':'var(--text2)')+';transition:all .15s">'+t.label+'</button>';
  }).join('');
  var daySettingsHtml='';
  if(STATE.activeTmpl==='fu1'){
    daySettingsHtml='<div class="fgrp" style="margin-bottom:14px"><label class="flbl">Send Follow-up 1 on</label>'+
      '<select class="sel" style="max-width:160px" id="fu1-day-sel" onchange="saveOutreachDay(\'fu1_day\',this.value)">'+
        '<option value="">— select day —</option>'+dayOpts(fu1Day,0)+
      '</select>'+
      '<div style="font-size:11px;color:var(--text3);margin-top:4px">Days after the outreach email was sent</div>'+
    '</div>';
  } else if(STATE.activeTmpl==='fu2'){
    daySettingsHtml='<div class="fgrp" style="margin-bottom:14px"><label class="flbl">Send Follow-up 2 on</label>'+
      '<select class="sel" style="max-width:160px" id="fu2-day-sel" onchange="saveOutreachDay(\'fu2_day\',this.value)">'+
        '<option value="">— select day —</option>'+dayOpts(fu2Day,fu1Day)+
      '</select>'+
      '<div style="font-size:11px;color:var(--text3);margin-top:4px">Must be after Follow-up 1 (Day '+fu1Day+')</div>'+
    '</div>';
  }
  var canEditTemplates=userHasAnyRole(u,'bd','bd_lead','admin');
  var tmplHtml=canEditTemplates?
    '<div style="max-width:720px">'+
      '<div style="padding:12px 14px;background:var(--accent-l);border-radius:var(--r2);margin-bottom:16px;font-size:13px;color:var(--text2)">'+
        '<strong>How this works:</strong> Pick your sending email → choose a message style → edit Outreach &amp; follow-ups → Save. Assigned leads use these templates automatically.'+
      '</div>'+
      renderSendingEmailCard(u.id,planEmails,planFromId,'selectPlanFromEmail')+
      '<div class="card cp mb3">'+
        '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:6px">'+
          '<div class="fw6" style="font-size:13px">Message style</div>'+
          '<div style="display:flex;align-items:center;gap:8px;font-size:12px">'+
            '<span style="color:var(--text3)">Template mode:</span>'+
            '<div style="display:flex;border:1px solid var(--border);border-radius:20px;overflow:hidden;background:var(--card)">'+
              '<button type="button" onclick="setTemplateModeSpecific()" style="padding:4px 14px;font-size:12px;font-weight:600;cursor:pointer;border:0;border-radius:20px 0 0 20px;background:'+(STATE.randomTemplateMode?'transparent':'var(--accent)')+';color:'+(STATE.randomTemplateMode?'var(--text3)':'#fff')+';transition:all .15s">Specific</button>'+
              '<button type="button" onclick="setTemplateModeRandom()" style="padding:4px 14px;font-size:12px;font-weight:600;cursor:pointer;border:0;border-radius:0 20px 20px 0;background:'+(STATE.randomTemplateMode?'var(--accent)':'transparent')+';color:'+(STATE.randomTemplateMode?'#fff':'var(--text3)')+';transition:all .15s">Random</button>'+
            '</div>'+
          '</div>'+
        '</div>'+
        (STATE.randomTemplateMode?
          '<div style="font-size:11.5px;color:var(--text3);margin-bottom:10px">Bulk outreach rotates through all '+Object.keys(OUTREACH_STYLE_PRESETS).length+' matched styles (outreach + follow-ups) — each used once before any repeat. Follow-up 1 and 2 use the same style as the original outreach for each contact.</div>'+
          '<div style="padding:10px 14px;background:var(--accent-l);border-radius:var(--r2);font-size:12.5px;color:var(--accent);font-weight:600;margin-bottom:10px">'+
            '&#8652; Random mode — outreach, FU1, and FU2 rotate together per contact'+
          '</div>':
          '<div style="font-size:11.5px;color:var(--text3);margin-bottom:10px">Start from a proven template — you can edit any field after applying.</div>'+
          '<div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px">'+styleBtns+'</div>'
        )+
        '<button class="btn btn-primary" onclick="saveTemplateModePreference()" style="font-size:12px;padding:6px 18px">Save preference</button>'+
      '</div>'+
      '<div style="display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap">'+tmplTabBtns+'</div>'+
      '<div class="card cp" style="border-top:3px solid '+activeTmpl.color+'">'+
        '<div style="margin-bottom:14px">'+
          '<div style="font-weight:700;font-size:14px;color:var(--text)">'+activeTmpl.label+'</div>'+
          '<div style="font-size:12px;color:var(--text3);margin-top:2px">'+activeTmpl.sublabel+'</div>'+
        '</div>'+
        daySettingsHtml+
        '<div class="fgrp"><label class="flbl">Subject</label><input class="inp" id="'+activeTmpl.subjId+'" value="'+htmlEsc(activeTmpl.subjVal)+'" onfocus="setVarInsertTarget(\'subject\')"/></div>'+
        '<div class="fgrp"><label class="flbl">Body</label><textarea class="txta w100" style="min-height:200px" id="'+activeTmpl.bodyId+'" onfocus="setVarInsertTarget(\'body\')">'+htmlEsc(activeTmpl.bodyVal)+'</textarea></div>'+
        renderVarChipBar(activeTmpl.subjId,activeTmpl.bodyId)+
        '<button class="btn btn-primary mt3" onclick="saveOutreachTemplate(\''+activeTmpl.key+'\',\''+activeTmpl.subjId+'\',\''+activeTmpl.bodyId+'\')">Save '+activeTmpl.label+'</button>'+
      '</div>'+

      // ── SIGNATURE EDITOR (per sending email ID) ───────────────
      (function(){
        var myEmails=(STATE.userEmailsCache&&STATE.userEmailsCache[u.id]||[]).filter(function(e){return e.is_active;});
        var sigEmailId=STATE.sigEmailId||(myEmails.find(function(e){return e.is_primary;})||myEmails[0]||{}).id;
        if(sigEmailId&&!STATE.sigEmailId)STATE.sigEmailId=sigEmailId;
        var sigEmail=myEmails.find(function(e){return e.id===sigEmailId;});
        var sig='';
        if(sigEmailId&&STATE.emailSignaturesCache&&STATE.emailSignaturesCache[sigEmailId]!==undefined){
          var rawSig=STATE.emailSignaturesCache[sigEmailId];
          sig=normalizeMailboxSignature(rawSig);
          syncMailboxSignatureIfNeeded(u.id,sigEmailId,rawSig,sig);
        } else if(sigEmailId){
          loadMailboxSignature(u.id,sigEmailId);
        }
        var editing=STATE.sigEditing;
        var presets=SIG_PRESETS;
        var presetNames={professional:'Professional',minimal:'Minimal',withLogo:'With logo'};
        var previewSender=(sigEmail&&sigEmail.display_name)||'Your Name';
        var previewEmail=(sigEmail&&sigEmail.email_address)||'you@fute-global.com';
        var previewSource=sig||(SIG_PRESETS&&SIG_PRESETS.professional)||'';
        var previewHtml=previewSource?(previewSource.replace(/{{sender}}/g,previewSender).replace(/{{senderemail}}/g,previewEmail)):'<em style="color:var(--text3);font-size:12px">Loading signature…</em>';
        var sigLabel=sigEmail?(htmlEsc(sigEmail.display_name||sigEmail.email_address)+' &lt;'+htmlEsc(sigEmail.email_address)+'&gt;'):'selected email above';
        return '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);margin-top:16px;overflow:hidden">'+
          '<div style="padding:14px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">'+
            '<div>'+
              '<div style="font-weight:700;font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em">Email Signature</div>'+
              '<div style="font-size:11.5px;color:var(--text3);margin-top:2px">For '+sigLabel+' — appended automatically on send</div>'+
            '</div>'+
            '<button onclick="STATE.sigEditing=!STATE.sigEditing;render()" style="font-size:12px;padding:5px 12px;border:1px solid var(--border2);border-radius:7px;background:var(--bg);cursor:pointer;color:var(--text2)">'+(editing?'Close editor':'Edit signature')+'</button>'+
          '</div>'+
          (!myEmails.length?'<div style="padding:12px 16px 0;font-size:12px;color:var(--amber)">Add a sending email ID in Admin → your profile before setting a signature.</div>':'')+
          (editing?
            '<div style="padding:16px">'+
              '<div style="margin-bottom:12px">'+
                '<div style="font-size:11.5px;font-weight:600;color:var(--text2);margin-bottom:7px">Start from a preset layout:</div>'+
                '<div style="display:flex;gap:8px;flex-wrap:wrap">'+
                Object.keys(presets).map(function(pk){
                  return '<button onclick="applySigPreset(\''+pk+'\')" style="font-size:12px;padding:5px 12px;border:1.5px solid var(--border2);border-radius:8px;background:var(--bg);cursor:pointer;color:var(--text2);transition:all .12s" onmouseover="this.style.borderColor=\'var(--accent)\'" onmouseout="this.style.borderColor=\'var(--border2)\'">'+presetNames[pk]+'</button>';
                }).join('')+
                '</div>'+
              '</div>'+
              '<div style="margin-bottom:10px">'+
                '<div style="font-size:11.5px;font-weight:600;color:var(--text2);margin-bottom:6px">Signature HTML <span style="font-weight:400;color:var(--text3)">({{sender}} = display name, {{senderemail}} = this email ID)</span></div>'+
                '<textarea id="sig-html-input" style="width:100%;min-height:110px;padding:10px;border:1.5px solid var(--border2);border-radius:8px;font-family:var(--mono);font-size:12px;line-height:1.6;resize:vertical;color:var(--text);background:var(--bg)" placeholder="<p>Best regards,<br><strong>{{sender}}</strong></p>">'+htmlEsc(sig)+'</textarea>'+
              '</div>'+
              '<div style="margin-bottom:12px">'+
                '<div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Live preview</div>'+
                '<div id="sig-live-preview" style="padding:14px 16px;background:#f8fafc;border:1px solid var(--border);border-radius:8px;font-family:Arial,sans-serif;min-height:48px">'+
                  previewHtml+
                '</div>'+
              '</div>'+
              '<div style="display:flex;gap:8px">'+
                '<button onclick="saveSig()" style="padding:7px 18px;background:var(--accent);color:#fff;border:0;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer">Save signature</button>'+
                (sig?'<button onclick="clearSig()" style="padding:7px 14px;background:transparent;color:var(--red);border:1px solid var(--red);border-radius:8px;font-size:13px;cursor:pointer">Clear</button>':'')+
              '</div>'+
            '</div>'
          :
            '<div style="padding:14px 16px">'+
              '<div style="padding:12px 16px;background:#f8fafc;border:1px solid var(--border);border-radius:8px;font-family:Arial,sans-serif;min-height:40px">'+previewHtml+'</div>'+
            '</div>'
          )+
        '</div>';
      })()+
    '</div>':
    '<div class="card cp"><div style="color:var(--text3);font-size:13px">Outreach plan editing is available to BD and Admin roles only.</div></div>';

  // ── COMPOSE TAB ──
  var myJobs=getMyJobs(u);

  // Build company list for step-1 picker
  var companyIds={};
  myJobs.forEach(function(j){
    if(j.company_id&&!companyIds[j.company_id])companyIds[j.company_id]={id:j.company_id,name:j.company_name};
  });
  var companyList=Object.values(companyIds).sort(function(a,b){return a.name.localeCompare(b.name);});
  var coOpts='<option value="">— Select company —</option>'+companyList.map(function(c){
    return '<option value="'+c.id+'"'+(STATE.composeCompanyId===c.id?' selected':'')+'>'+escHtml(c.name)+'</option>';
  }).join('');

  // Step-2: contacts for selected company
  var pocOpts='';
  if(STATE.composeCompanyId){
    var coJobs=myJobs.filter(function(j){return j.company_id===STATE.composeCompanyId;});
    var pocList=[];
    coJobs.forEach(function(j){
      STATE.contacts.filter(function(c){return c.job_id===j.id&&c.email;}).forEach(function(c){
        pocList.push({cid:c.id,jid:j.id,label:(c.first_name||'')+' '+(c.last_name||'').trim()+(c.email?' <'+c.email+'>':'')+(c.designation?' · '+c.designation:''),email:c.email});
      });
    });
    pocOpts='<option value="">— Select contact —</option>'+pocList.map(function(p){
      return '<option value="'+p.cid+'|'+p.jid+'"'+(STATE.composeContactId===p.cid+'|'+p.jid?' selected':'')+'>'+escHtml(p.label)+'</option>';
    }).join('');
  }

  var composeHtml='';
  if(STATE.emailTab==='compose'){
    var hasRecipient=!!(STATE.composeContactId||STATE.manualEmail);

    // Recipient badge
    var recipientBadge='';
    if(STATE.composeContactId){
      var parts=STATE.composeContactId.split('|');
      var cc=STATE.contacts.find(function(c){return c.id===parts[0];});
      var cj=myJobs.find(function(j){return j.id===parts[1];});
      if(cc)recipientBadge='<div style="display:flex;align-items:center;gap:10px;padding:9px 12px;background:var(--accent-l);border-radius:var(--r);margin-top:8px">'+
        '<div style="flex:1;font-size:13px"><strong>'+escHtml((cc.first_name||'')+' '+(cc.last_name||''))+'</strong>'+(cc.designation?' \u00b7 '+escHtml(cc.designation):'')+
          '<div style="font-size:12px;color:var(--accent);font-weight:600;margin-top:2px">'+escHtml(cc.email||'(no email on record)')+'</div>'+(cj?'<div style="font-size:11px;color:var(--text3)">'+escHtml(cj.company_name)+'</div>':'')+
        '</div>'+
        '<button class="btn-icon" onclick="STATE.composeContactId=null;STATE.composeCompanyId=null;STATE.genEmail=null;render()">'+ico('x',13)+'</button>'+
      '</div>';
    } else if(STATE.manualEmail){
      recipientBadge='<div style="display:flex;align-items:center;gap:10px;padding:9px 12px;background:var(--green-l);border-radius:var(--r);margin-top:8px">'+
        '<div style="flex:1;font-size:13px"><strong>'+htmlEsc(STATE.manualEmail)+'</strong><div style="font-size:11px;color:var(--text3)">Manual entry</div></div>'+
        '<button class="btn-icon" onclick="STATE.manualEmail=null;STATE.genEmail=null;render()">'+ico('x',13)+'</button>'+
      '</div>';
    }

    var composeFromOpts='';
    var composeEmails=(STATE.userEmailsCache&&STATE.userEmailsCache[u.id]||[]).filter(function(e){return e.is_active;});
    var composeFromId=STATE.composeFromEmailId||(composeEmails.find(function(e){return e.is_primary;})||composeEmails[0]||{}).id;
    if(composeFromId&&!STATE.composeFromEmailId)STATE.composeFromEmailId=composeFromId;
    if(composeEmails.length){
      composeFromOpts=composeEmails.map(function(e){
        return '<option value="'+e.id+'"'+(e.id===composeFromId?' selected':'')+'>'+htmlEsc(e.display_name||e.email_address)+' &lt;'+htmlEsc(e.email_address)+'&gt;</option>';
      }).join('');
    }

    composeHtml='<div style="max-width:520px">'+
      '<div class="card cp mb3">'+
        '<div class="fw6 mb2" style="font-size:13px">To</div>'+
        '<select class="sel mb2" onchange="STATE.composeCompanyId=this.value;STATE.composeContactId=null;render()">'+coOpts+'</select>'+
        (STATE.composeCompanyId?
          '<select class="sel" onchange="STATE.composeContactId=this.value;STATE.manualEmail=null;render()">'+pocOpts+'</select>':'')+
        '<div style="text-align:center;font-size:11px;color:var(--text3);margin:10px 0">or enter an email</div>'+
        '<input class="inp" placeholder="name@company.com" id="manual-email-inp" value="'+htmlEsc(STATE.manualEmail||'')+'" oninput="STATE.manualEmail=this.value||null;STATE.composeContactId=null;STATE.composeCompanyId=null;render()"/>'+
        recipientBadge+
      '</div>'+
      '<div class="card cp mb3">'+
        (composeEmails.length?
          '<div class="fgrp" style="margin-bottom:0"><label class="flbl">From</label><select class="sel" onchange="selectComposeFromEmail(this.value)">'+composeFromOpts+'</select></div>'
          :'<div style="font-size:12px;color:var(--amber)">No sending email ID assigned — ask your admin to add one.</div>')+
      '</div>'+
      (STATE.composeContext==='reminder'?
        '<div class="card cp mb3">'+
          '<div class="fw6 mb2" style="font-size:13px">Reminder templates</div>'+
          '<div style="font-size:11.5px;color:var(--text3);margin-bottom:8px">Pick a template (fills from the lead), edit if needed, then Send. It goes through the email engine.</div>'+
          REMINDER_TEMPLATES.map(function(t,i){return '<button type="button" class="btn btn-outline btn-sm" style="margin:0 6px 6px 0" onclick="applyReminderTemplate('+i+')">'+escHtml(t.name)+'</button>';}).join('')+
        '</div>':'')+
      '<div class="card cp mb3">'+
        '<div class="fgrp"><label class="flbl">Subject</label><input class="inp" id="email-subj" value="'+htmlEsc(STATE.composeSubj)+'" oninput="STATE.composeSubj=this.value" placeholder="Email subject"/></div>'+
        '<div class="fgrp"><label class="flbl">Message</label><textarea class="txta w100" style="min-height:180px" id="email-body" oninput="STATE.composeBody=this.value" placeholder="Write your message here...">'+htmlEsc(STATE.composeBody)+'</textarea></div>'+
        '<div style="display:flex;justify-content:flex-end;margin-top:12px">'+
          '<button class="btn btn-primary" onclick="'+(STATE.composeContext==='reminder'?'sendReminderViaEngine()':'sendEmail()')+'" '+((hasRecipient&&composeEmails.length)?'':'disabled style="opacity:.5;cursor:not-allowed"')+'>'+ico('send',13)+' Send</button>'+
        '</div>'+
      '</div>'+
    '</div>';
  }



  // OOO reminder cards for dashboard
  var today=todayIST();
  var oooReminders=(STATE.reminders||[]).filter(function(r){
    return r.reminder_type==='ooo_return'&&r.status==='pending';
  }).sort(function(a,b){return a.return_date>b.return_date?1:-1;});
  var dueOOO=oooReminders.filter(function(r){return r.return_date<=today;});
  var upcomingOOO=oooReminders.filter(function(r){return r.return_date>today;});

  var oooCards='';
  if(dueOOO.length){
    oooCards+='<div style="margin-bottom:16px">';
    oooCards+=dueOOO.map(function(r){
      var cid=(r.contact&&r.contact.id)||null;
      return '<div style="background:var(--green-l);border:1.5px solid var(--green);border-radius:var(--r2);padding:12px 16px;margin-bottom:8px;display:flex;align-items:center;gap:12px">'+
        '<div style="font-size:20px">🟢</div>'+
        '<div style="flex:1">'+
          '<div style="font-weight:600;font-size:13px;color:var(--text)">'+htmlEsc(r.contact_name||'Contact')+' has returned from OOO</div>'+
          '<div style="font-size:12px;color:var(--text2);margin-top:2px">'+htmlEsc(r.company_name||'')+(r.return_date?' \u00b7 Returned '+htmlEsc(r.return_date):'')+'</div>'+
        '</div>'+
        (cid?'<button onclick="composeReminderEmail(\''+r.id+'\',\''+cid+'\')" style="background:var(--green);color:#fff;border:0;padding:6px 12px;border-radius:7px;font-size:12px;font-weight:600;cursor:pointer">Compose Email</button>':'')+
        '<button onclick="dismissReminder(\''+r.id+'\')" style="background:transparent;border:1px solid var(--green);color:var(--green);padding:6px 10px;border-radius:7px;font-size:12px;cursor:pointer">Dismiss</button>'+
      '</div>';
    }).join('')+'</div>';
  }
  if(upcomingOOO.length){
    oooCards+='<div style="background:var(--amber-l);border:1px solid var(--amber);border-radius:var(--r2);padding:10px 14px;margin-bottom:16px">'+
      '<div style="font-size:12px;font-weight:600;color:var(--amber);margin-bottom:6px">⏰ Upcoming OOO Returns ('+upcomingOOO.length+')</div>'+
      upcomingOOO.slice(0,3).map(function(r){
        return '<div style="font-size:12px;color:var(--text2);padding:3px 0;border-bottom:1px solid rgba(0,0,0,.05)">'+
          htmlEsc(r.contact_name||'')+(r.company_name?' \u00b7 '+htmlEsc(r.company_name):'')+'<span style="float:right;color:var(--amber);font-weight:600">'+htmlEsc(r.return_date)+'</span>'+
        '</div>';
      }).join('')+
    '</div>';
  }

  // BD today summary card
  var bdSummaryCard='';
  if((u.role==='bd'||u.role==='bd_lead')&&STATE.todaySummary&&STATE.todaySummary.total>0){
    bdSummaryCard=renderTodaySummaryCard(STATE.todaySummary);
  }

  return '<div class="page">'+
    (oooCards?'<div style="padding:0 24px;padding-top:16px">'+oooCards+'</div>':'')+
    (bdSummaryCard?'<div style="padding:0 24px;padding-top:16px">'+bdSummaryCard+'</div>':'')+
    '<div class="ph"><div class="ptitle">Email</div>'+
      '<div class="psub">'+(isBD?'Compose emails or manage your outreach plan':'Email')+' · '+u.name+'</div>'+
    '</div>'+
    progressBar+
    '<div style="display:flex;gap:0;border-bottom:1px solid var(--border);margin-bottom:18px;overflow-x:auto">'+tabBar+'</div>'+
    (STATE.emailTab==='pending'?pendingHtml:'')+
    (STATE.emailTab==='compose'?composeHtml:'')+
    (STATE.emailTab==='sent'?sentHtml:'')+
    (STATE.emailTab==='outreachplan'?tmplHtml:'')+
  '</div>';
}

// ── ADMIN ──────────────────────────────────────
function renderAdmin(){
  var u=STATE.user;
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
    return '<div onclick="STATE.adminSelectedUser=\''+usr.id+'\';loadUserEmails(\''+usr.id+'\');render()" style="display:flex;align-items:center;gap:14px;padding:12px 16px;border-bottom:1px solid var(--border);cursor:pointer">'+
      av(usr,'36')+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-weight:600;font-size:13.5px">'+htmlEsc(usr.name)+'</div>'+
        '<div style="font-size:11.5px;color:var(--text3)">'+htmlEsc(usr.email)+(usr.empId?' · '+htmlEsc(usr.empId):'')+'</div>'+
      '</div>'+
      (roleLabel(usr.role)?'<span style="font-size:11px;padding:2px 8px;background:var(--bg);border:1px solid var(--border);color:var(--text2);border-radius:8px">'+htmlEsc(roleLabel(usr.role))+'</span>':'')+
      (emailCount?'<span style="font-size:11px;padding:2px 8px;background:var(--accent-l);color:var(--accent);border-radius:8px">'+emailCount+' email'+(emailCount>1?'s':'')+'</span>':'')+
      (teamCount?'<span style="font-size:11px;padding:2px 8px;background:var(--green-l);color:var(--green);border-radius:8px">'+teamCount+' member'+(teamCount>1?'s':'')+'</span>':'')+
      '<span style="font-size:11px;padding:3px 9px;background:'+(usr.is_active!==false?'var(--green-l)':'var(--red-l)')+';color:'+(usr.is_active!==false?'var(--green)':'var(--red)')+';border-radius:8px;font-weight:600">'+(usr.is_active!==false?'Active':'Inactive')+'</span>'+
      '<div style="color:var(--text3);font-size:18px;margin-left:4px">›</div>'+
    '</div>';
  }).join('');

  var canSeeEngine=userHasAnyRole(u,'admin','ra_lead');
  var engineBtn='<button onclick="openEmailEngineModal()" style="display:flex;align-items:center;gap:7px;padding:7px 14px;background:var(--card);border:1px solid var(--border2);border-radius:8px;font-size:13px;color:var(--text2);cursor:pointer">'+
    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>'+
    'Email Engine Schedule'+
  '</button>';

  return '<div class="page">'+
    '<div class="ph"><div class="flex jb aic">'+
      '<div><div class="ptitle">Admin</div><div class="psub">'+allUsers.length+' users · Fute Global LLC</div></div>'+
      '<div style="display:flex;gap:8px;align-items:center">'+
        (canSeeEngine?engineBtn:'')+
        '<button class="btn btn-primary btn-sm" onclick="openAddUser()">'+ico('plus',13)+'Add user</button>'+
      '</div>'+
    '</div></div>'+
    '<div style="margin-bottom:14px">'+
      '<input class="inp" placeholder="Search by name, email, employee ID…" value="'+htmlEsc(STATE.adminSearch||'')+'" oninput="STATE.adminSearch=this.value;render()" style="max-width:360px">'+
    '</div>'+
    '<div style="display:flex;gap:2px;border-bottom:2px solid var(--border);margin-bottom:16px">'+tabBar+'</div>'+
    '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden">'+
      (rows||'<div style="padding:40px;text-align:center;color:var(--text3);font-size:13px">'+(q?'No users match "'+htmlEsc(q)+'"':'No users in this group yet.')+'</div>')+
    '</div>'+
  '</div>';
}

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
    var connBtn=e.platform==='Microsoft'&&!msConn?'<button onclick="connectMicrosoftUserEmail(\''+userId+'\',\''+e.id+'\')" style="font-size:10px;padding:2px 8px;background:#0078d4;color:#fff;border:0;border-radius:6px;cursor:pointer">Connect</button>':(e.platform==='Microsoft'&&msConn?'<span style="font-size:10px;color:var(--green)">✓ Connected</span>':'');
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

// ── REMINDERS ─────────────────────────────────
function renderReminders(){
  var u=STATE.user;
  var today=todayIST();
  // API returns user_id, return_date, reminder_time, contact_name, company_name
  var myReminders=(STATE.reminders||[]).filter(function(r){return r.user_id===u.id;});
  var due=myReminders.filter(function(r){return r.status==='pending'&&r.return_date<=today;});
  var upcoming=myReminders.filter(function(r){return r.status==='pending'&&r.return_date>today;});
  var sent=myReminders.filter(function(r){return r.status==='sent';});

  function daysUntil(d){return Math.ceil((new Date(d)-new Date(today))/86400000);}

  var dueCards=due.map(function(r){
    var contactId=(r.contact&&r.contact.id)||null;
    var isOOO=r.reminder_type==='ooo_return';
    return '<div style="border:2px solid var(--amber);border-radius:var(--r2);padding:14px 16px;margin-bottom:10px;background:var(--amber-l)">'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">'+
        '<div style="display:flex;align-items:center;gap:8px">'+
          '<div style="width:8px;height:8px;border-radius:50%;background:var(--amber)"></div>'+
          '<div style="font-weight:600;font-size:14px">'+htmlEsc(r.contact_name||'Reminder')+'</div>'+
          '<span style="font-size:11px;padding:2px 7px;background:var(--amber);color:#fff;border-radius:10px">'+(isOOO?'OOO Return':'Due today')+'</span>'+
        '</div>'+
        '<div style="display:flex;gap:8px">'+
          (contactId?'<button class="btn btn-sm" style="background:var(--amber);color:#fff" onclick="composeReminderEmail(\''+r.id+'\',\''+contactId+'\')">'+ico('send',13)+' Compose email</button>':'')+
          '<button class="btn btn-outline btn-sm" onclick="dismissReminder(\''+r.id+'\')">Dismiss</button>'+
        '</div>'+
      '</div>'+
      '<div style="font-size:12px;color:var(--text2)">'+htmlEsc(r.company_name||'')+(r.email?' · '+htmlEsc(r.email):'')+'</div>'+
      '<div style="font-size:12px;color:var(--text3);margin-top:3px">Return date: '+htmlEsc(r.return_date||'')+' · '+htmlEsc(r.reminder_time||'09:00')+' IST</div>'+
      (r.note?'<div style="font-size:12px;margin-top:6px;padding:6px 8px;background:rgba(0,0,0,.04);border-radius:var(--r)">'+htmlEsc(r.note)+'</div>':'')+
    '</div>';
  }).join('');

  var upcomingRows=upcoming.map(function(r){
    var days=daysUntil(r.return_date);
    var isOOO=r.reminder_type==='ooo_return';
    return '<tr>'+
      '<td><div style="font-weight:500;font-size:13px">'+htmlEsc(r.contact_name||'—')+'</div>'+
        '<div style="font-size:11px;color:var(--text3)">'+htmlEsc(r.company_name||'')+'</div></td>'+
      '<td style="font-size:12px;color:var(--text3)">'+htmlEsc(r.email||'—')+'</td>'+
      '<td>'+(isOOO?'<span style="font-size:11px;padding:2px 7px;background:var(--amber-l);color:var(--amber);border-radius:8px;font-weight:600">OOO Return</span>':'<span style="font-size:11px;padding:2px 7px;background:var(--accent-l);color:var(--accent);border-radius:8px">Follow-up</span>')+'</td>'+
      '<td><span style="font-size:11.5px;padding:2px 8px;background:'+(days<=3?'var(--red-l)':'var(--accent-l)')+';color:'+(days<=3?'var(--red)':'var(--accent)')+';border-radius:10px">'+days+' day'+(days!==1?'s':'')+'</span></td>'+
      '<td style="font-size:12px;color:var(--text3)">'+htmlEsc(r.return_date||'')+'</td>'+
      '<td style="font-size:12px;color:var(--text3)">'+htmlEsc(r.reminder_time||'09:00')+'</td>'+
      '<td style="font-size:12px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+htmlEsc(r.note||'')+'</td>'+
      '<td><button class="btn btn-outline btn-xs" onclick="dismissReminder(\''+r.id+'\')">Remove</button></td>'+
    '</tr>';
  }).join('');

  var sentRows=sent.slice(0,10).map(function(r){
    return '<tr>'+
      '<td style="font-size:12px">'+htmlEsc(r.contact_name||'—')+'</td>'+
      '<td style="font-size:12px;color:var(--text3)">'+htmlEsc(r.company_name||'')+'</td>'+
      '<td style="font-size:12px;color:var(--text3)">'+htmlEsc(r.return_date||'')+'</td>'+
      '<td><span style="font-size:11px;padding:2px 7px;background:var(--green-l);color:var(--green);border-radius:8px">Done</span></td>'+
    '</tr>';
  }).join('');

  return '<div class="page">'+
    '<div class="ph"><div class="ptitle">Reminders</div>'+
      '<div class="psub">Follow-up reminders · '+myReminders.filter(function(r){return r.status==="pending";}).length+' pending</div>'+
    '</div>'+

    (due.length?
      '<div style="background:var(--amber-l);border:1.5px solid var(--amber);border-radius:var(--r2);padding:12px 16px;margin-bottom:16px;display:flex;align-items:center;gap:10px">'+
        '<div style="font-size:20px">\u23f0</div>'+
        '<div style="flex:1"><div style="font-weight:600;font-size:14px">'+due.length+' reminder'+(due.length>1?'s':'')+' due today</div>'+
          '<div style="font-size:12px;color:var(--text3)">These contacts are expected back — send your follow-up now.</div></div>'+
      '</div>'
    :'')+
    dueCards+

    '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden;margin-bottom:18px">'+
      '<div style="padding:12px 16px;border-bottom:1px solid var(--border);font-weight:600;font-size:13px">Upcoming reminders ('+upcoming.length+')</div>'+
      (upcoming.length?
        '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">'+
          '<thead style="background:var(--bg);color:var(--text3);font-size:11px;text-transform:uppercase;letter-spacing:.5px">'+
            '<tr><th style="padding:10px 12px;text-align:left">Contact</th><th style="padding:10px 12px;text-align:left">Email</th><th style="padding:10px 12px;text-align:left">Type</th><th style="padding:10px 12px;text-align:left">In</th><th style="padding:10px 12px;text-align:left">Date</th><th style="padding:10px 12px;text-align:left">Time</th><th style="padding:10px 12px;text-align:left">Note</th><th style="padding:10px 12px"></th></tr>'+
          '</thead>'+
          '<tbody>'+upcomingRows+'</tbody>'+
        '</table></div>'
      :'<div style="padding:24px;text-align:center;color:var(--text3);font-size:13px">No upcoming reminders.</div>')+
    '</div>'+

    (sent.length?
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden">'+
        '<div style="padding:12px 16px;border-bottom:1px solid var(--border);font-weight:600;font-size:13px;color:var(--text3)">Recently dismissed ('+sent.length+')</div>'+
        '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:13px">'+
          '<thead style="background:var(--bg);color:var(--text3);font-size:11px;text-transform:uppercase">'+
            '<tr><th style="padding:10px 12px;text-align:left">Contact</th><th style="padding:10px 12px;text-align:left">Company</th><th style="padding:10px 12px;text-align:left">Date</th><th style="padding:10px 12px;text-align:left">Status</th></tr>'+
          '</thead>'+
          '<tbody>'+sentRows+'</tbody>'+
        '</table></div>'+
      '</div>'
    :'')+
  '</div>';
}

// ── MAIL MERGE MODAL ───────────────────────────
function renderMailMergeModal(){
  var mm=STATE.mailMerge;
  if(!mm||!mm.leads||!mm.leads.length)return"";
  var idx=mm.currentIdx||0;
  var l=mm.leads[idx];
  var co=STATE.companies.find(function(c){return c.id===l.coid})||{};
  var total=mm.leads.length;
  var sent=mm.sent||0;
  var skipped=mm.skipped||0;

  // Current email content — use edited version if available, else build from template
  var current=mm.emails[idx]||{};
  var subj=current.subj||fillEmail(STATE.emailSubj,l,co,STATE.user.name);
  var body=current.body||fillEmail(STATE.emailBody,l,co,STATE.user.name);
  if(!mm.emails[idx])mm.emails[idx]={subj:subj,body:body,sent:false};

  var plt=STATE.user.plt||"Gmail";
  var isSent=mm.emails[idx]&&mm.emails[idx].sent;

  return '<div class="modal" style="width:700px;max-width:98vw;max-height:92vh;display:flex;flex-direction:column">'+
    // Header
    '<div class="mh">'+
      '<div>'+
        '<div class="mt">Mail Merge</div>'+
        '<div style="font-size:12px;color:var(--text3);margin-top:2px">'+
          sent+' sent · '+(total-sent-skipped)+' remaining · '+skipped+' skipped'+
        '</div>'+
      '</div>'+
      '<button class="btn-icon" onclick="closeMailMerge()">'+ico("x",14)+'</button>'+
    '</div>'+

    // Progress bar
    '<div style="padding:0 20px;background:var(--card)">'+
      '<div style="height:3px;background:var(--border);border-radius:2px">'+
        '<div style="height:3px;background:var(--accent);border-radius:2px;width:'+(sent/total*100)+'%;transition:width .3s"></div>'+
      '</div>'+
      '<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0">'+
        // Prev arrow
        '<button onclick="mailMergeNav(-1)" '+(idx===0?'disabled style="opacity:.3"':'')+
          ' style="width:32px;height:32px;border-radius:50%;border:1.5px solid var(--border2);background:var(--card);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:18px">‹</button>'+
        // Lead info
        '<div style="text-align:center;flex:1;padding:0 14px">'+
          '<div style="font-weight:600;font-size:14px">'+htmlEsc(l.fn+' '+l.ln)+'</div>'+
          '<div style="font-size:12px;color:var(--text3)">'+htmlEsc(l.desig||"")+(co.name?' · '+htmlEsc(co.name):'')+'</div>'+
          '<div style="font-size:12px;color:var(--accent);margin-top:2px">'+htmlEsc(l.email||"No email")+'</div>'+
          '<div style="font-size:11px;color:var(--text3);margin-top:4px">'+
            (idx+1)+' of '+total+
            (isSent?' · <span style="color:var(--green);font-weight:500">✓ Sent</span>':'')+
          '</div>'+
        '</div>'+
        // Next arrow
        '<button onclick="mailMergeNav(1)" '+(idx>=total-1?'disabled style="opacity:.3"':'')+
          ' style="width:32px;height:32px;border-radius:50%;border:1.5px solid var(--border2);background:var(--card);cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:18px">›</button>'+
      '</div>'+
    '</div>'+

    // Email editor
    '<div class="mb_" style="flex:1;overflow-y:auto;padding:16px 20px">'+
      '<div class="fgrp">'+
        '<label class="flbl">To</label>'+
        '<input class="inp" value="'+htmlEsc((l.fn||"")+" "+(l.ln||"")+" <"+(l.email||"")+">")+'" readonly style="background:var(--bg);color:var(--text2)"/>'+
      '</div>'+
      '<div class="fgrp">'+
        '<label class="flbl">Subject</label>'+
        '<input class="inp" id="mm-subj" value="'+htmlEsc(subj)+'" oninput="mailMergeEdit(\'subj\',this.value)"/>'+
      '</div>'+
      '<div class="fgrp">'+
        '<label class="flbl">Body</label>'+
        '<textarea class="txta w100" style="min-height:180px;font-size:13px" id="mm-body" oninput="mailMergeEdit(\'body\',this.value)">'+htmlEsc(body)+'</textarea>'+
      '</div>'+
    '</div>'+

    // Footer
    '<div class="mf" style="justify-content:space-between">'+
      '<div class="flex gap2">'+
        '<button class="btn btn-outline btn-sm" onclick="mailMergeSkip()" '+(isSent?'disabled style="opacity:.4"':'')+'>Skip</button>'+
        '<div class="flex gap1">'+
          '<button class="fc'+(plt==="Gmail"?" on":"")+'" onclick="setPlatform(\'Gmail\')">Gmail</button>'+
          '<button class="fc'+(plt==="Outlook"?" on":"")+'" onclick="setPlatform(\'Outlook\')">Outlook</button>'+
        '</div>'+
      '</div>'+
      '<div class="flex gap2">'+
        (isSent?
          '<span style="font-size:13px;color:var(--green);font-weight:500">✓ Sent</span>':
          '<button class="btn btn-primary" onclick="mailMergeSend()" '+(l.email?'':'disabled style="opacity:.4" title="No email address"')+'>'+ico("send",13)+' Send this email</button>'
        )+
        (idx<total-1?
          '<button class="btn btn-outline" onclick="mailMergeNav(1)">Next →</button>':
          '<button class="btn btn-outline" style="color:var(--green);border-color:var(--green)" onclick="closeMailMerge()">✓ Done</button>'
        )+
      '</div>'+
    '</div>'+
  '</div>';
}
function renderSetReminderModal(leadId, manualEmail){
  var lead=leadId?STATE.leads.find(function(l){return l.id===leadId}):null;
  var co=lead?STATE.companies.find(function(c){return c.id===lead.coid})||{}:{};
  var future=new Date();future.setDate(future.getDate()+7);
  var futureStr=future.toISOString().split("T")[0];
  var displayName=lead?(lead.fn+" "+lead.ln):(manualEmail||"");
  var displaySub=lead?(lead.desig+(co.name?" · "+co.name:"")+" · "+lead.email):(manualEmail||"");

  return '<div class="modal modal-w480">'+
    '<div class="mh"><div class="mt">Set reminder</div><button class="btn-icon" onclick="closeModal()">'+ico("x",14)+'</button></div>'+
    '<div class="mb_">'+
      '<div style="padding:10px 12px;background:var(--accent-l);border-radius:var(--r2);margin-bottom:16px;border:1px solid rgba(37,99,235,.15)">'+
        '<div class="fw5 f13">'+htmlEsc(displayName)+'</div>'+
        '<div class="f12 text3">'+htmlEsc(displaySub)+'</div>'+
      '</div>'+
      '<div class="g2 mb3">'+
        '<div class="fgrp"><label class="flbl">Return / follow-up date</label><input class="inp" type="date" id="rem-date" value="'+futureStr+'"/></div>'+
        '<div class="fgrp"><label class="flbl">Reminder time (IST)</label><input class="inp" type="time" id="rem-time" value="09:00"/></div>'+
      '</div>'+
      '<div class="fgrp"><label class="flbl">Note (optional)</label><textarea class="txta" id="rem-note" style="min-height:60px" placeholder="e.g. They are back from holiday after 15th"></textarea></div>'+
    '</div>'+
    '<div class="mf">'+
      '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" onclick="saveReminder(\''+( leadId||"")+'\',' +(manualEmail?'\''+manualEmail+'\'':'null')+')">Set reminder</button>'+
    '</div>'+
  '</div>';
}

// ── PROFILE ──────────────────────────────────
function renderProfile(){
  var u=STATE.user;
  var pltOpts=["Gmail","Outlook"].map(function(p){
    var sel=u.plt===p;
    return '<div onclick="setProfilePlt(\''+p+'\')" style="display:flex;align-items:center;gap:11px;padding:12px 13px;border:2px solid '+(sel?"var(--accent)":"var(--border)")+';border-radius:var(--r2);cursor:pointer;margin-bottom:8px;background:'+(sel?"var(--accent-l)":"var(--card)")+';transition:all .12s">'+
      '<div style="width:22px;height:22px;border-radius:5px;background:'+(sel?"var(--accent)":"var(--bg)")+';display:flex;align-items:center;justify-content:center">'+ico("email",13)+'</div>'+
      '<div style="flex:1"><div style="font-weight:500;font-size:13.5px;color:'+(sel?"var(--accent)":"var(--text)")+'">'+p+'</div><div class="f12 text3">'+(p==="Gmail"?"Google Workspace":"Microsoft 365")+'</div></div>'+
      (sel?'<div style="width:16px;height:16px;background:var(--accent);border-radius:50%;display:flex;align-items:center;justify-content:center"><svg viewBox="0 0 10 10" width="9" height="9" fill="none" stroke="#fff" stroke-width="1.6"><polyline points="1.5,5 4,7.5 8.5,2.5"/></svg></div>':"")+
    '</div>';
  }).join("");

  return '<div class="page">'+
    '<div class="ph"><div class="ptitle">My Profile</div><div class="psub">Manage your account details</div></div>'+
    '<div class="g2">'+
      '<div>'+
        '<div class="card cp mb4">'+
          '<div class="flex aic gap4 mb4">'+av(u,"48")+
            '<div><div style="font-family:var(--display);font-weight:600;font-size:18px">'+u.name+'</div>'+
            '<div class="text3 f12 mt1">'+roleLabel(u.role)+' · '+u.empId+'</div>'+
            '<span class="bdg '+(u.role==="admin"?"bdg-purple":u.role==="bd"?"bdg-blue":"bdg-green")+' mt1">'+roleLabel(u.role)+'</span></div>'+
          '</div>'+
          '<div class="hr"></div>'+
          '<div class="g2 mb3"><div class="fgrp"><label class="flbl">Full name</label><input class="inp" id="p-name" value="'+htmlEsc(u.name)+'"/></div><div class="fgrp"><label class="flbl">Work email</label><input class="inp" id="p-email" value="'+htmlEsc(u.email)+'"/></div></div>'+
          '<div class="g2 mb3"><div class="fgrp"><label class="flbl">Employee ID</label><input class="inp" id="p-eid" value="'+htmlEsc(u.empId)+'"/></div><div class="fgrp"><label class="flbl">Designation</label><input class="inp" id="p-desig" value="'+htmlEsc(u.desig)+'"/></div></div>'+
          '<button class="btn btn-primary" onclick="saveProfile()">Save changes</button>'+
        '</div>'+
        '<div class="card cp">'+
          '<div class="fw6 mb1">Change password</div>'+
          '<div class="fgrp mt3"><label class="flbl">Current password</label><input class="inp" type="password" id="pw-cur" placeholder="••••••••"/></div>'+
          '<div class="fgrp"><label class="flbl">New password</label><input class="inp" type="password" id="pw-new" placeholder="••••••••"/></div>'+
          '<div class="fgrp"><label class="flbl">Confirm new password</label><input class="inp" type="password" id="pw-con" placeholder="••••••••"/></div>'+
          '<button class="btn btn-outline" onclick="changePassword()">Update password</button>'+
        '</div>'+
      '</div>'+
      '<div>'+
        '<div class="card cp">'+
          '<div class="fw6 mb1">Email platform</div>'+
          '<div class="f12 text3 mb3">Choose your outreach platform. Emails will open in this app when you click Send.</div>'+
          pltOpts+
          '<div style="margin-top:13px;padding:9px 11px;background:var(--bg);border-radius:var(--r);font-size:12px;color:var(--text3)">In production: clicking Connect will open OAuth authorization to send emails from your account.</div>'+
        '</div>'+
      '</div>'+
    '</div>'+
  '</div>';
}

// ── ADD LEAD MODAL ─────────────────────────────
function renderAddLeadModal(){
  var u=STATE.user;
  var bds=u.role==="ra"?STATE.users.filter(function(x){return x.id===u.bdm}):STATE.users.filter(function(x){return x.role==="bd"||x.role==="admin"});
  var ras=u.role==="ra"?[u]:STATE.users.filter(function(x){return x.role==="ra"&&(u.role==="admin"||x.bdm===u.id)});
  var cos=STATE.companies;
  var indOpts=(getIndustriesList().length?getIndustriesList():INDUSTRIES).map(function(i){return'<option>'+htmlEsc(i)+'</option>'}).join("");
  var srcOpts=SOURCES.map(function(s){return'<option>'+s+'</option>'}).join("");
  var raOpts=ras.map(function(r){return'<option value="'+r.id+'">'+r.name+'</option>'}).join("");
  var bdOpts=bds.map(function(b){return'<option value="'+b.id+'">'+b.name+'</option>'}).join("");
  var coOpts='<option value="">— Choose existing —</option>'+cos.map(function(c){return'<option value="'+c.id+'">'+c.name+'</option>'}).join("");
  return '<div class="modal modal-w860">'+
    '<div class="mh"><div class="mt">Add new lead</div><button class="btn-icon" onclick="closeModal()">'+ico("x",14)+'</button></div>'+
    '<div class="mb_">'+
      '<div style="padding:12px 14px;background:var(--bg);border-radius:var(--r2);margin-bottom:14px">'+
        '<div class="fw5 f13 mb2">Company</div>'+
        '<div class="flex gap2 mb3"><button class="fc on" id="co-new-btn" onclick="toggleCoMode(true)">New company</button><button class="fc" id="co-exist-btn" onclick="toggleCoMode(false)">Existing company</button></div>'+
        '<div id="co-new-fields">'+
          '<div class="g3"><div class="fgrp"><label class="flbl">Company name <span style="color:var(--red)">*</span></label><input class="inp" id="f-coname" placeholder="e.g. Acme Corp"/></div>'+
          '<div class="fgrp"><label class="flbl">Website</label><input class="inp" id="f-web" placeholder="acme.com"/></div>'+
          '<div class="fgrp"><label class="flbl">Industry</label><select class="sel" id="f-ind">'+indOpts+'</select></div>'+
          '<div class="fgrp"><label class="flbl">Location</label><input class="inp" id="f-loc" placeholder="City"/></div></div>'+
        '</div>'+
        '<div id="co-exist-fields" style="display:none"><div class="fgrp"><label class="flbl">Select company</label><select class="sel" id="f-coid">'+coOpts+'</select></div></div>'+
      '</div>'+
      '<div class="fw5 f13 mb3">Point of Contact</div>'+
      '<div class="g3 mb4">'+
        '<div class="fgrp"><label class="flbl">First name <span style="color:var(--red)">*</span></label><input class="inp" id="f-fn"/></div>'+
        '<div class="fgrp"><label class="flbl">Last name</label><input class="inp" id="f-ln"/></div>'+
        '<div class="fgrp"><label class="flbl">Designation</label><input class="inp" id="f-desig" placeholder="e.g. CTO"/></div>'+
        '<div class="fgrp span2"><label class="flbl">Email ID <span style="color:var(--red)">*</span></label><input class="inp" id="f-email" type="email"/></div>'+
        '<div class="fgrp"><label class="flbl">Phone</label><input class="inp" id="f-phone" type="tel"/></div>'+
        '<div class="fgrp span3"><label class="flbl">LinkedIn URL</label><input class="inp" id="f-li" placeholder="linkedin.com/in/..."/></div>'+
      '</div>'+
      '<div class="fw5 f13 mb3">Job opening</div>'+
      '<div class="g3 mb4">'+
        '<div class="fgrp span2"><label class="flbl">Position / Role <span style="color:var(--red)">*</span></label><input class="inp" id="f-pos" placeholder="e.g. VP of Engineering"/></div>'+
        '<div class="fgrp"><label class="flbl">Source</label><select class="sel" id="f-src">'+srcOpts+'</select></div>'+
      '</div>'+
      '<div class="g2">'+
        '<div class="fgrp"><label class="flbl">Research Analyst</label><select class="sel" id="f-ra"'+(u.role==="ra"?" disabled":"")+'>'+raOpts+'</select></div>'+
        '<div class="fgrp"><label class="flbl">BD Manager</label><select class="sel" id="f-bd"'+(u.role==="ra"?" disabled":"")+'>'+bdOpts+'</select></div>'+
      '</div>'+
    '</div>'+
    '<div class="mf"><button class="btn btn-outline" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="saveLead()">Save lead</button></div>'+
  '</div>';
}

// ── ADD/EDIT USER MODAL ────────────────────────
function renderUserModal(existing){
  var u=existing||{name:"",email:"",role:"ra",empId:"FG-0"+(STATE.users.length+1),desig:"",bdm:"",plt:"Gmail"};
  var bds=STATE.users.filter(function(x){return x.role==="bd"||x.role==="admin";});
  var bdOpts='<option value="">— Unassigned —</option>'+bds.map(function(b){return'<option value="'+b.id+'"'+(u.bdm===b.id?" selected":"")+'>'+b.name+'</option>';}).join("");
  // Only show BD assignment field if role is RA — use onchange to show/hide dynamically
  var isRA=u.role==="ra";
  return '<div class="modal modal-w480">'+
    '<div class="mh"><div class="mt">'+(existing?"Edit user":"Add new user")+'</div><button class="btn-icon" onclick="closeModal()">'+ico("x",14)+'</button></div>'+
    '<div class="mb_">'+
      '<div class="g2 mb3">'+
        '<div class="fgrp"><label class="flbl">Full name <span style="color:var(--red)">*</span></label><input class="inp" id="u-name" value="'+htmlEsc(u.name)+'"/></div>'+
        '<div class="fgrp"><label class="flbl">Work email <span style="color:var(--red)">*</span></label><input class="inp" id="u-email" type="email" value="'+htmlEsc(u.email)+'"/></div>'+
      '</div>'+
      '<div class="g2 mb3">'+
        '<div class="fgrp"><label class="flbl">Employee ID</label><input class="inp" id="u-eid" value="'+htmlEsc(u.empId)+'"/></div>'+
        '<div class="fgrp"><label class="flbl">Designation</label><input class="inp" id="u-desig" value="'+htmlEsc(u.desig)+'"/></div>'+
      '</div>'+
      '<div class="g2 mb3">'+
        '<div class="fgrp"><label class="flbl">Role</label>'+
          '<select class="sel" id="u-role" onchange="toggleBDAssign(this.value)">'+
            '<option value="ra"'+(u.role==="ra"?" selected":"")+'>Research Analyst</option>'+
            '<option value="ra_lead"'+(u.role==="ra_lead"?" selected":"")+'>RA Team Lead</option>'+
            '<option value="bd"'+(u.role==="bd"?" selected":"")+'>BD Manager</option>'+
            '<option value="bd_lead"'+(u.role==="bd_lead"?" selected":"")+'>BD Team Lead</option>'+
            '<option value="admin"'+(u.role==="admin"?" selected":"")+'>Admin</option>'+
            '<option value="recruiter"'+(u.role==="recruiter"?" selected":"")+'>Recruiter</option>'+
          '</select>'+
        '</div>'+
        '<div class="fgrp"><label class="flbl">Email platform</label><select class="sel" id="u-plt"><option'+(u.plt==="Gmail"?" selected":"")+'>Gmail</option><option'+(u.plt==="Outlook"?" selected":"")+'>Outlook</option></select></div>'+
      '</div>'+
      '<div class="fgrp" id="u-bd-wrap" style="'+(isRA?"":"display:none")+'">'+
        '<label class="flbl">Assigned BD Manager <span style="font-size:11px;color:var(--text3)">(only for Research Analysts)</span></label>'+
        '<select class="sel" id="u-bd">'+bdOpts+'</select>'+
      '</div>'+
    '</div>'+
    '<div class="mf"><button class="btn btn-outline" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="saveUser('+(existing?'\''+existing.id+'\'':null)+')">'+( existing?"Save changes":"Add user")+'</button></div>'+
  '</div>';
}

// ── TOASTS & MODAL ─────────────────────────────
function renderToasts(){
  var tc={success:"var(--green)",error:"var(--red)",info:"var(--accent)",warning:"var(--amber)"};
  return '<div class="toast-wrap">'+STATE.toasts.map(function(t){
    var c=tc[t.type]||tc.info;
    return'<div class="toast" style="border-left:3px solid '+c+'"><div style="width:7px;height:7px;border-radius:50%;background:'+c+';flex-shrink:0"></div>'+htmlEsc(t.msg)+'</div>';
  }).join("")+'</div>';
}
function renderModal(){
  if(STATE.modal&&STATE.modal.type==="jobDetail")return renderJobDetailModal();
  if(STATE.modal&&STATE.modal.type==="addJob")return renderAddJobModal();
  if(STATE.modal&&STATE.modal.type==="addContact")return renderAddContactModal();
  if(STATE.mailMerge&&!STATE.modal)return'<div class="overlay">'+renderMailMergeModal()+'</div>';
  if(!STATE.modal)return"";
  return'<div class="overlay" onclick="overlayClick(event)">'+STATE.modal+'</div>';
}

function normalizeIndustry(raw){
  if(!raw)return'Other';
  var r=raw.toLowerCase();
  if(r.indexOf('engineer')>-1||r.indexOf('manufactur')>-1||r.indexOf('construction')>-1||r.indexOf('civil')>-1||r.indexOf('mechanical')>-1||r.indexOf('oil')>-1||r.indexOf('gas')>-1||r.indexOf('aerospace')>-1||r.indexOf('aviation')>-1||r.indexOf('transportation')>-1||r.indexOf('logistics')>-1||r.indexOf('real estate')>-1||r.indexOf('architecture')>-1||r.indexOf('industrial')>-1||r.indexOf('defense')>-1||r.indexOf('machinery')>-1||r.indexOf('automation')>-1)return'Engineering';
  if(r.indexOf('health')>-1||r.indexOf('medical')>-1||r.indexOf('pharma')>-1||r.indexOf('hospital')>-1||r.indexOf('wellness')>-1||r.indexOf('fitness')>-1||r.indexOf('biotech')>-1||r.indexOf('dental')>-1||r.indexOf('clinical')>-1)return'Healthcare';
  if(r.indexOf('legal')>-1||r.indexOf('law')>-1||r.indexOf('attorney')>-1||r.indexOf('compliance')>-1||r.indexOf('litigation')>-1)return'Legal';
  if(r.indexOf('account')>-1||r.indexOf('financ')>-1||r.indexOf('audit')>-1||r.indexOf('tax')>-1||r.indexOf('bookkeep')>-1||r.indexOf('cpa')>-1)return'Accounting';
  if(r.indexOf('manag')>-1||r.indexOf('consult')>-1||r.indexOf('staffing')>-1||r.indexOf('recruit')>-1||r.indexOf('human resource')>-1||r.indexOf('executive')>-1||r.indexOf('strategy')>-1)return'Management';
  return'Other';
}
function htmlEsc(s){
  return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ════════════════════════════════════════════════
// BIND EVENTS
// ════════════════════════════════════════════════
function bindLogin(){
  var passEl=document.getElementById("login-pass");
  if(passEl)passEl.addEventListener("keydown",function(e){if(e.key==="Enter")doLogin();});
  // Init canvas only once per login page load
  if(!document.getElementById('login-canvas')||document.getElementById('login-canvas')._running)return;
  try{initLoginCanvas();}catch(e){}
}

function initLoginCanvas(){
  var c=document.getElementById("login-canvas");
  if(!c||c._running)return;
  c._running=true;
  var ctx=c.getContext("2d");
  var W,H,pts=[],streams=[];
  function resize(){W=c.width=window.innerWidth;H=c.height=window.innerHeight;}
  window.addEventListener("resize",resize);resize();
  for(var i=0;i<80;i++)pts.push({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.35,vy:(Math.random()-.5)*.35,r:Math.random()*2+1,a:Math.random()*Math.PI*2,green:Math.random()<.7});
  for(var s=0;s<12;s++)streams.push({x:Math.random()*W,y:Math.random()*H,angle:Math.random()*Math.PI*2,speed:.7+Math.random()*.5,len:60+Math.random()*80,t:Math.random()*100});
  function draw(){
    if(!document.getElementById('login-canvas')){return;} // stop if logged in
    ctx.fillStyle="rgba(232,245,238,0.2)";ctx.fillRect(0,0,W,H);
    for(var i=0;i<pts.length;i++){for(var j=i+1;j<pts.length;j++){var dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y,d=Math.sqrt(dx*dx+dy*dy);if(d<120){ctx.strokeStyle="rgba(30,122,60,"+((1-d/120)*.2)+")";ctx.lineWidth=.6;ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);ctx.stroke();}}}
    streams.forEach(function(s){s.t+=.018;var a=Math.sin(s.t)*.5+.5,ex=s.x+Math.cos(s.angle)*s.len,ey=s.y+Math.sin(s.angle)*s.len,g=ctx.createLinearGradient(s.x,s.y,ex,ey);g.addColorStop(0,"rgba(210,140,0,0)");g.addColorStop(.5,"rgba(210,140,0,"+(a*.6)+")");g.addColorStop(1,"rgba(210,140,0,0)");ctx.strokeStyle=g;ctx.lineWidth=1.5;ctx.beginPath();ctx.moveTo(s.x,s.y);ctx.lineTo(ex,ey);ctx.stroke();s.x+=Math.cos(s.angle)*s.speed;s.y+=Math.sin(s.angle)*s.speed;if(s.x<-100||s.x>W+100||s.y<-100||s.y>H+100){s.x=Math.random()*W;s.y=Math.random()*H;s.angle=Math.random()*Math.PI*2;}});
    pts.forEach(function(p){p.x+=p.vx;p.y+=p.vy;if(p.x<0||p.x>W)p.vx*=-1;if(p.y<0||p.y>H)p.vy*=-1;p.a+=.008;var pulse=.4+Math.sin(p.a)*.3;ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);ctx.fillStyle=p.green?"rgba(22,101,52,"+pulse+")":"rgba(180,110,0,"+(pulse*.85)+")";ctx.fill();});
    requestAnimationFrame(draw);
  }
  ctx.fillStyle="#e8f5ee";ctx.fillRect(0,0,W,H);
  draw();
}
function bindApp(){}

// ════════════════════════════════════════════════
// ACTIONS (global functions called from HTML)
// ════════════════════════════════════════════════
window.loginAs=function(id){STATE.user=STATE.users.find(function(u){return u.id===id});STATE.page="dashboard";render();}
window.doLogin=function(){
  var email=document.getElementById("login-email").value.trim();
  var u=STATE.users.find(function(x){return x.email.toLowerCase()===email.toLowerCase()});
  if(u){STATE.user=u;STATE.page="dashboard";render();}
  else{var e=document.getElementById("login-err");if(e){e.textContent="No account found. Use a @futeglobal.com email.";e.style.display="block";}}
}
window.signOut=function(){stopBackgroundPoll();stopProgressPoll();STATE.user=null;STATE.token=null;sessionStorage.removeItem('fg_token');sessionStorage.removeItem('fg_user');STATE.page='login';STATE.modal=null;render();}
window.goPage=function(p){if(p==='email'){STATE.composeContext=null;STATE.composeReminderId=null;}STATE.page=p;STATE.detailLead=null;STATE.modal=null;if(p!=="dashboard")STATE.viewingUser=null;if(p!=='bdleadinsights')STATE.bdLeadSelectedBD=null;if(p!=='bdinsights')STATE.bdInsightsData=null;if(p==='email')loadEmailsForCurrentUser();render();}
window.setPeriod=function(p){STATE.period=p;render();}
window.setSearch=function(v){STATE.leadsFilter.search=v;STATE.leadsPage=0;render();}
window.setFilt=function(k,v){STATE.leadsFilter[k]=v;STATE.leadsPage=0;render();}
window.toggleSel=function(id,v){STATE.leadsSelected[id]=v;render();}
window.toggleAll=function(v){
  var fl=filterLeads(getMyLeads(STATE.user));
  fl.forEach(function(l){STATE.leadsSelected[l.id]=v;});render();
}
window.clearSel=function(){STATE.leadsSelected={};render();}
window.applyBulk=function(){
  var sel=document.getElementById("bulk-stage");
  if(!sel||!sel.value)return;
  var stage=sel.value;
  Object.keys(STATE.leadsSelected).forEach(function(id){
    if(STATE.leadsSelected[id]){
      STATE.leads=STATE.leads.map(function(l){return l.id===id?Object.assign({},l,{stage:stage}):l;});
    }
  });
  STATE.leadsSelected={};
  showToast("Stage updated for selected leads","success");
}
window.changeStage=function(id,stage){
  STATE.leads=STATE.leads.map(function(l){return l.id===id?Object.assign({},l,{stage:stage}):l;});
  if(STATE.detailLead&&STATE.detailLead.id===id)STATE.detailLead=Object.assign({},STATE.detailLead,{stage:stage});
  STATE.activities.push({id:"a"+Date.now(),lid:id,uid:STATE.user.id,type:"stage",txt:'Stage → "'+stage+'"',dt:todayIST()});
  showToast('Stage → "'+stage+'"',"success");
}
window.changeStageDetail=function(stage){if(STATE.detailLead)changeStage(STATE.detailLead.id,stage);}
window.viewLead=function(id){
  STATE.detailLead=STATE.leads.find(function(l){return l.id===id});
  render();
}
window.closeDetail=function(){STATE.detailLead=null;render();}
window.deleteLead=function(id){
  STATE.leads=STATE.leads.map(function(l){return l.id===id?Object.assign({},l,{del:todayIST()}):l;});
  if(STATE.detailLead&&STATE.detailLead.id===id)STATE.detailLead=null;
  showToast("Lead moved to trash (deleted after 60 days)","info");
}
window.saveNotes=function(){
  var el=document.getElementById("dp-notes");
  if(el&&STATE.detailLead){
    var notes=el.value;
    STATE.leads=STATE.leads.map(function(l){return l.id===STATE.detailLead.id?Object.assign({},l,{notes:notes}):l;});
    STATE.detailLead=Object.assign({},STATE.detailLead,{notes:notes});
    showToast("Notes saved","success");
  }
}
window.addContactPrompt=function(){showToast("Add contact: coming in full version","info");}
window.openAddLead=function(){STATE.modal=renderAddLeadModal();render();}
window.closeModal=function(){STATE.modal=null;render();}
window.overlayClick=function(e){if(e.target.classList.contains("overlay"))closeModal();}

var coNewMode=true;
window.toggleCoMode=function(isNew){
  coNewMode=isNew;
  var nf=document.getElementById("co-new-fields");
  var ef=document.getElementById("co-exist-fields");
  var nb=document.getElementById("co-new-btn");
  var eb=document.getElementById("co-exist-btn");
  if(nf&&ef){nf.style.display=isNew?"":"none";ef.style.display=isNew?"none":"";}
  if(nb&&eb){nb.className="fc"+(isNew?" on":"");eb.className="fc"+(!isNew?" on":"");}
}

window.saveLead=function(){
  var fn=document.getElementById("f-fn");
  var email=document.getElementById("f-email");
  var pos=document.getElementById("f-pos");
  if(!fn||!fn.value||!email||!email.value||!pos||!pos.value){showToast("First name, email and position are required","warning");return;}
  var coid;
  if(coNewMode){
    var coname=document.getElementById("f-coname");
    if(!coname||!coname.value){showToast("Company name is required","warning");return;}
    var newco={id:"c"+Date.now(),name:coname.value,web:(document.getElementById("f-web")||{}).value||"",ind:(document.getElementById("f-ind")||{}).value||"Technology",loc:(document.getElementById("f-loc")||{}).value||""};
    STATE.companies.push(newco);
    coid=newco.id;
  } else {
    coid=(document.getElementById("f-coid")||{}).value||STATE.companies[0].id;
  }
  var aid=(document.getElementById("f-ra")||{}).value||STATE.user.id;
  var bid=(document.getElementById("f-bd")||{}).value||STATE.user.bdm;
  var newlead={id:"l"+Date.now(),coid:coid,pos:pos.value,fn:fn.value,ln:(document.getElementById("f-ln")||{}).value||"",desig:(document.getElementById("f-desig")||{}).value||"",email:email.value,phone:(document.getElementById("f-phone")||{}).value||"",li:(document.getElementById("f-li")||{}).value||"",src:(document.getElementById("f-src")||{}).value||"LinkedIn",aid:aid,bid:bid||"u1",stage:"Active",date:todayIST(),sent:null,plt:null,notes:"",del:null};
  STATE.leads.push(newlead);
  STATE.activities.push({id:"a"+Date.now(),lid:newlead.id,uid:STATE.user.id,type:"created",txt:"Lead created",dt:todayIST()});
  closeModal();
  showToast("Lead added successfully","success");
}

window.exportXL=function(){
  try{
    var filtered=filterLeads(getMyLeads(STATE.user));
    var rows=filtered.map(function(l){
      var co=STATE.companies.find(function(c){return c.id===l.coid})||{};
      return{Date:l.date,Company:co.name,Website:co.web,Position:l.pos,Location:co.loc,Industry:co.ind,FirstName:l.fn,LastName:l.ln,Designation:l.desig,Email:l.email,Phone:l.phone,LinkedIn:l.li,Source:l.src,Stage:l.stage,Analyst:uname(l.aid,STATE.users),BDManager:uname(l.bid,STATE.users)};
    });
    if(typeof XLSX!=="undefined"){
      var ws=XLSX.utils.json_to_sheet(rows);
      var wb=XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb,ws,"Leads");
      XLSX.writeFile(wb,"FuteGlobal_Leads_"+todayIST()+".xlsx");
      showToast("Excel exported","success");
    } else {
      // CSV fallback
      var h=Object.keys(rows[0]);
      var csv=[h.join(",")].concat(rows.map(function(r){return h.map(function(k){return'"'+(r[k]||"")+'"'}).join(",")})).join("\n");
      var a=document.createElement("a");a.href="data:text/csv;charset=utf-8,"+encodeURIComponent(csv);a.download="FuteGlobal_Leads.csv";a.click();
      showToast("CSV exported","success");
    }
  }catch(e){showToast("Export failed: "+e.message,"error");}
}

window.setEmailTab=function(t){STATE.emailTab=t;STATE.raLeadSelectedBD=null;STATE.genEmail=null;STATE.emailSearch=null;STATE.previewEmail=null;STATE.showEmailPreview=false;STATE.composeFromEmailId=null;STATE.pendingEmailPage=0;STATE.sentEmailPage=0;loadEmailsForCurrentUser();if(t==='pending'){loadPendingSummary();startPendingSummaryPoll();}else{stopPendingSummaryPoll();}render();}


function loadPendingSummary(){
  if(!STATE.user||!STATE.token||STATE.token==='guest')return;
  var q='';
  if(userHasRole(STATE.user,'ra_lead')&&STATE.raLeadSelectedBD)q='?manager_id='+encodeURIComponent(STATE.raLeadSelectedBD);
  apiGet('/emails/pending-summary'+q).then(function(d){STATE.pendingSummary=d;scheduleRender();}).catch(function(){});
}
function startPendingSummaryPoll(){
  if(STATE._pendingSummaryTimer){clearInterval(STATE._pendingSummaryTimer);STATE._pendingSummaryTimer=null;}
  if(!STATE.user||STATE.emailTab!=='pending')return;
  loadPendingSummary();
  STATE._pendingSummaryTimer=setInterval(function(){
    if(STATE.emailTab==='pending'&&STATE.user)loadPendingSummary();
    else if(STATE._pendingSummaryTimer){clearInterval(STATE._pendingSummaryTimer);STATE._pendingSummaryTimer=null;}
  },60000);
}
function stopPendingSummaryPoll(){
  if(STATE._pendingSummaryTimer){clearInterval(STATE._pendingSummaryTimer);STATE._pendingSummaryTimer=null;}
}
function renderPendingScheduleBanner(){
  var ps=STATE.pendingSummary;
  if(!ps||!ps.total_pending)return '';
  var ready=ps.ready_now||0;
  var wait=ps.waiting_window||0;
  var winLbl=ps.send_window_label||'8:00 – 16:00 lead local time';
  var tzRows=(ps.by_timezone||[]).filter(function(t){return t.waiting_window>0;}).map(function(t){
    return '<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border)">'+
      '<span><strong>'+htmlEsc(t.timezone)+'</strong> · '+t.waiting_window+' waiting</span>'+
      '<span style="color:var(--amber);font-weight:600">Resumes: '+htmlEsc(t.resumes_label)+'</span></div>';
  }).join('');
  var retryBtn='';
  if(wait>0&&!userHasRole(STATE.user,'ra_lead')){
    retryBtn='<button onclick="retryPendingWindowNow()" style="margin-top:10px;background:var(--accent);color:#fff;border:0;padding:8px 14px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer">Send in-window emails now</button>';
  }
  return '<div style="background:#fffbeb;border:1px solid #f59e0b;border-radius:var(--r2);padding:14px 18px;margin-bottom:14px">'+
    '<div style="font-weight:700;font-size:14px;color:#92400e;margin-bottom:8px">Pending send schedule (US lead timezones)</div>'+
    '<div style="font-size:13px;color:#78350f;line-height:1.5;margin-bottom:10px">'+
      '<strong>'+ps.total_pending+'</strong> pending total · '+
      '<span style="color:var(--green);font-weight:600">'+ready+' ready to send now</span>'+
      (wait?' · <span style="color:#b45309;font-weight:600">'+wait+' waiting for send window</span>':'')+
      '<br><span style="font-size:12px">Send window: '+htmlEsc(winLbl)+'.</span>'+
    '</div>'+
    (tzRows?'<div style="font-size:12px;margin-top:8px">'+tzRows+'</div>':'')+
    retryBtn+
  '</div>';
}
window.retryPendingWindowNow=function(){
  var body={};
  if(userHasRole(STATE.user,'ra_lead')&&STATE.raLeadSelectedBD)body.manager_id=STATE.raLeadSelectedBD;
  apiPost('/emails/retry-pending-window',body).then(function(){
    showToast('Retrying in-window pending emails…','success');
    startProgressPoll();
    loadPendingSummary();
  }).catch(function(e){showToast('Retry failed: '+e.message,'error');});
};


// ── Send progress polling ──────────────────────
// Auto-starts on login for BD/BD_Lead. No button click required.
// Polls every 2s when sending is active, every 10s when idle.
function startProgressPoll(){
  if(STATE._progressPollTimer)return;
  var _emailRefreshCount=0;
  function pollOnce(){
    if(!STATE.user||!STATE.token||STATE.token==='guest'){STATE._progressPollTimer=null;return;}
    apiGet('/emails/send-progress').then(function(d){
      var newProgress=(d&&(d.active||d.done))?d:null;
      // A new active run clears any prior dismissal so fresh results show.
      if(d&&d.active)STATE._progressDismissed=false;
      // Honor a manual dismissal of a completed run until a new run starts.
      if(STATE._progressDismissed&&newProgress&&newProgress.done&&!newProgress.active)newProgress=null;
      var hadProgress=!!STATE.sendProgress;
      STATE.sendProgress=newProgress;
      if(d&&d.active){
        scheduleRender();
        _emailRefreshCount++;
        if(_emailRefreshCount%3===0)loadEmailsForCurrentUser();
      }
      else if(!!newProgress!==hadProgress){scheduleRender();}
      if(d&&d.done&&!d.active){
        _emailRefreshCount=0;
        loadEmailsForCurrentUser();
        // Auto-dismiss only clean runs; keep failures up until the user reviews/dismisses them.
        if(!d.failed){setTimeout(function(){STATE.sendProgress=null;scheduleRender();},30000);}
      }
      var delay=(d&&d.active)?2000:10000;
      STATE._progressPollTimer=setTimeout(pollOnce,delay);
    }).catch(function(){
      STATE._progressPollTimer=setTimeout(pollOnce,30000);
    });
  }
  STATE._progressPollTimer=setTimeout(pollOnce,2000);
}
function stopProgressPoll(){
  if(STATE._progressPollTimer){clearTimeout(STATE._progressPollTimer);STATE._progressPollTimer=null;}
}
function loadEmailsForCurrentUser(){
  var u=STATE.user;
  if(!u)return;
  var isBD=userHasAnyRole(u,'bd','bd_lead','admin','ra_lead');
  if(isBD){
    if(userHasRole(u,'ra_lead')){
      // RA Lead needs all emails across all BD users (no status filter)
      apiGet('/emails').then(function(d){
        var all=d||[];
        STATE.pendingEmails=all.filter(function(e){return e.status==='pending';});
        STATE.allBDEmails=all;
        loadPendingSummary();
        scheduleRender();
      }).catch(function(){});
    } else {
      apiGet('/emails?status=pending').then(function(d){STATE.pendingEmails=d||[];loadPendingSummary();scheduleRender();}).catch(function(){});
      apiGet('/emails?status=sent').then(function(d){STATE.sentEmails=d||[];scheduleRender();}).catch(function(){});
    }
  }
}

// ── Manager Users functions ──────────────────────────────────
window.loadUserEmails=function(userId){
  apiGet('/users/'+userId+'/emails').then(function(d){
    STATE.userEmailsCache=STATE.userEmailsCache||{};
    STATE.userEmailsCache[userId]=d||[];
    render();
  }).catch(function(){});
};

window.toggleUserRole=function(userId,role,checked){
  var usr=STATE.users.find(function(x){return x.id===userId;});
  if(!usr)return;
  var roles=usr.roles?usr.roles.slice():[usr.role];
  if(checked&&roles.indexOf(role)===-1)roles.push(role);
  else if(!checked)roles=roles.filter(function(r){return r!==role;});
  if(!roles.length){showToast('User must have at least one role','warning');return;}
  apiPut('/users/'+userId+'/roles',{roles:roles}).then(function(u){
    STATE.users=STATE.users.map(function(x){return x.id===userId?normaliseUser(u):x;});
    showToast('Roles updated','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.openAddUserEmail=function(userId,platform){
  platform=platform||'Microsoft';
  var isMicrosoft=platform==='Microsoft';
  STATE._addEmailUserId=userId;
  STATE._addEmailPlatform=platform;
  STATE.modal='<div class="modal modal-w420">'
    +'<div class="mh"><div class="mt">Add '+platform+' Email</div><button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'
    +'<div class="mb_">'
    +'<div class="fgrp"><label class="flbl">Email address *</label><input class="inp" id="ue-email" placeholder="e.g. john@futeglobal.com"/></div>'
    +'<div class="fgrp"><label class="flbl">Display name</label><input class="inp" id="ue-name" placeholder="John Smith"/></div>'
    +'<div class="fgrp"><label class="flbl">Daily limit</label><input class="inp" type="number" id="ue-limit" value="300" min="1" max="500" style="width:120px"/></div>'
    +'<label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;padding:6px 0">'
    +'<input type="checkbox" id="ue-primary"/> Set as primary email (login email)</label>'
    +'</div>'
    +'<div class="mf"><button class="btn btn-outline" onclick="closeModal()">Cancel</button>'
    +(isMicrosoft
      ?'<button class="btn btn-primary" onclick="submitAddUserEmailMicrosoft(STATE._addEmailUserId)" style="background:#0078d4">Save &amp; Connect Microsoft</button>'
      :'<button class="btn btn-primary" onclick="submitAddUserEmail(STATE._addEmailUserId,STATE._addEmailPlatform)" style="background:#16a34a">Save Gmail</button>')
    +'</div></div>';
  render();
};

window.submitAddUserEmail=function(userId,platform){
  var email=(document.getElementById('ue-email')||{}).value||'';
  var name=(document.getElementById('ue-name')||{}).value||'';
  var limit=parseInt((document.getElementById('ue-limit')||{}).value||'300');
  var isPrimary=(document.getElementById('ue-primary')||{}).checked||false;
  if(!email){showToast('Email address required','warning');return;}
  apiPost('/users/'+userId+'/emails',{email_address:email,display_name:name||email,platform:platform||'Gmail',daily_send_limit:limit,is_primary:isPrimary}).then(function(e){
    STATE.userEmailsCache=STATE.userEmailsCache||{};
    STATE.userEmailsCache[userId]=(STATE.userEmailsCache[userId]||[]).concat([e]);
    closeModal();showToast('Email added','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.submitAddUserEmailMicrosoft=function(userId){
  var email=(document.getElementById('ue-email')||{}).value||'';
  var name=(document.getElementById('ue-name')||{}).value||'';
  var limit=parseInt((document.getElementById('ue-limit')||{}).value||'300');
  var isPrimary=(document.getElementById('ue-primary')||{}).checked||false;
  if(!email){showToast('Email address required','warning');return;}
  apiPost('/users/'+userId+'/emails',{email_address:email,display_name:name||email,platform:'Microsoft',daily_send_limit:limit,is_primary:isPrimary}).then(function(e){
    STATE.userEmailsCache=STATE.userEmailsCache||{};
    STATE.userEmailsCache[userId]=(STATE.userEmailsCache[userId]||[]).concat([e]);
    closeModal();render();
    // Open Microsoft OAuth popup
    var url=API_URL+'/auth/microsoft/connect?userEmailId='+e.id+'&token='+STATE.token;
    window.open(url,'ms_oauth','width=600,height=700,scrollbars=yes');
    showToast('Complete Microsoft login in the popup','info');
    window._msOAuthHandler=function(event){
      if(event.data&&event.data.type==='ms_oauth_success'){
        window.removeEventListener('message',window._msOAuthHandler);
        loadUserEmails(userId);
        showToast('Microsoft connected: '+event.data.email,'success');
      } else if(event.data&&event.data.type==='ms_oauth_error'){
        window.removeEventListener('message',window._msOAuthHandler);
        showToast('Connection failed: '+event.data.error,'error');
      }
    };
    window.addEventListener('message',window._msOAuthHandler);
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.connectMicrosoftUserEmail=function(userId,userEmailId){
  var url=API_URL+'/auth/microsoft/connect?userEmailId='+userEmailId+'&token='+STATE.token;
  window.open(url,'ms_oauth','width=600,height=700,scrollbars=yes');
  showToast('Complete Microsoft login in the popup','info');
  window._msOAuthHandler=function(event){
    if(event.data&&event.data.type==='ms_oauth_success'){
      window.removeEventListener('message',window._msOAuthHandler);
      loadUserEmails(userId);
      showToast('Connected: '+event.data.email,'success');
    } else if(event.data&&event.data.type==='ms_oauth_error'){
      window.removeEventListener('message',window._msOAuthHandler);
      showToast('Failed: '+event.data.error,'error');
    }
  };
  window.addEventListener('message',window._msOAuthHandler);
};

window.toggleUserEmailActive=function(userId,emailId,active){
  apiPatch('/users/'+userId+'/emails/'+emailId,{is_active:active}).then(function(e){
    STATE.userEmailsCache[userId]=(STATE.userEmailsCache[userId]||[]).map(function(x){return x.id===emailId?e:x;});
    showToast(active?'Activated':'Deactivated','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.setPrimaryEmail=function(userId,emailId){
  apiPatch('/users/'+userId+'/emails/'+emailId,{is_primary:true}).then(function(){
    loadUserEmails(userId);
    showToast('Primary email updated','success');
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.deleteUserEmail=function(userId,emailId){
  if(!confirm('Remove this email ID?'))return;
  apiDelete('/users/'+userId+'/emails/'+emailId).then(function(){
    STATE.userEmailsCache[userId]=(STATE.userEmailsCache[userId]||[]).filter(function(x){return x.id!==emailId;});
    showToast('Email removed','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.openAssignToBDLead=function(leadId){
  STATE._assignManagerId=leadId;
  STATE._assignType='bd_to_bdlead';
  var bdManagers=STATE.users.filter(function(x){return userHasRole(x,'bd');});
  var existing=(STATE.teamAssignments||[]).filter(function(a){return a.manager_id===leadId&&a.assignment_type==='bd_to_bdlead';}).map(function(a){return a.member_id;});
  var available=bdManagers.filter(function(x){return existing.indexOf(x.id)===-1;});
  if(!available.length){showToast('All BD Managers already assigned to this lead','info');return;}
  var opts=available.map(function(u){return '<option value="'+u.id+'">'+htmlEsc(u.name)+'</option>';}).join('');
  STATE.modal='<div class="modal modal-w400"><div class="mh"><div class="mt">Assign BD Manager</div><button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'
    +'<div class="mb_"><div class="fgrp"><label class="flbl">Select BD Manager</label><select class="sel" id="assign-member"><option value="">— select —</option>'+opts+'</select></div></div>'
    +'<div class="mf"><button class="btn btn-outline" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="submitAssignment(STATE._assignManagerId,STATE._assignType)">Assign</button></div></div>';
  render();
};

window.openAssignRAToManager=function(managerId){
  STATE._assignManagerId=managerId;
  STATE._assignType='ra_to_bd';
  var raUsers=STATE.users.filter(function(x){return userHasRole(x,'ra');});
  var existing=(STATE.teamAssignments||[]).filter(function(a){return a.manager_id===managerId&&a.assignment_type==='ra_to_bd';}).map(function(a){return a.member_id;});
  var available=raUsers.filter(function(x){return existing.indexOf(x.id)===-1;});
  if(!available.length){showToast('All RAs already assigned to this manager','info');return;}
  var opts=available.map(function(u){return '<option value="'+u.id+'">'+htmlEsc(u.name)+'</option>';}).join('');
  STATE.modal='<div class="modal modal-w400"><div class="mh"><div class="mt">Assign Research Analyst</div><button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'
    +'<div class="mb_"><div class="fgrp"><label class="flbl">Select RA</label><select class="sel" id="assign-member"><option value="">— select —</option>'+opts+'</select></div></div>'
    +'<div class="mf"><button class="btn btn-outline" onclick="closeModal()">Cancel</button><button class="btn btn-primary" onclick="submitAssignment(STATE._assignManagerId,STATE._assignType)">Assign</button></div></div>';
  render();
};

window.submitAssignment=function(managerId,type){
  managerId=managerId||STATE._assignManagerId;
  type=type||STATE._assignType;
  var memberId=(document.getElementById('assign-member')||{}).value||'';
  if(!memberId){showToast('Please select a user','warning');return;}
  apiPost('/team-assignments',{member_id:memberId,manager_id:managerId,assignment_type:type}).then(function(a){
    STATE.teamAssignments=(STATE.teamAssignments||[]).concat([a]);
    closeModal();showToast('Assigned','success');
    apiGet('/team-assignments').then(function(d){STATE.teamAssignments=d||[];render();});
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.removeAssignment=function(event,assignmentId){
  event.stopPropagation();
  if(!confirm('Remove this assignment?'))return;
  apiDelete('/team-assignments/'+assignmentId).then(function(){
    STATE.teamAssignments=(STATE.teamAssignments||[]).filter(function(a){return a.id!==assignmentId;});
    showToast('Removed','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.connectMicrosoftAccount=function(accountId){
  var url=API_URL+'/auth/microsoft/connect?accountId='+accountId;
  var popup=window.open(url,'ms_oauth','width=600,height=700,scrollbars=yes');
  showToast('Complete Microsoft login in the popup window','info');
  window._msOAuthHandler=function(event){
    if(event.data&&event.data.type==='ms_oauth_success'){
      window.removeEventListener('message',window._msOAuthHandler);
      STATE.emailAccounts=STATE.emailAccounts.map(function(x){
        return x.id===event.data.accountId?Object.assign({},x,{platform:'Microsoft',ms_connected:true}):x;
      });
      showToast('Microsoft connected: '+event.data.email,'success');
      render();
    } else if(event.data&&event.data.type==='ms_oauth_error'){
      window.removeEventListener('message',window._msOAuthHandler);
      showToast('Connection failed: '+event.data.error,'error');
    }
  };
  window.addEventListener('message',window._msOAuthHandler);
};

window.selectPlanFromEmail=function(emailId){
  if(!emailId||!STATE.user)return;
  STATE.planFromEmailId=emailId;
  STATE.sigEmailId=emailId;
  loadMailboxSignature(STATE.user.id,emailId);
  render();
};
window.selectComposeFromEmail=function(emailId){
  if(!emailId||!STATE.user)return;
  STATE.composeFromEmailId=emailId;
  loadMailboxSignature(STATE.user.id,emailId);
  render();
};
window.applyOutreachStylePreset=function(presetKey){
  var preset=OUTREACH_STYLE_PRESETS[presetKey];
  if(!preset)return;
  STATE.outreachStylePreset=presetKey;
  STATE.randomTemplateMode=false;
  STATE.emailSubj=preset.o1.subj;STATE.emailBody=preset.o1.body;
  STATE.fu1Subj=preset.fu1.subj;STATE.fu1Body=preset.fu1.body;
  STATE.fu2Subj=preset.fu2.subj;STATE.fu2Body=preset.fu2.body;
  STATE.myOutreachPlan=STATE.myOutreachPlan||{};
  STATE.myOutreachPlan['tmpl_o1_subject']=preset.o1.subj;STATE.myOutreachPlan['tmpl_o1_body']=preset.o1.body;
  STATE.myOutreachPlan['tmpl_fu1_subject']=preset.fu1.subj;STATE.myOutreachPlan['tmpl_fu1_body']=preset.fu1.body;
  STATE.myOutreachPlan['tmpl_fu2_subject']=preset.fu2.subj;STATE.myOutreachPlan['tmpl_fu2_body']=preset.fu2.body;
  STATE.myOutreachPlan['compose_style_preset']=presetKey;
  if(userHasAnyRole(STATE.user,'bd','bd_lead','admin')){
    apiPost('/outreach-plan',{key:'compose_style_preset',value:presetKey}).catch(function(){});
  }
  showToast('Applied "'+preset.label+'" style to outreach + both follow-ups — review each tab and Save','success');
  render();
};
function persistOutreachTemplateMode(){
  var userId=STATE.user&&STATE.user.id;
  if(!userId)return;
  try{localStorage.setItem('fute_outreach_tmpl_mode_'+userId,JSON.stringify({random:STATE.randomTemplateMode}));}catch(e){}
}
window.setTemplateModeSpecific=function(){
  STATE.randomTemplateMode=false;
  persistOutreachTemplateMode();
  if(userHasAnyRole(STATE.user,'bd','bd_lead','admin'))apiPost('/outreach-plan',{key:'random_template_mode',value:'false'}).catch(function(){});
  render();
};
window.setTemplateModeRandom=function(){
  STATE.randomTemplateMode=true;
  persistOutreachTemplateMode();
  if(userHasAnyRole(STATE.user,'bd','bd_lead','admin'))apiPost('/outreach-plan',{key:'random_template_mode',value:'true'}).catch(function(){});
  render();
};
window.saveTemplateModePreference=function(){
  persistOutreachTemplateMode();
  if(userHasAnyRole(STATE.user,'bd','bd_lead','admin')){
    apiPost('/outreach-plan',{key:'random_template_mode',value:STATE.randomTemplateMode?'true':'false'})
      .then(function(){showToast('Outreach template mode saved','success');})
      .catch(function(){showToast('Save failed','error');});
  } else {
    showToast('Outreach template mode saved','success');
  }
};
window.setVarInsertTarget=function(target){
  STATE.varInsertTarget=target||'body';
  render();
};
window.insertVarChip=function(token,subjId,bodyId){
  if(!token)return;
  var targetId=(STATE.varInsertTarget==='subject')?subjId:bodyId;
  var where=(STATE.varInsertTarget==='subject')?'subject line':'email body';
  insertVarFromPicker(token,targetId);
  showToast('Added '+mergeVarFriendlyLabel(token)+' to '+where,'success');
};
window.saveOutreachTemplate=function(key,subjId,bodyId){
  var subj=(document.getElementById(subjId)||{}).value||'';
  var body=(document.getElementById(bodyId)||{}).value||'';
  var apiKey=outreachTmplApiKey(key);
  if(key==='outreach'){STATE.emailSubj=subj;STATE.emailBody=body;}
  else if(key==='fu1'){STATE.fu1Subj=subj;STATE.fu1Body=body;}
  else if(key==='fu2'){STATE.fu2Subj=subj;STATE.fu2Body=body;}
  STATE.myOutreachPlan=STATE.myOutreachPlan||{};
  STATE.myOutreachPlan['tmpl_'+apiKey+'_subject']=subj;
  STATE.myOutreachPlan['tmpl_'+apiKey+'_body']=body;
  Promise.all([
    apiPost('/outreach-plan',{key:'tmpl_'+apiKey+'_subject',value:subj}),
    apiPost('/outreach-plan',{key:'tmpl_'+apiKey+'_body',value:body})
  ]).then(function(){showToast('Template saved','success');}).catch(function(e){showToast('Save failed: '+e.message,'error');});
};

window.saveOutreachDay=function(key,val){
  if(!val)return;
  var day=parseInt(val,10);
  STATE.myOutreachPlan=STATE.myOutreachPlan||{};
  STATE.myOutreachPlan[key]=String(day);
  apiPost('/outreach-plan',{key:key,value:String(day)}).then(function(){
    showToast('Schedule saved — '+key.replace('_day','').toUpperCase()+' set to Day '+day,'success');
    render();
  }).catch(function(e){showToast('Save failed: '+e.message,'error');});
};

window.saveEmailTemplate=function(key,subjId,bodyId){
  var subj=(document.getElementById(subjId)||{}).value||'';
  var body=(document.getElementById(bodyId)||{}).value||'';
  if(key==='outreach'){STATE.emailSubj=subj;STATE.emailBody=body;}
  else if(key==='fu1'){STATE.fu1Subj=subj;STATE.fu1Body=body;}
  else if(key==='fu2'){STATE.fu2Subj=subj;STATE.fu2Body=body;}
  var saves=[
    apiPost('/app-settings',{key:'template_'+key+'_subject',value:subj}),
    apiPost('/app-settings',{key:'template_'+key+'_body',value:body})
  ];
  Promise.all(saves).then(function(){showToast('Template saved','success');}).catch(function(e){showToast('Save failed: '+e.message,'error');});
};

window.openEmailEngineModal=function(){
  var outreachTime=(STATE.appSettings&&STATE.appSettings['outreach_send_time'])||'08:00';
  var followupTime=(STATE.appSettings&&STATE.appSettings['followup_send_time'])||'08:30';
  var tzOpts=[
    {val:'Asia/Kolkata',label:'IST — India (UTC+5:30)'},
    {val:'America/New_York',label:'EST — New York (UTC-5)'},
    {val:'America/Chicago',label:'CST — Chicago (UTC-6)'},
    {val:'America/Denver',label:'MST — Denver (UTC-7)'},
    {val:'America/Los_Angeles',label:'PST — Los Angeles (UTC-8)'}
  ].map(function(tz){
    var sel=tz.val==='Asia/Kolkata';
    return '<option value="'+tz.val+'"'+(sel?' selected':'')+'>'+tz.label+'</option>';
  }).join('');
  STATE.modal='<div class="modal modal-w480">'+
    '<div class="mh"><div class="mt">Email Engine Schedule</div><button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'+
    '<div class="mb_">'+
      '<div style="font-size:13px;color:var(--text2);margin-bottom:18px">Set the daily send times for outreach and follow-up emails. The engine runs automatically at these times every day.</div>'+
      '<div class="fgrp"><label class="flbl">Timezone</label><select class="sel" id="engine-tz">'+tzOpts+'</select></div>'+
      '<div class="g2">'+
        '<div class="fgrp"><label class="flbl">Outreach send time</label><input class="inp" type="time" id="admin-outreach-time" value="'+outreachTime+'"/></div>'+
        '<div class="fgrp"><label class="flbl">Follow-up send time</label><input class="inp" type="time" id="admin-followup-time" value="'+followupTime+'"/></div>'+
      '</div>'+
      '<div style="padding:10px 12px;background:var(--amber-l);border-radius:var(--r);font-size:12px;color:var(--amber);margin-top:4px">'+
        '<strong>Testing:</strong> Use "Run now" to trigger the follow-up engine immediately without waiting for the scheduled time.'+
      '</div>'+
    '</div>'+
    '<div class="mf">'+
      '<button class="btn btn-outline btn-sm" onclick="runFollowupEngineNow()" style="color:var(--amber);border-color:var(--amber);margin-right:auto">▶ Run now</button>'+
      '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" onclick="saveAdminSendTimes()">Save schedule</button>'+
    '</div>'+
  '</div>';
  render();
};

window.saveAdminSendTimes=function(){
  var ot=(document.getElementById('admin-outreach-time')||{}).value||'08:00';
  var ft=(document.getElementById('admin-followup-time')||{}).value||'08:30';
  var saves=[
    apiPost('/app-settings',{key:'outreach_send_time',value:ot}),
    apiPost('/app-settings',{key:'followup_send_time',value:ft})
  ];
  Promise.all(saves).then(function(){
    STATE.appSettings=STATE.appSettings||{};
    STATE.appSettings['outreach_send_time']=ot;
    STATE.appSettings['followup_send_time']=ft;
    closeModal();
    showToast('Send times saved','success');
  }).catch(function(e){showToast('Save failed: '+e.message,'error');});
};

window.generatePendingEmails=function(){
  // Get all assigned job IDs
  var assignedJobs=STATE.jobs.filter(function(j){return j.stage==='Assigned';});
  if(!assignedJobs.length){showToast('No assigned leads found','warning');return;}
  var jobIds=assignedJobs.map(function(j){return j.id;});
  showToast('Generating emails for '+jobIds.length+' leads...','info');
  apiPost('/emails/generate',{job_ids:jobIds}).then(function(r){
    showToast(r.generated+' emails generated','success');
    apiGet('/emails?status=pending').then(function(d){
      STATE.pendingEmails=d||[];render();
    });
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.runFollowupEngineNow=function(){
  showToast('Running follow-up engine...','info');
  apiPost('/follow-ups/run',{}).then(function(r){
    showToast('Done — FU1: '+r.fu1_queued+', FU2: '+r.fu2_queued+', Skipped quota: '+r.skipped_quota,'success');
    apiGet('/emails?status=pending').then(function(d){STATE.pendingEmails=d||[];render();});
  }).catch(function(e){showToast('Error: '+e.message,'error');});
};
window.previewEmail=function(id){
  var e=STATE.emails.find(function(x){return x.id===id;});
  STATE.previewEmail=e||null;
  render();
};
window.setMergeLead=function(id){STATE.mergeLeadId=id;STATE.genEmail=null;render();}
window.setPlatform=function(p){STATE.user.plt=p;render();}

window.openEmailPreviewModal=function(){
  // Build genEmail if not already set (fill template variables from selected lead)
  if(!STATE.genEmail){
    // Use loose equality (==) so UUID strings match even if stored as different types
    var ml=null;
    if(STATE.mergeLeadId){
      ml=STATE.leads.find(function(l){return l.id==STATE.mergeLeadId;});
      if(!ml){console.warn('[preview] mergeLeadId not found in STATE.leads:',STATE.mergeLeadId);}
    }
    if(ml){
      // Prefer flat company fields from normaliseLead; fall back to STATE.companies lookup; final fallback to nested l.company
      var co={
        name:ml.coName||(STATE.companies.find(function(c){return c.id==ml.coid;})||{}).name||(ml.company&&ml.company.name)||'',
        ind:ml.coInd||(STATE.companies.find(function(c){return c.id==ml.coid;})||{}).ind||(ml.company&&ml.company.industry)||'',
        loc:ml.coLoc||(STATE.companies.find(function(c){return c.id==ml.coid;})||{}).loc||(ml.company&&ml.company.location)||''
      };
      STATE.genEmail={to:(ml.fn||'')+' '+(ml.ln||''),email:ml.email,subj:fillEmail(STATE.emailSubj,ml,co,STATE.user.name),body:fillEmail(STATE.emailBody,ml,co,STATE.user.name),lid:ml.id};
    } else if(STATE.manualEmail){
      STATE.genEmail={to:STATE.manualEmail,email:STATE.manualEmail,subj:STATE.emailSubj.replace(/{{[\w]+}}/g,''),body:STATE.emailBody.replace(/{{[\w]+}}/g,''),lid:null};
    } else {
      showToast('Select a recipient first','warning');return;
    }
  }
  var ge=STATE.genEmail;
  STATE.modal='<div class="modal modal-w640">'+
    '<div class="mh">'+
      '<div class="mt">Email Preview</div>'+
      '<button class="btn-icon" onclick="closeModal()">'+ico("x",14)+'</button>'+
    '</div>'+
    '<div class="mb_" style="padding:0">'+
      '<div style="padding:12px 20px;background:var(--accent-l);border-bottom:1px solid rgba(37,99,235,.15)">'+
        '<div class="f12 text3"><strong style="color:var(--text)">To:</strong> '+htmlEsc(ge.to)+' &lt;'+htmlEsc(ge.email)+'&gt;</div>'+
        '<div class="f12 text3 mt1"><strong style="color:var(--text)">Subject:</strong> '+htmlEsc(ge.subj)+'</div>'+
      '</div>'+
      '<div style="padding:18px 20px;font-size:13.5px;line-height:1.8;white-space:pre-wrap;max-height:60vh;overflow-y:auto">'+htmlEsc(ge.body)+'</div>'+
    '</div>'+
    '<div class="mf">'+
      '<button class="btn btn-outline" onclick="closeModal()">Close</button>'+
      '<button class="btn btn-primary" onclick="closeModal();sendEmail()">'+ico("send",13)+' Send this email</button>'+
    '</div>'+
  '</div>';
  render();
};

window.appendPrompt=function(text){
  STATE.aiPrompt=(STATE.aiPrompt||STATE.aiPromptDefault)+"\n"+text;
  var el=document.getElementById("ai-prompt-inp");
  if(el)el.value=STATE.aiPrompt;
}
window.resetAIPrompt=function(){
  STATE.aiPrompt=STATE.aiPromptDefault;
  var el=document.getElementById("ai-prompt-inp");
  if(el)el.value=STATE.aiPromptDefault;
  showToast("Prompt reset to default","info");
}

window.emailSearchInput=function(v){
  STATE.emailSearch=v;
  if(v){STATE.mergeLeadId=null;STATE.manualEmail=null;STATE.manualEmailName=null;STATE.genEmail=null;}
  render();
  setTimeout(function(){var el=document.getElementById("email-search-inp");if(el){el.focus();el.setSelectionRange(v.length,v.length);}},0);
}
window.selectEmailRecipient=function(lid){
  STATE.mergeLeadId=lid;STATE.manualEmail=null;STATE.manualEmailName=null;
  STATE.emailSearch=null;STATE.genEmail=null;render();
}
window.useManualEmail=function(){
  var email=STATE.emailSearch||"";
  if(!email.includes("@")){showToast("Please enter a valid email address","warning");return;}
  STATE.manualEmail=email;STATE.manualEmailName=email;
  STATE.mergeLeadId=null;STATE.emailSearch=null;STATE.genEmail=null;render();
}

window.generateAI=function(){
  var customInstructions=STATE.aiPrompt||STATE.aiPromptDefault;
  // resolve recipient from composeContactId
  if(STATE.composeContactId&&!STATE.mergeLeadId){
    var parts=STATE.composeContactId.split('|');
    var cc=STATE.contacts.find(function(c){return c.id===parts[0];});
    var cj=STATE.jobs.find(function(j){return j.id===parts[1];});
    if(cc&&cj){
      STATE.mergeLeadId=null;
      STATE.manualEmail=cc.email;
      STATE.manualEmailName=(cc.first_name||'')+' '+(cc.last_name||'');
      // pass contact+company into AI call directly
      STATE.aiGenerating=true;render();
      apiPost('/ai/generate-email',{
        contact:{first_name:cc.first_name,last_name:cc.last_name,designation:cc.designation,position:cj.position},
        company:{name:cj.company_name,industry:cj.company_ind,location:cj.location},
        position:cj.position
      }).then(function(d){
        STATE.genEmail={to:(cc.first_name||'')+' '+(cc.last_name||''),email:cc.email,subj:d.subject,body:d.body,lid:null};
        STATE.aiGenerating=false;render();
      }).catch(function(e){STATE.aiGenerating=false;showToast('AI error: '+e.message,'error');render();});
      return;
    }
  }
  var promptEl=document.getElementById("ai-prompt-inp");
  if(promptEl&&promptEl.value)customInstructions=promptEl.value;

  // Handle manual email — no AI needed
  if(STATE.manualEmail&&!STATE.mergeLeadId){
    var subj=STATE.emailSubj.replace(/{{[\w]+}}/g,"");
    var body=STATE.emailBody.replace(/{{fn}}/g,"").replace(/{{[\w]+}}/g,"");
    STATE.genEmail={to:STATE.manualEmailName||STATE.manualEmail,email:STATE.manualEmail,subj:subj,body:body,lid:null};
    render();return;
  }
  if(!STATE.mergeLeadId){showToast("Select a recipient first","warning");return;}
  var ml=STATE.leads.find(function(l){return l.id==STATE.mergeLeadId;});
  if(!ml){showToast("Selected lead not found","error");return;}
  var co=STATE.companies.find(function(c){return c.id==ml.coid;})||{name:ml.coName,ind:ml.coInd,loc:ml.coLoc};

  // Show spinner — render() preserves scroll
  STATE.aiGenerating=true;render();

  // Helper: build a fallback genEmail from template (no AI)
  function fallbackToTemplate(){
    STATE.genEmail={to:ml.fn+" "+ml.ln,email:ml.email,subj:fillEmail(STATE.emailSubj,ml,co,STATE.user.name),body:fillEmail(STATE.emailBody,ml,co,STATE.user.name),lid:ml.id};
    STATE.aiGenerating=false;render();
  }

  // If running in LIVE (API layer present), call backend proxy. Otherwise fall back to local template fill.
  if(typeof apiPost==="function"){
    apiPost("/ai/generate-email",{
      lead:{first_name:ml.fn,last_name:ml.ln,position:ml.pos,designation:ml.desig,email:ml.email},
      company:{name:co.name,industry:co.ind,location:co.loc},
      template:{subject:STATE.emailSubj,body:STATE.emailBody},
      instructions:customInstructions
    }).then(function(data){
      var subj=data.subject||fillEmail(STATE.emailSubj,ml,co,STATE.user.name);
      var body=data.body||fillEmail(STATE.emailBody,ml,co,STATE.user.name);
      STATE.genEmail={to:ml.fn+" "+ml.ln,email:ml.email,subj:subj,body:body,lid:ml.id};
      STATE.aiGenerating=false;render();
      showToast("Email generated","success");
    }).catch(function(err){
      console.error("[generateAI] backend call failed:",err);
      showToast("AI generation failed — used template instead","warning");
      fallbackToTemplate();
    });
  } else {
    // Standalone offline mode — just use template fill
    fallbackToTemplate();
  }
};

function resolveComposeRecipient(){
  if(STATE.composeContactId){
    var parts=STATE.composeContactId.split('|');
    var cc=STATE.contacts.find(function(c){return c.id===parts[0];});
    var cj=STATE.jobs.find(function(j){return j.id===parts[1];});
    if(cc&&cc.email){
      return{
        to:((cc.first_name||'')+' '+(cc.last_name||'')).trim(),
        email:cc.email,
        lid:parts[1]||null,
        lead:{fn:cc.first_name||'',ln:cc.last_name||'',email:cc.email,desig:cc.designation||'',pos:(cj&&cj.position)||''},
        co:{name:(cj&&cj.company_name)||'',ind:(cj&&cj.industry)||'',loc:(cj&&cj.location)||''}
      };
    }
  }
  if(STATE.manualEmail&&STATE.manualEmail.includes('@')){
    return{to:STATE.manualEmail,email:STATE.manualEmail,lid:null,lead:null,co:null};
  }
  return null;
}
window.sendEmail=function(){
  if(STATE.user&&STATE.user.isGuest){guestSimulate('sendEmail',{to:(STATE.genEmail&&STATE.genEmail.email)||'contact'});return;}
  var ge=STATE.genEmail;
  if(!ge){
    var recip=resolveComposeRecipient();
    if(!recip){showToast('Select a contact or enter an email address','warning');return;}
    var subjEl=document.getElementById('email-subj');
    var bodyEl=document.getElementById('email-body');
    var subj=(subjEl&&subjEl.value)||STATE.composeSubj||'';
    var body=(bodyEl&&bodyEl.value)||STATE.composeBody||'';
    if(!subj.trim()){showToast('Add a subject line','warning');return;}
    if(!body.trim()){showToast('Write a message','warning');return;}
    var fromEmForName=STATE.composeFromEmailId?(STATE.userEmailsCache[STATE.user.id]||[]).find(function(e){return e.id===STATE.composeFromEmailId;}):null;
    var senderName=(fromEmForName&&fromEmForName.display_name)||STATE.user.name||'';
    if(recip.lead){
      subj=fillEmail(subj,recip.lead,recip.co,senderName);
      body=fillEmail(body,recip.lead,recip.co,senderName);
    }
    ge={to:recip.to,email:recip.email,subj:subj,body:body,lid:recip.lid};
  }
  // Attach from email if selected
  var fromEmail=null;
  var fromEmailAddress=null;
  if(STATE.composeFromEmailId){
    var fromEm=(STATE.userEmailsCache[STATE.user.id]||[]).find(function(e){return e.id===STATE.composeFromEmailId;});
    if(fromEm){fromEmail=fromEm.email_address;fromEmailAddress=fromEm.email_address;}
  }
  var plt=STATE.user.plt||"Gmail";
  var gmailFrom=fromEmail||STATE.user.email||'';
  // Build body for sending — HTML with signature for Outlook, plain text for Gmail deeplink
  var sigEmailId=STATE.composeFromEmailId||STATE.sigEmailId;
  var sigHtml=normalizeMailboxSignature((sigEmailId&&STATE.emailSignaturesCache&&STATE.emailSignaturesCache[sigEmailId])||'');
  var fromEmForSig=sigEmailId?(STATE.userEmailsCache[STATE.user.id]||[]).find(function(e){return e.id===sigEmailId;}):null;
  var senderName=(fromEmForSig&&fromEmForSig.display_name)||STATE.user.name||'';
  var senderEmail=(fromEmForSig&&fromEmForSig.email_address)||fromEmailAddress||STATE.user.email||'';
  var plainBody=ge.body||'';
  var sigPlain=sigHtml?htmlSignatureToPlainText(sigHtml,senderName,senderEmail):'';
  var url;
  if(plt==="Gmail"){
    // Gmail deeplink only supports plain text body
    var gmailBody=sigPlain?plainBody+'\n\n-- \n'+sigPlain:plainBody;
    url="https://mail.google.com/mail/?view=cm&to="+encodeURIComponent(ge.email)+"&su="+encodeURIComponent(ge.subj)+"&body="+encodeURIComponent(gmailBody)+(gmailFrom?"&authuser="+encodeURIComponent(gmailFrom):'');
  } else {
    // Outlook deeplink — compose window accepts plain text only in the URL param
    var outlookBody=sigPlain?plainBody+'\n\n'+sigPlain:plainBody;
    url="https://outlook.live.com/mail/0/deeplink/compose?to="+encodeURIComponent(ge.email)+"&subject="+encodeURIComponent(ge.subj)+"&body="+encodeURIComponent(outlookBody);
  }
  window.open(url,"_blank");
  STATE.emails.push({id:"e"+Date.now(),lid:ge.lid,by:STATE.user.id,to:ge.email,from_email:fromEmail||null,subj:ge.subj,body:plainBody,plt:plt,dt:todayIST(),status:"sent"});
  showToast("Email opened in "+plt+(fromEmail?' from '+fromEmail:'')+(sigPlain?' · signature appended':''),"success");
}

window.copyToClip=function(text){
  if(navigator.clipboard){
    navigator.clipboard.writeText(text).then(function(){showToast("Copied: "+text,"success");}).catch(function(){fallbackCopy(text);});
  } else {fallbackCopy(text);}
};
function fallbackCopy(text){
  var el=document.createElement("textarea");
  el.value=text;el.style.position="fixed";el.style.opacity="0";
  document.body.appendChild(el);el.select();
  try{document.execCommand("copy");showToast("Copied: "+text,"success");}catch(e){showToast("Copy failed","error");}
  document.body.removeChild(el);
}

// Insert a merge variable at cursor position in any textarea by element ID
window.insertVarFromPicker=function(v,targetId){
  if(!v)return;
  var el=document.getElementById(targetId);
  if(!el){
    // fallback: insert into the body textarea for the compose tab
    var bodyEl=document.getElementById('email-body');
    if(bodyEl){
      var s=bodyEl.selectionStart!==undefined?bodyEl.selectionStart:bodyEl.value.length;
      var e2=bodyEl.selectionEnd!==undefined?bodyEl.selectionEnd:s;
      bodyEl.value=bodyEl.value.slice(0,s)+v+bodyEl.value.slice(e2);
      bodyEl.selectionStart=bodyEl.selectionEnd=s+v.length;
      STATE.emailBody=bodyEl.value;
    }
    return;
  }
  var start=el.selectionStart!==undefined?el.selectionStart:el.value.length;
  var end2=el.selectionEnd!==undefined?el.selectionEnd:start;
  el.value=el.value.slice(0,start)+v+el.value.slice(end2);
  el.selectionStart=el.selectionEnd=start+v.length;
  el.focus();
  if(el.id==='email-subj')STATE.composeSubj=el.value;
  else if(el.id==='email-body')STATE.composeBody=el.value;
};

// Legacy insertVar (kept for any remaining callers) — inserts into email-body textarea
window.insertVar=function(v){
  var el=document.getElementById('email-body')||document.getElementById('tmpl-o1-body')||document.getElementById('tmpl-fu1-body')||document.getElementById('tmpl-fu2-body');
  if(el){
    var s=el.selectionStart!==undefined?el.selectionStart:el.value.length;
    var e2=el.selectionEnd!==undefined?el.selectionEnd:s;
    el.value=el.value.slice(0,s)+v+el.value.slice(e2);
    el.selectionStart=el.selectionEnd=s+v.length;
    el.focus();
  }
};

// Signature helpers
var SIGNATURE_TAGLINE='Making Recruitment Easier with Future Tech';
var LEGACY_SIGNATURE_TAGLINES=['Staffing solutions for healthcare & enterprise','Staffing solutions for healthcare &amp; enterprise'];
function isLegacyBlockSignature(sigHtml){
  return /&#128231;|&#128222;|&#127760;|&#128205;/.test(sigHtml)||/border-right:3px solid #1E7A3C/.test(sigHtml);
}
function upgradeSignatureTagline(sigHtml){
  var html=String(sigHtml||'');
  LEGACY_SIGNATURE_TAGLINES.forEach(function(oldTagline){
    html=html.split(oldTagline).join(SIGNATURE_TAGLINE);
  });
  return html.replace(/Staffing solutions for healthcare(?:\s*(?:&amp;|&)\s*)?enterprise/gi,SIGNATURE_TAGLINE);
}
function syncMailboxSignatureIfNeeded(userId,emailId,raw,normalized){
  if(!userId||!emailId||!normalized||normalized===raw||STATE.sigMigrated&&STATE.sigMigrated[emailId])return;
  STATE.sigMigrated=STATE.sigMigrated||{};
  STATE.sigMigrated[emailId]=true;
  STATE.emailSignaturesCache=STATE.emailSignaturesCache||{};
  STATE.emailSignaturesCache[emailId]=normalized;
  apiPut('/users/'+userId+'/emails/'+emailId+'/signature',{signature_html:normalized}).catch(function(){});
}
function upgradeSignatureTitle(sigHtml){
  return String(sigHtml||'')
    .replace(/BD Manager at Fute Global LLC/gi,'Recruitment Manager at Fute Global LLC')
    .replace(/BD Manager \|/gi,'Recruitment Manager |');
}
function normalizeMailboxSignature(sigHtml){
  if(!sigHtml||!String(sigHtml).trim())return'';
  if(isLegacyBlockSignature(sigHtml))return(SIG_PRESETS&&SIG_PRESETS.professional)||sigHtml;
  return upgradeSignatureTitle(upgradeSignatureTagline(sigHtml));
}
function normalizeSenderTitle(text){
  return String(text||'')
    .replace(/BD Manager at Fute Global LLC/gi,'Recruitment Manager at Fute Global LLC')
    .replace(/BD Manager \|/gi,'Recruitment Manager |');
}
function fillSignatureHtml(sigHtml,senderName,senderEmail){
  return String(sigHtml||'')
    .replace(/{{sender}}/g,senderName||'')
    .replace(/{{senderemail}}/g,senderEmail||'');
}
function htmlSignatureToPlainText(sigHtml,senderName,senderEmail){
  if(!sigHtml||!String(sigHtml).trim())return'';
  var html=fillSignatureHtml(sigHtml,senderName,senderEmail);
  html=html.replace(/<a[^>]+href=["']mailto:([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi,function(_,href,text){
    var label=(text||'').replace(/<[^>]+>/g,'').trim();
    return label||href;
  });
  html=html.replace(/<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi,function(_,href,text){
    var label=(text||'').replace(/<[^>]+>/g,'').trim();
    if(!label)return href.replace(/^https?:\/\//i,'');
    return label.replace(/^https?:\/\//i,'');
  });
  html=html.replace(/<img[^>]*>/gi,'');
  html=html.replace(/<br\s*\/?>/gi,'\n');
  html=html.replace(/<\/p>/gi,'\n');
  html=html.replace(/<\/tr>/gi,'\n');
  html=html.replace(/<\/td>/gi,' ');
  html=html.replace(/<\/div>/gi,'\n');
  html=html.replace(/<[^>]+>/g,'');
  var ta=document.createElement('textarea');
  ta.innerHTML=html;
  var text=ta.value;
  return text.replace(/[ \t]+\n/g,'\n').replace(/[ \t]{2,}/g,' ').replace(/\n{3,}/g,'\n\n').trim();
}
var SIG_PRESETS={professional:'<div style="font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#222;line-height:1.45"><p style="margin:0 0 3px"><strong>{{sender}}</strong></p><p style="margin:0 0 3px;color:#333">Recruitment Manager | <strong>Fute Global LLC</strong></p><p style="margin:0 0 3px;color:#333"><a href="mailto:{{senderemail}}" style="color:#1E7A3C;text-decoration:none">{{senderemail}}</a> | +1 (972)-452-6644 | <a href="https://www.futeglobal.com/" style="color:#1E7A3C;text-decoration:none">www.futeglobal.com</a></p><p style="margin:0 0 3px;color:#555;font-size:12px">8111 Lyndon B. Johnson Freeway, Suite 1340, Dallas, TX 75251</p><p style="margin:0 0 12px;color:#555;font-size:12px;font-style:italic">Making Recruitment Easier with Future Tech</p><img src="data:image/png;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCAA+AGMDASIAAhEBAxEB/8QAHAAAAQUBAQEAAAAAAAAAAAAAAAQFBgcIAwEC/8QAPxAAAQMDAgQDAwYMBwAAAAAAAQIDBAAFEQYhBxIxQQgTURRhgSIyNnN1shUWIyc1N3FydLPBwzhSYoKSobH/xAAZAQACAwEAAAAAAAAAAAAAAAAABAIDBQH/xAApEQABBAECBgEEAwAAAAAAAAABAAIDEQQSMQUTIUFRgWEGMzThcZGh/9oADAMBAAIRAxEAPwDXdFFeLUlCSpSglIGSScACrVFe0VCZvFfQESYYrmoG1rCuVSmmXHED/clJBH7CalVnuluvEFE61zWJkZewcZWFDPofQ+471BsjXGgVBsrHmmuBSyiiipqaKKKKEIooooQiiq9umt56bg+iCmOYyV8rZUgkkDv179aedK3HUV3UH5CIzEL/AD+WeZfuTk/91g4/1FiZM/IhDnO+B0/m/Hyn5OHyxs1voBSmiiit5IIqrvEtd5Vu0E1EiuKb9vlBl4pOCWwlSin4kD4ZHerRrNPiH0jcrdqOVqp9+IqFcZKG2W0LUXUkND5wKcAfIPQntS2W4tiNBJcQe5kB0jf/ABN3BvhzG1y1cn5lweiNRORCA0kEqWoE5OewwNu+e1Xnwu0pB0JYnba5PjvzHnlOvu5CebsgYJ2ATj4k1nfh9w8vWt40t+1SreymKtKFiS4tJJUCRjlSr0pv4g2aVp7Uq7LNcZckRWGULUySUE+Wk7EgHv6UhFIImB+j2snHlGPGJOX7vdbLSpKkhSSFJIyCDsRXNyTGaXyOSGkK9FLANM3Dr9X2nPsqL/KTWdvEZ+tKZ9Qz9wVoTT8uMPpbGTlcmISVdq4/EDOLHDSWuJMLTxdZKS07hRBWOmDnFQLwyXSS9qG7C4XF1xAiJ5Q++SAeftk0ycRNJTXtAWDWKZMcRGLREjKZOfMKsncbYx8od6jHDrRNw1vPlQ7fLixlxmg4ov8ANggnG2AaRfK8zhwHpZcs8hymuDe3QXutgtONup5m1pWn1Scim3VDoRaHmvb4kFTo5PNkOhCQD1wfXFVuZUjg3wqESU7GmXR6S4IgbzyFSt+Y5AOEgZPrsO9VDYtP6y4m3mTNS4qW4k/lpcpzlbbzuEjbb91I29BV+RNqZyiDbh1r5+Vov4g6JzQ1lv3rwr90vpW3yJHtDtzh3FlGCERnQtJP+ojt7qniUpQkJSAlIGAAMACsi6r0hq3hzOizn3fIK1YYmwnjy8w35c4BBx2I3364NaA4K62c1nppa5oSLnCUGpPKMBeRlK8ds4O3qD2pXhWLjYQMMTNJPsn2rxxaXMl0TinDsp3RRRWyr0VT/ip+h1r+0P7a6uCqf8VP0Otf2h/bXS+V9pyUzvx3JH4Uf0Rfvr2vuqqvfEGPzsXb9xj+SirC8KP6Iv317X3VU0+JnSc1N4b1XEYU7EdaS1KKRnylp2SpXoCMDPqPeKTe0uxW12/azZGF2A2u37Vx8N1JXw906UnI/BcYfENJBrOviKWlXFOcEqBKWWQrHY+WD/UUm0lxV1bpyxpssByK/HQClgvsla2cnOEkEZ3J2OajWrGL2zenHdQpeFxlJTId875/yxkZHbbG3bpt0qE+Q2SINAVWXmNmgaxo2q1duuf8M1r/AIaH/wCppi8Kn0kvP8Gn79TpywSNS+HuDaYYBlLtjDjAJxzLRyqCfjgj41QujdUX3QV/kSITDaJPIpiRHltKx1BwoAgggj1FTkPLlY87UrZ3cqeKR21BWb4sS77Rp0HPlckjHpzZbz/SoNoWbxMi2VSNItXM29TylKMaKlxJcwAdyk74AqWWb8YOL+kbtFuSc3CDJEq3yvL5GTlOFR89BsAR1O+TUP0zqvWPDS4yLelgscy+Z6FMaJQpXTmGCD26pODt12quQgyczqAVTM4Om51kNd3H9Jx1Exxf1DbxAvNtvcyMFhwNqggYUM4OQkHuanPhs0/qCx3W8G72mbAaeYb5C+0UBSgo9M+41CL1xc15qKQxEt60wlFxJbZtzSudxQOQDkqJ/YNj3BrSGkpV2m6cgyb5BTBuLjQL7CVZCVevuz1x2zjtV2O1j5NQJNeUzhxxyTa2uJI8p0ooorSW0ik1wt8C4tJauEKNLbSrmSl9pKwD6gEdaU0VzdBF7pLb7bbrclabfAiw0rOVhhlLYUffgb0pWlK0FC0hSVDBBGQRXtFFUgADoE1RNN6diSxMiWC1R5IOQ81DbSvPrzAZrrNsllnSDIm2i3yXiAC49GQtRA6bkZpwormkeFHQ2qpfEdlmOwhiO0hpptIShCEhKUgdAAOgpBc9P2C6Ph+52O2TnQMBciKhxQHplQNOVFdIB6FdLQRRC5RI8eJHRHisNMMoGENtICUpHuA2FcrjbrfcmgzcYMWY2DkIfZS4B8CDSqiihsu0KpIbZZrPayTbLVAhEjB9njobz/xApdRRQABsgADoEUUUV1C//9k=" alt="Fute Global" style="height:40px;display:block"></div>',minimal:'<div style="font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#222;line-height:1.45"><p style="margin:0 0 3px"><strong>{{sender}}</strong></p><p style="margin:0 0 3px;color:#333">Recruitment Manager | <strong>Fute Global LLC</strong></p><p style="margin:0"><a href="mailto:{{senderemail}}" style="color:#1E7A3C;text-decoration:none">{{senderemail}}</a> | +1 (972)-452-6644 | <a href="https://www.futeglobal.com/" style="color:#1E7A3C;text-decoration:none">www.futeglobal.com</a></p><p style="margin:3px 0 0;color:#555;font-size:12px">8111 Lyndon B. Johnson Freeway, Suite 1340, Dallas, TX 75251</p></div>',withLogo:'<div style="font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#222;line-height:1.45"><p style="margin:0 0 3px"><strong>{{sender}}</strong></p><p style="margin:0 0 3px;color:#333">Recruitment Manager | <strong>Fute Global LLC</strong></p><p style="margin:0 0 3px;color:#333"><a href="mailto:{{senderemail}}" style="color:#1E7A3C;text-decoration:none">{{senderemail}}</a> | +1 (972)-452-6644 | <a href="https://www.futeglobal.com/" style="color:#1E7A3C;text-decoration:none">www.futeglobal.com</a></p><p style="margin:0 0 3px;color:#555;font-size:12px">8111 Lyndon B. Johnson Freeway, Suite 1340, Dallas, TX 75251</p><p style="margin:0 0 12px;color:#555;font-size:12px;font-style:italic">Making Recruitment Easier with Future Tech</p><img src="data:image/png;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCAA+AGMDASIAAhEBAxEB/8QAHAAAAQUBAQEAAAAAAAAAAAAAAAQFBgcIAwEC/8QAPxAAAQMDAgQDAwYMBwAAAAAAAQIDBAAFEQYhBxIxQQgTURRhgSIyNnN1shUWIyc1N3FydLPBwzhSYoKSobH/xAAZAQACAwEAAAAAAAAAAAAAAAAABAIDBQH/xAApEQABBAECBgEEAwAAAAAAAAABAAIDEQQSMQUTIUFRgWEGMzThcZGh/9oADAMBAAIRAxEAPwDXdFFeLUlCSpSglIGSScACrVFe0VCZvFfQESYYrmoG1rCuVSmmXHED/clJBH7CalVnuluvEFE61zWJkZewcZWFDPofQ+471BsjXGgVBsrHmmuBSyiiipqaKKKKEIooooQiiq9umt56bg+iCmOYyV8rZUgkkDv179aedK3HUV3UH5CIzEL/AD+WeZfuTk/91g4/1FiZM/IhDnO+B0/m/Hyn5OHyxs1voBSmiiit5IIqrvEtd5Vu0E1EiuKb9vlBl4pOCWwlSin4kD4ZHerRrNPiH0jcrdqOVqp9+IqFcZKG2W0LUXUkND5wKcAfIPQntS2W4tiNBJcQe5kB0jf/ABN3BvhzG1y1cn5lweiNRORCA0kEqWoE5OewwNu+e1Xnwu0pB0JYnba5PjvzHnlOvu5CebsgYJ2ATj4k1nfh9w8vWt40t+1SreymKtKFiS4tJJUCRjlSr0pv4g2aVp7Uq7LNcZckRWGULUySUE+Wk7EgHv6UhFIImB+j2snHlGPGJOX7vdbLSpKkhSSFJIyCDsRXNyTGaXyOSGkK9FLANM3Dr9X2nPsqL/KTWdvEZ+tKZ9Qz9wVoTT8uMPpbGTlcmISVdq4/EDOLHDSWuJMLTxdZKS07hRBWOmDnFQLwyXSS9qG7C4XF1xAiJ5Q++SAeftk0ycRNJTXtAWDWKZMcRGLREjKZOfMKsncbYx8od6jHDrRNw1vPlQ7fLixlxmg4ov8ANggnG2AaRfK8zhwHpZcs8hymuDe3QXutgtONup5m1pWn1Scim3VDoRaHmvb4kFTo5PNkOhCQD1wfXFVuZUjg3wqESU7GmXR6S4IgbzyFSt+Y5AOEgZPrsO9VDYtP6y4m3mTNS4qW4k/lpcpzlbbzuEjbb91I29BV+RNqZyiDbh1r5+Vov4g6JzQ1lv3rwr90vpW3yJHtDtzh3FlGCERnQtJP+ojt7qniUpQkJSAlIGAAMACsi6r0hq3hzOizn3fIK1YYmwnjy8w35c4BBx2I3364NaA4K62c1nppa5oSLnCUGpPKMBeRlK8ds4O3qD2pXhWLjYQMMTNJPsn2rxxaXMl0TinDsp3RRRWyr0VT/ip+h1r+0P7a6uCqf8VP0Otf2h/bXS+V9pyUzvx3JH4Uf0Rfvr2vuqqvfEGPzsXb9xj+SirC8KP6Iv317X3VU0+JnSc1N4b1XEYU7EdaS1KKRnylp2SpXoCMDPqPeKTe0uxW12/azZGF2A2u37Vx8N1JXw906UnI/BcYfENJBrOviKWlXFOcEqBKWWQrHY+WD/UUm0lxV1bpyxpssByK/HQClgvsla2cnOEkEZ3J2OajWrGL2zenHdQpeFxlJTId875/yxkZHbbG3bpt0qE+Q2SINAVWXmNmgaxo2q1duuf8M1r/AIaH/wCppi8Kn0kvP8Gn79TpywSNS+HuDaYYBlLtjDjAJxzLRyqCfjgj41QujdUX3QV/kSITDaJPIpiRHltKx1BwoAgggj1FTkPLlY87UrZ3cqeKR21BWb4sS77Rp0HPlckjHpzZbz/SoNoWbxMi2VSNItXM29TylKMaKlxJcwAdyk74AqWWb8YOL+kbtFuSc3CDJEq3yvL5GTlOFR89BsAR1O+TUP0zqvWPDS4yLelgscy+Z6FMaJQpXTmGCD26pODt12quQgyczqAVTM4Om51kNd3H9Jx1Exxf1DbxAvNtvcyMFhwNqggYUM4OQkHuanPhs0/qCx3W8G72mbAaeYb5C+0UBSgo9M+41CL1xc15qKQxEt60wlFxJbZtzSudxQOQDkqJ/YNj3BrSGkpV2m6cgyb5BTBuLjQL7CVZCVevuz1x2zjtV2O1j5NQJNeUzhxxyTa2uJI8p0ooorSW0ik1wt8C4tJauEKNLbSrmSl9pKwD6gEdaU0VzdBF7pLb7bbrclabfAiw0rOVhhlLYUffgb0pWlK0FC0hSVDBBGQRXtFFUgADoE1RNN6diSxMiWC1R5IOQ81DbSvPrzAZrrNsllnSDIm2i3yXiAC49GQtRA6bkZpwormkeFHQ2qpfEdlmOwhiO0hpptIShCEhKUgdAAOgpBc9P2C6Ph+52O2TnQMBciKhxQHplQNOVFdIB6FdLQRRC5RI8eJHRHisNMMoGENtICUpHuA2FcrjbrfcmgzcYMWY2DkIfZS4B8CDSqiihsu0KpIbZZrPayTbLVAhEjB9njobz/xApdRRQABsgADoEUUUV1C//9k=" alt="Fute Global" style="height:40px;display:block"></div>'};
window.applySigPreset=function(pk){
  var html=SIG_PRESETS[pk]||'';
  var el=document.getElementById('sig-html-input');
  if(el){el.value=html;updateSigPreview(html);}
};
function getSigPreviewIdentity(){
  var uid=STATE.user&&STATE.user.id;
  var emails=(uid&&STATE.userEmailsCache&&STATE.userEmailsCache[uid])||[];
  var sigEmail=emails.find(function(e){return e.id===STATE.sigEmailId;})||emails.find(function(e){return e.is_primary;})||emails[0];
  return {
    name:(sigEmail&&sigEmail.display_name)||'Your Name',
    email:(sigEmail&&sigEmail.email_address)||'you@fute-global.com'
  };
}
function updateSigPreview(html){
  var prev=document.getElementById('sig-live-preview');
  if(!prev)return;
  var id=getSigPreviewIdentity();
  var filled=html.replace(/{{sender}}/g,id.name).replace(/{{senderemail}}/g,id.email);
  prev.innerHTML=filled||'<em style="color:#94A3B8;font-size:12px">Preview will appear here</em>';
}
window.loadMailboxSignature=function(userId,emailId){
  if(!userId||!emailId)return;
  apiGet('/users/'+userId+'/emails/'+emailId+'/signature').then(function(d){
    var raw=d.signature_html||'';
    var normalized=normalizeMailboxSignature(raw);
    STATE.emailSignaturesCache=STATE.emailSignaturesCache||{};
    STATE.emailSignaturesCache[emailId]=normalized;
    if(normalized&&normalized!==raw){
      apiPut('/users/'+userId+'/emails/'+emailId+'/signature',{signature_html:normalized}).catch(function(){});
    }
    render();
  }).catch(function(){});
};
window.selectSigEmail=function(emailId){
  if(!emailId||!STATE.user)return;
  STATE.sigEmailId=emailId;
  STATE.planFromEmailId=emailId;
  if(STATE.emailSignaturesCache&&STATE.emailSignaturesCache[emailId]!==undefined){render();return;}
  loadMailboxSignature(STATE.user.id,emailId);
};
// Wire live preview on input (called via oninput on the textarea via a delegated approach)
document.addEventListener('input',function(e){
  if(e.target&&e.target.id==='sig-html-input'){updateSigPreview(e.target.value);}
});
window.saveSig=function(){
  var el=document.getElementById('sig-html-input');
  var html=(el&&el.value)||'';
  var emailId=STATE.sigEmailId;
  if(!emailId||!STATE.user){showToast('Select a sending email first','warning');return;}
  STATE.emailSignaturesCache=STATE.emailSignaturesCache||{};
  STATE.emailSignaturesCache[emailId]=html;
  STATE.sigEditing=false;
  apiPut('/users/'+STATE.user.id+'/emails/'+emailId+'/signature',{signature_html:html}).then(function(){
    showToast('Signature saved for this email ID','success');render();
  }).catch(function(e){showToast('Save failed: '+e.message,'error');});
};
window.clearSig=function(){
  var emailId=STATE.sigEmailId;
  if(!emailId||!STATE.user){showToast('Select a sending email first','warning');return;}
  STATE.emailSignaturesCache=STATE.emailSignaturesCache||{};
  STATE.emailSignaturesCache[emailId]='';
  STATE.sigEditing=false;
  apiPut('/users/'+STATE.user.id+'/emails/'+emailId+'/signature',{signature_html:''}).then(function(){
    showToast('Signature cleared — default will be used on send','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

// Build the HTML email body from plain-text template + signature for sending
function buildHtmlEmail(plainBody, sigHtml, senderName, senderEmail){
  // Convert plain-text line breaks to <br> and wrap paragraphs
  var htmlBody=plainBody
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/\n\n/g,'</p><p>').replace(/\n/g,'<br>');
  htmlBody='<p>'+htmlBody+'</p>';
  var sig='';
  if(sigHtml&&sigHtml.trim()){
    var filled=sigHtml
      .replace(/{{sender}}/g,htmlEsc(senderName||''))
      .replace(/{{senderemail}}/g,htmlEsc(senderEmail||''));
    sig='<hr style="border:none;border-top:1px solid #e2e8f0;margin:18px 0">'+filled;
  }
  return '<div style="font-family:Arial,sans-serif;font-size:14px;line-height:1.6;color:#0F172A">'+htmlBody+sig+'</div>';
}

window.toggleBDAssign=function(role){
  var wrap=document.getElementById("u-bd-wrap");
  if(wrap)wrap.style.display=role==="ra"?"":"none";
};
window.openAddUser=function(){
  var managers=STATE.users.filter(function(x){return x.role==='bd'||x.role==='bd_lead'||x.role==='admin';});
  var roleOpts=['ra','ra_lead','bd','bd_lead','admin','recruiter'].map(function(r){
    var labels={ra:'Research Analyst',ra_lead:'RA Team Lead',bd:'Manager',bd_lead:'BD Team Lead',admin:'Admin',recruiter:'Recruiter'};
    return '<option value="'+r+'">'+labels[r]+'</option>';
  }).join('');
  STATE.modal='<div class="modal modal-w480">'+
    '<div class="mh"><div class="mt">Add new user</div><button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'+
    '<div class="mb_">'+
      '<div class="g2 mb3">'+
        '<div class="fgrp"><label class="flbl">Full name <span style="color:var(--red)">*</span></label><input class="inp" id="u-name"/></div>'+
        '<div class="fgrp"><label class="flbl">Work email <span style="color:var(--red)">*</span></label><input class="inp" id="u-email" type="email"/></div>'+
      '</div>'+
      '<div class="g2 mb3">'+
        '<div class="fgrp"><label class="flbl">Employee ID</label><input class="inp" id="u-eid"/></div>'+
        '<div class="fgrp"><label class="flbl">Designation</label><input class="inp" id="u-desig"/></div>'+
      '</div>'+
      '<div class="g2 mb3">'+
        '<div class="fgrp"><label class="flbl">Role</label><select class="sel" id="u-role">'+roleOpts+'</select></div>'+
        '<div class="fgrp"><label class="flbl">Platform</label><select class="sel" id="u-plt"><option>Gmail</option><option>Outlook</option></select></div>'+
      '</div>'+
      '<div style="font-size:12px;color:var(--text3);padding:8px 10px;background:var(--bg);border-radius:var(--r)">Default password: <strong>Fute@2024</strong></div>'+
    '</div>'+
    '<div class="mf"><button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" onclick="saveUser(null)">Add user</button></div>'+
  '</div>';
  render();
};
window.editUser=function(id){var u=STATE.users.find(function(x){return x.id===id});if(u){STATE.modal=renderUserModal(u);render();}}
window.removeUser=function(id,fromDetail){
  if(id===STATE.user.id){showToast("Cannot remove yourself","warning");return;}
  if(!confirm("Deactivate this user? They will no longer be able to log in."))return;
  apiDelete('/users/'+id).then(function(){
    STATE.users=STATE.users.filter(function(u){return u.id!==id;});
    if(fromDetail){STATE.adminSelectedUser=null;}
    showToast("User deactivated","success");render();
  }).catch(function(e){showToast("Failed: "+e.message,"error");});
};
window.unassignRA=function(id){
  STATE.users=STATE.users.map(function(u){return u.id===id?Object.assign({},u,{bdm:null}):u;});
  showToast("RA unassigned","info");render();
}
window.saveUser=function(existingId){
  var name=(document.getElementById('u-name')||{}).value||'';
  var email=(document.getElementById('u-email')||{}).value||'';
  name=name.trim();email=email.trim();
  if(!name||!email){showToast('Name and email required','warning');return;}
  var role=(document.getElementById('u-role')||{}).value||'ra';
  var eid=(document.getElementById('u-eid')||{}).value||'';
  var desig=(document.getElementById('u-desig')||{}).value||'';
  var plt=(document.getElementById('u-plt')||{}).value||'Gmail';
  var payload={name:name,email:email,role:role,employee_id:eid||undefined,designation:desig||undefined,platform:plt};
  apiPost('/users',payload).then(function(u){
    STATE.users.push(normaliseUser(u));
    closeModal();
    showToast('User added — '+name,'success');
    render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
}

window.saveProfile=function(){
  var name=(document.getElementById("p-name")||{}).value||STATE.user.name;
  var email=(document.getElementById("p-email")||{}).value||STATE.user.email;
  var eid=(document.getElementById("p-eid")||{}).value||STATE.user.empId;
  var desig=(document.getElementById("p-desig")||{}).value||STATE.user.desig;
  STATE.users=STATE.users.map(function(u){return u.id===STATE.user.id?Object.assign({},u,{name:name,email:email,empId:eid,desig:desig}):u;});
  STATE.user=Object.assign({},STATE.user,{name:name,email:email,empId:eid,desig:desig});
  showToast("Profile updated","success");render();
}
window.setProfilePlt=function(p){
  STATE.user=Object.assign({},STATE.user,{plt:p});
  STATE.users=STATE.users.map(function(u){return u.id===STATE.user.id?Object.assign({},u,{plt:p}):u;});
  showToast("Platform set to "+p,"success");render();
}
window.changePassword=function(){
  var n=(document.getElementById("pw-new")||{}).value;
  var c=(document.getElementById("pw-con")||{}).value;
  if(!n||n.length<6){showToast("Password must be at least 6 characters","warning");return;}
  if(n!==c){showToast("Passwords don't match","warning");return;}
  showToast("Password updated","success");
}

window.setAdminView=function(v){STATE.adminView=v;render();}

window.submitUserDetailSave=function(existingId){
  var name=(document.getElementById('ud-name')||{}).value||'';
  var email=(document.getElementById('ud-email')||{}).value||'';
  var eid=(document.getElementById('ud-eid')||{}).value||'';
  var desig=(document.getElementById('ud-desig')||{}).value||'';
  var role=(document.getElementById('ud-role')||{}).value||'ra';
  var plt=(document.getElementById('ud-plt')||{}).value||'Gmail';
  if(!name||!email){showToast('Name and email required','warning');return;}
  apiPut('/users/'+existingId,{name:name,email:email,employee_id:eid,designation:desig,role:role,platform:plt}).then(function(updated){
    STATE.users=STATE.users.map(function(u){return u.id===existingId?normaliseUser(updated):u;});
    showToast('User updated','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.dismissReminder=function(rid){
  apiFetch('PATCH','/reminders/'+rid,{status:'sent'}).then(function(){
    STATE.reminders=(STATE.reminders||[]).map(function(r){return r.id===rid?Object.assign({},r,{status:'sent'}):r;});
    render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.viewAs=function(uid){
  var target=STATE.users.find(function(u){return u.id===uid});
  if(!target)return;
  STATE.viewingUser=target;
  STATE.page="dashboard";
  render();
}
window.stopViewing=function(){
  STATE.viewingUser=null;
  STATE.page="dashboard";
  render();
}

window.reminderSearchInput=function(v){
  STATE.reminderSearch=v;render();
  setTimeout(function(){var el=document.getElementById("rem-search-inp");if(el){el.focus();el.setSelectionRange(v.length,v.length);}},0);
}
window.openNewReminder=function(){STATE.modal=renderSetReminderModal(null,null);render();}
window.openSetReminderFromSearch=function(lid){STATE.reminderSearch=null;STATE.modal=renderSetReminderModal(lid,null);render();}
window.openSetReminderManual=function(email){STATE.reminderSearch=null;STATE.modal=renderSetReminderModal(null,email);render();}
window.openSetReminder=function(lid){STATE.modal=renderSetReminderModal(lid,null);render();}

window.saveReminder=function(lid,manualEmail){
  var lead=lid?STATE.leads.find(function(l){return l.id===lid}):null;
  var co=lead?STATE.companies.find(function(c){return c.id===lead.coid})||{}:{};
  var dt=(document.getElementById("rem-date")||{}).value;
  var tm=(document.getElementById("rem-time")||{}).value||"09:00";
  var note=(document.getElementById("rem-note")||{}).value||"";
  if(!dt){showToast("Please set a date","warning");return;}
  STATE.reminders.push({
    id:"r"+Date.now(),lid:lid||null,uid:STATE.user.id,
    name:lead?(lead.fn+" "+lead.ln):(manualEmail||""),
    company:lead?(co.name||""):"",
    email:lead?lead.email:(manualEmail||""),
    returnDate:dt,reminderTime:tm,note:note,status:"pending",createdAt:todayIST()
  });
  closeModal();STATE.reminderSearch=null;
  showToast("Reminder set for "+fmtDate(dt)+" at "+tm,"success");
  render();
}

window.editReminder=function(rid){
  var r=STATE.reminders.find(function(x){return x.id===rid});
  if(!r)return;
  STATE.modal=renderSetReminderModal(r.lid||null,r.lid?null:r.email);
  render();
}
window.dismissReminder=function(rid){
  STATE.reminders=STATE.reminders.filter(function(r){return r.id!==rid});
  showToast("Reminder removed","info");render();
}
window.sendReminderEmail=function(rid){
  var r=STATE.reminders.find(function(x){return x.id===rid});
  if(!r)return;
  var subj="Following up, hope you're back!";
  var body="Hi "+((r.contact_name||r.name||"").split(" ")[0]||"there")+",\n\nHope you had a great break! I wanted to follow up on my earlier message.\n\nWould you have 15 minutes for a quick call this week?\n\nWarm regards,\n"+STATE.user.name+"\nFute Global LLC";
  var plt=STATE.user.plt||"Gmail";
  window.open(plt==="Gmail"
    ?"https://mail.google.com/mail/?view=cm&to="+encodeURIComponent(r.email)+"&su="+encodeURIComponent(subj)+"&body="+encodeURIComponent(body)
    :"https://outlook.live.com/mail/0/deeplink/compose?to="+encodeURIComponent(r.email)+"&subject="+encodeURIComponent(subj)+"&body="+encodeURIComponent(body),"_blank");
  STATE.reminders=STATE.reminders.map(function(x){return x.id===rid?Object.assign({},x,{status:"sent"}):x;});
  showToast("Follow-up email opened","success");render();
}
window.sendAllDue=function(){
  var today=todayIST();
  var due=STATE.reminders.filter(function(r){return r.user_id===STATE.user.id&&r.status==="pending"&&r.return_date<=today});
  due.forEach(function(r){sendReminderEmail(r.id);});
}

// ── PAGINATION ─────────────────────────────────
window.setLeadsPage=function(p){STATE.leadsPage=Math.max(0,p);render();}
window.toggleJobFilter=function(key,val,checked){
  var arr=(STATE.jobsFilter[key]||[]).slice();
  if(checked){if(arr.indexOf(val)===-1)arr.push(val);}
  else{arr=arr.filter(function(x){return x!==val;});}
  STATE.jobsFilter[key]=arr;STATE.leadsPage=0;render();
};
window.openEditPendingEmail=function(id){
  var pe=(STATE.pendingEmails||[]).find(function(e){return e.id===id;});
  if(!pe)return;
  STATE.modal='<div class="modal modal-w640">'+
    '<div class="mh"><div class="mt">Edit Email \u2014 '+htmlEsc(pe.to_email||'')+'</div><button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'+
    '<div class="mb_" style="padding:18px 20px">'+
      '<div class="fgrp"><label class="flbl">Subject</label><input class="inp" id="edit-pe-subj" value="'+htmlEsc(pe.subject||'')+'" onfocus="setVarInsertTarget(\'subject\')"/></div>'+
      '<div class="fgrp"><label class="flbl">Body</label><textarea class="txta w100" id="edit-pe-body" style="min-height:300px;line-height:1.7" onfocus="setVarInsertTarget(\'body\')">'+htmlEsc(pe.body||'')+'</textarea></div>'+
      renderVarChipBar('edit-pe-subj','edit-pe-body')+
    '</div>'+
    '<div class="mf">'+
      '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" onclick="savePendingEmailEdit(\''+id+'\')">Save changes</button>'+
    '</div>'+
  '</div>';
  render();
};
window.savePendingEmailEdit=function(id){
  var subj=(document.getElementById('edit-pe-subj')||{}).value||'';
  var body=(document.getElementById('edit-pe-body')||{}).value||'';
  apiFetch('PATCH','/emails/'+id,{subject:subj,body:body}).then(function(updated){
    STATE.pendingEmails=(STATE.pendingEmails||[]).map(function(e){return e.id===id?Object.assign({},e,{subject:updated.subject||subj,body:updated.body||body}):e;});
    closeModal();showToast('Email updated','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};
document.addEventListener('click',function(){
  if(STATE.openDrop!==null){STATE.openDrop=null;render();}
});
window.setLeadsPageSize=function(n){STATE.leadsPageSize=n;STATE.leadsPage=0;render();}

// ── MAIL MERGE ─────────────────────────────────
window.openMailMerge=function(ids){
  if(!ids||!ids.length){showToast("No leads selected","warning");return;}
  var leads=ids.map(function(id){return STATE.leads.find(function(l){return l.id===id;});}).filter(function(l){return l&&!l.del;});
  if(!leads.length){showToast("No valid leads","warning");return;}
  STATE.mailMerge={leads:leads,currentIdx:0,emails:{},sent:0,skipped:0};
  // Pre-fill emails for all leads
  leads.forEach(function(l,i){
    var co=STATE.companies.find(function(c){return c.id===l.coid;})||{};
    STATE.mailMerge.emails[i]={subj:fillEmail(STATE.emailSubj,l,co,STATE.user.name),body:fillEmail(STATE.emailBody,l,co,STATE.user.name),sent:false};
  });
  STATE.modal=renderMailMergeModal();
  render();
}

window.closeMailMerge=function(){
  var mm=STATE.mailMerge;
  if(mm&&mm.sent>0)showToast(mm.sent+" email"+(mm.sent>1?"s":"")+" sent via mail merge","success");
  STATE.mailMerge=null;STATE.modal=null;STATE.leadsSelected={};render();
}

window.mailMergeNav=function(dir){
  var mm=STATE.mailMerge;
  if(!mm)return;
  // Save current edits before navigating
  var subjEl=document.getElementById("mm-subj");
  var bodyEl=document.getElementById("mm-body");
  if(subjEl)mm.emails[mm.currentIdx].subj=subjEl.value;
  if(bodyEl)mm.emails[mm.currentIdx].body=bodyEl.value;
  mm.currentIdx=Math.max(0,Math.min(mm.leads.length-1,mm.currentIdx+dir));
  STATE.modal=renderMailMergeModal();render();
}

window.mailMergeEdit=function(field,val){
  if(!STATE.mailMerge)return;
  STATE.mailMerge.emails[STATE.mailMerge.currentIdx][field]=val;
}

window.mailMergeSend=function(){
  var mm=STATE.mailMerge;
  if(!mm)return;
  var idx=mm.currentIdx;
  var l=mm.leads[idx];
  var e=mm.emails[idx];
  if(!l.email){showToast("No email for this lead","warning");return;}
  if(mm.emails[idx].sent){showToast("Already sent to this lead","info");return;}

  // Save edits from textarea
  var subjEl=document.getElementById("mm-subj");
  var bodyEl=document.getElementById("mm-body");
  if(subjEl)e.subj=subjEl.value;
  if(bodyEl)e.body=bodyEl.value;

  var plt=STATE.user.plt||"Gmail";
  // Open in correct Gmail/Outlook account
  var url=plt==="Gmail"
    ?"https://mail.google.com/mail/u/0/?view=cm&to="+encodeURIComponent(l.email)+"&su="+encodeURIComponent(e.subj)+"&body="+encodeURIComponent(e.body)
    :"https://outlook.live.com/mail/0/deeplink/compose?to="+encodeURIComponent(l.email)+"&subject="+encodeURIComponent(e.subj)+"&body="+encodeURIComponent(e.body);
  window.open(url,"_blank");

  // Mark as sent
  mm.emails[idx].sent=true;
  mm.sent=(mm.sent||0)+1;

  // Log
  STATE.emails.push({id:"e"+Date.now(),lid:l.id,by:STATE.user.id,to:l.email,subj:e.subj,body:e.body,plt:plt,dt:todayIST(),status:"sent"});
  STATE.activities.push({id:"a"+Date.now(),lid:l.id,uid:STATE.user.id,type:"email",txt:"Email sent via mail merge ("+plt+")",dt:todayIST()});

  // Auto-advance to next unsent lead
  var next=mm.currentIdx+1;
  while(next<mm.leads.length&&mm.emails[next]&&mm.emails[next].sent)next++;
  if(next<mm.leads.length)mm.currentIdx=next;

  STATE.modal=renderMailMergeModal();render();
}

window.mailMergeSkip=function(){
  var mm=STATE.mailMerge;
  if(!mm)return;
  mm.skipped=(mm.skipped||0)+1;
  mm.currentIdx=Math.min(mm.leads.length-1,mm.currentIdx+1);
  STATE.modal=renderMailMergeModal();render();
}
// ════════════════════════════════════════════════
// MAIL MERGE ENGINE
// ════════════════════════════════════════════════
window.openMailMerge=function(ids){
  if(!ids||!ids.length)return;
  var leads=ids.map(function(id){return STATE.leads.find(function(l){return l.id===id;});}).filter(function(l){return l&&l.email;});
  if(!leads.length){showToast("No email addresses in selected leads","warning");return;}

  // Build per-lead email drafts
  var queue=leads.map(function(l){
    var co=STATE.companies.find(function(c){return c.id===l.coid;})||{name:l.coName,ind:l.coInd,loc:l.coLoc};
    return{
      lid:l.id,
      name:l.fn+" "+l.ln,
      desig:l.desig,
      company:co.name||l.coName||"",
      email:l.email,
      subj:fillEmail(STATE.emailSubj,l,co,STATE.user.name),
      body:fillEmail(STATE.emailBody,l,co,STATE.user.name),
      status:"pending"
    };
  });

  STATE.mailMerge={queue:queue,index:0};
  STATE.modal=renderMailMergeModal();
  render();
};

function renderMailMergeModal(){
  var mm=STATE.mailMerge;
  if(!mm)return"";
  var q=mm.queue;
  var i=mm.index;
  var current=q[i];
  var total=q.length;
  var sentCount=q.filter(function(x){return x.status==="sent";}).length;
  var plt=STATE.user.plt||"Gmail";
  var allDone=q.every(function(x){return x.status==="sent"||x.status==="skipped";});

  return '<div class="modal" style="width:680px;max-width:95vw;max-height:90vh;display:flex;flex-direction:column">'+
    // Header
    '<div class="mh">'+
      '<div>'+
        '<div class="mt">Mail Merge</div>'+
        '<div style="font-size:12px;color:var(--text3);margin-top:2px">'+sentCount+' sent · '+(total-sentCount-(q.filter(function(x){return x.status==="skipped";}).length))+' remaining · '+total+' total</div>'+
      '</div>'+
      '<button class="btn-icon" onclick="STATE.mailMerge=null;closeModal()">'+ico("x",14)+'</button>'+
    '</div>'+

    // Progress counter
    '<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 20px;background:var(--bg);border-bottom:1px solid var(--border)">'+
      '<div style="font-size:13px;font-weight:500;color:var(--text2)">Email <span style="color:var(--accent);font-weight:700">'+(i+1)+'</span> of <span style="font-weight:700">'+total+'</span></div>'+
      '<div style="display:flex;gap:6px;align-items:center">'+
        (sentCount>0?'<span style="font-size:12px;padding:2px 8px;background:var(--green-l);color:var(--green);border-radius:10px;font-weight:500">'+sentCount+' sent ✓</span>':"")+
        (q.filter(function(x){return x.status==="skipped";}).length>0?'<span style="font-size:12px;padding:2px 8px;background:var(--bg);color:var(--text3);border-radius:10px">'+q.filter(function(x){return x.status==="skipped";}).length+' skipped</span>':"")+
      '</div>'+
    '</div>'+

    (allDone?
      '<div style="padding:40px;text-align:center">'+
        '<div style="font-size:40px;margin-bottom:12px">✅</div>'+
        '<div style="font-family:var(--display);font-size:18px;font-weight:600;margin-bottom:6px">All done!</div>'+
        '<div style="font-size:13px;color:var(--text3);margin-bottom:20px">'+sentCount+' email'+(sentCount!==1?"s":"")+" sent successfully."+'</div>'+
        '<button class="btn btn-primary" onclick="STATE.mailMerge=null;closeModal()">Close</button>'+
      '</div>'
    :
      '<div style="padding:18px 20px;flex:1;overflow-y:auto">'+
        '<div style="display:flex;align-items:center;gap:12px;padding:10px 14px;background:var(--accent-l);border-radius:var(--r2);margin-bottom:14px;border:1px solid rgba(37,99,235,.15)">'+
          '<div style="flex:1">'+
            '<div style="font-weight:600;font-size:14px">'+htmlEsc(current.name)+'<span style="font-weight:400;color:var(--text2);font-size:12.5px"> · '+htmlEsc(current.desig||"")+'</span></div>'+
            '<div style="font-size:12px;color:var(--text3);margin-top:2px">'+htmlEsc(current.company)+' · '+htmlEsc(current.email)+'</div>'+
          '</div>'+
          (current.status==="sent"?'<span style="font-size:11px;padding:3px 9px;background:var(--green);color:#fff;border-radius:10px">✓ Sent</span>':"")+
        '</div>'+
        '<div class="fgrp">'+
          '<label class="flbl">Subject</label>'+
          '<input class="inp" id="mm-subj" value="'+htmlEsc(current.subj)+'" oninput="mmUpdateSubj(this.value)" onfocus="setVarInsertTarget(\'subject\')"/>'+
        '</div>'+
        '<div class="fgrp">'+
          '<label class="flbl">Body</label>'+
          '<textarea class="txta w100" id="mm-body" style="min-height:200px;font-size:13px;line-height:1.6" oninput="mmUpdateBody(this.value)" onfocus="setVarInsertTarget(\'body\')">'+htmlEsc(current.body)+'</textarea>'+
        '</div>'+
        renderVarChipBar('mm-subj','mm-body')+
      '</div>'+

      '<div style="padding:12px 20px;border-top:1px solid var(--border);display:flex;align-items:center;gap:10px;flex-wrap:wrap;background:var(--card)">'+
        '<button class="btn btn-outline btn-sm" onclick="mmPrev()" '+(i===0?'disabled style="opacity:.4"':'')+'>← Prev</button>'+
        '<button class="btn btn-outline btn-sm" onclick="mmNext()">Next →</button>'+
        '<button class="btn btn-outline btn-sm" style="color:var(--red);border-color:var(--red)" onclick="mmSkipAll()">Skip all</button>'+
        '<div style="flex:1"></div>'+
        '<div class="flex gap1">'+
          '<button class="fc'+(plt==="Gmail"?" on":"")+'" onclick="setPlatform(\'Gmail\')" style="font-size:12px">Gmail</button>'+
          '<button class="fc'+(plt==="Outlook"?" on":"")+'" onclick="setPlatform(\'Outlook\')" style="font-size:12px">Outlook</button>'+
        '</div>'+
        '<button class="btn btn-outline btn-sm" style="color:var(--accent);border-color:var(--accent)" onclick="mmSendAll()" title="Opens all remaining emails at once in '+plt+'">'+
          ico("send",13)+' Send all ('+q.filter(function(x){return x.status==="pending";}).length+')'+
        '</button>'+
        '<button class="btn btn-primary btn-sm" onclick="mmSend()">'+
          ico("send",13)+' Send'+(i<total-1?' & Next':' & Finish')+
        '</button>'+
      '</div>'
    )+
  '</div>';
}

window.mmGoTo=function(idx){
  STATE.mailMerge.index=idx;
  STATE.modal=renderMailMergeModal();render();
};
window.mmPrev=function(){
  if(STATE.mailMerge.index>0){STATE.mailMerge.index--;STATE.modal=renderMailMergeModal();render();}
};
window.mmNext=function(){
  var mm=STATE.mailMerge;
  if(mm.index<mm.queue.length-1){mm.index++;STATE.modal=renderMailMergeModal();render();}
};
window.mmSkip=function(){
  var mm=STATE.mailMerge;
  mm.queue[mm.index].status="skipped";
  var next=mm.queue.findIndex(function(x,idx){return idx>mm.index&&x.status==="pending";});
  if(next>=0)mm.index=next;
  STATE.modal=renderMailMergeModal();render();
};
window.mmSkipAll=function(){
  if(!confirm("Skip all remaining unsent emails?"))return;
  STATE.mailMerge.queue.forEach(function(x){if(x.status==="pending")x.status="skipped";});
  STATE.modal=renderMailMergeModal();render();
};
window.mmSendAll=function(){
  var mm=STATE.mailMerge;
  var pending=mm.queue.filter(function(x){return x.status==="pending";});
  if(!pending.length){showToast("No pending emails","info");return;}
  if(!confirm("Open all "+pending.length+" remaining emails in "+( STATE.user.plt||"Gmail")+"? Your browser may block multiple popups — allow them if prompted."))return;

  var plt=STATE.user.plt||"Gmail";
  var gmailUser=STATE.user.email||"";
  pending.forEach(function(item,idx){
    setTimeout(function(){
      // Sync any edits on current
      if(mm.queue[mm.index]===item){
        var subjEl=document.getElementById("mm-subj");
        var bodyEl=document.getElementById("mm-body");
        if(subjEl)item.subj=subjEl.value;
        if(bodyEl)item.body=bodyEl.value;
      }
      var url;
      if(plt==="Gmail"){
        url="https://mail.google.com/mail/u/0/?authuser="+encodeURIComponent(gmailUser)+
            "&view=cm&to="+encodeURIComponent(item.email)+
            "&su="+encodeURIComponent(item.subj)+
            "&body="+encodeURIComponent(item.body);
      } else {
        url="https://outlook.office.com/mail/deeplink/compose?to="+encodeURIComponent(item.email)+
            "&subject="+encodeURIComponent(item.subj)+
            "&body="+encodeURIComponent(item.body);
      }
      window.open(url,"_blank");
      item.status="sent";
      STATE.emails.push({id:"e"+Date.now()+idx,lid:item.lid,by:STATE.user.id,to:item.email,subj:item.subj,body:item.body,plt:plt,dt:todayIST(),status:"sent"});
    },idx*600); // 600ms gap between each to avoid popup blocker
  });

  // Mark all as sent after delay and refresh
  setTimeout(function(){
    STATE.modal=renderMailMergeModal();render();
    showToast(pending.length+" emails opened in "+plt,"success");
  },pending.length*600+200);
};
window.mmUpdateBody=function(v){if(STATE.mailMerge)STATE.mailMerge.queue[STATE.mailMerge.index].body=v;};

window.mmSend=function(){
  var mm=STATE.mailMerge;
  var current=mm.queue[mm.index];
  var plt=STATE.user.plt||"Gmail";

  // Sync any edits from textarea
  var subjEl=document.getElementById("mm-subj");
  var bodyEl=document.getElementById("mm-body");
  if(subjEl)current.subj=subjEl.value;
  if(bodyEl)current.body=bodyEl.value;

  // Build Gmail URL with user's actual account
  var gmailUser=STATE.user.email||"";
  var url;
  if(plt==="Gmail"){
    // authuser param forces correct Google account
    url="https://mail.google.com/mail/u/0/?authuser="+encodeURIComponent(gmailUser)+
        "&view=cm&to="+encodeURIComponent(current.email)+
        "&su="+encodeURIComponent(current.subj)+
        "&body="+encodeURIComponent(current.body);
  } else {
    url="https://outlook.office.com/mail/deeplink/compose?to="+encodeURIComponent(current.email)+
        "&subject="+encodeURIComponent(current.subj)+
        "&body="+encodeURIComponent(current.body);
  }
  window.open(url,"_blank");

  // Mark sent and log
  current.status="sent";
  STATE.emails.push({id:"e"+Date.now(),lid:current.lid,by:STATE.user.id,to:current.email,subj:current.subj,body:current.body,plt:plt,dt:todayIST(),status:"sent"});
  STATE.activities.push({id:"a"+Date.now(),lid:current.lid,uid:STATE.user.id,type:"email",txt:"Email sent via "+plt+" (mail merge)",dt:todayIST()});

  // Move to next unsent
  var next=mm.queue.findIndex(function(x,idx){return idx>mm.index&&x.status==="pending";});
  if(next>=0){mm.index=next;}
  // else stay on current (all done state will show)

  STATE.modal=renderMailMergeModal();render();
};

// Keep quickSendEmail for single row icon
window.quickSendEmail=function(lid){
  openMailMerge([lid]);
};

window.bulkSendEmail=function(){
  var ids=Object.keys(STATE.leadsSelected).filter(function(id){return STATE.leadsSelected[id];});
  openMailMerge(ids);
};
// Parse date from Excel — handles dd/mm/yyyy, yyyy-mm-dd, Excel serial numbers
function parseExcelDateToISO(v){
  if(!v)return null;
  if(!isNaN(v)){var d=new Date(Math.round((Number(v)-25569)*86400000));return d.toISOString().split('T')[0];}
  var d2=new Date(v);
  if(!isNaN(d2))return d2.toISOString().split('T')[0];
  return null;
}
function parseExcelDate(val){
  if(!val)return todayIST();
  if(typeof val==="number"){var d=new Date((val-25569)*86400000);return d.toISOString().split("T")[0];}
  var s=String(val).trim();
  if(/^\d{4}-\d{2}-\d{2}$/.test(s))return s;
  var m=s.match(/^(\d{1,2})[\/\-\.](\d{1,2})[\/\-\.](\d{4})$/);
  if(m)return m[3]+"-"+m[2].padStart(2,"0")+"-"+m[1].padStart(2,"0");
  var d2=new Date(s);
  if(!isNaN(d2))return d2.toISOString().split("T")[0];
  return todayIST();
}

window.triggerImport=function(){
  if(STATE.user&&STATE.user.isGuest){guestSimulate('importExcel',{});return;}
  var el=document.getElementById("xl-import");
  if(el){el.value="";el.click();}
}

window.importXL=function(input){
  if(!input.files||!input.files[0])return;
  var file=input.files[0];
  var reader=new FileReader();
  reader.onload=function(e){
    try{
      var data=new Uint8Array(e.target.result);
      var wb=XLSX.read(data,{type:"array"});
      var sheets=wb.SheetNames;
      STATE.importWB=wb;
      if(sheets.length===1){
        // Only one sheet — go straight to preview
        var ws=wb.Sheets[sheets[0]];
        var rows=XLSX.utils.sheet_to_json(ws,{defval:""});
        if(!rows.length){showToast("No data found in file","warning");return;}
        STATE.importPreview=rows;
        STATE.importSheet=sheets[0];
        STATE.modal=renderImportModal(rows,sheets[0]);
      } else {
        // Multiple sheets — show sheet picker first
        STATE.modal=renderSheetPickerModal(sheets);
      }
      render();
    }catch(err){showToast("Could not read file: "+err.message,"error");}
  };
  reader.readAsArrayBuffer(file);
}

function renderSheetPickerModal(sheets){
  var items=sheets.map(function(s,i){
    return '<div onclick="selectSheet(\''+htmlEsc(s)+'\')" style="display:flex;align-items:center;gap:12px;padding:12px 14px;border:1.5px solid var(--border);border-radius:var(--r2);cursor:pointer;margin-bottom:8px;transition:all .12s" onmouseenter="this.style.borderColor=\'var(--accent)\';this.style.background=\'var(--accent-l)\'" onmouseleave="this.style.borderColor=\'var(--border)\';this.style.background=\'\'">'+
      '<div style="width:32px;height:32px;background:var(--accent-l);border-radius:var(--r);display:flex;align-items:center;justify-content:center;font-weight:600;font-size:13px;color:var(--accent)">'+(i+1)+'</div>'+
      '<div><div style="font-weight:500;font-size:13.5px">'+htmlEsc(s)+'</div>'+
      '<div class="f12 text3">Sheet '+(i+1)+' of '+sheets.length+'</div></div>'+
      '<div style="margin-left:auto;color:var(--text3);font-size:18px">›</div>'+
    '</div>';
  }).join("");
  return '<div class="modal modal-w480">'+
    '<div class="mh"><div class="mt">Select sheet to import</div><button class="btn-icon" onclick="closeModal()">'+ico("x",14)+'</button></div>'+
    '<div class="mb_">'+
      '<div style="font-size:13px;color:var(--text3);margin-bottom:14px">This file has '+sheets.length+' sheets. Choose which one contains your leads.</div>'+
      items+
    '</div>'+
  '</div>';
}

window.selectSheet=function(sheetName){
  if(!STATE.importWB)return;
  var ws=STATE.importWB.Sheets[sheetName];
  var rows=XLSX.utils.sheet_to_json(ws,{defval:""});
  if(!rows.length){showToast("No data found in sheet: "+sheetName,"warning");return;}
  STATE.importPreview=rows;
  STATE.importSheet=sheetName;
  STATE.modal=renderImportModal(rows,sheetName);
  render();
}

// Column name mapping — accepts many variations
function mapCol(row, keys){
  var r={};
  Object.keys(row).forEach(function(k){
    var kl=k.toLowerCase().replace(/[\s_\-\.]/g,"");
    keys.forEach(function(pair){
      if(pair[0].some(function(v){return kl===v||kl.includes(v);})){
        if(!r[pair[1]])r[pair[1]]=String(row[k]||"").trim();
      }
    });
  });
  return r;
}

var COL_MAP=[
  [["companyname","company","firm","organisation","organization"],"company"],
  [["website","web","url","site"],"website"],
  [["industry","sector","vertical"],"industry"],
  [["location","city","place","region"],"location"],
  [["position","role","jobtitle","jobrole","openrole","vacancy","opening"],"position"],
  [["firstname","fname","first"],"firstName"],
  [["lastname","lname","last","surname"],"lastName"],
  [["designation","title","jobtitle","currenttitle"],"designation"],
  [["email","emailid","emailaddress","mail"],"email"],
  [["contact","phone","mobile","phonenumber","contactno","contactnumber"],"phone"],
  [["linkedin","linkedinurl","linkedinprofile","li"],"linkedin"],
  [["source","leadsource","foundon","platform"],"source"],
  [["date","leaddate","dateadded","createdon"],"date"],
  [["notes","note","comments","remarks"],"notes"],
  [["jobdescription","jobdesc","jd","description","requirements","jobdetails","jobposting","posting"],"jdText"],
  [["analystname","analyst","raname","researchanalyst","ra"],"analystName"],
  [["bdmassigned","bdm","bdmanager","managername","assignedto"],"bdmAssigned"],
  [["salaryrange","salary","compensation","pay","salaryband"],"salaryRange"],
  [["jobcreateddate","jobcreated","datecreated","createdate"],"jobCreatedDate"],
];

function renderImportModal(rows, sheetName){
  var sample=rows.slice(0,3);
  var cols=Object.keys(rows[0]);
  var mapped=rows.map(function(r){return mapCol(r,COL_MAP);});
  var groups=groupImportRows(mapped);
  var totalContacts=groups.reduce(function(s,g){return s+g.contacts.length;},0);
  var skippedRows=rows.length-totalContacts;
  var multiSheet=STATE.importWB&&STATE.importWB.SheetNames.length>1;

  // new companies not yet in STATE
  var newCoNames={};
  groups.forEach(function(g){
    if(!g.coName)return;
    var exists=STATE.companies.find(function(c){return c.name.toLowerCase()===g.coName.toLowerCase();});
    if(!exists)newCoNames[g.coName.toLowerCase()]=1;
  });
  var newCoCnt=Object.keys(newCoNames).length;

  // duplicate jobs (already exist client-side)
  var dupeCnt=0;
  groups.forEach(function(g){
    var exists=STATE.jobs.find(function(j){
      return j.company_name.toLowerCase()===g.coName.toLowerCase()&&
             j.position.toLowerCase()===g.position.toLowerCase();
    });
    if(exists)dupeCnt++;
  });
  var newJobs=groups.length-dupeCnt;

  var colRows=cols.map(function(c){
    var kl=c.toLowerCase().replace(/[\s_\-\.]/g,"");
    var match=COL_MAP.find(function(pair){return pair[0].some(function(v){return kl===v||kl.includes(v);});});
    var status=match?
      '<span style="color:var(--green);font-weight:500">\u2192 '+match[1]+'</span>':
      '<span style="color:var(--text3)">\u2014 not mapped</span>';
    return '<tr><td style="padding:5px 10px;font-size:12.5px">'+htmlEsc(c)+'</td><td style="padding:5px 10px">'+status+'</td></tr>';
  }).join("");

  return '<div class="modal modal-w640">'+
    '<div class="mh">'+
      '<div>'+
        '<div class="mt">Import Jobs from Excel</div>'+
        '<div style="font-size:12px;color:var(--text3);margin-top:3px">Sheet: <strong style="color:var(--accent)">'+htmlEsc(sheetName||"Sheet1")+'</strong>'+
        (multiSheet?' \u00b7 <span style="cursor:pointer;color:var(--accent);text-decoration:underline" onclick="STATE.modal=renderSheetPickerModal(STATE.importWB.SheetNames);render()">Change sheet</span>':'')+
        '</div>'+
      '</div>'+
      '<button class="btn-icon" onclick="closeModal()">'+ico("x",14)+'</button>'+
    '</div>'+
    '<div class="mb_">'+
      '<div style="padding:12px 14px;background:var(--accent-l);border-radius:var(--r2);margin-bottom:14px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;text-align:center">'+
        '<div><div style="font-size:22px;font-weight:700;color:var(--accent)">'+newJobs+'</div><div style="color:var(--text2);font-size:11px;margin-top:2px">NEW JOBS</div></div>'+
        '<div><div style="font-size:22px;font-weight:700;color:var(--teal)">'+totalContacts+'</div><div style="color:var(--text2);font-size:11px;margin-top:2px">CONTACTS</div></div>'+
        '<div><div style="font-size:22px;font-weight:700;color:var(--purple)">'+newCoCnt+'</div><div style="color:var(--text2);font-size:11px;margin-top:2px">NEW COMPANIES</div></div>'+
      '</div>'+
      (dupeCnt?'<div style="padding:8px 12px;background:var(--amber-l);border-radius:var(--r2);margin-bottom:10px;font-size:12.5px;color:var(--amber)">\u26a0 '+dupeCnt+' job'+(dupeCnt>1?'s':'')+' already exist and will be skipped.</div>':'')+
      (skippedRows?'<div style="padding:8px 12px;background:var(--bg);border-radius:var(--r2);margin-bottom:10px;font-size:12.5px;color:var(--text3)">'+skippedRows+' row'+(skippedRows>1?'s':'')+' skipped (no company/name).</div>':'')+
      '<div class="fw5 f13 mb2">Column mapping</div>'+
      '<div class="tbl-wrap mb4" style="max-height:180px;overflow-y:auto">'+
        '<table><thead><tr><th>Your column</th><th>Maps to</th></tr></thead>'+
        '<tbody>'+colRows+'</tbody></table>'+
      '</div>'+
      '<div class="fw5 f13 mb2">Preview (first 3 rows)</div>'+
      '<div style="background:var(--bg);border-radius:var(--r2);padding:10px;font-size:12px;max-height:130px;overflow-y:auto">'+
        sample.map(function(r){
          var m=mapCol(r,COL_MAP);
          return '<div style="padding:6px 0;border-bottom:1px solid var(--border);display:flex;gap:6px;flex-wrap:wrap">'+
            (m.firstName?'<span class="bdg bdg-blue">'+htmlEsc(m.firstName+(m.lastName?" "+m.lastName:""))+'</span>':"")+
            (m.company?'<span class="bdg bdg-gray">'+htmlEsc(m.company)+'</span>':"")+
            (m.position?'<span class="bdg bdg-gray">'+htmlEsc(m.position)+'</span>':"")+
            (m.email?'<span class="bdg bdg-teal" style="background:var(--teal-l);color:var(--teal)">'+htmlEsc(m.email)+'</span>':"")+
          '</div>';
        }).join("")+
      '</div>'+
    '</div>'+
    '<div class="mf">'+
      '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      (newJobs>0
        ?'<button class="btn btn-primary" onclick="confirmImport()">'+ico("plus",13)+' Import '+newJobs+' job'+(newJobs>1?'s':'')+'</button>'
        :'<button class="btn btn-primary" disabled style="opacity:.5;cursor:not-allowed">Nothing new to import</button>')+
    '</div>'+
  '</div>';
}

// ── Drop C helpers ──────────────────────────────
function groupImportRows(mapped){
  var groups={};var order=[];
  var norm=function(s){return(s||"").trim().toLowerCase().replace(/\s+/g," ");};
  mapped.forEach(function(r){
    if(!r.company&&!r.firstName){return;}
    var coKey=norm(r.company||"unknown");
    var posKey=norm(r.position||"unknown");
    var key=coKey+"||"+posKey;
    if(!groups[key]){
      groups[key]={
        coName:(r.company||"").trim(),
        website:(r.website||"").trim(),
        industry:(r.industry||"").trim(),
        location:(r.location||"").trim(),
        position:(r.position||"").trim(),
        source:(r.source||"Import").trim(),
        salaryRange:(r.salaryRange||"").trim(),
        jobCreatedDate:(r.jobCreatedDate||"").trim(),
        bdmAssigned:(r.bdmAssigned||"").trim(),
        analystName:(r.analystName||"").trim(),
        notes:"",
        jdText:"",
        contacts:[]
      };
      order.push(key);
    }
    if(r.notes){
      var noteText=(r.notes||"").trim();
      if(noteText){groups[key].notes=groups[key].notes?(groups[key].notes+"\n"+noteText):noteText;}
    }
    if(r.jdText){
      var jd=(r.jdText||"").trim();
      if(jd){groups[key].jdText=groups[key].jdText?(groups[key].jdText+"\n"+jd):jd;}
    }
    if(r.firstName||r.email){
      groups[key].contacts.push({
        first_name:(r.firstName||"").trim(),
        last_name:(r.lastName||"").trim(),
        designation:(r.designation||"").trim(),
        email:(r.email||"").trim(),
        phone:(r.phone||"").trim(),
        linkedin:(r.linkedin||"").trim()
      });
    }
  });
  return order.map(function(k){return groups[k];}).filter(function(g){return g.contacts.length>0;});
}

function renderImportProgressModal(done,total,logLines,finished,summary){
  var pct=total>0?Math.round(done/total*100):0;
  return '<div class="modal modal-w480">'+
    '<div class="mh"><div class="mt">'+(finished?'Import complete':'Importing\u2026')+'</div></div>'+
    '<div class="mb_">'+
      '<div style="margin-bottom:12px">'+
        '<div style="display:flex;justify-content:space-between;font-size:12.5px;color:var(--text2);margin-bottom:6px">'+
          '<span>'+(finished?'Done':'Processing job '+Math.min(done+1,total)+' of '+total)+'</span>'+
          '<span>'+pct+'%</span>'+
        '</div>'+
        '<div style="height:8px;background:var(--border);border-radius:99px;overflow:hidden">'+
          '<div style="height:100%;width:'+pct+'%;background:var(--accent);border-radius:99px;transition:width .3s"></div>'+
        '</div>'+
      '</div>'+
      (finished&&summary?'<div style="padding:10px 12px;background:var(--accent-l);border-radius:var(--r2);margin-bottom:10px;font-size:13px">'+htmlEsc(summary)+'</div>':'')+
      '<div style="background:var(--bg);border-radius:var(--r2);padding:8px 10px;font-size:11.5px;max-height:160px;overflow-y:auto;font-family:var(--mono);color:var(--text2)" id="import-log">'+
        (logLines.length?logLines.map(function(l){return '<div style="padding:2px 0">'+htmlEsc(l)+'</div>';}).join(''):'<div style="color:var(--text3)">Starting\u2026</div>')+
      '</div>'+
    '</div>'+
    (finished?'<div class="mf"><button class="btn btn-primary" onclick="closeModal();refreshJobs().then(function(){if(STATE.user&&(STATE.user.role===\'bd\'||STATE.user.role===\'bd_lead\')){var myJobIds=STATE.jobs.filter(function(j){return j.assigned_to_bd===STATE.user.id&&j.stage===\'Unassigned\';}).map(function(j){return j.id;});if(myJobIds.length)apiPost(\'/emails/generate\',{job_ids:myJobIds}).then(function(r){showToast(r.generated+\' emails generated\',\'success\');apiGet(\'/emails?status=pending\').then(function(d){STATE.pendingEmails=d;render();});});}});">Done</button></div>':'')+
  '</div>';
}

window.confirmImport=function(){
  if(STATE.user&&STATE.user.isGuest){guestSimulate('importExcel',{});return;}
  if(!STATE.importPreview||!STATE.importPreview.length){closeModal();return;}
  var mapped=STATE.importPreview.map(function(r){return mapCol(r,COL_MAP);});
  var groups=groupImportRows(mapped);
  STATE.importPreview=null;

  var toProcess=groups.filter(function(g){
    return !STATE.jobs.find(function(j){
      return j.company_name.toLowerCase()===g.coName.toLowerCase()&&
             j.position.toLowerCase()===g.position.toLowerCase();
    });
  });
  if(!toProcess.length){closeModal();showToast('All jobs already exist \u2014 nothing to import.','warning');return;}

  var allEmails=[];
  toProcess.forEach(function(g){
    g.contacts.forEach(function(c){if(c.email)allEmails.push(c.email.toLowerCase().trim());});
  });

  function startImport(dupEmailMap){
    STATE._pendingImport=toProcess;
    STATE._pendingDupMap=dupEmailMap||{};
    doImportProcess(toProcess,dupEmailMap||{});
  }

  if(allEmails.length){
    apiPost('/jobs/check-duplicates',{emails:allEmails}).then(function(res){
      var dupEmailMap={};
      (res.duplicates||[]).forEach(function(d){
        if(d.email){dupEmailMap[d.email.toLowerCase()]={
          position:(d.job&&d.job.position)||'',
          company:(d.job&&d.job.company&&d.job.company.name)||''
        };}
      });
      if(Object.keys(dupEmailMap).length){
        STATE._pendingImport=toProcess;
        STATE._pendingDupMap=dupEmailMap;
        STATE.modal=renderDuplicateWarningModal(toProcess,dupEmailMap);
        render();
      } else { startImport({}); }
    }).catch(function(){startImport({});});
  } else { startImport({}); }
};

function renderDuplicateWarningModal(groups,dupEmailMap){
  var dupCount=Object.keys(dupEmailMap).length;
  var items=Object.keys(dupEmailMap).slice(0,6).map(function(email){
    var d=dupEmailMap[email];
    return '<div style="padding:5px 0;border-bottom:1px solid var(--border);font-size:12px">'+
      '<span style="color:var(--amber);font-weight:600">'+htmlEsc(email)+'</span>'+
      (d.company?' \u2014 already in <strong>'+htmlEsc(d.company)+'</strong>'+(d.position?' ('+htmlEsc(d.position)+')':''):'')+
    '</div>';
  }).join('');
  return '<div class="modal modal-w480">'+
    '<div class="mh"><div class="mt">\u26a0 Duplicate emails found</div>'+
    '<button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'+
    '<div class="mb_">'+
      '<div style="padding:10px 12px;background:var(--amber-l);border-radius:var(--r2);margin-bottom:12px;font-size:13px;color:var(--amber)">'+
        '<strong>'+dupCount+' email ID'+(dupCount>1?'s':'')+' already exist</strong> in the system. These leads will be imported but flagged as <strong>DUPLICATE</strong> for the Team Lead to review.'+
      '</div>'+
      items+
      (Object.keys(dupEmailMap).length>6?'<div style="font-size:12px;color:var(--text3);padding-top:6px">+'+(Object.keys(dupEmailMap).length-6)+' more</div>':'')+
    '</div>'+
    '<div class="mf">'+
      '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" onclick="doImportProcess(STATE._pendingImport,STATE._pendingDupMap)">Proceed (flag as duplicates)</button>'+
    '</div>'+
  '</div>';
}

window.doImportProcess=function(toProcess,dupEmailMap){
  STATE.modal=null;
  var total=toProcess.length;
  STATE.modal=renderImportProgressModal(0,total,['Preparing batch\u2026 '+total+' jobs'],false,'');
  render();

  // ── Step 1: resolve all companies in bulk ──
  var newCoNames={};
  toProcess.forEach(function(g){
    var key=g.coName.toLowerCase();
    if(!STATE.companies.find(function(c){return c.name.toLowerCase()===key;})){
      newCoNames[key]=g;
    }
  });
  var newCoList=Object.values(newCoNames);

  function buildAndSend(coCache){
    // Build job payloads
    var jobPayloads=toProcess.map(function(g){
      var key=g.coName.toLowerCase();
      var coId=coCache[key];
      if(!coId)return null; // skip if company resolution failed
      var groupIsDup=g.contacts.some(function(c){return c.email&&dupEmailMap[c.email.toLowerCase().trim()];});
      var payload={
        company_id:coId,
        position:g.position||'(unknown)',
        contacts:g.contacts,
        is_duplicate:groupIsDup
      };
      if(g.location)payload.location=g.location;
      if(g.source)payload.source=g.source;
      if(g.industry)payload.industry=g.industry;
      if(g.salaryRange)payload.salary_range=g.salaryRange;
      if(g.jobCreatedDate)payload.job_created_date=parseExcelDateToISO(g.jobCreatedDate);
      if(g.bdmAssigned)payload.bdm_assigned_name=g.bdmAssigned;
      if(g.notes)payload.notes=g.notes;
      if(g.jdText)payload.jd_text=g.jdText;
      return payload;
    }).filter(Boolean);

    if(!jobPayloads.length){
      STATE.modal=renderImportProgressModal(total,total,['No valid jobs to import.'],true,'0 jobs imported.');
      render();return;
    }

    STATE.modal=renderImportProgressModal(0,total,['Uploading '+jobPayloads.length+' jobs in one batch\u2026'],false,'');
    render();

    // Single bulk API call
    apiPost('/jobs/bulk',{jobs:jobPayloads}).then(function(res){
      var summary=res.imported+' job'+(res.imported!==1?'s':'')+' imported, '+res.contacts+' contacts created.';
      var logs=[
        '\u2713 Batch complete',
        'Jobs imported: '+res.imported,
        'Contacts created: '+res.contacts,
        (Object.keys(dupEmailMap).length?' Flagged as duplicates: '+toProcess.filter(function(g){return g.contacts.some(function(c){return c.email&&dupEmailMap[c.email.toLowerCase().trim()];});}).length:'')
      ].filter(Boolean);
      STATE.modal=renderImportProgressModal(res.imported,res.imported,logs,true,summary);
      render();
    }).catch(function(err){
      var logs=['\u2717 Batch failed: '+err.message,'Check your data and try again.'];
      STATE.modal=renderImportProgressModal(0,total,logs,true,'Import failed: '+err.message);
      render();
    });
  }

  // Build company cache from existing
  var coCache={};
  STATE.companies.forEach(function(c){coCache[c.name.toLowerCase()]=c.id;});

  if(newCoList.length){
    STATE.modal=renderImportProgressModal(0,total,['Creating '+newCoList.length+' new companies\u2026'],false,'');
    render();
    // Bulk create new companies
    var coPayloads=newCoList.map(function(g){
      var p={name:g.coName};
      if(g.website)p.website=g.website;
      if(g.industry)p.industry=g.industry;
      if(g.location)p.location=g.location;
      return p;
    });
    apiPost('/companies/bulk',{companies:coPayloads}).then(function(created){
      created.forEach(function(c){
        coCache[c.name.toLowerCase()]=c.id;
        STATE.companies.push({id:c.id,name:c.name,web:'',ind:'',loc:''});
      });
      buildAndSend(coCache);
    }).catch(function(err){
      // If bulk company creation fails, fall back to individual
      var promises=coPayloads.map(function(p){
        return apiPost('/companies',p).then(function(c){
          coCache[c.name.toLowerCase()]=c.id;
          STATE.companies.push({id:c.id,name:c.name,web:'',ind:'',loc:''});
        }).catch(function(){});
      });
      Promise.all(promises).then(function(){buildAndSend(coCache);});
    });
  } else {
    buildAndSend(coCache);
  }
};



// ════════════════════════════════════════════════
// RA LEAD ENTRY FORM — Drop P
// ════════════════════════════════════════════════
function defaultRaFormResearch(){
  return{jd_raw:'',suggested_skills:[],company:{expertise:'',notes:'',headcount:'',hiring_volume:''},outreach:{angle:'',avoid:''},requirements:{skill_1:'',skill_2:'',skill_3:'',salary_min:null,salary_max:null,salary_period:'year',salary_display:'',location:'',local_hint:'',travel:''},contacts:[]};
}
function renderSuggestedSkillChips(suggested,assignHandler,skillsSource){
  assignHandler=assignHandler||'raFormAssignSkill';
  if(!suggested||!suggested.length)return '';
  var unique=[],seen={};
  suggested.forEach(function(s){
    var k=String(s||'').trim().toLowerCase();
    if(!k||seen[k])return;
    seen[k]=1;
    unique.push(String(s).trim());
  });
  if(!unique.length)return '';
  var sourceNote='';
  if(skillsSource==='title_inference')sourceNote='<div style="font-size:10.5px;color:var(--amber);margin-bottom:6px">⚠ Guessed from the job title (no JD on file) — verify before sending</div>';
  else if(skillsSource==='history_match')sourceNote='<div style="font-size:10.5px;color:var(--accent);margin-bottom:6px">Based on similar past leads (no JD on file) — verify before sending</div>';
  return '<div class="mb3" style="padding:10px 12px;background:var(--bg);border:1px solid var(--border2);border-radius:var(--r2)">'+
    sourceNote+
    '<div style="font-size:11px;color:var(--text3);margin-bottom:8px">Suggested skills — click 1, 2, or 3 to assign</div>'+
    '<div style="display:flex;flex-direction:column;gap:8px">'+
    unique.map(function(sk){
      var esc=htmlEsc(sk);
      return '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">'+
        '<span style="font-size:12px;color:var(--text);flex:1;min-width:140px">'+esc+'</span>'+
        '<span style="display:inline-flex;gap:4px">'+
          [1,2,3].map(function(slot){
            return '<button type="button" class="btn btn-outline btn-sm" style="padding:2px 8px;font-size:10px;min-width:28px" onclick="'+assignHandler+'(this)" data-skill="'+esc.replace(/"/g,'&quot;')+'" data-slot="'+slot+'">'+slot+'</button>';
          }).join('')+
        '</span></div>';
    }).join('')+
    '</div></div>';
}
function raFormEnsureResearch(){
  if(!STATE.raForm.research)STATE.raForm.research=defaultRaFormResearch();
  if(!STATE.raForm.research.company)STATE.raForm.research.company={};
  if(!STATE.raForm.research.outreach)STATE.raForm.research.outreach={};
  if(!STATE.raForm.research.requirements)STATE.raForm.research.requirements={};
  if(!STATE.raForm.research.contacts)STATE.raForm.research.contacts=[];
  // Imported leads keep parsed/inferred skills under requirements — surface them
  // at the top level so the suggested-skill chips render.
  if((!STATE.raForm.research.suggested_skills||!STATE.raForm.research.suggested_skills.length)
    &&STATE.raForm.research.requirements.suggested_skills
    &&STATE.raForm.research.requirements.suggested_skills.length){
    STATE.raForm.research.suggested_skills=STATE.raForm.research.requirements.suggested_skills.slice();
  }
  return STATE.raForm.research;
}
function buildRaFormResearchPayload(){
  var r=raFormEnsureResearch();
  var req=Object.assign({},r.requirements||{});
  syncResearchSkillsArray(req);
  if(req.salary_min!=null&&req.salary_max!=null){
    req.salary_display=req.salary_display||buildSalaryDisplay(req.salary_min,req.salary_max,req.salary_period||'year');
    req.salary_range=req.salary_display;
  }
  var hasReq=req.skill_1||req.skill_2||req.skill_3||req.salary_display||req.location||req.local_hint||req.travel;
  var hasCo=r.company.expertise||r.company.notes||r.company.headcount||r.company.hiring_volume;
  var hasOut=r.outreach.angle||r.outreach.avoid;
  var hasContacts=(r.contacts||[]).some(function(c){return c.seniority||c.decision_maker||c.best_time||c.notes;});
  if(!r.jd_raw&&!hasReq&&!hasCo&&!hasOut&&!hasContacts)return null;
  return{jd_raw:r.jd_raw||null,suggested_skills:(r.suggested_skills||[]).slice(),company:Object.assign({},r.company),outreach:Object.assign({},r.outreach),requirements:req,contacts:(r.contacts||[]).slice()};
}
function renderRaFormSalaryRange(req){
  return renderSalaryRangeControl('ra-form',req,'raForm');
}
function renderRaFormContactIntel(f){
  var r=raFormEnsureResearch();
  return f.contacts.map(function(c,idx){
    var ci=(r.contacts[idx])||{};
    var cName=htmlEsc(((c.firstName||'')+' '+(c.lastName||'')).trim())||('Contact '+(idx+1));
    var senOpts=['','Junior','Mid','Senior','Director','VP','C-Level'].map(function(v){
      return '<option value="'+v+'"'+(ci.seniority===v?' selected':'')+'>'+(v||'— Select —')+'</option>';
    }).join('');
    var dmOpts=['','Yes','No','Unknown'].map(function(v){
      return '<option value="'+v+'"'+(ci.decision_maker===v?' selected':'')+'>'+(v||'— Select —')+'</option>';
    }).join('');
    var timeOpts=['','Morning','Afternoon','Evening'].map(function(v){
      return '<option value="'+v+'"'+(ci.best_time===v?' selected':'')+'>'+(v||'— Select —')+'</option>';
    }).join('');
    return '<div style="padding:10px 0;border-bottom:1px solid var(--border)">'+
      '<div style="font-weight:500;font-size:12px;margin-bottom:8px;color:var(--text2)">'+cName+'</div>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:6px">'+
        '<div><label style="font-size:10px;color:var(--text3)">Seniority</label><select class="sel" style="font-size:12px;padding:5px 8px" onchange="raFormUpdateContactIntel('+idx+',\'seniority\',this.value)">'+senOpts+'</select></div>'+
        '<div><label style="font-size:10px;color:var(--text3)">Decision maker?</label><select class="sel" style="font-size:12px;padding:5px 8px" onchange="raFormUpdateContactIntel('+idx+',\'decision_maker\',this.value)">'+dmOpts+'</select></div>'+
        '<div><label style="font-size:10px;color:var(--text3)">Best time</label><select class="sel" style="font-size:12px;padding:5px 8px" onchange="raFormUpdateContactIntel('+idx+',\'best_time\',this.value)">'+timeOpts+'</select></div>'+
      '</div>'+
      '<input class="inp" style="font-size:12px" placeholder="Notes about this contact..." value="'+htmlEsc(ci.notes||'')+'" oninput="raFormUpdateContactIntel('+idx+',\'notes\',this.value)"/>'+
    '</div>';
  }).join('');
}
function renderRALeadForm(){
  var f=STATE.raForm;
  var isEditing=!!f.editJobId;
  var r=raFormEnsureResearch();
  var req=r.requirements||{};
  var indOpts=buildIndustrySelectOptions(f.industry||'');
  var headcountOpts=['','1-10','11-50','51-200','201-500','500+'].map(function(v){
    return '<option value="'+v+'"'+(r.company.headcount===v?' selected':'')+'>'+(v||'— Select —')+'</option>';
  }).join('');
  var hiringOpts=['','Low','Medium','High'].map(function(v){
    return '<option value="'+v+'"'+(r.company.hiring_volume===v?' selected':'')+'>'+(v||'— Select —')+'</option>';
  }).join('');

  // Company info banner
  var coBanner='';
  if(f.coInfo){
    var ci=f.coInfo;
    coBanner='<div style="margin-top:6px;padding:8px 12px;background:var(--accent-l);border-radius:var(--r);font-size:12px;color:var(--text2)">'+
      '\u2139\ufe0f <strong>'+htmlEsc(ci.name)+'</strong> already exists'+
      (ci.job_count?' \u00b7 '+ci.job_count+' open job'+(ci.job_count!==1?'s':'')+' in system':'')+
      (ci.bd_name?' \u00b7 Manager: <strong>'+htmlEsc(ci.bd_name)+'</strong>':'')+
    '</div>';
  }

  // Zip suggestions dropdown
  var zipSuggestions='';
  if(STATE.raFormZipSuggestions&&STATE.raFormZipSuggestions.length){
    zipSuggestions='<div style="position:absolute;top:100%;left:0;right:0;background:var(--card);border:1px solid var(--border2);border-radius:var(--r2);box-shadow:var(--sh2);z-index:100;margin-top:2px" id="zip-suggestions">'+
      STATE.raFormZipSuggestions.map(function(z,i){
        return '<div class="_zip-sug" data-idx="'+i+'" style="padding:9px 13px;cursor:pointer;border-bottom:1px solid var(--border);font-size:13px">'+
          htmlEsc(z.display)+'</div>';
      }).join('')+
    '</div>';
  }

  // Contact rows
  var contactRows=(f.contacts||[]).map(function(c,idx){
    var dupWarning='';
    if(c.emailDupInfo&&c.emailDupInfo.duplicate){
      var d=c.emailDupInfo;
      dupWarning='<div style="margin-top:4px;padding:6px 10px;background:var(--red-l);border-radius:var(--r);font-size:11.5px;color:var(--red)">'+
        '\u26a0 Added '+d.days_ago+' day'+(d.days_ago!==1?'s':'')+' ago'+(d.added_by?' by <strong>'+htmlEsc(d.added_by)+'</strong>':'')+
        (d.company?' at <strong>'+htmlEsc(d.company)+'</strong>':'')+'. Will be flagged duplicate.</div>';
    } else if(c.emailStatus==='ok'){
      dupWarning='<div style="margin-top:3px;font-size:11px;color:var(--green)">\u2713 Email looks good</div>';
    }
    return '<div style="background:var(--bg);border:1px solid var(--border2);border-radius:var(--r2);padding:14px;margin-bottom:10px">'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">'+
        '<div style="font-weight:600;font-size:12px;color:var(--text2)">Contact '+(idx+1)+(idx===0?' <span style="font-size:10px;color:var(--green);background:var(--green-l);padding:1px 6px;border-radius:5px;margin-left:4px">PRIMARY</span>':'')+'</div>'+
        (idx>0?'<button onclick="raFormRemoveContact('+idx+')" style="background:transparent;border:0;color:var(--red);font-size:12px;cursor:pointer">\u2715 Remove</button>':'')+
      '</div>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:8px">'+
        '<input class="inp" placeholder="First name *" value="'+htmlEsc(c.firstName||'')+'" oninput="raFormUpdateContact('+idx+',\'firstName\',this.value)"/>'+
        '<input class="inp" placeholder="Last name" value="'+htmlEsc(c.lastName||'')+'" oninput="raFormUpdateContact('+idx+',\'lastName\',this.value)"/>'+
      '</div>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:8px">'+
        '<input class="inp" placeholder="Designation" value="'+htmlEsc(c.designation||'')+'" oninput="raFormUpdateContact('+idx+',\'designation\',this.value)"/>'+
        '<div>'+
          '<input class="inp" placeholder="Email ID *" value="'+htmlEsc(c.email||'')+'" oninput="raFormUpdateContact('+idx+',\'email\',this.value)" onblur="raFormCheckEmail('+idx+',this.value)"/>'+
          dupWarning+
        '</div>'+
      '</div>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">'+
        '<input class="inp" placeholder="Phone" value="'+htmlEsc(c.phone||'')+'" oninput="raFormUpdateContact('+idx+',\'phone\',this.value)"/>'+
        '<input class="inp" placeholder="LinkedIn URL (POC\'s profile)" value="'+htmlEsc(c.linkedin||'')+'" oninput="raFormUpdateContact('+idx+',\'linkedin\',this.value)"/>'+
      '</div>'+
    '</div>';
  }).join('');

  return '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:20px;margin-bottom:8px">'+
    '<div style="font-weight:700;font-size:14px;margin-bottom:16px;color:var(--text)">'+(isEditing?'\u270f\ufe0f Edit Lead':'Add New Lead')+'</div>'+

    // ── Company ──
    '<div style="font-size:12px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">Company</div>'+
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">'+
      '<div>'+
        '<div style="position:relative">'+
          '<input class="inp" id="ra-co-name" placeholder="Company name *" value="'+htmlEsc(f.coName||'')+'" autocomplete="off" oninput="raFormCoSearch(this.value)" onblur="raFormCoBlur()" style="'+(companyCooldownCheck(f.coName)?'border-color:#f59e0b':'')+'"/>'+
          (STATE.raFormCoSuggestions&&STATE.raFormCoSuggestions.length?
            '<div style="position:absolute;top:100%;left:0;right:0;background:var(--card);border:1px solid var(--border2);border-radius:var(--r2);box-shadow:var(--sh2);z-index:100;max-height:200px;overflow-y:auto;margin-top:2px" id="co-suggestions">'+
              STATE.raFormCoSuggestions.map(function(co,i){
                var cool=companyCooldownCheck(co.name);
                return '<div class="_co-sug" data-idx="'+i+'" style="padding:9px 13px;cursor:pointer;border-bottom:1px solid var(--border);opacity:'+(cool?'.5':'1')+'">'+
                  '<div style="font-weight:500;font-size:13px">'+htmlEsc(co.name)+(cool?'<span style="margin-left:6px;font-size:10px;background:#fef3c7;color:#92400e;padding:1px 6px;border-radius:4px">Cooldown '+cool.daysLeft+'d</span>':'')+'</div>'+
                  '<div style="font-size:11px;color:var(--text3)">'+htmlEsc(co.industry||'')+(co.location?' \u00b7 '+htmlEsc(co.location):'')+( co.job_count?' \u00b7 '+co.job_count+' jobs':'')+( co.bd_name?' \u00b7 '+htmlEsc(co.bd_name):'')+'</div>'+
                '</div>';
              }).join('')+
            '</div>':'')+
        '</div>'+
        (function(){var cool=companyCooldownCheck(f.coName);return cool?'<div style="margin-top:5px;padding:8px 10px;background:#fef3c7;border:1px solid #f59e0b;border-radius:6px;font-size:11.5px;color:#92400e"><strong>⚠ 21-day cooldown active</strong> — '+htmlEsc(f.coName)+' was added '+cool.daysAgo+' day'+(cool.daysAgo!==1?'s':'')+' ago ('+htmlEsc(cool.position)+'). '+cool.daysLeft+' day'+(cool.daysLeft!==1?'s':'')+' remaining.</div>':'';})()  +
        coBanner+
      '</div>'+
      '<input class="inp" placeholder="Website" value="'+htmlEsc(f.website||'')+'" oninput="raFormSet(\'website\',this.value)"/>'+
    '</div>'+
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">'+
      '<select class="sel" onchange="raFormSet(\'industry\',this.value)">'+indOpts+'</select>'+
      '<div>'+
        '<div style="position:relative">'+
          '<input class="inp" id="ra-zip" placeholder="Zip code (e.g. 10001)" value="'+htmlEsc(f.zipCode||'')+'" autocomplete="off" oninput="raFormZipSearch(this.value)" onblur="raFormZipBlur()"/>'+
          zipSuggestions+
        '</div>'+
        '<div style="font-size:11px;color:var(--text3);margin-top:3px">Type zip to auto-fill location</div>'+
      '</div>'+
    '</div>'+
    '<div style="margin-bottom:10px">'+
      '<input class="inp" id="ra-location" placeholder="Location (City, State) *" value="'+htmlEsc(f.location||'')+'" oninput="raFormSet(\'location\',this.value)" style="border-color:'+(f.location?'var(--border)':'')+'"/>'+
      (!f.location?'<div style="font-size:11px;color:var(--red);margin-top:3px">Location is required</div>':'')+
    '</div>'+
    '<div class="fgrp mb4"><label class="flbl">Company expertise</label><input class="inp" placeholder="e.g. Healthcare staffing, ERP implementations..." value="'+htmlEsc(r.company.expertise||'')+'" oninput="raFormUpdateResearch(\'company\',\'expertise\',this.value)"/></div>'+

    // ── Job ──
    '<div style="font-size:12px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">Job Details</div>'+
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">'+
      '<input class="inp" placeholder="Job title *" value="'+htmlEsc(f.position||'')+'" oninput="raFormSet(\'position\',this.value)"/>'+
      '<input class="inp" placeholder="Job URL" value="'+htmlEsc(f.jobUrl||'')+'" oninput="raFormSet(\'jobUrl\',this.value)"/>'+
    '</div>'+
    '<div style="margin-bottom:10px">'+
      '<input class="inp" placeholder="Source (LinkedIn, Indeed...)" value="'+htmlEsc(f.source||'')+'" oninput="raFormSet(\'source\',this.value)"/>'+
    '</div>'+
    '<div style="margin-bottom:16px;max-width:280px">'+
      '<label style="font-size:11px;color:var(--text3);display:block;margin-bottom:4px">Job Created Date</label>'+
      '<input type="date" class="inp" value="'+htmlEsc(f.jobCreatedDate||'')+'" oninput="raFormSet(\'jobCreatedDate\',this.value)"/>'+
      '<div style="font-size:11px;color:var(--text3);margin-top:4px">Job opened date is set automatically when the lead is converted to a job.</div>'+
    '</div>'+

    // ── Contacts ──
    '<div style="font-size:12px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">Contacts / POCs</div>'+
    contactRows+
    '<button onclick="raFormAddContact()" style="background:transparent;border:1.5px dashed var(--border2);color:var(--text3);padding:8px 16px;border-radius:8px;font-size:12px;cursor:pointer;width:100%;margin-bottom:16px">+ Add another contact</button>'+

    // ── Job Description (requirements) ──
    '<div style="font-size:12px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">Job Description</div>'+
    '<div class="fgrp mb2"><label class="flbl">Paste job description</label>'+
      '<textarea class="txta w100" style="min-height:120px;font-size:12px" id="ra-jd-raw" placeholder="Paste the full JD here, then click Extract..." oninput="raFormUpdateResearch(\'jd_raw\',\'__root__\',this.value)">'+htmlEsc(r.jd_raw||'')+'</textarea>'+
    '</div>'+
    '<div style="margin-bottom:12px">'+
      '<button type="button" class="btn btn-outline btn-sm" onclick="raFormParseJD()">Extract requirements</button>'+
    '</div>'+
    renderSuggestedSkillChips(r.suggested_skills||[],'raFormAssignSkill',(r.requirements||{}).skills_source)+
    '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:10px">'+
      '<div class="fgrp"><label class="flbl">Skill 1</label><input class="inp" style="font-size:12px" placeholder="Primary skill from JD" value="'+htmlEsc(req.skill_1||'')+'" oninput="raFormUpdateRequirements(\'skill_1\',this.value)"/></div>'+
      '<div class="fgrp"><label class="flbl">Skill 2</label><input class="inp" style="font-size:12px" placeholder="Secondary skill" value="'+htmlEsc(req.skill_2||'')+'" oninput="raFormUpdateRequirements(\'skill_2\',this.value)"/></div>'+
      '<div class="fgrp"><label class="flbl">Skill 3</label><input class="inp" style="font-size:12px" placeholder="Third skill (optional)" value="'+htmlEsc(req.skill_3||'')+'" oninput="raFormUpdateRequirements(\'skill_3\',this.value)"/></div>'+
      renderRaFormSalaryRange(req)+
      '<div class="fgrp"><label class="flbl">Location</label><input class="inp" style="font-size:12px" placeholder="" value="'+htmlEsc(req.location||'')+'" oninput="raFormUpdateRequirements(\'location\',this.value)"/></div>'+
      '<div class="fgrp"><label class="flbl">City / local hint</label><input class="inp" style="font-size:12px" placeholder="" value="'+htmlEsc(req.local_hint||'')+'" oninput="raFormUpdateRequirements(\'local_hint\',this.value)"/></div>'+
      '<div class="fgrp"><label class="flbl">Travel</label><select class="sel" style="font-size:12px" onchange="raFormUpdateRequirements(\'travel\',this.value)">'+
        ['','none','25%','required'].map(function(v){
          var labels={'':'— Select —','none':'None','25%':'25%','required':'Required'};
          return '<option value="'+v+'"'+(req.travel===v?' selected':'')+'>'+labels[v]+'</option>';
        }).join('')+
      '</select></div>'+
    '</div>'+

    // ── Contact Intel ──
    '<div style="font-size:12px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 10px">Contact Intel</div>'+
    renderRaFormContactIntel(f)+

    // ── Company Research ──
    '<div style="font-size:12px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin:16px 0 10px">Company Research</div>'+
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">'+
      '<div><label style="font-size:11px;color:var(--text3);display:block;margin-bottom:4px">Headcount</label><select class="sel" style="font-size:12px" onchange="raFormUpdateResearch(\'company\',\'headcount\',this.value)">'+headcountOpts+'</select></div>'+
      '<div><label style="font-size:11px;color:var(--text3);display:block;margin-bottom:4px">Hiring volume</label><select class="sel" style="font-size:12px" onchange="raFormUpdateResearch(\'company\',\'hiring_volume\',this.value)">'+hiringOpts+'</select></div>'+
    '</div>'+
    '<div class="fgrp mb2"><label class="flbl">Company notes / recent news</label><textarea class="txta w100" style="min-height:60px;font-size:12px" placeholder="Any relevant company news, context..." oninput="raFormUpdateResearch(\'company\',\'notes\',this.value)">'+htmlEsc(r.company.notes||'')+'</textarea></div>'+
    '<div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin:14px 0 10px">Outreach Notes</div>'+
    '<div class="fgrp mb2"><label class="flbl">Recommended angle</label><input class="inp" style="font-size:12px" placeholder="What angle to use in outreach..." value="'+htmlEsc(r.outreach.angle||'')+'" oninput="raFormUpdateResearch(\'outreach\',\'angle\',this.value)"/></div>'+
    '<div class="fgrp mb4"><label class="flbl">What to avoid</label><input class="inp" style="font-size:12px" placeholder="Topics or approaches to avoid..." value="'+htmlEsc(r.outreach.avoid||'')+'" oninput="raFormUpdateResearch(\'outreach\',\'avoid\',this.value)"/></div>'+

    // ── Actions ──
    '<div style="display:flex;justify-content:space-between;align-items:center;padding-top:14px;border-top:1px solid var(--border)">'+
      '<button onclick="raFormClear()" style="background:transparent;border:1px solid var(--border);color:var(--text3);padding:8px 16px;border-radius:8px;font-size:13px;cursor:pointer">'+(isEditing?'Cancel edit':'Clear form')+'</button>'+
      '<button onclick="raFormSubmit()" style="background:var(--accent);color:#fff;border:0;padding:10px 24px;border-radius:8px;font-weight:600;font-size:13px;cursor:pointer'+(STATE.raFormSubmitting?';opacity:.6':'')+'">'+( STATE.raFormSubmitting?'Saving\u2026':(isEditing?'Save changes':'Submit Lead'))+'</button>'+
    '</div>'+
  '</div>';
}

// ── RA Form actions ──────────────────────────────
window.raFormUpdateResearch=function(section,field,val){
  var r=raFormEnsureResearch();
  if(section==='jd_raw'&&field==='__root__'){r.jd_raw=val;STATE.raFormTouchedAt=Date.now();return;}
  if(!r[section])r[section]={};
  r[section][field]=val;
  STATE.raFormTouchedAt=Date.now();
};
window.raFormUpdateRequirements=function(field,val){
  var r=raFormEnsureResearch();
  if(!r.requirements)r.requirements={};
  r.requirements[field]=val;
  if(field==='skill_1'||field==='skill_2'||field==='skill_3')syncResearchSkillsArray(r.requirements);
};
window.raFormAssignSkill=function(btn){
  var skill=btn.getAttribute('data-skill');
  var slot=Number(btn.getAttribute('data-slot'));
  if(!skill||!slot)return;
  var r=raFormEnsureResearch();
  if(!r.requirements)r.requirements={};
  r.requirements['skill_'+slot]=skill;
  syncResearchSkillsArray(r.requirements);
  render();
};
window.raFormUpdateContactIntel=function(idx,field,val){
  var r=raFormEnsureResearch();
  while(r.contacts.length<=idx)r.contacts.push({});
  r.contacts[idx][field]=val;
};
function raFormRefreshSalaryUi(){
  var r=raFormEnsureResearch();
  var req=r.requirements||{};
  var st=getSalaryReqState(req);
  var displayEl=document.getElementById('salary-display-ra-form');
  var fillEl=document.getElementById('salary-fill-ra-form');
  var minEl=document.getElementById('salary-min-ra-form');
  var maxEl=document.getElementById('salary-max-ra-form');
  if(displayEl)displayEl.textContent=req.salary_display||buildSalaryDisplay(st.min,st.max,st.period);
  if(fillEl){
    var leftPct=((st.min-st.cfg.min)/(st.cfg.max-st.cfg.min))*100;
    var widthPct=((st.max-st.min)/(st.cfg.max-st.cfg.min))*100;
    fillEl.style.left=leftPct+'%';
    fillEl.style.width=widthPct+'%';
  }
  if(minEl){minEl.min=st.cfg.min;minEl.max=st.cfg.max;minEl.step=st.cfg.step;minEl.value=st.min;}
  if(maxEl){maxEl.min=st.cfg.min;maxEl.max=st.cfg.max;maxEl.step=st.cfg.step;maxEl.value=st.max;}
}
window.raFormUpdateSalaryRange=function(which,val){
  var r=raFormEnsureResearch();
  if(!r.requirements)r.requirements={};
  var req=r.requirements;
  var st=getSalaryReqState(req);
  var num=Number(val);
  if(which==='min')req.salary_min=Math.min(num,st.max);
  else req.salary_max=Math.max(num,st.min);
  req.salary_display=buildSalaryDisplay(req.salary_min,req.salary_max,req.salary_period||st.period);
  req.salary_range=req.salary_display;
  raFormRefreshSalaryUi();
};
window.raFormUpdateSalaryPeriod=function(period){
  var r=raFormEnsureResearch();
  if(!r.requirements)r.requirements={};
  var req=r.requirements;
  req.salary_period=period;
  var st=getSalaryReqState(req);
  req.salary_min=st.min;
  req.salary_max=st.max;
  req.salary_display=buildSalaryDisplay(st.min,st.max,period);
  req.salary_range=req.salary_display;
  render();
};
window.raFormParseJD=function(){
  var r=raFormEnsureResearch();
  var jdEl=document.getElementById('ra-jd-raw');
  var jdText=jdEl?jdEl.value:(r.jd_raw||'');
  if(!jdText||!jdText.trim()){showToast('Paste a job description first','warning');return;}
  apiPost('/parse-jd',{jd_text:jdText,industry:STATE.raForm.industry||''}).then(function(parsed){
    r.jd_raw=jdText;
    r.requirements=Object.assign({},r.requirements||{},parsed);
    r.suggested_skills=parsed.suggested_skills||parsed.skills||[];
    var skills=r.suggested_skills;
    if(skills[0])r.requirements.skill_1=skills[0];
    if(skills[1])r.requirements.skill_2=skills[1];
    if(skills[2])r.requirements.skill_3=skills[2];
    syncResearchSkillsArray(r.requirements);
    if(parsed.travel&&!['none','25%','required'].includes(parsed.travel)){
      r.requirements.travel=parsed.travel.indexOf('25')>-1?'25%':'required';
    }
    if(parsed.salary_display)STATE.raForm.salaryRange=parsed.salary_display;
    var n=skills.length;
    showToast(n?'Extracted '+n+' skill'+(n!==1?'s':'')+' — review before submit':'Extracted — review fields before submit','success');
    render();
  }).catch(function(e){showToast('Extract failed: '+e.message,'error');});
};
window.raFormSet=function(field,val){
  STATE.raForm[field]=val;
  STATE.raFormTouchedAt=Date.now();
};

window.raFormDetectTimezone=function(location){
  if(!location)return;
  var tzMap={ny:'EST',nj:'EST',fl:'EST',ma:'EST',pa:'EST',ga:'EST',nc:'EST',sc:'EST',va:'EST',ct:'EST',oh:'EST',mi:'EST',ky:'EST',tn:'EST',tx:'CST',il:'CST',mn:'CST',wi:'CST',mo:'CST',ok:'CST',la:'CST',ar:'CST',ms:'CST',al:'CST',co:'MST',az:'MST',nm:'MST',ut:'MST',ca:'PST',wa:'PST',or:'PST',nv:'PST'};
  var loc=location.toLowerCase();
  var tz='EST';
  Object.keys(tzMap).forEach(function(state){if(loc.indexOf(state)>-1)tz=tzMap[state];});
  STATE.raForm.timezone=tz;
  var el=document.querySelector('input[placeholder="Timezone (auto-detected)"]');
  if(el)el.value=tz;
};

window.raFormEdit=function(jobId){
  var j=STATE.jobs.find(function(x){return x.id===jobId;});
  if(!j)return;
  var cs=STATE.contacts.filter(function(c){return c.job_id===jobId;})
    .sort(function(a,b){return (b.is_primary?1:0)-(a.is_primary?1:0);});
  var co=STATE.companies.find(function(c){return c.id===j.company_id;})||{};
  var savedResearch=parseResearchObject(j.research)||defaultRaFormResearch();
  STATE.raForm={
    editJobId:jobId,
    coName:j.company_name||'',coId:j.company_id,coInfo:null,
    website:co.web||'',industry:j.industry||co.ind||'',
    location:j.location||'',zipCode:'',
    position:j.position||'',jobUrl:j.job_url||'',
    salaryRange:j.salary_range||'',source:j.source||'',
    jobCreatedDate:j.job_created_date||'',
    contacts:cs.length?cs.map(function(c){
      return{firstName:c.first_name,lastName:c.last_name,designation:c.designation,
             email:c.email,phone:c.phone,linkedin:c.linkedin,emailStatus:'',emailDupInfo:null};
    }):[{firstName:'',lastName:'',designation:'',email:'',phone:'',linkedin:'',emailStatus:'',emailDupInfo:null}],
    research:JSON.parse(JSON.stringify(savedResearch))
  };
  STATE.raFormCoSuggestions=[];
  STATE.raFormZipSuggestions=[];
  // Scroll to top of page
  window.scrollTo(0,0);
  render();
};

// ── Autocomplete DOM patchers — update only the dropdown, never the whole page ──
function _patchZipSuggestions(){
  var input=document.getElementById('ra-zip');
  if(!input)return;
  var wrap=input.parentElement;if(!wrap)return;
  var existing=document.getElementById('zip-suggestions');
  var sugs=STATE.raFormZipSuggestions||[];
  if(!sugs.length){if(existing)existing.remove();return;}
  var html='<div id="zip-suggestions" style="position:absolute;top:100%;left:0;right:0;background:var(--card);border:1px solid var(--border2);border-radius:var(--r2);box-shadow:var(--sh2);z-index:100;margin-top:2px">'+
    sugs.map(function(z,i){return'<div class="_zip-sug" data-idx="'+i+'" style="padding:9px 13px;cursor:pointer;border-bottom:1px solid var(--border);font-size:13px">'+htmlEsc(z.display)+'</div>';}).join('')+'</div>';
  if(existing){existing.outerHTML=html;}else{var d=document.createElement('div');d.innerHTML=html;wrap.appendChild(d.firstChild);}
  Array.prototype.forEach.call(document.querySelectorAll('._zip-sug'),function(el){
    el.addEventListener('mouseenter',function(){this.style.background='var(--accent-l)';});
    el.addEventListener('mouseleave',function(){this.style.background='';});
    el.addEventListener('mousedown',function(e){
      e.preventDefault(); // prevent input blur before selection
      var z=STATE.raFormZipSuggestions[parseInt(this.getAttribute('data-idx'))];
      if(!z)return;
      STATE.raForm.location=z.display;STATE.raForm.zipCode=z.zip;STATE.raFormZipSuggestions=[];
      var loc=document.getElementById('ra-location');if(loc)loc.value=z.display;
      render();
    });
  });
}

function _patchCoSuggestions(){
  var input=document.getElementById('ra-co-name');
  if(!input)return;
  var wrap=input.parentElement;if(!wrap)return;
  var existing=document.getElementById('co-suggestions');
  var sugs=STATE.raFormCoSuggestions||[];
  if(!sugs.length){if(existing)existing.remove();return;}
  var html='<div id="co-suggestions" style="position:absolute;top:100%;left:0;right:0;background:var(--card);border:1px solid var(--border2);border-radius:var(--r2);box-shadow:var(--sh2);z-index:100;max-height:200px;overflow-y:auto;margin-top:2px">'+
    sugs.map(function(co,i){
      var cool=companyCooldownCheck(co.name);
      return'<div class="_co-sug" data-idx="'+i+'" style="padding:9px 13px;cursor:pointer;border-bottom:1px solid var(--border);opacity:'+(cool?'.5':'1')+'">'+
        '<div style="font-weight:500;font-size:13px">'+htmlEsc(co.name)+(cool?'<span style="margin-left:6px;font-size:10px;background:#fef3c7;color:#92400e;padding:1px 6px;border-radius:4px">Cooldown '+cool.daysLeft+'d</span>':'')+'</div>'+
        '<div style="font-size:11px;color:var(--text3)">'+htmlEsc(co.industry||'')+(co.location?' · '+htmlEsc(co.location):'')+(co.job_count?' · '+co.job_count+' jobs':'')+(co.bd_name?' · '+htmlEsc(co.bd_name):'')+'</div>'+
      '</div>';
    }).join('')+'</div>';
  if(existing){existing.outerHTML=html;}else{var d=document.createElement('div');d.innerHTML=html;wrap.appendChild(d.firstChild);}
  Array.prototype.forEach.call(document.querySelectorAll('._co-sug'),function(el){
    el.addEventListener('mouseenter',function(){this.style.background='var(--accent-l)';});
    el.addEventListener('mouseleave',function(){this.style.background='';});
    el.addEventListener('mousedown',function(e){
      e.preventDefault(); // prevent input blur before selection
      var co=STATE.raFormCoSuggestions[parseInt(this.getAttribute('data-idx'))];
      if(!co)return;
      STATE.raForm.coName=co.name;STATE.raForm.coId=co.id;STATE.raForm.coInfo=co;
      STATE.raForm.industry=co.industry||STATE.raForm.industry;
      STATE.raForm.location=co.location||STATE.raForm.location;
      STATE.raForm.website=co.website||STATE.raForm.website;
      STATE.raFormCoSuggestions=[];
      if(co.location)raFormDetectTimezone(co.location);
      render();
    });
  });
}

window.raFormZipSearch=function(val){
  STATE.raForm.zipCode=val;
  STATE.raFormTouchedAt=Date.now();
  if(!val||val.length<3){STATE.raFormZipSuggestions=[];_patchZipSuggestions();return;}
  apiGet('/lookup/zipcode?zip='+encodeURIComponent(val)).then(function(results){
    STATE.raFormZipSuggestions=results;_patchZipSuggestions();
  }).catch(function(){STATE.raFormZipSuggestions=[];_patchZipSuggestions();});
};

window.raFormZipBlur=function(){
  if(STATE._rendering)return; // blur from DOM rebuild, not user action — skip
  setTimeout(function(){STATE.raFormZipSuggestions=[];_patchZipSuggestions();},200);
};

// ── Company cooldown helper ─────────────────────
function companyCooldownCheck(coName){
  if(!coName)return null;
  var COOLDOWN_DAYS=21;
  var cutoff=new Date(Date.now()-COOLDOWN_DAYS*24*3600000);
  var match=STATE.jobs.find(function(j){
    if(j.company_name.toLowerCase()!==coName.toLowerCase())return false;
    var d=j.created_at?new Date(j.created_at):j.created_date?new Date(j.created_date):null;
    return d&&d>cutoff;
  });
  if(!match)return null;
  var daysAgo=Math.floor((Date.now()-new Date(match.created_at||match.created_date).getTime())/(24*3600000));
  var daysLeft=COOLDOWN_DAYS-daysAgo;
  return{daysLeft:daysLeft,daysAgo:daysAgo,position:match.position,addedBy:match.created_by_name||'an RA'};
}

window.raFormCoSearch=function(val){
  STATE.raForm.coName=val;STATE.raForm.coId=null;STATE.raForm.coInfo=null;
  STATE.raFormTouchedAt=Date.now();
  if(!val||val.length<3){STATE.raFormCoSuggestions=[];_patchCoSuggestions();return;}
  apiGet('/companies/search?q='+encodeURIComponent(val)).then(function(results){
    STATE.raFormCoSuggestions=results;_patchCoSuggestions();
  }).catch(function(){STATE.raFormCoSuggestions=[];});
};

window.raFormCoBlur=function(){
  if(STATE._rendering)return; // blur from DOM rebuild, not user action — skip
  setTimeout(function(){STATE.raFormCoSuggestions=[];_patchCoSuggestions();},200);
};

window.raFormCheckEmail=function(idx,email){
  if(!email||email.indexOf('@')<0)return;
  var contacts=STATE.raForm.contacts;
  apiPost('/contacts/check-email',{email:email}).then(function(res){
    contacts[idx].emailStatus=res.duplicate?'dup':'ok';
    contacts[idx].emailDupInfo=res;
    scheduleRender();
  }).catch(function(){});
};

window.raFormUpdateContact=function(idx,field,val){
  STATE.raForm.contacts[idx][field]=val;
  if(field==='email')STATE.raForm.contacts[idx].emailStatus='';
  STATE.raFormTouchedAt=Date.now();
};

window.raFormAddContact=function(){
  STATE.raForm.contacts.push({firstName:'',lastName:'',designation:'',email:'',phone:'',linkedin:'',emailStatus:'',emailDupInfo:null});
  raFormEnsureResearch().contacts.push({});
  render();
};

window.raFormRemoveContact=function(idx){
  STATE.raForm.contacts.splice(idx,1);
  var r=raFormEnsureResearch();
  if(r.contacts)r.contacts.splice(idx,1);
  render();
};

window.raFormClear=function(){
  STATE.raForm={coName:'',coId:null,coInfo:null,website:'',industry:'',location:'',zipCode:'',position:'',jobUrl:'',jobCreatedDate:'',salaryRange:'',source:'',editJobId:null,contacts:[{firstName:'',lastName:'',designation:'',email:'',phone:'',linkedin:'',emailStatus:'',emailDupInfo:null}],research:defaultRaFormResearch()};
  STATE.raFormCoSuggestions=[];
  STATE.raFormZipSuggestions=[];
  STATE.raFormTouchedAt=null;
  render();
};

window.raFormSubmit=function(){
  var f=STATE.raForm;
  if(!f.coName){showToast('Company name is required','warning');return;}
  if(!f.location){showToast('Location is required','warning');return;}
  if(!f.position){showToast('Job title is required','warning');return;}
  var validContacts=f.contacts.filter(function(c){return c.firstName||c.email;});
  if(!validContacts.length){showToast('At least one contact is required','warning');return;}
  // 21-day company cooldown check
  var cooldown=companyCooldownCheck(f.coName);
  if(cooldown){showToast(f.coName+' is in a 21-day cooldown. '+cooldown.daysLeft+' day'+(cooldown.daysLeft!==1?'s':'')+' remaining.','warning');return;}
  if(guestSimulate('addJob',{coName:f.coName,position:f.position,industry:f.industry,location:f.location,contacts:validContacts}))return;

  STATE.raFormSubmitting=true;render();

  function doSave(coId){
    var hasDup=validContacts.some(function(c){return c.emailDupInfo&&c.emailDupInfo.duplicate;});
    var researchPayload=buildRaFormResearchPayload();
    var salaryFromReq=researchPayload&&researchPayload.requirements&&researchPayload.requirements.salary_display;
    var payload={
      company_id:coId,
      position:f.position,
      stage:'Unassigned',
      source:f.source||'Manual',
      location:f.location||undefined,
      industry:f.industry||undefined,
      salary_range:salaryFromReq||f.salaryRange||undefined,
      job_created_date:f.jobCreatedDate||undefined,
      job_url:f.jobUrl||undefined,
      is_duplicate:hasDup,
      research:researchPayload||undefined,
      contacts:validContacts.map(function(c){
        return{first_name:c.firstName,last_name:c.lastName,designation:c.designation,email:c.email,phone:c.phone,linkedin:c.linkedin};
      })
    };
    var isEdit=!!f.editJobId;
    var apiCall=isEdit?apiPut('/jobs/'+f.editJobId,payload):apiPost('/jobs',payload);
    apiCall.then(function(){
      showToast(isEdit?'Lead updated':'Lead submitted successfully','success');
      STATE.raFormSubmitting=false;
      raFormClear();
      refreshJobs();
    }).catch(function(e){
      STATE.raFormSubmitting=false;
      showToast('Failed: '+e.message,'error');
      render();
    });
  }

  if(f.coId){
    doSave(f.coId);
  } else {
    // Create new company first
    var cp={name:f.coName};
    if(f.website)cp.website=f.website;
    if(f.industry)cp.industry=f.industry;
    if(f.location)cp.location=f.location;
    apiPost('/companies',cp).then(function(co){
      STATE.companies.push({id:co.id,name:co.name,web:co.website||'',ind:co.industry||'',loc:co.location||''});
      doSave(co.id);
    }).catch(function(e){
      STATE.raFormSubmitting=false;
      showToast('Failed to create company: '+e.message,'error');
      render();
    });
  }
};

// ── Export leads (RA Lead / Admin) ───────────────
window.openExportLeads=function(){
  var today=todayIST();
  var monthAgo=new Date();monthAgo.setMonth(monthAgo.getMonth()-1);
  var fromDefault=monthAgo.toISOString().split('T')[0];
  STATE.modal='<div class="modal modal-w400">'+
    '<div class="mh"><div class="mt">Export Leads</div><button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'+
    '<div class="mb_">'+
      '<div class="g2 mb3">'+
        '<div class="fgrp"><label class="flbl">From date</label><input type="date" class="inp" id="exp-from" value="'+fromDefault+'"/></div>'+
        '<div class="fgrp"><label class="flbl">To date</label><input type="date" class="inp" id="exp-to" value="'+today+'"/></div>'+
      '</div>'+
      '<div class="fgrp"><label class="flbl">Stage filter</label>'+
        '<select class="sel" id="exp-stage">'+
          '<option value="">All stages</option>'+
          ['Unassigned','Assigned','Connected','Rejected','Future','In Discussion'].map(function(s){return'<option value="'+s+'">'+s+'</option>';}).join('')+
        '</select>'+
      '</div>'+
    '</div>'+
    '<div class="mf"><button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" onclick="submitExportLeads()">'+ico('dl',13)+' Download Excel</button></div>'+
  '</div>';
  render();
};

window.submitExportLeads=function(){
  var from=(document.getElementById('exp-from')||{}).value||'';
  var to=(document.getElementById('exp-to')||{}).value||'';
  var stage=(document.getElementById('exp-stage')||{}).value||'';
  var url='/jobs/export?from='+from+'&to='+to+(stage?'&stage='+stage:'');
  closeModal();
  showToast('Preparing export\u2026','info');
  apiGet(url).then(function(data){
    if(!data||!data.length){showToast('No leads found for selected range','warning');return;}
    // Build XLSX using the XLSX library
    var rows=[['Date','Company','Website','Industry','Location','Timezone','Freshness','Job Title','Job Created Date','Job Opened Date','Salary Range','Source','BDM Assigned','Stage','First Name','Last Name','Designation','Email','Phone','LinkedIn']];
    data.forEach(function(j){
      var co=j.company||{};
      var contacts=j.contacts||[];
      if(!contacts.length)contacts=[{}];
      contacts.forEach(function(c,ci){
        rows.push([
          ci===0?(j.created_at||'').slice(0,10):'',
          ci===0?htmlEsc(co.name||''):'',
          ci===0?htmlEsc(co.website||''):'',
          ci===0?htmlEsc(j.industry||co.industry||''):'',
          ci===0?htmlEsc(j.location||co.location||''):'',
          ci===0?htmlEsc(j.timezone||''):'',
          ci===0?htmlEsc(j.freshness||''):'',
          ci===0?htmlEsc(j.position||''):'',
          ci===0?htmlEsc(j.job_created_date||''):'',
          ci===0?htmlEsc(j.job_opened_date||''):'',
          ci===0?htmlEsc(j.salary_range||''):'',
          ci===0?htmlEsc(j.source||''):'',
          ci===0?htmlEsc(j.bdm_assigned_name||''):'',
          ci===0?htmlEsc(j.stage||''):'',
          htmlEsc(c.first_name||''),
          htmlEsc(c.last_name||''),
          htmlEsc(c.designation||''),
          htmlEsc(c.email||''),
          htmlEsc(c.phone||''),
          htmlEsc(c.linkedin||'')
        ]);
      });
    });
    var ws=XLSX.utils.aoa_to_sheet(rows);
    var wb=XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb,ws,'Leads');
    XLSX.writeFile(wb,'FuteGlobal_Leads_'+from+'_to_'+to+'.xlsx');
    showToast(data.length+' leads exported','success');
  }).catch(function(e){showToast('Export failed: '+e.message,'error');});
};

// ════════════════════════════════════════════════
// INSIGHTS TAB — RA activity + RA Lead team view
// ════════════════════════════════════════════════
function renderInsights(){
  var u=STATE.user;
  var isRALead=(u.role==='ra_lead'||u.role==='admin');
  var selectedRA=STATE.insightsSelectedRA;
  var data=STATE.insightsData;

  // Admin: show RA/BD team switcher
  var isAdmin=userHasRole(u,'admin');
  var insightsTeam=STATE.insightsTeam||'ra';

  // Admin BD Team view
  if(isAdmin&&insightsTeam==='bd'&&!selectedRA){
    var allBDs=STATE.users.filter(function(x){return userHasRole(x,'bd')||userHasRole(x,'bd_lead');});
    var allJobs=STATE.jobs;
    function jAtBD(j){return j.assigned_at?new Date(j.assigned_at).toISOString().slice(0,10):'';}
    var nowBD=new Date();var todayStrBD=todayIST();
    function dAgoBD(n){var d=new Date(nowBD.getTime()+5.5*3600000);d.setDate(d.getDate()-n);return d.toISOString().slice(0,10);}
    var weekAgoBD=dAgoBD(7),monthAgoBD=dAgoBD(30);

    var bdStats=allBDs.map(function(bd){
      var bdJobs=allJobs.filter(function(j){return j.assigned_to_bd===bd.id;});
      var convJ=bdJobs.filter(function(j){return j.stage==='Connected'||j.stage==='In Discussion';});
      var posJ=bdJobs.filter(function(j){return j.stage==='Positive';});
      var sentE=(STATE.emails||[]).filter(function(e){return e.assigned_to===bd.id&&e.status==='sent';});
      var todayJ=bdJobs.filter(function(j){return jAtBD(j)===todayStrBD;});
      var weekJ=bdJobs.filter(function(j){return jAtBD(j)>=weekAgoBD;});
      var monthJ=bdJobs.filter(function(j){return jAtBD(j)>=monthAgoBD;});
      var convRate=bdJobs.length?Math.round(convJ.length/bdJobs.length*100):0;
      return{bd:bd,total:bdJobs.length,today:todayJ.length,week:weekJ.length,month:monthJ.length,conv:convJ.length,pos:posJ.length,sent:sentE.length,convRate:convRate};
    }).sort(function(a,b){return b.convRate-a.convRate;});

    var leaderBD=bdStats.find(function(r){return r.total>0&&r.convRate>0;})||(bdStats.find(function(r){return r.total>0;})||null);
    var leaderBannerBD=leaderBD?
      '<div style="background:linear-gradient(135deg,#1a3a6e,#2563eb);border-radius:var(--r2);padding:20px 24px;margin-bottom:16px;display:flex;align-items:center;gap:20px;color:#fff">'+
        '<div style="font-size:32px">\uD83C\uDFC6</div><div style="flex:1">'+
          '<div style="font-size:11px;font-weight:700;letter-spacing:.1em;opacity:.75;text-transform:uppercase;margin-bottom:4px">Top Performer</div>'+
          '<div style="font-size:20px;font-weight:700;font-family:var(--display)">'+htmlEsc(leaderBD.bd.name)+'</div>'+
          '<div style="font-size:12px;opacity:.82;margin-top:2px">'+leaderBD.convRate+'% conversion \u00b7 '+leaderBD.month+' leads this month</div></div>'+
        '<div style="text-align:right"><div style="font-size:36px;font-weight:700;font-family:var(--display);line-height:1">'+leaderBD.convRate+'%</div><div style="font-size:11px;opacity:.78">conversion</div></div>'+
      '</div>':'';

    var teamTotalBD=bdStats.reduce(function(s,r){return s+r.total;},0);
    var teamSentBD=bdStats.reduce(function(s,r){return s+r.sent;},0);
    var teamConvBD=bdStats.reduce(function(s,r){return s+r.conv;},0);
    var teamConvRateBD=teamTotalBD?Math.round(teamConvBD/teamTotalBD*100):0;

    var lbRowsBD=bdStats.map(function(r,i){
      return '<tr style="cursor:default" onmouseenter="this.style.background=\'var(--accent-l)\'" onmouseleave="this.style.background=\'\'">'+
        '<td style="padding:10px 14px;font-weight:500;font-size:13px"><div style="display:flex;align-items:center;gap:9px"><span style="font-size:11px;font-weight:700;color:var(--text3);min-width:16px">'+(i+1)+'</span>'+av(r.bd,'28')+'<span>'+htmlEsc(r.bd.name)+'</span></div></td>'+
        '<td style="padding:10px 8px;text-align:center;font-size:13px;font-weight:600;color:var(--accent)">'+r.today+'</td>'+
        '<td style="padding:10px 8px;text-align:center;font-size:13px">'+r.week+'</td>'+
        '<td style="padding:10px 8px;text-align:center;font-size:13px;font-weight:600">'+r.month+'</td>'+
        '<td style="padding:10px 8px;text-align:center;font-size:13px;color:var(--teal)">'+r.sent+'</td>'+
        '<td style="padding:10px 8px;text-align:center;font-size:13px;color:var(--green)">'+r.pos+'</td>'+
        '<td style="padding:10px 8px;text-align:center;font-size:13px;font-weight:600;color:var(--green)">'+r.convRate+'%</td>'+
      '</tr>';
    }).join('');

    var switcherBD='<div style="display:inline-flex;background:var(--bg);border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:16px">'+
      '<button onclick="STATE.insightsTeam=\'ra\';STATE.insightsSelectedRA=null;render()" style="padding:8px 20px;font-size:13px;font-weight:600;border:0;cursor:pointer;background:transparent;color:var(--text3)">RA Team</button>'+
      '<button style="padding:8px 20px;font-size:13px;font-weight:600;border:0;cursor:pointer;background:var(--accent);color:#fff;border-radius:6px">BD Team</button>'+
    '</div>';

    return '<div class="page">'+
      '<div class="ph"><div class="flex jb aic">'+
        '<div><div class="ptitle">Insights</div><div class="psub">'+allBDs.length+' BD Manager'+(allBDs.length!==1?'s':'')+' \u00b7 '+teamTotalBD+' leads \u00b7 '+teamSentBD+' emails sent</div></div>'+
      '</div></div>'+
      switcherBD+
      leaderBannerBD+
      '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px">'+
        '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--accent)">'+teamTotalBD+'</div><div style="font-size:12px;color:var(--text3);margin-top:3px">Total leads</div></div>'+
        '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--teal)">'+teamSentBD+'</div><div style="font-size:12px;color:var(--text3);margin-top:3px">Emails sent</div></div>'+
        '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--green)">'+teamConvRateBD+'%</div><div style="font-size:12px;color:var(--text3);margin-top:3px">Team conv. rate</div></div>'+
      '</div>'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden;margin-bottom:14px">'+
        '<div style="padding:12px 16px;border-bottom:1px solid var(--border);font-weight:700;font-size:13px">BD Manager performance</div>'+
        (allBDs.length?
          '<div class="tbl-wrap"><table style="width:100%;border-collapse:collapse"><thead><tr style="background:var(--bg)">'+
            '<th style="padding:9px 14px;text-align:left;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">BD Manager</th>'+
            '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Today</th>'+
            '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Week</th>'+
            '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Month</th>'+
            '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Sent</th>'+
            '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Positive</th>'+
            '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Conv %</th>'+
          '</tr></thead><tbody>'+lbRowsBD+'</tbody></table></div>':
          '<div style="padding:40px;text-align:center;color:var(--text3);font-size:13px">No BD Managers in the system yet.</div>')+
      '</div></div>';
  }

  // If RA Lead and no RA selected, show RA team overview (mirrors BD Lead layout)
  if(isRALead&&!selectedRA){
    var ras=STATE.users.filter(function(x){return x.role==='ra';});
    var now=new Date();
    var todayStr=todayIST();
    function raDaysAgo(n){var d=new Date(now.getTime()+5.5*3600000);d.setDate(d.getDate()-n);return d.toISOString().slice(0,10);}
    var weekAgo=raDaysAgo(7),monthAgo=raDaysAgo(30);

    var raStats=ras.map(function(ra){
      var raJobs=STATE.jobs.filter(function(j){return j.created_by===ra.id;});
      var todayJ=raJobs.filter(function(j){return j.created_date===todayStr;});
      var weekJ=raJobs.filter(function(j){return j.created_date>=weekAgo;});
      var monthJ=raJobs.filter(function(j){return j.created_date>=monthAgo;});
      var dups=raJobs.filter(function(j){return j.is_duplicate;}).length;
      var assigned=raJobs.filter(function(j){return j.stage!=='Unassigned';}).length;
      var conv=raJobs.filter(function(j){return j.stage==='Connected'||j.stage==='In Discussion';}).length;
      var assignPct=raJobs.length?Math.round(assigned/raJobs.length*100):0;
      var convPct=raJobs.length?Math.round(conv/raJobs.length*100):0;
      return{ra:ra,total:raJobs.length,today:todayJ.length,week:weekJ.length,month:monthJ.length,dups:dups,assigned:assigned,assignPct:assignPct,conv:conv,convPct:convPct};
    }).sort(function(a,b){return b.month-a.month;});

    var leader=raStats.find(function(r){return r.month>0;})||null;
    var leaderBanner=leader?
      '<div style="background:linear-gradient(135deg,#1a3a6e,#2563eb);border-radius:var(--r2);padding:20px 24px;margin-bottom:16px;display:flex;align-items:center;gap:20px;color:#fff">'+
        '<div style="font-size:32px">\uD83C\uDFC6</div><div style="flex:1">'+
          '<div style="font-size:11px;font-weight:700;letter-spacing:.1em;opacity:.75;text-transform:uppercase;margin-bottom:4px">Top Performer this month</div>'+
          '<div style="font-size:20px;font-weight:700;font-family:var(--display)">'+htmlEsc(leader.ra.name)+'</div>'+
          '<div style="font-size:12px;opacity:.82;margin-top:2px">'+leader.month+' leads this month \u00b7 '+leader.assignPct+'% assigned</div></div>'+
        '<div style="text-align:right"><div style="font-size:36px;font-weight:700;font-family:var(--display);line-height:1">'+leader.month+'</div><div style="font-size:11px;opacity:.78">leads</div></div>'+
      '</div>':'';

    var teamTotal=raStats.reduce(function(s,r){return s+r.total;},0);
    var teamMonth=raStats.reduce(function(s,r){return s+r.month;},0);
    var teamAssigned=raStats.reduce(function(s,r){return s+r.assigned;},0);
    var teamAssignPct=teamTotal?Math.round(teamAssigned/teamTotal*100):0;
    var teamDups=raStats.reduce(function(s,r){return s+r.dups;},0);

    var lbRows=raStats.map(function(r,i){
      return '<tr onclick="loadRAInsights(\''+r.ra.id+'\')" style="cursor:pointer" onmouseenter="this.style.background=\'var(--accent-l)\'" onmouseleave="this.style.background=\'\'">'+
        '<td style="padding:10px 14px;font-weight:500;font-size:13px"><div style="display:flex;align-items:center;gap:9px"><span style="font-size:11px;font-weight:700;color:var(--text3);min-width:16px">'+(i+1)+'</span>'+av(r.ra,'28')+'<span>'+htmlEsc(r.ra.name)+'</span></div></td>'+
        '<td style="padding:10px 8px;text-align:center;font-size:13px;font-weight:600;color:var(--accent)">'+r.today+'</td>'+
        '<td style="padding:10px 8px;text-align:center;font-size:13px">'+r.week+'</td>'+
        '<td style="padding:10px 8px;text-align:center;font-size:13px;font-weight:600">'+r.month+'</td>'+
        '<td style="padding:10px 8px;text-align:center;font-size:13px;color:var(--amber)">'+r.dups+'</td>'+
        '<td style="padding:10px 8px;text-align:center;font-size:13px;color:var(--teal)">'+r.assignPct+'%</td>'+
        '<td style="padding:10px 8px;text-align:center;font-size:13px;font-weight:600;color:var(--green)">'+r.convPct+'%</td>'+
      '</tr>';
    }).join('');

    var switcherRA=isAdmin?'<div style="display:inline-flex;background:var(--bg);border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:16px">'+
      '<button style="padding:8px 20px;font-size:13px;font-weight:600;border:0;cursor:pointer;background:var(--accent);color:#fff;border-radius:6px">RA Team</button>'+
      '<button onclick="STATE.insightsTeam=\'bd\';STATE.insightsSelectedRA=null;render()" style="padding:8px 20px;font-size:13px;font-weight:600;border:0;cursor:pointer;background:transparent;color:var(--text3)">BD Team</button>'+
    '</div>':'';

    return '<div class="page">'+
      '<div class="ph"><div class="flex jb aic">'+
        '<div><div class="ptitle">Insights</div><div class="psub">'+ras.length+' Research Analyst'+(ras.length!==1?'s':'')+' \u00b7 '+teamTotal+' leads \u00b7 '+teamAssignPct+'% assigned</div></div>'+
      '</div></div>'+
      switcherRA+
      leaderBanner+
      '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">'+
        '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--accent)">'+teamTotal+'</div><div style="font-size:12px;color:var(--text3);margin-top:3px">Total leads</div></div>'+
        '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--teal)">'+teamMonth+'</div><div style="font-size:12px;color:var(--text3);margin-top:3px">This month</div></div>'+
        '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--green)">'+teamAssignPct+'%</div><div style="font-size:12px;color:var(--text3);margin-top:3px">Assign rate</div></div>'+
        '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--amber)">'+teamDups+'</div><div style="font-size:12px;color:var(--text3);margin-top:3px">Duplicates</div></div>'+
      '</div>'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden;margin-bottom:14px">'+
        '<div style="padding:12px 16px;border-bottom:1px solid var(--border);font-weight:700;font-size:13px">RA performance <span style="font-size:11px;font-weight:400;color:var(--text3)">click a row for detail</span></div>'+
        (ras.length?
          '<div class="tbl-wrap"><table style="width:100%;border-collapse:collapse"><thead><tr style="background:var(--bg)">'+
            '<th style="padding:9px 14px;text-align:left;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Research Analyst</th>'+
            '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Today</th>'+
            '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Week</th>'+
            '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Month</th>'+
            '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Dups</th>'+
            '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Assign %</th>'+
            '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Conv %</th>'+
          '</tr></thead><tbody>'+lbRows+'</tbody></table></div>':
          '<div style="padding:40px;text-align:center;color:var(--text3);font-size:13px">No Research Analysts in the system yet.</div>')+
      '</div></div>';
  }

  // Show individual RA insights
  var raUser=isRALead?STATE.users.find(function(x){return x.id===selectedRA;}):u;
  var d=data||{total_month:0,total_week:0,total_today:0,duplicates:0,last_7_days:{},by_industry:{},by_timezone:{},by_freshness:{},by_stage:{}};

  // Bar chart for last 7 days
  var l7=d.last_7_days||{};
  var l7keys=Object.keys(l7);
  var l7max=Math.max(1,Math.max.apply(null,l7keys.map(function(k){return l7[k];})));
  var barChart=l7keys.map(function(k){
    var val=l7[k];
    var pct=Math.round(val/l7max*100);
    var day=new Date(k).toLocaleDateString('en-US',{weekday:'short'});
    return '<div style="display:flex;flex-direction:column;align-items:center;gap:4px;flex:1">'+
      '<div style="font-size:11px;font-weight:600;color:var(--accent)">'+val+'</div>'+
      '<div style="width:100%;background:var(--border);border-radius:4px;height:48px;display:flex;align-items:flex-end">'+
        '<div style="width:100%;background:var(--accent);border-radius:4px;height:'+pct+'%;min-height:'+(val>0?'4px':'0')+'"></div>'+
      '</div>'+
      '<div style="font-size:10px;color:var(--text3)">'+day+'</div>'+
    '</div>';
  }).join('');

  function categoryRows(obj,isIndustry){
    var src=isIndustry?normalizeIndustryMap(obj):obj;
    var entries=Object.keys(src).map(function(k){return{k:k,v:src[k]};}).sort(function(a,b){return b.v-a.v;});
    var total=entries.reduce(function(s,e){return s+e.v;},0)||1;
    return entries.map(function(e){
      var pct=Math.round(e.v/total*100);
      return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">'+
        '<div style="width:90px;font-size:12px;color:var(--text2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+htmlEsc(e.k)+'</div>'+
        '<div style="flex:1;background:var(--border);border-radius:99px;height:6px">'+
          '<div style="width:'+pct+'%;background:var(--accent);border-radius:99px;height:6px"></div>'+
        '</div>'+
        '<div style="width:36px;text-align:right;font-size:12px;font-weight:600">'+e.v+'</div>'+
      '</div>';
    }).join('');
  }

  return '<div class="page">'+
    '<div class="ph"><div class="flex aic gap3">'+
      (isRALead?'<button onclick="STATE.insightsSelectedRA=null;STATE.insightsData=null;render()" style="background:transparent;border:0;color:var(--text3);font-size:22px;cursor:pointer">\u2190</button>':'')+
      (raUser?av(raUser,'40'):'')+
      '<div><div class="ptitle" style="margin:0">'+(raUser?htmlEsc(raUser.name):'My')+' Insights</div>'+
        '<div class="psub" style="margin:0">Last 30 days activity</div></div>'+
    '</div></div>'+

    // ── Top stats ──
    '<div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:12px;margin-bottom:18px">'+
      [['Today',d.total_today,'var(--accent)'],['This Week',d.total_week,'var(--teal)'],['This Month',d.total_month,'var(--purple)'],['Duplicates',d.duplicates,'var(--amber)']].map(function(s){
        return '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center">'+
          '<div style="font-size:28px;font-weight:700;color:'+s[2]+'">'+s[1]+'</div>'+
          '<div style="font-size:12px;color:var(--text3);margin-top:3px">'+s[0]+'</div>'+
        '</div>';
      }).join('')+
    '</div>'+

    // ── Last 7 days bar chart ──
    '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:16px;margin-bottom:14px">'+
      '<div style="font-weight:600;font-size:13px;margin-bottom:12px">Last 7 days</div>'+
      '<div style="display:flex;gap:6px;align-items:flex-end">'+barChart+'</div>'+
    '</div>'+

    // ── Category breakdowns ──
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px">'+
        '<div style="font-weight:600;font-size:13px;margin-bottom:10px">By Industry</div>'+
        categoryRows(d.by_industry,true)+
      '</div>'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px">'+
        '<div style="font-weight:600;font-size:13px;margin-bottom:10px">By Timezone</div>'+
        categoryRows(d.by_timezone)+
      '</div>'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px">'+
        '<div style="font-weight:600;font-size:13px;margin-bottom:10px">By Freshness</div>'+
        categoryRows(d.by_freshness)+
      '</div>'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px">'+
        '<div style="font-weight:600;font-size:13px;margin-bottom:10px">By Stage</div>'+
        categoryRows(d.by_stage)+
      '</div>'+
    '</div>'+
  '</div>';
}

window.loadRAInsights=function(raId){
  STATE.insightsSelectedRA=raId;
  STATE.insightsData=null;
  render();
  apiGet('/insights/ra/'+raId).then(function(d){
    STATE.insightsData=d;render();
  }).catch(function(e){showToast('Could not load insights: '+e.message,'error');});
};

// Auto-load insights for RA on page visit
function loadMyInsights(){
  var u=STATE.user;
  if(u&&u.role==='ra'){
    apiGet('/insights/ra/'+u.id).then(function(d){STATE.insightsData=d;render();}).catch(function(){});
  }
}

// ── BD Manager: load own insights ──────────────────────────────
function loadBDInsights(){
  var u=STATE.user;
  if(!u)return;
  apiGet('/insights/bd/'+u.id).then(function(d){STATE.bdInsightsData=d;render();}).catch(function(){});
}

// ════════════════════════════════════════════════════════════════
// BD MANAGER — OWN INSIGHTS PAGE
// Metrics: email pipeline, conversion funnel, stage breakdown,
//          7-day email chart, 7-day leads chart, industry breakdown
// ════════════════════════════════════════════════════════════════
function renderBDInsights(){
  var u=STATE.user;
  var d=STATE.bdInsightsData;

  if(!d){
    return '<div class="page"><div class="ph"><div class="ptitle">My Insights</div><div class="psub">Loading your performance data\u2026</div></div>'+
      '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">'+
        ['Emails Sent','Leads','Converted','Conv Rate'].map(function(l){
          return '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--border)">—</div><div style="font-size:12px;color:var(--text3);margin-top:3px">'+l+'</div></div>';
        }).join('')+
      '</div></div>';
  }

  // ── Conversion funnel bar ──────────────────────────────────
  var funnelTotal=d.total_all||1;
  function fBar(label,val,color){
    var pct=Math.round(val/funnelTotal*100);
    return '<div style="margin-bottom:10px">'+
      '<div style="display:flex;justify-content:space-between;margin-bottom:4px">'+
        '<span style="font-size:12px;color:var(--text2)">'+label+'</span>'+
        '<span style="font-size:12px;font-weight:700;color:'+color+'">'+val+' <span style="font-weight:400;color:var(--text3)">('+pct+'%)</span></span>'+
      '</div>'+
      '<div style="background:var(--border);border-radius:99px;height:7px;overflow:hidden">'+
        '<div style="width:'+Math.max(pct,val?2:0)+'%;background:'+color+';height:100%;border-radius:99px;transition:width .4s"></div>'+
      '</div>'+
    '</div>';
  }

  var funnel=
    fBar('Assigned (in queue)',d.assigned,'var(--text3)')+
    fBar('Positive (interested)',d.positive,'var(--teal)')+
    fBar('Connected / In Discussion',d.converted,'var(--green)')+
    fBar('No Response / Negative',d.negative,'var(--red)')+
    fBar('Out of Office',d.ooo,'var(--amber)')+
    fBar('Future follow-up',d.future,'var(--purple)');

  // ── 7-day email chart ──────────────────────────────────────
  var e7=d.last_7_emails||{};
  var e7keys=Object.keys(e7).sort();
  var e7max=Math.max(1,Math.max.apply(null,e7keys.map(function(k){return e7[k];})));
  var todayStr=todayIST();
  var emailChart=e7keys.map(function(k){
    var val=e7[k]; var pct=Math.round(val/e7max*100);
    var isT=k===todayStr;
    var lbl=new Date(k+'T12:00:00').toLocaleDateString('en-US',{weekday:'short'});
    return '<div style="display:flex;flex-direction:column;align-items:center;gap:3px;flex:1">'+
      '<div style="font-size:11px;font-weight:600;color:'+(isT?'var(--green)':'var(--teal)')+'">'+val+'</div>'+
      '<div style="width:100%;background:var(--border);border-radius:4px;height:64px;display:flex;align-items:flex-end">'+
        '<div style="width:100%;background:'+(isT?'var(--green)':'var(--teal)')+';border-radius:4px;height:'+Math.max(pct,val?4:0)+'%;opacity:'+(isT?'1':'.7')+'"></div>'+
      '</div>'+
      '<div style="font-size:10px;color:'+(isT?'var(--green)':'var(--text3)')+';font-weight:'+(isT?700:400)+'">'+lbl+'</div>'+
    '</div>';
  }).join('');

  // ── 7-day leads assigned chart ─────────────────────────────
  var l7=d.last_7_leads||{};
  var l7keys=Object.keys(l7).sort();
  var l7max=Math.max(1,Math.max.apply(null,l7keys.map(function(k){return l7[k];})));
  var leadsChart=l7keys.map(function(k){
    var val=l7[k]; var pct=Math.round(val/l7max*100);
    var isT=k===todayStr;
    var lbl=new Date(k+'T12:00:00').toLocaleDateString('en-US',{weekday:'short'});
    return '<div style="display:flex;flex-direction:column;align-items:center;gap:3px;flex:1">'+
      '<div style="font-size:11px;font-weight:600;color:'+(isT?'var(--green)':'var(--accent)')+'">'+val+'</div>'+
      '<div style="width:100%;background:var(--border);border-radius:4px;height:64px;display:flex;align-items:flex-end">'+
        '<div style="width:100%;background:'+(isT?'var(--green)':'var(--accent)')+';border-radius:4px;height:'+Math.max(pct,val?4:0)+'%;opacity:'+(isT?'1':'.65')+'"></div>'+
      '</div>'+
      '<div style="font-size:10px;color:'+(isT?'var(--green)':'var(--text3)')+';font-weight:'+(isT?700:400)+'">'+lbl+'</div>'+
    '</div>';
  }).join('');

  // ── Industry breakdown ─────────────────────────────────────
  var ind=d.by_industry||{};
  var indEntries=Object.keys(ind).map(function(k){return{k:k,v:ind[k]};}).sort(function(a,b){return b.v-a.v;}).slice(0,8);
  var indTotal=indEntries.reduce(function(s,e){return s+e.v;},0)||1;
  var indRows=indEntries.map(function(e){
    var pct=Math.round(e.v/indTotal*100);
    return '<div style="display:flex;align-items:center;gap:8px;margin-bottom:7px">'+
      '<div style="width:110px;font-size:12px;color:var(--text2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;flex-shrink:0">'+htmlEsc(e.k)+'</div>'+
      '<div style="flex:1;background:var(--border);border-radius:99px;height:6px"><div style="width:'+pct+'%;background:var(--accent);border-radius:99px;height:6px"></div></div>'+
      '<div style="width:28px;text-align:right;font-size:12px;font-weight:600;flex-shrink:0">'+e.v+'</div>'+
    '</div>';
  }).join('');

  // ── Stage breakdown ────────────────────────────────────────
  var stg=d.by_stage||{};
  var stgOrder=['Connected','In Discussion','Positive','Assigned','No Response','Negative','Future','Out of Office'];
  var stgColors={Connected:'var(--green)','In Discussion':'var(--accent)',Positive:'var(--teal)',Assigned:'var(--text3)','No Response':'var(--amber)',Negative:'var(--red)',Future:'var(--purple)','Out of Office':'var(--amber)'};
  var stgRows=stgOrder.filter(function(s){return stg[s]>0;}).map(function(s){
    return '<div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border2)">'+
      '<div style="display:flex;align-items:center;gap:8px">'+
        '<div style="width:8px;height:8px;border-radius:50%;background:'+(stgColors[s]||'var(--text3)')+'"></div>'+
        '<span style="font-size:13px;color:var(--text2)">'+s+'</span>'+
      '</div>'+
      '<span style="font-size:13px;font-weight:700;color:'+(stgColors[s]||'var(--text)')+'">'+stg[s]+'</span>'+
    '</div>';
  }).join('');

  return '<div class="page">'+
    '<div class="ph"><div class="flex aic gap2">'+
      av(u,'40')+
      '<div><div class="ptitle" style="margin:0">My Insights</div><div class="psub" style="margin:0">Your personal performance dashboard</div></div>'+
    '</div></div>'+

    // ── Top 4 stat cards ──
    '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">'+
      [
        ['Emails Sent',d.emails_sent,'var(--teal)','this month'],
        ['Leads Assigned',d.total_all,'var(--accent)','total'],
        ['Converted',d.converted,'var(--green)','Connected + In Discussion'],
        ['Conv Rate',d.conv_rate+'%','var(--green)','of total leads']
      ].map(function(s){
        return '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:16px;text-align:center">'+
          '<div style="font-size:30px;font-weight:700;color:'+s[2]+';font-family:var(--display)">'+s[1]+'</div>'+
          '<div style="font-size:12px;font-weight:600;color:var(--text2);margin-top:2px">'+s[0]+'</div>'+
          '<div style="font-size:11px;color:var(--text3);margin-top:1px">'+s[3]+'</div>'+
        '</div>';
      }).join('')+
    '</div>'+

    // ── Email pipeline (today focus) ──
    '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:16px;margin-bottom:14px">'+
      '<div style="font-weight:700;font-size:13px;margin-bottom:12px">Email pipeline</div>'+
      '<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:10px">'+
        [
          ['Sent today',d.emails_sent_today,'var(--green)'],
          ['Sent (month)',d.emails_sent,'var(--teal)'],
          ['Pending',d.emails_pending,'var(--amber)'],
          ['Failed',d.emails_failed,'var(--red)'],
          ['Response rate',d.response_rate+'%','var(--accent)']
        ].map(function(s){
          return '<div style="text-align:center;padding:10px;background:var(--bg);border-radius:var(--r2)">'+
            '<div style="font-size:22px;font-weight:700;color:'+s[2]+'">'+s[1]+'</div>'+
            '<div style="font-size:11px;color:var(--text3);margin-top:3px">'+s[0]+'</div>'+
          '</div>';
        }).join('')+
      '</div>'+
    '</div>'+

    // ── This month at a glance ──
    '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:14px">'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center">'+
        '<div style="font-size:24px;font-weight:700;color:var(--accent)">'+d.total_today+'</div>'+
        '<div style="font-size:12px;color:var(--text3);margin-top:2px">Leads today</div>'+
      '</div>'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center">'+
        '<div style="font-size:24px;font-weight:700;color:var(--teal)">'+d.total_week+'</div>'+
        '<div style="font-size:12px;color:var(--text3);margin-top:2px">Leads this week</div>'+
      '</div>'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center">'+
        '<div style="font-size:24px;font-weight:700;color:var(--purple)">'+d.total_month+'</div>'+
        '<div style="font-size:12px;color:var(--text3);margin-top:2px">Leads this month</div>'+
      '</div>'+
    '</div>'+

    // ── Charts row ──
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px">'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:16px">'+
        '<div style="font-weight:600;font-size:13px;margin-bottom:12px">Emails sent — last 7 days <span style="font-size:11px;color:var(--green)">\u25cf today</span></div>'+
        '<div style="display:flex;gap:5px;align-items:flex-end">'+(emailChart||'<div style="font-size:12px;color:var(--text3)">No data</div>')+'</div>'+
      '</div>'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:16px">'+
        '<div style="font-weight:600;font-size:13px;margin-bottom:12px">Leads assigned — last 7 days</div>'+
        '<div style="display:flex;gap:5px;align-items:flex-end">'+(leadsChart||'<div style="font-size:12px;color:var(--text3)">No data</div>')+'</div>'+
      '</div>'+
    '</div>'+

    // ── Funnel + Stage + Industry ──
    '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px">'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:16px">'+
        '<div style="font-weight:700;font-size:13px;margin-bottom:12px">Conversion funnel <span style="font-size:11px;font-weight:400;color:var(--text3)">% of '+d.total_all+' leads</span></div>'+
        funnel+
      '</div>'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:16px">'+
        '<div style="font-weight:700;font-size:13px;margin-bottom:10px">Stage breakdown</div>'+
        (stgRows||'<div style="font-size:13px;color:var(--text3)">No leads yet.</div>')+
      '</div>'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:16px">'+
        '<div style="font-weight:700;font-size:13px;margin-bottom:12px">By industry</div>'+
        (indRows||'<div style="font-size:13px;color:var(--text3)">No leads yet.</div>')+
      '</div>'+
    '</div>'+

  '</div>';
}

// ════════════════════════════════════════════════════════════════
// BD LEAD — OWN TEAM INSIGHTS PAGE
// ════════════════════════════════════════════════════════════════
function renderBDLeadInsights(){
  var u=STATE.user;
  var selectedBD=STATE.bdLeadSelectedBD||null;
  var assignments=STATE.teamAssignments||[];
  var allJobs=STATE.jobs;
  function jAt(j){return j.assigned_at?new Date(j.assigned_at).toISOString().slice(0,10):'';}
  var now=new Date(); var todayStr=todayIST();
  function dAgo(n){var d=new Date(now.getTime()+5.5*3600000);d.setDate(d.getDate()-n);return d.toISOString().slice(0,10);}
  var weekAgo=dAgo(7),monthAgo=dAgo(30);

  // ── Drill-down: individual BD Manager ──
  if(selectedBD){
    var bdUser=STATE.users.find(function(x){return x.id===selectedBD;});
    if(!bdUser)return'<div class="page"><div style="padding:40px;text-align:center;color:var(--text3)">Not found</div></div>';
    var bdJobs=allJobs.filter(function(j){return j.assigned_to_bd===selectedBD;});
    var convJ=bdJobs.filter(function(j){return j.stage==='Connected'||j.stage==='In Discussion';});
    var posJ=bdJobs.filter(function(j){return j.stage==='Positive';});
    var negJ=bdJobs.filter(function(j){return j.stage==='Negative'||j.stage==='No Response';});
    var todayJ=bdJobs.filter(function(j){return jAt(j)===todayStr;});
    var weekJ=bdJobs.filter(function(j){return jAt(j)>=weekAgo;});
    var monthJ=bdJobs.filter(function(j){return jAt(j)>=monthAgo;});
    var sentE=(STATE.emails||[]).filter(function(e){return e.assigned_to===selectedBD&&e.status==='sent';});
    var pendE=(STATE.emails||[]).filter(function(e){return e.assigned_to===selectedBD&&e.status==='pending';});
    var stgColors={Connected:'var(--green)','In Discussion':'var(--accent)',Positive:'var(--teal)',Assigned:'var(--text3)','No Response':'var(--amber)',Negative:'var(--red)',Future:'var(--purple)','Out of Office':'var(--amber)'};
    var stgRows=['Connected','In Discussion','Positive','Assigned','No Response','Negative','Future','Out of Office'].map(function(s){
      var cnt=bdJobs.filter(function(j){return j.stage===s;}).length; if(!cnt)return'';
      return '<div style="display:flex;align-items:center;justify-content:space-between;padding:7px 0;border-bottom:1px solid var(--border2)">'+
        '<div style="display:flex;align-items:center;gap:8px"><div style="width:8px;height:8px;border-radius:50%;background:'+(stgColors[s]||'var(--text3)')+'"></div><span style="font-size:13px;color:var(--text2)">'+s+'</span></div>'+
        '<span style="font-size:13px;font-weight:700;color:'+(stgColors[s]||'var(--text)')+'">'+cnt+'</span></div>';
    }).join('');
    return '<div class="page">'+
      '<div class="ph"><div class="flex aic gap3">'+
        '<button onclick="STATE.bdLeadSelectedBD=null;render()" style="background:transparent;border:0;color:var(--text3);font-size:22px;cursor:pointer">\u2190</button>'+
        av(bdUser,'40')+
        '<div><div class="ptitle" style="margin:0">'+htmlEsc(bdUser.name)+'</div><div class="psub" style="margin:0">BD Manager performance</div></div>'+
      '</div></div>'+
      '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">'+
        [['Today',todayJ.length,'var(--accent)'],['This Week',weekJ.length,'var(--teal)'],['This Month',monthJ.length,'var(--purple)'],['Converted',convJ.length,'var(--green)']].map(function(s){
          return '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center"><div style="font-size:28px;font-weight:700;color:'+s[2]+'">'+s[1]+'</div><div style="font-size:12px;color:var(--text3);margin-top:3px">'+s[0]+'</div></div>';
        }).join('')+
      '</div>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">'+
        '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:16px">'+
          '<div style="font-weight:700;font-size:13px;margin-bottom:10px">Email pipeline</div>'+
          '<div style="display:flex;gap:10px;margin-bottom:10px">'+
            '<div style="flex:1;text-align:center;padding:10px;background:var(--bg);border-radius:var(--r2)"><div style="font-size:22px;font-weight:700;color:var(--green)">'+sentE.length+'</div><div style="font-size:11px;color:var(--text3)">Sent</div></div>'+
            '<div style="flex:1;text-align:center;padding:10px;background:var(--bg);border-radius:var(--r2)"><div style="font-size:22px;font-weight:700;color:var(--amber)">'+pendE.length+'</div><div style="font-size:11px;color:var(--text3)">Pending</div></div>'+
          '</div>'+
          '<div style="font-size:12px;color:var(--text3)">Conv: <strong style="color:var(--green)">'+(bdJobs.length?Math.round(convJ.length/bdJobs.length*100):0)+'%</strong> \u00b7 Positive: <strong style="color:var(--teal)">'+posJ.length+'</strong> \u00b7 Negative: <strong style="color:var(--red)">'+negJ.length+'</strong></div>'+
        '</div>'+
        '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:16px">'+
          '<div style="font-weight:700;font-size:13px;margin-bottom:10px">Stage breakdown</div>'+
          (stgRows||'<div style="font-size:13px;color:var(--text3)">No leads.</div>')+
        '</div>'+
      '</div></div>';
  }

  // ── Team overview ──
  var myBDIds=assignments.filter(function(a){return a.manager_id===u.id&&a.assignment_type==='bd_to_bdlead';}).map(function(a){return a.member_id;});
  var myBDs=STATE.users.filter(function(x){return myBDIds.indexOf(x.id)>-1;});
  var bdStats=myBDs.map(function(bd){
    var bdJobs=allJobs.filter(function(j){return j.assigned_to_bd===bd.id;});
    var convJ=bdJobs.filter(function(j){return j.stage==='Connected'||j.stage==='In Discussion';});
    var posJ=bdJobs.filter(function(j){return j.stage==='Positive';});
    var sentE=(STATE.emails||[]).filter(function(e){return e.assigned_to===bd.id&&e.status==='sent';});
    var todayJ=bdJobs.filter(function(j){return jAt(j)===todayStr;});
    var weekJ=bdJobs.filter(function(j){return jAt(j)>=weekAgo;});
    var monthJ=bdJobs.filter(function(j){return jAt(j)>=monthAgo;});
    var convRate=bdJobs.length?Math.round(convJ.length/bdJobs.length*100):0;
    return{bd:bd,total:bdJobs.length,today:todayJ.length,week:weekJ.length,month:monthJ.length,conv:convJ.length,pos:posJ.length,sent:sentE.length,convRate:convRate};
  }).sort(function(a,b){return b.convRate-a.convRate;});
  var leader=bdStats.find(function(r){return r.total>0&&r.convRate>0;})||(bdStats.find(function(r){return r.total>0;})||null);
  var leaderBanner=leader?
    '<div style="background:linear-gradient(135deg,#1a3a6e,#2563eb);border-radius:var(--r2);padding:20px 24px;margin-bottom:16px;display:flex;align-items:center;gap:20px;color:#fff">'+
      '<div style="font-size:32px">\uD83C\uDFC6</div><div style="flex:1">'+
        '<div style="font-size:11px;font-weight:700;letter-spacing:.1em;opacity:.75;text-transform:uppercase;margin-bottom:4px">Top Performer</div>'+
        '<div style="font-size:20px;font-weight:700;font-family:var(--display)">'+htmlEsc(leader.bd.name)+'</div>'+
        '<div style="font-size:12px;opacity:.82;margin-top:2px">'+leader.convRate+'% conversion \u00b7 '+leader.month+' leads this month</div></div>'+
      '<div style="text-align:right"><div style="font-size:36px;font-weight:700;font-family:var(--display);line-height:1">'+leader.convRate+'%</div><div style="font-size:11px;opacity:.78">conversion</div></div>'+
    '</div>':'';
  var teamTotal=bdStats.reduce(function(s,r){return s+r.total;},0);
  var teamSent=bdStats.reduce(function(s,r){return s+r.sent;},0);
  var teamConv=bdStats.reduce(function(s,r){return s+r.conv;},0);
  var teamConvRate=teamTotal?Math.round(teamConv/teamTotal*100):0;
  var lbRows=bdStats.map(function(r,i){
    return '<tr onclick="STATE.bdLeadSelectedBD=\''+r.bd.id+'\';render()" style="cursor:pointer" onmouseenter="this.style.background=\'var(--accent-l)\'" onmouseleave="this.style.background=\'\'">'+
      '<td style="padding:10px 14px;font-weight:500;font-size:13px"><div style="display:flex;align-items:center;gap:9px"><span style="font-size:11px;font-weight:700;color:var(--text3);min-width:16px">'+(i+1)+'</span>'+av(r.bd,'28')+'<span>'+htmlEsc(r.bd.name)+'</span></div></td>'+
      '<td style="padding:10px 8px;text-align:center;font-size:13px;font-weight:600;color:var(--accent)">'+r.today+'</td>'+
      '<td style="padding:10px 8px;text-align:center;font-size:13px">'+r.week+'</td>'+
      '<td style="padding:10px 8px;text-align:center;font-size:13px;font-weight:600">'+r.month+'</td>'+
      '<td style="padding:10px 8px;text-align:center;font-size:13px;color:var(--teal)">'+r.sent+'</td>'+
      '<td style="padding:10px 8px;text-align:center;font-size:13px;color:var(--green)">'+r.pos+'</td>'+
      '<td style="padding:10px 8px;text-align:center;font-size:13px;font-weight:600;color:var(--green)">'+r.convRate+'%</td>'+
    '</tr>';
  }).join('');
  return '<div class="page">'+
    '<div class="ph"><div class="flex jb aic">'+
      '<div><div class="ptitle">Team Insights</div><div class="psub">'+myBDs.length+' BD Manager'+(myBDs.length!==1?'s':'')+' \u00b7 '+teamTotal+' leads \u00b7 '+teamSent+' emails sent</div></div>'+
      '<button onclick="openAssignBDToLead()" style="padding:8px 16px;background:var(--accent);color:#fff;border:0;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer">+ Assign BD Manager</button>'+
    '</div></div>'+
    leaderBanner+
    '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px">'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--accent)">'+teamTotal+'</div><div style="font-size:12px;color:var(--text3);margin-top:3px">Total leads</div></div>'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--teal)">'+teamSent+'</div><div style="font-size:12px;color:var(--text3);margin-top:3px">Emails sent</div></div>'+
      '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px;text-align:center"><div style="font-size:28px;font-weight:700;color:var(--green)">'+teamConvRate+'%</div><div style="font-size:12px;color:var(--text3);margin-top:3px">Team conv. rate</div></div>'+
    '</div>'+
    '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden;margin-bottom:14px">'+
      '<div style="padding:12px 16px;border-bottom:1px solid var(--border);font-weight:700;font-size:13px">BD Manager performance <span style="font-size:11px;font-weight:400;color:var(--text3)">click a row for detail</span></div>'+
      (myBDs.length?
        '<div class="tbl-wrap"><table style="width:100%;border-collapse:collapse"><thead><tr style="background:var(--bg)">'+
          '<th style="padding:9px 14px;text-align:left;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">BD Manager</th>'+
          '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Today</th>'+
          '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Week</th>'+
          '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Month</th>'+
          '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Sent</th>'+
          '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Positive</th>'+
          '<th style="padding:9px 8px;text-align:center;font-size:10.5px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.07em">Conv %</th>'+
        '</tr></thead><tbody>'+lbRows+'</tbody></table></div>':
        '<div style="padding:40px;text-align:center;color:var(--text3);font-size:13px">No BD Managers on your team yet.<br><br>Click <strong>+ Assign BD Manager</strong> above.</div>')+
    '</div></div>';
}

window.openAssignBDToLead=function(){
  var u=STATE.user;
  var assignments=STATE.teamAssignments||[];
  var alreadyIds=assignments.filter(function(a){return a.manager_id===u.id&&a.assignment_type==='bd_to_bdlead';}).map(function(a){return a.member_id;});
  var available=STATE.users.filter(function(x){return (userHasRole(x,'bd')||userHasRole(x,'bd_lead'))&&alreadyIds.indexOf(x.id)===-1&&x.id!==u.id;});
  var opts=available.map(function(x){return '<option value="'+x.id+'">'+htmlEsc(x.name)+' ('+htmlEsc(x.email)+')</option>';}).join('');
  STATE.modal='<div class="modal modal-w400"><div class="mh"><div class="mt">Assign BD Manager to your team</div><button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'+
    '<div class="mb_">'+(available.length?'<div class="fgrp"><label class="flbl">Select BD Manager</label><select class="inp" id="assign-bd-select"><option value="">-- Choose --</option>'+opts+'</select></div>':'<div style="font-size:13px;color:var(--text3);padding:8px 0">All BD Managers already assigned or none exist.</div>')+'</div>'+
    '<div class="mf"><button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+(available.length?'<button class="btn btn-primary" onclick="submitAssignBDToLead()">Assign</button>':'')+'</div></div>';
  render();
};

window.submitAssignBDToLead=function(){
  var sel=document.getElementById('assign-bd-select');
  if(!sel||!sel.value){showToast('Select a BD Manager','warning');return;}
  var u=STATE.user;
  apiPost('/team-assignments',{manager_id:u.id,member_id:sel.value,assignment_type:'bd_to_bdlead'}).then(function(a){
    STATE.teamAssignments=(STATE.teamAssignments||[]).concat([a]);
    closeModal();showToast('BD Manager added to your team','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

// ════════════════════════════════════════════════
// RESEARCH SECTION — inside job detail modal
// ════════════════════════════════════════════════
function parseResearchObject(raw){
  if(!raw)return{};
  if(typeof raw==='string'){
    try{return JSON.parse(raw)||{};}catch(e){return{};}
  }
  return raw||{};
}
function getMergedResearch(job){
  var base=parseResearchObject(job.research);
  var draft=window._researchDraft&&window._researchDraft[job.id];
  if(!draft)return base;
  var merged=Object.assign({},base,draft);
  if(draft.company)merged.company=Object.assign({},base.company||{},draft.company);
  if(draft.outreach)merged.outreach=Object.assign({},base.outreach||{},draft.outreach);
  if(draft.requirements)merged.requirements=Object.assign({},base.requirements||{},draft.requirements);
  if(draft.contacts)merged.contacts=draft.contacts;
  if(draft.jd_raw!==undefined)merged.jd_raw=draft.jd_raw;
  return merged;
}
function canEditResearch(u,j){
  return userHasRole(u,'ra')&&!userHasAnyRole(u,'ra_lead','admin')&&j.created_by===u.id;
}
var SALARY_PERIOD_CONFIG={
  hour:{min:15,max:250,step:5,label:'per hour'},
  week:{min:400,max:15000,step:100,label:'per week'},
  year:{min:30000,max:350000,step:5000,label:'per year'}
};
function getSalaryReqState(req){
  req=req||{};
  var period=req.salary_period||'year';
  var cfg=SALARY_PERIOD_CONFIG[period]||SALARY_PERIOD_CONFIG.year;
  var min=req.salary_min!=null?Number(req.salary_min):Math.round(cfg.min+(cfg.max-cfg.min)*0.3);
  var max=req.salary_max!=null?Number(req.salary_max):Math.round(cfg.min+(cfg.max-cfg.min)*0.6);
  if(min>max){var tmp=min;min=max;max=tmp;}
  min=Math.max(cfg.min,Math.min(cfg.max,min));
  max=Math.max(cfg.min,Math.min(cfg.max,max));
  return{period:period,min:min,max:max,cfg:cfg};
}
function formatSalaryMoney(n,period){
  n=Number(n)||0;
  if(period==='year'&&n>=1000)return'$'+Math.round(n/1000)+'K';
  return'$'+n.toLocaleString();
}
function buildSalaryDisplay(min,max,period){
  var cfg=SALARY_PERIOD_CONFIG[period]||SALARY_PERIOD_CONFIG.year;
  var suffix=period==='year'?'':(' '+cfg.label);
  return formatSalaryMoney(min,period)+'–'+formatSalaryMoney(max,period)+suffix;
}
function syncResearchSkillsArray(req){
  if(!req)return;
  var list=[req.skill_1,req.skill_2,req.skill_3].map(function(s){return String(s||'').trim();}).filter(Boolean);
  req.skills=list.slice(0,3);
}
function renderSalaryRangeControl(idPrefix,req,handlerMode){
  handlerMode=handlerMode||'research';
  var st=getSalaryReqState(req);
  var display=req.salary_display||buildSalaryDisplay(st.min,st.max,st.period);
  var periodOpts=['year','week','hour'].map(function(p){
    var lbl=SALARY_PERIOD_CONFIG[p].label;
    return '<option value="'+p+'"'+(st.period===p?' selected':'')+'>'+lbl.charAt(0).toUpperCase()+lbl.slice(1)+'</option>';
  }).join('');
  var leftPct=((st.min-st.cfg.min)/(st.cfg.max-st.cfg.min))*100;
  var widthPct=((st.max-st.min)/(st.cfg.max-st.cfg.min))*100;
  var onPeriod=handlerMode==='raForm'?'raFormUpdateSalaryPeriod(this.value)':'researchUpdateSalaryPeriod(\''+idPrefix+'\',this.value)';
  var onMin=handlerMode==='raForm'?'raFormUpdateSalaryRange(\'min\',this.value)':'researchUpdateSalaryRange(\''+idPrefix+'\',\'min\',this.value)';
  var onMax=handlerMode==='raForm'?'raFormUpdateSalaryRange(\'max\',this.value)':'researchUpdateSalaryRange(\''+idPrefix+'\',\'max\',this.value)';
  return '<div class="salary-range-wrap" style="grid-column:1/-1">'+
    '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap">'+
      '<label class="flbl" style="margin:0">Salary range</label>'+
      '<select class="sel" style="font-size:12px;max-width:160px" onchange="'+onPeriod+'">'+periodOpts+'</select>'+
    '</div>'+
    '<div id="salary-display-'+idPrefix+'" style="font-size:15px;font-weight:600;color:var(--accent);margin-top:6px">'+htmlEsc(display)+'</div>'+
    '<div class="salary-range-track" id="salary-track-'+idPrefix+'">'+
      '<div class="salary-range-fill" id="salary-fill-'+idPrefix+'" style="left:'+leftPct+'%;width:'+widthPct+'%"></div>'+
      '<input type="range" id="salary-min-'+idPrefix+'" min="'+st.cfg.min+'" max="'+st.cfg.max+'" step="'+st.cfg.step+'" value="'+st.min+'" oninput="'+onMin+'"/>'+
      '<input type="range" id="salary-max-'+idPrefix+'" min="'+st.cfg.min+'" max="'+st.cfg.max+'" step="'+st.cfg.step+'" value="'+st.max+'" oninput="'+onMax+'"/>'+
    '</div>'+
    '<div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text3)">'+
      '<span>'+formatSalaryMoney(st.cfg.min,st.period)+'</span>'+
      '<span>Drag handles to set min and max</span>'+
      '<span>'+formatSalaryMoney(st.cfg.max,st.period)+'</span>'+
    '</div>'+
  '</div>';
}
function renderResearchSection(j, canEdit){
  var r=getMergedResearch(j);
  var company=r.company||{};
  var outreach=r.outreach||{};
  var req=r.requirements||{};
  var jdRaw=r.jd_raw||'';
  syncResearchSkillsArray(req);

  var headcountOpts=['','1-10','11-50','51-200','201-500','500+'].map(function(v){
    return '<option value="'+v+'"'+(company.headcount===v?' selected':'')+'>'+( v||'— Select —')+'</option>';
  }).join('');
  var hiringOpts=['','Low','Medium','High'].map(function(v){
    return '<option value="'+v+'"'+(company.hiring_volume===v?' selected':'')+'>'+( v||'— Select —')+'</option>';
  }).join('');

  // Contact intel rows
  var cs=(j.contacts||[]);
  var contactIntel=cs.map(function(c,idx){
    var ci=(r.contacts||[])[idx]||{};
    var senOpts=['','Junior','Mid','Senior','Director','VP','C-Level'].map(function(v){
      return '<option value="'+v+'"'+(ci.seniority===v?' selected':'')+'>'+( v||'— Select —')+'</option>';
    }).join('');
    var dmOpts=['','Yes','No','Unknown'].map(function(v){
      return '<option value="'+v+'"'+(ci.decision_maker===v?' selected':'')+'>'+( v||'— Select —')+'</option>';
    }).join('');
    var timeOpts=['','Morning','Afternoon','Evening'].map(function(v){
      return '<option value="'+v+'"'+(ci.best_time===v?' selected':'')+'>'+( v||'— Select —')+'</option>';
    }).join('');
    var cName=escHtml((c.first_name||'')+' '+(c.last_name||'')).trim();

    if(!canEdit){
      // Read-only for BD
      if(!ci.seniority&&!ci.decision_maker&&!ci.best_time&&!ci.notes)return '';
      return '<div style="padding:8px 0;border-bottom:1px solid var(--border)">'+
        '<div style="font-weight:500;font-size:12px;margin-bottom:4px">'+cName+'</div>'+
        '<div style="display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--text2)">'+
          (ci.seniority?'<span>\ud83d\udcbc '+htmlEsc(ci.seniority)+'</span>':'')+
          (ci.decision_maker?'<span>\ud83d\udd11 Decision maker: '+htmlEsc(ci.decision_maker)+'</span>':'')+
          (ci.best_time?'<span>\u23f0 Best time: '+htmlEsc(ci.best_time)+'</span>':'')+
          (ci.notes?'<div style="width:100%;margin-top:3px;color:var(--text3)">'+htmlEsc(ci.notes)+'</div>':'')+
        '</div>'+
      '</div>';
    }

    return '<div style="padding:10px 0;border-bottom:1px solid var(--border)">'+
      '<div style="font-weight:500;font-size:12px;margin-bottom:8px;color:var(--text2)">'+cName+'</div>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:6px">'+
        '<div><label style="font-size:10px;color:var(--text3)">Seniority</label><select class="sel" style="font-size:12px;padding:5px 8px" onchange="researchUpdateContact(\''+j.id+'\','+idx+',\'seniority\',this.value)">'+senOpts+'</select></div>'+
        '<div><label style="font-size:10px;color:var(--text3)">Decision maker?</label><select class="sel" style="font-size:12px;padding:5px 8px" onchange="researchUpdateContact(\''+j.id+'\','+idx+',\'decision_maker\',this.value)">'+dmOpts+'</select></div>'+
        '<div><label style="font-size:10px;color:var(--text3)">Best time</label><select class="sel" style="font-size:12px;padding:5px 8px" onchange="researchUpdateContact(\''+j.id+'\','+idx+',\'best_time\',this.value)">'+timeOpts+'</select></div>'+
      '</div>'+
      '<input class="inp" style="font-size:12px" placeholder="Notes about this contact..." value="'+htmlEsc(ci.notes||'')+'" oninput="researchUpdateContact(\''+j.id+'\','+idx+',\'notes\',this.value)"/>'+
    '</div>';
  }).join('');

  if(!canEdit){
    // BD read-only view
    var hasReq=req.skill_1||req.skill_2||req.skill_3||(req.skills||[]).length||req.salary_display||req.location||req.local_hint||req.travel;
    var hasData=company.headcount||company.hiring_volume||company.notes||outreach.angle||outreach.avoid||hasReq||jdRaw;
    if(!hasData&&!contactIntel.trim())return '';
    return '<div style="background:var(--bg);border:1px solid var(--border2);border-radius:var(--r2);padding:14px;margin-top:14px">'+
      '<div style="font-weight:700;font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">\ud83d\udd2c RA Research</div>'+
      (hasReq?
        '<div style="margin-bottom:10px">'+
          '<div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;margin-bottom:6px">JD requirements</div>'+
          '<div style="display:flex;gap:8px;flex-wrap:wrap;font-size:12px;color:var(--text2)">'+
            (req.skill_1?'<span style="background:var(--accent-l);color:var(--accent);padding:2px 8px;border-radius:6px">'+htmlEsc(req.skill_1)+'</span>':'')+
            (req.skill_2?'<span style="background:var(--accent-l);color:var(--accent);padding:2px 8px;border-radius:6px">'+htmlEsc(req.skill_2)+'</span>':'')+
            (req.skill_3?'<span style="background:var(--accent-l);color:var(--accent);padding:2px 8px;border-radius:6px">'+htmlEsc(req.skill_3)+'</span>':'')+
            (req.salary_display?'<span style="background:var(--bg);border:1px solid var(--border);padding:2px 8px;border-radius:6px">'+htmlEsc(req.salary_display)+'</span>':'')+
            (req.location?'<span style="background:var(--bg);border:1px solid var(--border);padding:2px 8px;border-radius:6px">'+htmlEsc(req.location)+'</span>':'')+
            (req.local_hint?'<span style="background:var(--bg);border:1px solid var(--border);padding:2px 8px;border-radius:6px">Local: '+htmlEsc(req.local_hint)+'</span>':'')+
            (req.travel?'<span style="background:var(--bg);border:1px solid var(--border);padding:2px 8px;border-radius:6px">Travel: '+htmlEsc(req.travel)+'</span>':'')+
          '</div>'+
        '</div>':'')+
      (company.expertise?
        '<div style="margin-bottom:10px">'+
          '<div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;margin-bottom:6px">Company expertise</div>'+
          '<div style="font-size:12px;color:var(--text2)">'+htmlEsc(company.expertise)+'</div>'+
        '</div>':'')+
      (contactIntel?'<div style="margin-bottom:10px"><div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;margin-bottom:6px">Contact Intel</div>'+contactIntel+'</div>':'')+
      (company.headcount||company.hiring_volume||company.notes?
        '<div style="margin-bottom:10px">'+
          '<div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;margin-bottom:6px">Company Research</div>'+
          '<div style="display:flex;gap:10px;flex-wrap:wrap;font-size:12px;color:var(--text2)">'+
            (company.headcount?'<span style="background:var(--bg);border:1px solid var(--border);padding:2px 8px;border-radius:6px">'+htmlEsc(company.headcount)+' employees</span>':'')+
            (company.hiring_volume?'<span style="background:var(--green-l);color:var(--green);padding:2px 8px;border-radius:6px">Hiring: '+htmlEsc(company.hiring_volume)+'</span>':'')+
          '</div>'+
          (company.notes?'<div style="font-size:12px;color:var(--text2);margin-top:6px;padding:8px;background:var(--card);border-radius:var(--r)">'+htmlEsc(company.notes)+'</div>':'')+
        '</div>':'')+
      (outreach.angle||outreach.avoid?
        '<div>'+
          '<div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;margin-bottom:6px">Outreach notes</div>'+
          (outreach.angle?'<div style="font-size:12px;color:var(--text2);margin-bottom:4px">\ud83c\udfaf Angle: '+htmlEsc(outreach.angle)+'</div>':'')+
          (outreach.avoid?'<div style="font-size:12px;color:var(--red)">\u26d4 Avoid: '+htmlEsc(outreach.avoid)+'</div>':'')+
        '</div>':'')+
    '</div>';
  }

  // RA editable view — JD/requirements live on lead form; here: contact intel + company research only
  return '<div style="border-top:2px solid var(--border2);margin-top:18px;padding-top:16px">'+
    '<div style="font-weight:700;font-size:13px;margin-bottom:14px">\ud83d\udd2c Research Notes</div>'+
    '<div style="font-size:12px;color:var(--text3);margin-bottom:14px">Job description and requirements are edited on the lead form. Use this section for contact intel and company research.</div>'+

    (cs.length?
      '<div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px">Contact Intel</div>'+
      contactIntel:'') +

    '<div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin:14px 0 10px">Company Research</div>'+
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">'+
      '<div><label style="font-size:11px;color:var(--text3);display:block;margin-bottom:4px">Headcount</label><select class="sel" style="font-size:12px" id="res-headcount" onchange="researchUpdate(\''+j.id+'\',\'company\',\'headcount\',this.value)">'+headcountOpts+'</select></div>'+
      '<div><label style="font-size:11px;color:var(--text3);display:block;margin-bottom:4px">Hiring volume</label><select class="sel" style="font-size:12px" id="res-hiring" onchange="researchUpdate(\''+j.id+'\',\'company\',\'hiring_volume\',this.value)">'+hiringOpts+'</select></div>'+
    '</div>'+
    '<div class="fgrp mb2"><label class="flbl">Company notes / recent news</label><textarea class="txta w100" style="min-height:60px;font-size:12px" id="res-notes" oninput="researchUpdate(\''+j.id+'\',\'company\',\'notes\',this.value)" placeholder="Any relevant company news, context...">'+htmlEsc(company.notes||'')+'</textarea></div>'+
    '<div style="font-size:11px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin:14px 0 10px">Outreach Notes</div>'+
    '<div class="fgrp mb2"><label class="flbl">Recommended angle</label><input class="inp" style="font-size:12px" placeholder="What angle to use in outreach..." value="'+htmlEsc(outreach.angle||'')+'" oninput="researchUpdate(\''+j.id+'\',\'outreach\',\'angle\',this.value)"/></div>'+
    '<div class="fgrp mb3"><label class="flbl">What to avoid</label><input class="inp" style="font-size:12px" placeholder="Topics or approaches to avoid..." value="'+htmlEsc(outreach.avoid||'')+'" oninput="researchUpdate(\''+j.id+'\',\'outreach\',\'avoid\',this.value)"/></div>'+

    '<div style="display:flex;justify-content:flex-end;padding-top:10px;border-top:1px solid var(--border2)">'+
      '<button onclick="saveResearch(\''+j.id+'\')" class="btn btn-primary btn-sm">\ud83d\udcbe Save research</button>'+
    '</div>'+
  '</div>';
}

// ── Research state management ──────────────────
if(!window._researchDraft)window._researchDraft={};

window.researchUpdate=function(jobId,section,field,val){
  if(!window._researchDraft[jobId])window._researchDraft[jobId]=JSON.parse(JSON.stringify((STATE.jobs.find(function(j){return j.id===jobId;})||{}).research||{}));
  if(section==='jd_raw'&&field==='__root__'){
    window._researchDraft[jobId].jd_raw=val;
    return;
  }
  if(!window._researchDraft[jobId][section])window._researchDraft[jobId][section]={};
  window._researchDraft[jobId][section][field]=val;
};

window.researchUpdateRequirements=function(jobId,field,val){
  if(!window._researchDraft[jobId])window._researchDraft[jobId]=JSON.parse(JSON.stringify((STATE.jobs.find(function(j){return j.id===jobId;})||{}).research||{}));
  if(!window._researchDraft[jobId].requirements)window._researchDraft[jobId].requirements={};
  window._researchDraft[jobId].requirements[field]=val;
  if(field==='skill_1'||field==='skill_2'||field==='skill_3')syncResearchSkillsArray(window._researchDraft[jobId].requirements);
};
function researchRefreshSalaryUi(jobId){
  var draft=window._researchDraft[jobId]||{};
  var req=draft.requirements||{};
  var st=getSalaryReqState(req);
  var displayEl=document.getElementById('salary-display-'+jobId);
  var fillEl=document.getElementById('salary-fill-'+jobId);
  var minEl=document.getElementById('salary-min-'+jobId);
  var maxEl=document.getElementById('salary-max-'+jobId);
  if(displayEl)displayEl.textContent=req.salary_display||buildSalaryDisplay(st.min,st.max,st.period);
  if(fillEl){
    var leftPct=((st.min-st.cfg.min)/(st.cfg.max-st.cfg.min))*100;
    var widthPct=((st.max-st.min)/(st.cfg.max-st.cfg.min))*100;
    fillEl.style.left=leftPct+'%';
    fillEl.style.width=widthPct+'%';
  }
  if(minEl){minEl.min=st.cfg.min;minEl.max=st.cfg.max;minEl.step=st.cfg.step;minEl.value=st.min;}
  if(maxEl){maxEl.min=st.cfg.min;maxEl.max=st.cfg.max;maxEl.step=st.cfg.step;maxEl.value=st.max;}
}
window.researchUpdateSalaryRange=function(jobId,which,val){
  if(!window._researchDraft[jobId])window._researchDraft[jobId]=JSON.parse(JSON.stringify((STATE.jobs.find(function(j){return j.id===jobId;})||{}).research||{}));
  if(!window._researchDraft[jobId].requirements)window._researchDraft[jobId].requirements={};
  var req=window._researchDraft[jobId].requirements;
  var st=getSalaryReqState(req);
  var num=Number(val);
  if(which==='min'){
    req.salary_min=Math.min(num,st.max);
  } else {
    req.salary_max=Math.max(num,st.min);
  }
  req.salary_display=buildSalaryDisplay(req.salary_min,req.salary_max,req.salary_period||st.period);
  req.salary_range=req.salary_display;
  researchRefreshSalaryUi(jobId);
};
window.researchUpdateSalaryPeriod=function(jobId,period){
  if(!window._researchDraft[jobId])window._researchDraft[jobId]=JSON.parse(JSON.stringify((STATE.jobs.find(function(j){return j.id===jobId;})||{}).research||{}));
  if(!window._researchDraft[jobId].requirements)window._researchDraft[jobId].requirements={};
  var req=window._researchDraft[jobId].requirements;
  req.salary_period=period;
  var st=getSalaryReqState(req);
  req.salary_min=st.min;
  req.salary_max=st.max;
  req.salary_display=buildSalaryDisplay(st.min,st.max,period);
  req.salary_range=req.salary_display;
  render();
};

window.parseJobDescription=function(jobId){
  var jdEl=document.getElementById('res-jd-raw');
  var jdText=jdEl?jdEl.value:(window._researchDraft[jobId]&&window._researchDraft[jobId].jd_raw)||'';
  if(!jdText||!jdText.trim()){showToast('Paste a job description first','warning');return;}
  var job=STATE.jobs.find(function(j){return j.id===jobId;})||{};
  var industry=job.industry||(job.company&&job.company.industry)||'';
  apiPost('/jobs/'+jobId+'/parse-jd',{jd_text:jdText,industry:industry}).then(function(parsed){
    if(!window._researchDraft[jobId])window._researchDraft[jobId]=JSON.parse(JSON.stringify(job.research||{}));
    window._researchDraft[jobId].jd_raw=jdText;
    window._researchDraft[jobId].requirements=Object.assign({},window._researchDraft[jobId].requirements||{},parsed);
    var skills=parsed.skills||[];
    window._researchDraft[jobId].suggested_skills=parsed.suggested_skills||parsed.skills||[];
    var skills=window._researchDraft[jobId].suggested_skills;
    if(skills[0])window._researchDraft[jobId].requirements.skill_1=skills[0];
    if(skills[1])window._researchDraft[jobId].requirements.skill_2=skills[1];
    if(skills[2])window._researchDraft[jobId].requirements.skill_3=skills[2];
    syncResearchSkillsArray(window._researchDraft[jobId].requirements);
    if(parsed.travel&&!['none','25%','required'].includes(parsed.travel)){
      window._researchDraft[jobId].requirements.travel=parsed.travel.indexOf('25')>-1?'25%':'required';
    }
    var n=skills.length;
    showToast(n?'Extracted '+n+' skill'+(n!==1?'s':'')+' — review and save':'Extracted — review fields and save','success');
    render();
  }).catch(function(e){showToast('Extract failed: '+e.message,'error');});
};

window.researchUpdateContact=function(jobId,idx,field,val){
  if(!window._researchDraft[jobId])window._researchDraft[jobId]={};
  if(!window._researchDraft[jobId].contacts)window._researchDraft[jobId].contacts=[];
  while(window._researchDraft[jobId].contacts.length<=idx)window._researchDraft[jobId].contacts.push({});
  window._researchDraft[jobId].contacts[idx][field]=val;
};

window.saveResearch=function(jobId){
  var draft=window._researchDraft[jobId];
  if(!draft){showToast('Nothing to save','warning');return;}
  // Merge with existing research
  var j=STATE.jobs.find(function(x){return x.id===jobId;})||{};
  var merged=Object.assign({},j.research||{},draft);
  if(draft.company)merged.company=Object.assign({},( j.research&&j.research.company)||{},draft.company);
  if(draft.outreach)merged.outreach=Object.assign({},(j.research&&j.research.outreach)||{},draft.outreach);
  if(draft.requirements)merged.requirements=Object.assign({},(j.research&&j.research.requirements)||{},draft.requirements);
  if(draft.jd_raw!==undefined)merged.jd_raw=draft.jd_raw;
  if(draft.contacts)merged.contacts=draft.contacts;
  if(draft.suggested_skills)merged.suggested_skills=draft.suggested_skills;
  if(merged.requirements){
    syncResearchSkillsArray(merged.requirements);
    if(!merged.requirements.salary_display&&merged.requirements.salary_min!=null&&merged.requirements.salary_max!=null){
      merged.requirements.salary_display=buildSalaryDisplay(merged.requirements.salary_min,merged.requirements.salary_max,merged.requirements.salary_period||'year');
      merged.requirements.salary_range=merged.requirements.salary_display;
    }
  }
  apiFetch('PATCH','/jobs/'+jobId+'/research',{research:merged}).then(function(res){
    var saved=parseResearchObject((res&&res.research)||merged);
    STATE.jobs=STATE.jobs.map(function(x){return x.id===jobId?Object.assign({},x,{research:saved}):x;});
    delete window._researchDraft[jobId];
    showToast('Research saved','success');
    render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

// ════════════════════════════════════════════════
// DROP G — Email status + OOO + Reminder actions
// ════════════════════════════════════════════════
window.changeEmailStatus=function(cid, newStatus, email, contactName){
  if(newStatus==='out_of_office'){
    // Show OOO date picker modal
    STATE.modal='<div class="modal modal-w480">'+
      '<div class="mh"><div class="mt">Out of Office — '+htmlEsc(contactName)+'</div>'+
      '<button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'+
      '<div class="mb_">'+
        '<div style="font-size:13px;color:var(--text2);margin-bottom:14px">'+
          htmlEsc(contactName)+' ('+htmlEsc(email)+') will be marked as Out of Office.<br>'+
          'A reminder will be created for their return date and shown on your dashboard.'+
        '</div>'+
        '<div class="fgrp"><label class="flbl">Out of office until <span style="color:var(--red)">*</span></label>'+
          '<input type="date" class="inp" id="ooo-date-inp" style="font-size:13px" min="'+todayIST()+'"/>'+
        '</div>'+
      '</div>'+
      '<div class="mf">'+
        '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
        '<button class="btn btn-primary" onclick="submitOOO(\''+cid+'\',\''+htmlEsc(contactName)+'\')">Set OOO & Create Reminder</button>'+
      '</div>'+
    '</div>';
    render();
  } else {
    // Directly update status
    apiFetch('PATCH','/contacts/'+cid+'/email-status',{email_status:newStatus}).then(function(){
      showToast(htmlEsc(contactName)+' marked as '+(newStatus==='valid'?'Valid':newStatus),'success');
      return refreshJobs();
    }).catch(function(e){showToast('Failed: '+e.message,'error');});
  }
};

window.submitOOO=function(cid, contactName){
  var dateEl=document.getElementById('ooo-date-inp');
  if(!dateEl||!dateEl.value){showToast('Please pick a return date','warning');return;}
  var oooUntil=dateEl.value;
  closeModal();
  apiFetch('PATCH','/contacts/'+cid+'/email-status',{email_status:'out_of_office',ooo_until:oooUntil}).then(function(){
    showToast(htmlEsc(contactName)+' marked OOO until '+oooUntil+' \u2014 reminder created','success');
    return Promise.all([refreshJobs(), loadReminders()]);
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

function loadReminders(){
  return apiGet('/reminders').then(function(d){
    STATE.reminders=d;render();
  }).catch(function(){});
}

// ════════════════════════════════════════════════
// EMAIL ACTIONS — Drop F
// ════════════════════════════════════════════════
window.previewPendingEmail=function(id){STATE.previewPendingId=id;render();};

window.openSendAllConfirm=function(){
  var pending=STATE.pendingEmails||[];
  if(!pending.length){showToast('No pending emails','warning');return;}
  var now=new Date();
  var dateStr=now.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'});
  var timeStr=now.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'});
  STATE.modal='<div class="modal modal-w480">'+
    '<div class="mh"><div class="mt">Confirm: Send all pending</div></div>'+
    '<div class="mb_">'+
      '<div style="padding:16px;background:var(--accent-l);border-radius:var(--r2);margin-bottom:12px">'+
        '<div style="font-size:22px;font-weight:700;color:var(--accent);margin-bottom:4px">'+pending.length+' emails</div>'+
        '<div style="font-size:14px;color:var(--text2)">→ '+pending.length+' recipients</div>'+
        '<div style="font-size:12px;color:var(--text3);margin-top:6px">'+dateStr+' · '+timeStr+'</div>'+
      '</div>'+
      '<div style="font-size:13px;color:var(--text2)">Emails will be marked as <strong>queued</strong> and sent automatically once your Outlook account is connected. Each email is unique — generated by AI for each contact.</div>'+
    '</div>'+
    '<div class="mf">'+
      '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" onclick="submitSendAll()">Confirm & Queue</button>'+
    '</div>'+
  '</div>';
  render();
};

window.submitSendAll=function(){
  var pending=STATE.pendingEmails||[];
  closeModal();
  // Show progress bar immediately — don't wait for first poll
  STATE.sendProgress={active:true,total:pending.length,sent:0,failed:0,current:'Initiating send...',failDetails:[],startedAt:new Date().toISOString()};
  STATE.pendingEmails=[];
  render(); // bar is visible right now
  stopProgressPoll(); // clear any stale timer from previous send
  startProgressPoll(); // start polling for real backend updates
  apiPost('/emails/queue-all',{}).then(function(res){
    showToast(res.queued+' emails queued for sending','success');
  }).catch(function(e){
    STATE.sendProgress=null;
    loadEmailsForCurrentUser();
    showToast('Failed: '+e.message,'error');
  });
};

window.saveEmailEdit=function(id){
  var el=document.getElementById('edit-email-body-'+id);
  if(!el)return;
  apiPut='/emails/'+id; // using apiPatch
  apiFetch('PATCH','/emails/'+id,{body:el.value}).then(function(updated){
    STATE.pendingEmails=(STATE.pendingEmails||[]).map(function(e){return e.id===id?Object.assign({},e,{body:updated.body}):e;});
    showToast('Email updated','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

function normalizeIndustryMap(obj){
  var out={};
  Object.keys(obj).forEach(function(k){
    var norm=normalizeIndustry(k);
    out[norm]=(out[norm]||0)+obj[k];
  });
  return out;
}
function renderTodaySummaryCard(ts){
  var bf=ts.by_freshness||{};
  var bi=normalizeIndustryMap(ts.by_industry||{});
  var btz=ts.by_timezone||{};
  function rows(obj){
    return Object.keys(obj).sort().map(function(k){
      return '<div style="display:flex;justify-content:space-between;padding:1px 0">'+
        '<span>'+htmlEsc(k)+'</span><span style="font-weight:600">'+obj[k]+'</span></div>';
    }).join('');
  }
  return '<div style="background:var(--accent-l);border:1.5px solid var(--accent);border-radius:var(--r2);padding:14px 18px">'+
    '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">'+
      '<div style="font-weight:700;font-size:14px;color:var(--accent)">Today\'s assignment summary</div>'+
      '<div style="font-size:24px;font-weight:700;color:var(--accent)">'+ts.total+' leads</div>'+
    '</div>'+
    '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;font-size:12px">'+
      '<div><div style="color:var(--text3);font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">Freshness</div>'+rows(bf)+'</div>'+
      '<div><div style="color:var(--text3);font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">Industry</div>'+rows(bi)+'</div>'+
      '<div><div style="color:var(--text3);font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">Timezone</div>'+rows(btz)+'</div>'+
    '</div>'+
  '</div>';
}

// ════════════════════════════════════════════════
// DISTRIBUTION ACTIONS — Drop N
// ════════════════════════════════════════════════

function refreshPoolStats(){
  apiGet('/distribute/pool-stats').then(function(d){
    STATE.distributePoolStats=d;render();
  }).catch(function(){});
}

window.updateAssignCountPreview=function(){
  // If manual count is set, regenerate the ratio with that count
  var el=document.getElementById('assign-manual-count');
  if(el&&el.value){
    clearTimeout(window._assignCountDebounce);
    window._assignCountDebounce=setTimeout(function(){generateAutoRatio();},400);
  }
};

window.openAssignToManager=function(managerId){
  var m=STATE.users.find(function(u){return u.id===managerId;})||{name:'Manager'};
  // Use API pool stats if loaded, fallback to counting directly from STATE.jobs
  var _unassignedJobs=STATE.jobs.filter(function(j){return j.stage==='Unassigned'&&!j.assigned_to_bd;});
  var pool=STATE.distributePoolStats&&STATE.distributePoolStats.total>0
    ?STATE.distributePoolStats
    :{total:_unassignedJobs.length,by_industry:{},by_timezone:{},duplicates:_unassignedJobs.filter(function(j){return j.is_duplicate;}).length};
  var emailAccounts=(STATE.userEmailsCache[managerId]||[]).filter(function(a){return a.is_active;});
  var capacity=emailAccounts.reduce(function(s,a){return s+(a.daily_send_limit||300);},0);
  STATE._assignManagerId=managerId;
  STATE._assignRatio=null;
  STATE._assignGenerating=false;

  STATE.modal='<div class="modal modal-w540">'+
    '<div class="mh">'+
      '<div><div class="mt">Assign leads \u2014 '+htmlEsc(m.name)+'</div>'+
        '<div style="font-size:12px;color:var(--text3);margin-top:3px">'+pool.total+' unassigned leads \u00b7 '+capacity+' email capacity today</div>'+
      '</div>'+
      '<button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button>'+
    '</div>'+
    '<div class="mb_">'+
      // Manual count override
      '<div style="display:flex;align-items:center;gap:10px;padding:12px 14px;background:var(--bg);border-radius:var(--r2);margin-bottom:14px;border:1px solid var(--border)">'+
        '<div style="flex:1">'+
          '<div style="font-size:12px;font-weight:600;color:var(--text2);margin-bottom:2px">Number of leads to assign</div>'+
          '<div style="font-size:11px;color:var(--text3)">Leave blank to let AI decide based on capacity ('+capacity+' max)</div>'+
        '</div>'+
        '<input type="number" id="assign-manual-count" min="1" max="'+pool.total+'" placeholder="Auto" style="width:80px;padding:8px 10px;border:1px solid var(--border2);border-radius:8px;font-size:14px;font-weight:600;text-align:center;font-family:inherit" oninput="updateAssignCountPreview()"/>'+
        '<span style="font-size:12px;color:var(--text3)">/ '+pool.total+'</span>'+
      '</div>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:16px">'+
        '<div onclick="setAssignMode(\'auto\')" id="mode-auto" style="padding:14px;border:2px solid var(--accent);border-radius:var(--r2);cursor:pointer;background:var(--accent-l);text-align:center">'+
          '<div style="font-size:18px;margin-bottom:4px">\u26a1</div>'+
          '<div style="font-weight:600;font-size:13px;color:var(--accent)">Auto</div>'+
          '<div style="font-size:11px;color:var(--text3);margin-top:3px">System picks balanced ratio</div>'+
        '</div>'+
        '<div onclick="setAssignMode(\'text\')" id="mode-text" style="padding:14px;border:2px solid var(--border);border-radius:var(--r2);cursor:pointer;text-align:center">'+
          '<div style="font-size:18px;margin-bottom:4px">\u270f\ufe0f</div>'+
          '<div style="font-weight:600;font-size:13px">Priority text</div>'+
          '<div style="font-size:11px;color:var(--text3);margin-top:3px">Tell AI what to prioritise</div>'+
        '</div>'+
      '</div>'+
      '<div id="assign-text-panel" style="display:none;margin-bottom:12px">'+
        '<label style="font-size:12px;font-weight:600;color:var(--text2);display:block;margin-bottom:6px">Describe your priorities</label>'+
        '<textarea id="assign-priority-text" style="width:100%;padding:10px;border:1px solid var(--border);border-radius:8px;font-size:13px;min-height:80px;resize:vertical;font-family:inherit" placeholder="e.g. Focus on old leads first, prioritise healthcare and legal, send mostly to EST timezone, exclude duplicates..."></textarea>'+
        '<button onclick="generateAssignRatio()" style="margin-top:8px;background:var(--purple);color:#fff;border:0;padding:8px 16px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer" id="gen-ratio-btn">\u2728 Generate ratio with AI</button>'+
      '</div>'+
      '<div id="assign-ratio-preview" style="display:none"></div>'+
    '</div>'+
    '<div class="mf">'+
      '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" id="assign-confirm-btn" onclick="confirmAssignToManager()" disabled style="opacity:.5;cursor:not-allowed">Preview assignment</button>'+
    '</div>'+
  '</div>';
  render();
  // Auto mode selected by default — trigger auto ratio generation
  setTimeout(function(){generateAutoRatio();},100);
};

window.setAssignMode=function(mode){
  var autoEl=document.getElementById('mode-auto');
  var textEl=document.getElementById('mode-text');
  var textPanel=document.getElementById('assign-text-panel');
  if(!autoEl||!textEl)return;
  if(mode==='auto'){
    autoEl.style.border='2px solid var(--accent)';autoEl.style.background='var(--accent-l)';
    textEl.style.border='2px solid var(--border)';textEl.style.background='';
    if(textPanel)textPanel.style.display='none';
    generateAutoRatio();
  } else {
    textEl.style.border='2px solid var(--accent)';textEl.style.background='var(--accent-l)';
    autoEl.style.border='2px solid var(--border)';autoEl.style.background='';
    if(textPanel)textPanel.style.display='block';
    STATE._assignRatio=null;
    var btn=document.getElementById('assign-confirm-btn');
    if(btn){btn.disabled=true;btn.style.opacity='.5';btn.style.cursor='not-allowed';}
    var prev=document.getElementById('assign-ratio-preview');
    if(prev)prev.style.display='none';
  }
};

function showRatioPreview(ratio){
  STATE._assignRatio=ratio;
  var prev=document.getElementById('assign-ratio-preview');
  var btn=document.getElementById('assign-confirm-btn');
  if(!prev)return;
  var bf=ratio.by_freshness||{};
  var bi=ratio.by_industry||{};
  var btz=ratio.by_timezone||{};
  prev.style.display='block';
  prev.innerHTML='<div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--r2);padding:12px 14px">'+
    '<div style="font-size:12px;font-weight:600;color:var(--text2);margin-bottom:8px">Distribution preview \u2014 '+ratio.total_to_send+' leads</div>'+
    '<div style="font-size:12px;color:var(--text2);line-height:1.6;margin-bottom:8px">'+htmlEsc(ratio.summary||'')+'</div>'+
    '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;font-size:11.5px">'+
      '<div><div style="color:var(--text3);margin-bottom:3px">Freshness</div>'+Object.keys(bf).map(function(k){return '<div>'+k+': <strong>'+bf[k]+'%</strong></div>';}).join('')+'</div>'+
      '<div><div style="color:var(--text3);margin-bottom:3px">Industry</div>'+Object.keys(bi).filter(function(k){return bi[k]>0;}).map(function(k){return '<div>'+k+': <strong>'+bi[k]+'%</strong></div>';}).join('')+'</div>'+
      '<div><div style="color:var(--text3);margin-bottom:3px">Timezone</div>'+Object.keys(btz).map(function(k){return '<div>'+k+': <strong>'+btz[k]+'%</strong></div>';}).join('')+'</div>'+
    '</div>'+
  '</div>';
  if(btn){btn.disabled=false;btn.style.opacity='1';btn.style.cursor='pointer';}
}

function generateAutoRatio(){
  var _unassignedJobs=STATE.jobs.filter(function(j){return j.stage==='Unassigned'&&!j.assigned_to_bd;});
  var pool=STATE.distributePoolStats&&STATE.distributePoolStats.total>0
    ?STATE.distributePoolStats
    :{total:_unassignedJobs.length,by_industry:{},by_timezone:{},duplicates:0};
  var managerId=STATE._assignManagerId;
  var emailAccounts=(STATE.userEmailsCache[managerId]||[]).filter(function(a){return a.is_active;});
  var capacity=emailAccounts.reduce(function(s,a){return s+(a.daily_send_limit||300);},0);
  // Respect manual count if set
  var manualEl=document.getElementById('assign-manual-count');
  var manualCount=manualEl&&manualEl.value?parseInt(manualEl.value):0;
  if(manualCount>0)capacity=Math.min(manualCount,pool.total||99999);
  var ps=Object.assign({},pool,{capacity:capacity});
  var prev=document.getElementById('assign-ratio-preview');
  if(prev){prev.style.display='block';prev.innerHTML='<div style="font-size:12px;color:var(--text3);padding:10px">Calculating balanced ratio\u2026</div>';}
  apiPost('/distribute/generate-ratio',{priority_text:'balanced auto distribution',pool_stats:ps,manager_id:managerId}).then(function(ratio){
    showRatioPreview(ratio);
  }).catch(function(e){
    if(prev){prev.style.display='block';prev.innerHTML='<div style="font-size:12px;color:var(--red);padding:10px">Could not generate ratio: '+htmlEsc(e.message)+'</div>';}
  });
}

window.generateAssignRatio=function(){
  var text=(document.getElementById('assign-priority-text')||{}).value||'';
  if(!text.trim()){showToast('Enter priority instructions first','warning');return;}
  var _unassignedJobs=STATE.jobs.filter(function(j){return j.stage==='Unassigned'&&!j.assigned_to_bd;});
  var pool=STATE.distributePoolStats&&STATE.distributePoolStats.total>0
    ?STATE.distributePoolStats
    :{total:_unassignedJobs.length,by_industry:{},by_timezone:{},duplicates:0};
  var managerId=STATE._assignManagerId;
  var emailAccounts=(STATE.userEmailsCache[managerId]||[]).filter(function(a){return a.is_active;});
  var capacity=emailAccounts.reduce(function(s,a){return s+(a.daily_send_limit||300);},0);
  var ps=Object.assign({},pool,{capacity:capacity});
  var btn=document.getElementById('gen-ratio-btn');
  if(btn){btn.textContent='Generating\u2026';btn.disabled=true;}
  var prev=document.getElementById('assign-ratio-preview');
  if(prev){prev.style.display='block';prev.innerHTML='<div style="font-size:12px;color:var(--text3);padding:10px">\u2728 AI is generating your ratio\u2026</div>';}
  apiPost('/distribute/generate-ratio',{priority_text:text,pool_stats:ps,manager_id:managerId}).then(function(ratio){
    showRatioPreview(ratio);
    if(btn){btn.textContent='\u2728 Regenerate';btn.disabled=false;}
  }).catch(function(e){
    if(prev){prev.style.display='block';prev.innerHTML='<div style="font-size:12px;color:var(--red);padding:10px">AI error: '+htmlEsc(e.message)+'</div>';}
    if(btn){btn.textContent='\u2728 Generate ratio with AI';btn.disabled=false;}
  });
};

window.confirmAssignToManager=function(){
  var ratio=STATE._assignRatio;
  var managerId=STATE._assignManagerId;
  if(!ratio||!managerId)return;
  if(guestSimulate('assignLeads',{count:ratio.total_to_send||3}))return;
  var m=STATE.users.find(function(u){return u.id===managerId;})||{name:'Manager'};
  var emailAccounts=(STATE.userEmailsCache[managerId]||[]).filter(function(a){return a.is_active;});
  var totalCapacity=emailAccounts.reduce(function(s,a){return s+(a.daily_send_limit||300);},0);
  var now=new Date();
  var dateStr=now.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'});
  var timeStr=now.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'});

  // Build email IDs breakdown
  var perEmail=emailAccounts.length>0?Math.ceil(ratio.total_to_send/emailAccounts.length):0;
  var emailIDRows=emailAccounts.length?
    emailAccounts.map(function(a,idx){
      var count=idx===emailAccounts.length-1
        ?ratio.total_to_send-perEmail*(emailAccounts.length-1)
        :perEmail;
      count=Math.max(0,Math.min(count,a.daily_send_limit||300));
      return '<div style="display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--card);border-radius:var(--r);margin-bottom:6px;border:1px solid var(--border)">'+
        '<span style="font-size:10px;padding:2px 7px;border-radius:5px;font-weight:600;background:'+(a.platform==='Microsoft'?'#e0f2fe':'#f0fdf4')+';color:'+(a.platform==='Microsoft'?'#0369a1':'#166534')+'">'+htmlEsc(a.platform||'Email')+'</span>'+
        '<div style="flex:1;min-width:0">'+
          '<div style="font-size:12.5px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+htmlEsc(a.display_name||a.email_address)+'</div>'+
          '<div style="font-size:11px;color:var(--text3)">'+htmlEsc(a.email_address)+'</div>'+
        '</div>'+
        '<div style="text-align:right;flex-shrink:0">'+
          '<div style="font-size:14px;font-weight:700;color:var(--accent)">'+count+'</div>'+
          '<div style="font-size:10px;color:var(--text3)">emails</div>'+
        '</div>'+
      '</div>';
    }).join(''):
    '<div style="font-size:12px;color:var(--red);padding:8px">No active email IDs found for this manager.</div>';

  STATE.modal='<div class="modal modal-w480">'+
    '<div class="mh"><div class="mt">Confirm assignment</div>'+
    '<button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'+
    '<div class="mb_">'+
      '<div style="padding:14px 16px;background:var(--accent-l);border-radius:var(--r2);margin-bottom:14px;display:flex;align-items:center;gap:14px">'+
        '<div style="flex:1">'+
          '<div style="font-size:22px;font-weight:700;color:var(--accent);line-height:1">'+ratio.total_to_send+' leads</div>'+
          '<div style="font-size:13px;color:var(--text2);margin-top:3px">→ <strong>'+htmlEsc(m.name)+'</strong></div>'+
          '<div style="font-size:11px;color:var(--text3);margin-top:3px">'+dateStr+' · '+timeStr+'</div>'+
        '</div>'+
        '<div style="text-align:center;padding:10px 14px;background:var(--card);border-radius:var(--r2);border:1px solid rgba(37,99,235,.15)">'+
          '<div style="font-size:18px;font-weight:700;color:var(--accent)">'+emailAccounts.length+'</div>'+
          '<div style="font-size:10px;color:var(--text3);margin-top:2px">email ID'+(emailAccounts.length!==1?'s':'')+'</div>'+
          '<div style="font-size:10px;color:var(--text3)">'+totalCapacity+'/day cap</div>'+
        '</div>'+
      '</div>'+
      '<div style="font-size:12px;font-weight:600;color:var(--text3);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Sending via</div>'+
      emailIDRows+
      '<div style="font-size:12px;color:var(--text3);margin-top:10px;padding:8px 10px;background:var(--bg);border-radius:var(--r)">'+
        htmlEsc(ratio.summary||'AI-generated emails will be sent for each contact.')+
      '</div>'+
    '</div>'+
    '<div class="mf">'+
      '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" '+(emailAccounts.length?'':'disabled style="opacity:.5;cursor:not-allowed"')+' onclick="submitAssignToManager()">Confirm &amp; Assign</button>'+
    '</div>'+
  '</div>';
  render();
};

window.submitAssignToManager=function(){
  var ratio=STATE._assignRatio;
  var managerId=STATE._assignManagerId;
  if(!ratio||!managerId)return;
  closeModal();
  apiPost('/distribute/execute',{manager_id:managerId,ratio:ratio}).then(function(res){
    var msg=res.total_assigned+' leads assigned · emails sending automatically';
    showToast(msg,'success');
    STATE._assignRatio=null;STATE._assignManagerId=null;
    STATE.sendProgress=null;
    STATE.page='email'; // go to email page so progress bar is visible
    render();
    startProgressPoll();
    return Promise.all([refreshPoolStats(),refreshJobs()]);
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

// ════════════════════════════════════════════════
// EMAIL ACCOUNTS PAGE — Drop M
// ════════════════════════════════════════════════
function renderManagerUsers(){
  var u=STATE.user;
  var tab=STATE.managerUsersTab||'bd';
  var allUsers=STATE.users||[];
  var assignments=STATE.teamAssignments||[];
  if(STATE.selectedManagerUser){return renderManagerUserDetail(STATE.selectedManagerUser);}
  var tabDefs=[{key:'bd',label:'BD Managers'},{key:'ra',label:'Research Analysts'},{key:'bdteam',label:'BD Team'},{key:'rateam',label:'RA Team'}];
  var tabBar=tabDefs.map(function(t){
    var isActive=tab===t.key;
    return '<button onclick="STATE.managerUsersTab=\''+t.key+'\';render()" style="padding:8px 16px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border:2px solid '+(isActive?'var(--accent)':'var(--border)')+';background:'+(isActive?'var(--accent)':'var(--card)')+';color:'+(isActive?'#fff':'var(--text2)')+';transition:all .15s">'+t.label+'</button>';
  }).join('');
  var body='';
  if(tab==='bd'){
    var bdUsers=allUsers.filter(function(x){return userHasRole(x,'bd')||userHasRole(x,'bd_lead');});
    var rows=bdUsers.map(function(usr){
      var emailCount=(STATE.userEmailsCache[usr.id]||[]).length;
      var teamCount=assignments.filter(function(a){return a.manager_id===usr.id;}).length;
      return '<div class="user-list-row" onclick="STATE.selectedManagerUser=\''+usr.id+'\';loadUserEmails(\''+usr.id+'\');render()" style="display:flex;align-items:center;gap:14px;padding:12px 16px;border-bottom:1px solid var(--border);cursor:pointer">'+av(usr,'36')+'<div style="flex:1"><div style="font-weight:600;font-size:13.5px">'+htmlEsc(usr.name)+'</div><div style="font-size:11.5px;color:var(--text3)">'+htmlEsc(usr.email)+'</div></div><span style="font-size:11px;padding:2px 8px;background:var(--accent-l);color:var(--accent);border-radius:8px">'+emailCount+' email'+(emailCount!==1?'s':'')+'</span>'+(teamCount?'<span style="font-size:11px;padding:2px 8px;background:var(--green-l);color:var(--green);border-radius:8px">'+teamCount+' member'+(teamCount!==1?'s':'')+'</span>':'')+'<div style="color:var(--text3);font-size:18px">&#8250;</div></div>';
    }).join('');
    body='<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden">'+(rows||'<div style="padding:30px;text-align:center;color:var(--text3);font-size:13px">No BD Managers yet. Add users from the Admin tab.</div>')+'</div>';
  } else if(tab==='ra'){
    var raUsers=allUsers.filter(function(x){return userHasRole(x,'ra')&&!userHasAnyRole(x,'bd','bd_lead','admin');});
    var rows=raUsers.map(function(usr){
      var myManagers=assignments.filter(function(a){return a.member_id===usr.id&&a.assignment_type==='ra_to_bd';}).map(function(a){return a.manager&&a.manager.name||'';}).filter(Boolean);
      return '<div class="user-list-row" onclick="STATE.selectedManagerUser=\''+usr.id+'\';render()" style="display:flex;align-items:center;gap:14px;padding:12px 16px;border-bottom:1px solid var(--border);cursor:pointer">'+av(usr,'36')+'<div style="flex:1"><div style="font-weight:600;font-size:13.5px">'+htmlEsc(usr.name)+'</div><div style="font-size:11.5px;color:var(--text3)">'+htmlEsc(usr.email)+'</div></div>'+(myManagers.length?'<span style="font-size:11px;padding:2px 8px;background:var(--accent-l);color:var(--accent);border-radius:8px">&#8594; '+htmlEsc(myManagers.join(', '))+'</span>':'<span style="font-size:11px;color:var(--text3)">Unassigned</span>')+'<div style="color:var(--text3);font-size:18px">&#8250;</div></div>';
    }).join('');
    body='<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden">'+(rows||'<div style="padding:30px;text-align:center;color:var(--text3);font-size:13px">No Research Analysts yet.</div>')+'</div>';
  } else if(tab==='bdteam'){
    var bdLeads=allUsers.filter(function(x){return userHasRole(x,'bd_lead');});
    body=bdLeads.length?bdLeads.map(function(lead){
      var members=assignments.filter(function(a){return a.manager_id===lead.id&&a.assignment_type==='bd_to_bdlead';});
      var memberRows=members.length?members.map(function(a){var m=a.member;if(!m)return'';return '<div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border2)">'+av(m,'30')+'<div style="flex:1"><div style="font-size:13px;font-weight:500">'+htmlEsc(m.name)+'</div><div style="font-size:11px;color:var(--text3)">'+htmlEsc(m.email)+'</div></div><button onclick="removeAssignment(event,\''+a.id+'\')" style="font-size:11px;color:var(--red);background:transparent;border:0;cursor:pointer">Remove</button></div>';}).join(''):'<div style="padding:12px 16px;font-size:12px;color:var(--text3)">No BD Managers assigned yet.</div>';
      return '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);margin-bottom:14px;overflow:hidden"><div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><div style="display:flex;align-items:center;gap:10px">'+av(lead,'32')+'<div style="font-weight:700;font-size:13.5px">'+htmlEsc(lead.name)+'</div></div><button onclick="openAssignToBDLead(\''+lead.id+'\')" style="font-size:12px;padding:5px 12px;background:var(--accent);color:#fff;border:0;border-radius:7px;cursor:pointer">+ Assign BD Manager</button></div>'+memberRows+'</div>';
    }).join(''):'<div style="padding:30px;text-align:center;color:var(--text3);font-size:13px;background:var(--card);border:1px solid var(--border);border-radius:var(--r2)">No BD Team Leads yet.</div>';
  } else if(tab==='rateam'){
    var bdManagers=allUsers.filter(function(x){return userHasRole(x,'bd');});
    body=bdManagers.length?bdManagers.map(function(mgr){
      var members=assignments.filter(function(a){return a.manager_id===mgr.id&&a.assignment_type==='ra_to_bd';});
      var memberRows=members.length?members.map(function(a){var m=a.member;if(!m)return'';return '<div style="display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border2)">'+av(m,'30')+'<div style="flex:1"><div style="font-size:13px;font-weight:500">'+htmlEsc(m.name)+'</div><div style="font-size:11px;color:var(--text3)">'+htmlEsc(m.email)+'</div></div><button onclick="removeAssignment(event,\''+a.id+'\')" style="font-size:11px;color:var(--red);background:transparent;border:0;cursor:pointer">Remove</button></div>';}).join(''):'<div style="padding:12px 16px;font-size:12px;color:var(--text3)">No RAs assigned yet.</div>';
      return '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);margin-bottom:14px;overflow:hidden"><div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><div style="display:flex;align-items:center;gap:10px">'+av(mgr,'32')+'<div style="font-weight:700;font-size:13.5px">'+htmlEsc(mgr.name)+'</div></div><button onclick="openAssignRAToManager(\''+mgr.id+'\')" style="font-size:12px;padding:5px 12px;background:var(--accent);color:#fff;border:0;border-radius:7px;cursor:pointer">+ Assign RA</button></div>'+memberRows+'</div>';
    }).join(''):'<div style="padding:30px;text-align:center;color:var(--text3);font-size:13px;background:var(--card);border:1px solid var(--border);border-radius:var(--r2)">No BD Managers yet.</div>';
  }
  return '<div class="page"><div class="ph"><div class="flex jb aic"><div><div class="ptitle">Manager Users</div><div class="psub">'+allUsers.length+' users</div></div><button class="btn btn-primary btn-sm" onclick="STATE.page=\'admin\';STATE.adminSelectedUser=null;render()">'+ico('plus',13)+' Manage Users</button></div></div><div style="display:flex;gap:10px;margin-bottom:20px">'+tabBar+'</div>'+body+'</div>';
}

function renderManagerUserDetail(userId){
  var usr=STATE.users.find(function(x){return x.id===userId;});
  if(!usr)return'';
  var userEmails=STATE.userEmailsCache[userId]||[];
  var assignments=STATE.teamAssignments||[];
  var myManagers=assignments.filter(function(a){return a.member_id===userId;});
  var myMembers=assignments.filter(function(a){return a.manager_id===userId;});
  var rolesAll=['admin','ra_lead','bd_lead','bd','ra'];
  var roleLabelsMap={admin:'Admin',ra_lead:'RA Team Lead',bd_lead:'BD Team Lead',bd:'BD Manager',ra:'Research Analyst'};
  var userRoles=usr.roles||[usr.role];
  var roleCheckboxes=rolesAll.map(function(r){
    var checked=userRoles.indexOf(r)>-1;
    return '<label style="display:flex;align-items:center;gap:8px;font-size:13px;cursor:pointer;padding:6px 0"><input type="checkbox" '+(checked?'checked':'')+' onchange="toggleUserRole(\''+userId+'\',\''+r+'\',this.checked)" style="width:15px;height:15px"/>'+roleLabelsMap[r]+'</label>';
  }).join('');
  var emailRows=userEmails.map(function(e){
    var msConnected=e.ms_connected;
    return '<div style="display:flex;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid var(--border);flex-wrap:wrap"><div style="flex:1;min-width:180px"><div style="font-weight:500;font-size:13px">'+htmlEsc(e.display_name||e.email_address)+'</div><div style="font-size:11px;color:var(--text3)">'+htmlEsc(e.email_address)+'</div></div><span style="font-size:10px;padding:2px 7px;border-radius:6px;font-weight:600;background:'+(e.platform==='Microsoft'?'#e0f2fe':'#f0fdf4')+';color:'+(e.platform==='Microsoft'?'#0369a1':'#166534')+'">'+e.platform+'</span>'+(e.is_primary?'<span style="font-size:10px;padding:2px 7px;background:var(--amber-l);color:var(--amber);border-radius:6px;font-weight:600">Primary</span>':'')+'<span style="font-size:10px;padding:2px 7px;border-radius:6px;font-weight:600;background:'+(e.is_active?'var(--green-l)':'var(--red-l)')+';color:'+(e.is_active?'var(--green)':'var(--red)')+'">'+( e.is_active?'Active':'Inactive')+'</span>'+(e.platform==='Microsoft'&&!msConnected?'<button onclick="connectMicrosoftUserEmail(\''+userId+'\',\''+e.id+'\')" style="font-size:10px;padding:2px 8px;background:#0078d4;color:#fff;border:0;border-radius:6px;cursor:pointer">Connect</button>':(e.platform==='Microsoft'&&msConnected?'<span style="font-size:10px;color:var(--green)">&#10003; Connected</span>':''))+'<button onclick="toggleUserEmailActive(\''+userId+'\',\''+e.id+'\','+(e.is_active?'false':'true')+')" style="font-size:11px;color:'+(e.is_active?'var(--red)':'var(--green)')+';background:transparent;border:0;cursor:pointer">'+(e.is_active?'Deactivate':'Activate')+'</button>'+(e.is_primary?'':'<button onclick="setPrimaryEmail(\''+userId+'\',\''+e.id+'\')" style="font-size:11px;color:var(--text3);background:transparent;border:0;cursor:pointer">Set Primary</button>')+'<button onclick="deleteUserEmail(\''+userId+'\',\''+e.id+'\')" style="font-size:11px;color:var(--red);background:transparent;border:0;cursor:pointer">&#10005;</button></div>';
  }).join('');
  return '<div class="page"><div class="ph"><div class="flex aic gap3"><button onclick="STATE.selectedManagerUser=null;render()" style="background:transparent;border:0;color:var(--text3);font-size:22px;cursor:pointer">&#8592;</button>'+av(usr,'40')+'<div><div class="ptitle" style="margin:0">'+htmlEsc(usr.name)+'</div><div class="psub" style="margin:0">'+htmlEsc(usr.email)+'</div></div></div></div><div style="max-width:640px"><div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:18px;margin-bottom:16px"><div style="font-weight:700;font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px">Roles</div>'+roleCheckboxes+'</div><div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);overflow:hidden;margin-bottom:16px"><div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center"><div style="font-weight:700;font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em">Email IDs <span style="font-weight:400">('+userEmails.length+' · max 4 active)</span></div><div style="display:flex;gap:6px"><button onclick="openAddUserEmail(\''+userId+'\',\'Microsoft\')" style="font-size:12px;padding:5px 10px;background:#0078d4;color:#fff;border:0;border-radius:7px;cursor:pointer">+ Microsoft</button><button onclick="openAddUserEmail(\''+userId+'\',\'Gmail\')" style="font-size:12px;padding:5px 10px;background:#16a34a;color:#fff;border:0;border-radius:7px;cursor:pointer">+ Gmail</button></div></div>'+(emailRows||'<div style="padding:20px;text-align:center;font-size:13px;color:var(--text3)">No email IDs added yet.</div>')+'</div><div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:18px;margin-bottom:16px"><div style="font-weight:700;font-size:12px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px">Team Assignment</div>'+(myManagers.length?'<div style="font-size:13px;margin-bottom:8px">Reports to: '+myManagers.map(function(a){return'<strong>'+(a.manager&&a.manager.name||'')+'</strong>';}).join(', ')+'</div>':'')+(myMembers.length?'<div style="font-size:13px">Members: '+myMembers.map(function(a){return(a.member&&a.member.name)||'';}).filter(Boolean).join(', ')+'</div>':'<div style="font-size:13px;color:var(--text3)">No team members assigned.</div>')+'</div></div></div>';
}

window.openAddEmailAccount=function(managerId,fromDetail,platform){
  platform=platform||'Microsoft';
  var managerUser=managerId?STATE.users.find(function(u){return u.id===managerId;}):null;
  var isMicrosoft=platform==='Microsoft';
  var platformBadge=isMicrosoft?
    '<span style="font-size:11px;padding:2px 8px;background:#e0f2fe;color:#0369a1;border-radius:6px;font-weight:600;margin-left:8px">Microsoft / Outlook</span>':
    '<span style="font-size:11px;padding:2px 8px;background:#f0fdf4;color:#166534;border-radius:6px;font-weight:600;margin-left:8px">Gmail</span>';
  STATE.modal='<div class="modal modal-w480">'+'<div class="mh">'+'<div>'+'<div class="mt">Add Email Account'+platformBadge+'</div>'+(managerUser?'<div style="font-size:12px;color:var(--text3);margin-top:3px">Assign to '+htmlEsc(managerUser.name)+'</div>':'')+'</div>'+'<button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button>'+'</div>'+'<div class="mb_">'+(isMicrosoft?'<div style="padding:12px 14px;background:#f0f9ff;border:1px solid #bae6fd;border-radius:var(--r2);margin-bottom:16px;font-size:13px;color:#0c4a6e">First enter the email address and display name, then click <strong>Save &amp; Connect Microsoft</strong> to authorise sending via Microsoft OAuth.</div>':'<div style="padding:12px 14px;background:#f0fdf4;border:1px solid #bbf7d0;border-radius:var(--r2);margin-bottom:16px;font-size:13px;color:#14532d">Enter the Gmail address and display name. Google OAuth sending will be added in a future update.</div>')+'<div class="fgrp"><label class="flbl">Email address <span style="color:var(--red)">*</span></label><input class="inp" id="ea-email" placeholder="e.g. john@futeglobal.com" autocomplete="off"/></div>'+'<div class="fgrp"><label class="flbl">Display name <span style="color:var(--red)">*</span></label><input class="inp" id="ea-name" placeholder="John Smith"/></div>'+'<div class="fgrp"><label class="flbl">Daily outreach limit</label><div style="display:flex;align-items:center;gap:10px"><input class="inp" type="number" id="ea-limit" value="300" min="1" max="500" style="width:120px"/><span style="font-size:12px;color:var(--text3)">emails per day</span></div></div>'+'</div>'+'<div class="mf">'+'<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+(isMicrosoft?'<button class="btn btn-primary" onclick="submitCreateEmailAndConnectMicrosoft(\''+managerId+'\')" style="background:#0078d4">Save &amp; Connect Microsoft</button>':'<button class="btn btn-primary" onclick="submitCreateAndAssignEmailAccount(\''+managerId+'\')" style="background:#16a34a">Save Gmail Account</button>')+'</div>'+'</div>';
  render();
};

window.selectEmailAccountToAssign=function(accountId, managerId){
  // Show limit picker before assigning
  var a=STATE.emailAccounts.find(function(x){return x.id===accountId;});
  if(!a)return;
  STATE.modal='<div class="modal modal-w400">'+
    '<div class="mh"><div class="mt">Assign '+htmlEsc(a.display_name)+'</div>'+
    '<button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'+
    '<div class="mb_">'+
      '<div style="padding:12px 14px;background:var(--accent-l);border-radius:var(--r2);margin-bottom:14px">'+
        '<div style="font-weight:600;font-size:13px">'+htmlEsc(a.display_name)+'</div>'+
        '<div style="font-size:12px;color:var(--text3)">'+htmlEsc(a.email_address)+'</div>'+
      '</div>'+
      '<div class="fgrp"><label class="flbl">Daily outreach limit</label>'+
        '<div style="display:flex;align-items:center;gap:10px">'+
          '<input class="inp" type="number" id="ea-assign-limit" value="'+htmlEsc(String(a.daily_send_limit||300))+'" min="1" max="500" style="width:120px"/>'+
          '<span style="font-size:12px;color:var(--text3)">emails per day</span>'+
        '</div>'+
      '</div>'+
    '</div>'+
    '<div class="mf">'+
      '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" onclick="submitAssignExistingEmailAccount(\''+accountId+'\',\''+managerId+'\')">Assign to Manager</button>'+
    '</div>'+
  '</div>';
  render();
};

window.submitAssignExistingEmailAccount=function(accountId, managerId){
  var limit=parseInt((document.getElementById('ea-assign-limit')||{}).value||'300');
  apiPut('/email-accounts/'+accountId,{assigned_to:managerId,daily_send_limit:limit}).then(function(a){
    STATE.emailAccounts=STATE.emailAccounts.map(function(x){return x.id===accountId?a:x;});
    closeModal();showToast('Email ID assigned','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.emailAccountTypeahead=function(val){
  var sugBox=document.getElementById('ea-suggestions');
  if(!sugBox)return;
  if(!val||val.length<2){sugBox.style.display='none';return;}
  var q=val.toLowerCase();
  var raUsers=(STATE.users||[]).filter(function(u){return u.role==='ra';});
  var matches=raUsers.filter(function(u){
    return (u.email||'').toLowerCase().indexOf(q)>-1||(u.name||'').toLowerCase().indexOf(q)>-1;
  }).slice(0,6);
  if(!matches.length){sugBox.style.display='none';return;}
  var html='';
  matches.forEach(function(u){
    html+='<div class="_ea-sug" data-email="'+htmlEsc(u.email)+'" data-name="'+htmlEsc(u.name)+'" style="padding:9px 13px;cursor:pointer;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px">'+
      '<div style="flex:1">'+
        '<div style="font-size:13px;font-weight:500">'+htmlEsc(u.name)+'</div>'+
        '<div style="font-size:11px;color:var(--text3)">'+htmlEsc(u.email)+'</div>'+
      '</div>'+
      '<span style="font-size:11px;padding:2px 6px;background:var(--green-l);color:var(--green);border-radius:6px">RA</span>'+
    '</div>';
  });
  sugBox.innerHTML=html;
  sugBox.style.display='block';
  // bind click and hover on each suggestion
  Array.prototype.forEach.call(sugBox.querySelectorAll('._ea-sug'),function(el){
    el.addEventListener('mouseenter',function(){this.style.background='var(--accent-l)';});
    el.addEventListener('mouseleave',function(){this.style.background='';});
    el.addEventListener('click',function(){
      pickEmailAccountSuggestion(this.getAttribute('data-email'),this.getAttribute('data-name'),300);
    });
  });
};

window.pickEmailAccountSuggestion=function(email,name,limit){
  var emailEl=document.getElementById('ea-email');
  var nameEl=document.getElementById('ea-name');
  var limitEl=document.getElementById('ea-limit');
  var sugBox=document.getElementById('ea-suggestions');
  if(emailEl)emailEl.value=email;
  if(nameEl)nameEl.value=name;
  if(limitEl)limitEl.value=limit||300;
  if(sugBox)sugBox.style.display='none';
};

window.submitCreateEmailAndConnectMicrosoft=function(managerId){
  var email=(document.getElementById('ea-email')||{}).value||'';
  var name=(document.getElementById('ea-name')||{}).value||'';
  var limit=parseInt((document.getElementById('ea-limit')||{}).value||'300');
  if(!email||!name){showToast('Email address and display name required','warning');return;}
  // Sanitise managerId — treat string "null" or empty as no assignment
  var assignTo=(managerId&&managerId!=='null'&&managerId!=='')?managerId:undefined;
  // First create the email account record
  apiPost('/email-accounts',{email_address:email,display_name:name,assigned_to:assignTo,daily_send_limit:limit,platform:'Microsoft'}).then(function(a){
    STATE.emailAccounts.push(a);
    closeModal();
    render();
    // Then open Microsoft OAuth popup
    var url=API_URL+'/auth/microsoft/connect?accountId='+a.id+'&token='+STATE.token;
    var popup=window.open(url,'ms_oauth','width=600,height=700,scrollbars=yes');
    showToast('Account created — complete Microsoft login in the popup','info');
    // Listen for popup callback
    window._msOAuthHandler=function(event){
      if(event.data&&event.data.type==='ms_oauth_success'){
        window.removeEventListener('message',window._msOAuthHandler);
        STATE.emailAccounts=STATE.emailAccounts.map(function(x){
          return x.id===event.data.accountId?Object.assign({},x,{platform:'Microsoft',ms_connected:true}):x;
        });
        showToast('Microsoft account connected: '+event.data.email,'success');
        render();
      } else if(event.data&&event.data.type==='ms_oauth_error'){
        window.removeEventListener('message',window._msOAuthHandler);
        showToast('Microsoft connection failed: '+event.data.error,'error');
      }
    };
    window.addEventListener('message',window._msOAuthHandler);
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.submitCreateAndAssignEmailAccount=function(managerId){
  var email=(document.getElementById('ea-email')||{}).value||'';
  var name=(document.getElementById('ea-name')||{}).value||'';
  var limit=parseInt((document.getElementById('ea-limit')||{}).value||'300');
  if(!email||!name){showToast('Email address and display name required','warning');return;}
  var assignTo=(managerId&&managerId!=='null'&&managerId!=='')?managerId:undefined;
  apiPost('/email-accounts',{email_address:email,display_name:name,assigned_to:assignTo,daily_send_limit:limit}).then(function(a){
    STATE.emailAccounts.push(a);
    closeModal();showToast('Email ID created and assigned','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};;

window.openEditEmailAccount=function(id){
  var a=STATE.emailAccounts.find(function(x){return x.id===id;});
  if(!a)return;
  var managers=STATE.users.filter(function(x){return x.role==='bd'||x.role==='bd_lead'||x.role==='admin';});
  var mOpts='<option value="">— Unassigned —</option>'+managers.map(function(m){
    return '<option value="'+m.id+'"'+(a.assigned_to===m.id?' selected':'')+'>'+htmlEsc(m.name)+'</option>';
  }).join('');
  STATE.modal='<div class="modal modal-w480">'+
    '<div class="mh"><div class="mt">Edit Email ID</div><button class="btn-icon" onclick="closeModal()">'+ico('x',14)+'</button></div>'+
    '<div class="mb_">'+
      '<div class="fgrp"><label class="flbl">Email address</label><input class="inp" id="ea-email" value="'+htmlEsc(a.email_address)+'"/></div>'+
      '<div class="fgrp"><label class="flbl">Display name</label><input class="inp" id="ea-name" value="'+htmlEsc(a.display_name)+'"/></div>'+
      '<div class="fgrp"><label class="flbl">Assign to Manager</label><select class="sel" id="ea-manager">'+mOpts+'</select></div>'+
      '<div class="fgrp"><label class="flbl">Daily send limit</label><input class="inp" type="number" id="ea-limit" value="'+htmlEsc(String(a.daily_send_limit||300))+'" min="1" max="500"/></div>'+
    '</div>'+
    '<div class="mf"><button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" onclick="submitEditEmailAccount(\''+id+'\')">Save changes</button></div>'+
  '</div>';
  render();
};

;

window.submitEditEmailAccount=function(id){
  var email=(document.getElementById('ea-email')||{}).value||'';
  var name=(document.getElementById('ea-name')||{}).value||'';
  var manager=(document.getElementById('ea-manager')||{}).value||null;
  var limit=parseInt((document.getElementById('ea-limit')||{}).value||'300');
  apiPut('/email-accounts/'+id,{email_address:email,display_name:name,assigned_to:manager||null,daily_send_limit:limit}).then(function(a){
    STATE.emailAccounts=STATE.emailAccounts.map(function(x){return x.id===id?a:x;});
    closeModal();showToast('Email ID updated','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

window.toggleEmailAccount=function(id,active){
  apiPut('/email-accounts/'+id,{is_active:active}).then(function(a){
    STATE.emailAccounts=STATE.emailAccounts.map(function(x){return x.id===id?a:x;});
    showToast(active?'Email ID activated':'Email ID deactivated','success');render();
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

// ════════════════════════════════════════════════
// ASSIGN LEADS — RA Team Lead bulk assign UI (Drop E)
// ════════════════════════════════════════════════
function renderAssignLeads(){
  var u=STATE.user;
  // Use API pool stats if loaded, otherwise count from STATE.jobs directly
  var poolStats=STATE.distributePoolStats||{total:0,by_industry:{},by_timezone:{},duplicates:0};
  if(!STATE.distributePoolStats){
    // Fallback: count unassigned from STATE.jobs while API loads
    var _unassigned=STATE.jobs.filter(function(j){return j.stage==='Unassigned'&&!j.assigned_to_bd;});
    poolStats={total:_unassigned.length,by_industry:{},by_timezone:{},duplicates:_unassigned.filter(function(j){return j.is_duplicate;}).length};
  }
  var managers=STATE.users.filter(function(x){return x.role==='bd'||x.role==='bd_lead';});

  // Show manager cards
  var managerCards=managers.map(function(m){
    var emailAccounts=(STATE.userEmailsCache[m.id]||[]).filter(function(a){return a.is_active;});
    var capacity=emailAccounts.reduce(function(s,a){return s+(a.daily_send_limit||300);},0);
    var hasCapacity=emailAccounts.length>0;
    return '<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:16px;display:flex;align-items:center;gap:14px;margin-bottom:12px">'+
      av(m,'40')+
      '<div style="flex:1;min-width:0">'+
        '<div style="font-weight:600;font-size:14px">'+htmlEsc(m.name)+'</div>'+
        '<div style="font-size:12px;color:var(--text3);margin-top:3px">'+
          emailAccounts.length+' email ID'+(emailAccounts.length!==1?'s':'')+
          ' \u00b7 '+capacity+' emails/day capacity'+
        '</div>'+
        (emailAccounts.length?
          '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:6px">'+
            emailAccounts.map(function(a){
              return '<span style="font-size:11px;padding:2px 8px;background:var(--accent-l);color:var(--accent);border-radius:6px">'+htmlEsc(a.display_name)+'</span>';
            }).join('')+
          '</div>':
          '<div style="font-size:12px;color:var(--red);margin-top:4px">No email IDs assigned</div>')+
      '</div>'+
      (hasCapacity&&poolStats.total>0?
        '<button onclick="openAssignToManager(\''+m.id+'\')" style="background:var(--accent);color:#fff;border:0;padding:10px 20px;border-radius:8px;font-weight:600;font-size:13px;cursor:pointer;white-space:nowrap">Assign leads</button>':
        '<span style="font-size:12px;color:var(--text3);padding:8px 12px">'+(!hasCapacity?'No email IDs':'No leads')+'</span>')+
    '</div>';
  }).join('');

  // Pool summary bar
  var poolBar='';
  if(poolStats.total>0){
    var bf=poolStats.by_freshness||{};
    var bi=poolStats.by_industry||{};
    var btz=poolStats.by_timezone||{};
    poolBar='<div style="background:var(--card);border:1px solid var(--border);border-radius:var(--r2);padding:14px 16px;margin-bottom:18px">'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">'+
        '<div style="font-weight:600;font-size:13px">Unassigned lead pool</div>'+
        '<div style="font-size:22px;font-weight:700;color:var(--accent)">'+poolStats.total+'</div>'+
      '</div>'+
      '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;font-size:12px">'+
        '<div>'+
          '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">Freshness</div>'+
          Object.keys(bf).map(function(k){
            var col=k==='Old'?'var(--red)':k==='New'?'var(--green)':'var(--accent)';
            return '<div style="display:flex;justify-content:space-between;padding:2px 0"><span style="color:'+col+';font-weight:500">'+k+'</span><span>'+bf[k]+'</span></div>';
          }).join('')+
        '</div>'+
        '<div>'+
          '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">Industry</div>'+
          Object.keys(bi).slice(0,5).map(function(k){
            return '<div style="display:flex;justify-content:space-between;padding:2px 0"><span>'+htmlEsc(k)+'</span><span>'+bi[k]+'</span></div>';
          }).join('')+
        '</div>'+
        '<div>'+
          '<div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.05em;margin-bottom:4px">Timezone</div>'+
          Object.keys(btz).map(function(k){
            return '<div style="display:flex;justify-content:space-between;padding:2px 0"><span>'+htmlEsc(k)+'</span><span>'+btz[k]+'</span></div>';
          }).join('')+
        '</div>'+
      '</div>'+
      (poolStats.duplicates?'<div style="margin-top:8px;font-size:12px;color:var(--amber)">\u26a0 '+poolStats.duplicates+' duplicate leads in pool</div>':'')+
    '</div>';
  } else {
    poolBar='<div style="background:var(--green-l);border:1px solid var(--green);border-radius:var(--r2);padding:14px 16px;margin-bottom:18px;font-size:13px;color:var(--green);font-weight:600">\u2713 No unassigned leads — pool is clear for today.</div>';
  }

  return '<div class="page">'+
    '<div class="ph"><div class="flex jb aic">'+
      '<div><div class="ptitle">Assign Leads</div>'+
        '<div class="psub">'+poolStats.total+' unassigned leads in pool \u00b7 '+managers.length+' managers</div></div>'+
      '<button onclick="refreshPoolStats()" style="background:transparent;border:1px solid var(--border);color:var(--text2);padding:7px 13px;border-radius:8px;font-size:12px;cursor:pointer">\u21bb Refresh pool</button>'+
    '</div></div>'+
    poolBar+
    '<div style="font-weight:600;font-size:13px;color:var(--text2);margin-bottom:10px;text-transform:uppercase;letter-spacing:.05em">Managers</div>'+
    managerCards+
  '</div>';
}

window.toggleAssignSel=function(id,v){
  if(!STATE.assignSel)STATE.assignSel={};
  STATE.assignSel[id]=v;render();
};
window.toggleAllAssign=function(v){
  if(!STATE.assignSel)STATE.assignSel={};
  var f=STATE.assignFilter||{ra:'',dup:'all'};
  STATE.jobs.filter(function(j){
    if(j.stage!=='Unassigned')return false;
    if(f.ra&&j.created_by!==f.ra)return false;
    if(f.dup==='dup'&&!j.is_duplicate)return false;
    if(f.dup==='clean'&&j.is_duplicate)return false;
    return true;
  }).forEach(function(j){STATE.assignSel[j.id]=v;});
  render();
};
window.setAssignFilter=function(k,v){
  if(!STATE.assignFilter)STATE.assignFilter={ra:'',dup:'all'};
  STATE.assignFilter[k]=v;
  STATE.assignSel={};render();
};
window.openAssignConfirm=function(){
  var sel=STATE.assignSel||{};
  var selIds=Object.keys(sel).filter(function(k){return sel[k];});
  var bdId=STATE.assignTargetBD;
  if(!selIds.length||!bdId){showToast('Select leads and a BD first','warning');return;}
  var bd=STATE.users.find(function(u){return u.id===bdId;})||{name:'Unknown'};
  var now=new Date();
  var dateStr=now.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'});
  var timeStr=now.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit'});
  STATE.modal='<div class="modal modal-w480">'+
    '<div class="mh"><div class="mt">Confirm Assignment</div></div>'+
    '<div class="mb_">'+
      '<div style="padding:16px;background:var(--accent-l);border-radius:var(--r2);margin-bottom:12px">'+
        '<div style="font-size:22px;font-weight:700;color:var(--accent);margin-bottom:4px">'+selIds.length+' leads</div>'+
        '<div style="font-size:14px;color:var(--text2)">\u2192 <strong>'+htmlEsc(bd.name)+'</strong></div>'+
        '<div style="font-size:12px;color:var(--text3);margin-top:6px">'+dateStr+' \u00b7 '+timeStr+'</div>'+
      '</div>'+
      '<div style="font-size:13px;color:var(--text2)">Once confirmed, these leads will be marked <strong>Assigned</strong> and the email engine will begin sending outreach emails over the next 2\u20133 minutes.</div>'+
    '</div>'+
    '<div class="mf">'+
      '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
      '<button class="btn btn-primary" onclick="submitBulkAssign()">Confirm & Assign</button>'+
    '</div>'+
  '</div>';
  render();
};
window.submitBulkAssign=function(){
  var sel=STATE.assignSel||{};
  var selIds=Object.keys(sel).filter(function(k){return sel[k];});
  var bdId=STATE.assignTargetBD;
  if(!selIds.length||!bdId)return;
  closeModal();
  apiPost('/jobs/bulk-assign',{job_ids:selIds,assigned_to_bd:bdId}).then(function(res){
    showToast(res.assigned+' leads assigned to '+res.bd_name,'success');
    STATE.assignSel={};STATE.assignTargetBD='';
    // Generate AI emails in background
    return apiPost('/emails/generate',{job_ids:selIds}).then(function(genRes){
      showToast('Generating '+genRes.generated+' emails for '+res.bd_name+'...','info');
      return refreshJobs();
    });
  }).catch(function(e){showToast('Failed: '+e.message,'error');});
};

// ════════════════════════════════════════════════
// BOOT (standalone) — disabled, API layer below boots instead
// ════════════════════════════════════════════════

// ════════════════════════════════════════════════
// API LAYER — Drop B2 (Jobs wired to backend)
// ════════════════════════════════════════════════
var IS_FILE=window.location.protocol==='file:';
var API_URL=(function(){var h=window.location.hostname;if(h===''||h==='localhost'||h.indexOf('127.')===0)return'https://fute-lms-backend.onrender.com';if(h.indexOf('onrender.com')>=0)return'';return'https://fute-lms-backend.onrender.com';})();
function apiFetch(method,path,body){var headers={'Content-Type':'application/json'};if(STATE.token)headers['Authorization']='Bearer '+STATE.token;return fetch(API_URL+path,{method:method,headers:headers,body:body?JSON.stringify(body):undefined}).then(function(r){return r.json().then(function(d){if(!r.ok)throw new Error(d.error||('HTTP '+r.status));return d;});});}
function apiGet(p){return apiFetch('GET',p);}
function apiPost(p,b){return apiFetch('POST',p,b);}
function apiPut(p,b){return apiFetch('PUT',p,b);}
function apiPatch(p,b){return apiFetch('PATCH',p,b);}
function apiDelete(p){return apiFetch('DELETE',p);}

// ── Restore session if present ─────────────────
STATE.token=sessionStorage.getItem('fg_token')||null;
try{var _su=sessionStorage.getItem('fg_user');if(_su){var _parsed=JSON.parse(_su);STATE.user=normaliseUser(_parsed);}}catch(e){}
// Restore outreach template mode from localStorage
try{
  if(STATE.user&&STATE.user.id){
    var _tmpl=localStorage.getItem('fute_outreach_tmpl_mode_'+STATE.user.id)||localStorage.getItem('fute_tmpl_mode_'+STATE.user.id);
    if(_tmpl){var _tm=JSON.parse(_tmpl);if(typeof _tm.random==='boolean')STATE.randomTemplateMode=_tm.random;}
  }
}catch(e){}
// Wipe demo seed data — will be replaced by API on login
STATE.jobs=[];STATE.contacts=[];STATE.users=[];STATE.companies=[];STATE.emails=[];STATE.reminders=[];STATE.activities=[];STATE.leads=[];

function normaliseUser(u){
  var nm=u.name||'';
  var parts=nm.trim().split(/\s+/);
  var initials=((parts[0]||'')[0]||'')+((parts[1]||'')[0]||'');
  var roles=u.roles||(u.role?[u.role]:[]);
  var primaryRole=roles[0]||u.role||'ra';
  var roleAvc={admin:'av-admin',bd:'av-bd',ra:'av-ra',ra_lead:'av-admin',bd_lead:'av-bd'};
  return{id:u.id,name:nm,email:u.email,role:primaryRole,roles:roles,empId:u.employee_id,desig:u.designation,plt:u.platform||'Gmail',ooo:u.ooo_until||null,av:initials.toUpperCase()||'?',avc:roleAvc[primaryRole]||'av-ra',bdm:null};
}
function userHasRole(u,role){
  if(!u)return false;
  if(Array.isArray(u.roles)&&u.roles.length)return u.roles.indexOf(role)>-1;
  return u.role===role;
}
function userHasAnyRole(u){
  var roles=Array.prototype.slice.call(arguments,1);
  return roles.some(function(r){return userHasRole(u,r);});
}
function normaliseJob(j){
  var co=j.company||{};
  var bd=j.bd_assignee||{};
  var sa=j.sending_account||{};
  return{id:j.id,company_id:j.company_id,company_name:co.name||'',company_ind:co.industry||'',company_web:co.website||'',
    position:j.position,location:j.location||'',source:j.source||'',job_url:j.job_url||'',
    stage:j.stage||'Unassigned',notes:j.notes||'',created_by:j.created_by,assigned_to:j.assigned_to,
    assigned_to_bd:j.assigned_to_bd||null,assigned_bd_name:bd.name||'',assigned_at:j.assigned_at||null,
    is_duplicate:!!j.is_duplicate,duplicate_of:j.duplicate_of||null,
    salary_range:j.salary_range||'',job_created_date:j.job_created_date||'',job_opened_date:j.job_opened_date||'',
    timezone:j.timezone||'',freshness:j.freshness||'',industry:j.industry||'',
    bdm_assigned_name:j.bdm_assigned_name||'',
    sending_email_id:j.sending_email_id||null,sending_email:sa.email_address||'',sending_display:sa.display_name||'',
    research:(function(){var r=parseResearchObject(j.research);return Object.keys(r).length?r:null;})(),
    created_date:j.created_date,created_at:j.created_at};
}
function flattenContacts(jobs){var out=[];jobs.forEach(function(j){(j.contacts||[]).forEach(function(c){out.push({id:c.id,job_id:c.job_id,first_name:c.first_name,last_name:c.last_name||'',designation:c.designation||'',email:c.email||'',phone:c.phone||'',linkedin:c.linkedin||'',is_primary:!!c.is_primary,email_status:c.email_status||'valid',ooo_until:c.ooo_until||null});});});return out;}

function loadAppData(){
  STATE.loading=true;render();
  var calls=[apiGet('/users'),apiGet('/jobs'),apiGet('/companies'),apiGet('/reminders'),apiGet('/industries')];
  var u=STATE.user;
  var isBD=(u&&(u.role==='bd'||u.role==='bd_lead'||u.role==='admin'||u.role==='ra_lead'));
  if(isBD)calls.push(apiGet('/emails?status=pending'));
  if(isBD)calls.push(apiGet('/emails?status=queued'));
  return Promise.all(calls).then(function(r){
    STATE.users=r[0].map(normaliseUser);
    STATE.jobs=r[1].map(normaliseJob);
    STATE.contacts=flattenContacts(r[1]);
    STATE.companies=r[2].map(function(c){return{id:c.id,name:c.name,web:c.website,ind:c.industry,loc:c.location};});
    STATE.reminders=r[3]||[];
    STATE.industriesList=r[4]||[];
    STATE.emailAccounts=[];
    // Load pool stats for ra_lead/admin
    if(STATE.user&&(STATE.user.role==='ra_lead'||STATE.user.role==='admin')){
      apiGet('/distribute/pool-stats').then(function(d){STATE.distributePoolStats=d;scheduleRender();}).catch(function(){});
    }
    // Load today's summary for BD
    if(STATE.user&&(STATE.user.role==='bd'||STATE.user.role==='bd_lead')){
      apiGet('/distribute/today-summary').then(function(d){STATE.todaySummary=d;scheduleRender();}).catch(function(){});
    }
    if(isBD){
      STATE.pendingEmails=(r[5]||[]);
      STATE.emails=(r[6]||[]);
      apiGet('/emails?status=sent').then(function(d){STATE.sentEmails=d||[];render();}).catch(function(){STATE.sentEmails=[];});
    }
    // Load app settings (global send times)
    apiGet('/app-settings').then(function(s){
      STATE.appSettings=s||{};
      render();
    }).catch(function(){});
    // Load current user's own email IDs for compose From selector
    if(STATE.user){
      apiGet('/users/'+STATE.user.id+'/emails').then(function(emails){
        STATE.userEmailsCache=STATE.userEmailsCache||{};
        STATE.userEmailsCache[STATE.user.id]=emails||[];
        render();
      }).catch(function(){});
    }
    // Load this user's personal outreach plan
    if(STATE.user&&userHasAnyRole(STATE.user,'bd','bd_lead','admin')){
      apiGet('/outreach-plan').then(function(plan){
        STATE.myOutreachPlan=plan||{};
        STATE.emailSubj=plan['tmpl_o1_subject']||STATE.emailSubj;
        STATE.emailBody=plan['tmpl_o1_body']||STATE.emailBody;
        STATE.fu1Subj=plan['tmpl_fu1_subject']||STATE.fu1Subj;
        STATE.fu1Body=plan['tmpl_fu1_body']||STATE.fu1Body;
        STATE.fu2Subj=plan['tmpl_fu2_subject']||STATE.fu2Subj;
        STATE.fu2Body=plan['tmpl_fu2_body']||STATE.fu2Body;
        // restore template mode preference
        if(plan['random_template_mode'])STATE.randomTemplateMode=plan['random_template_mode']==='true';
        if(plan['compose_style_preset'])STATE.outreachStylePreset=plan['compose_style_preset'];
        render();
      }).catch(function(){});
      apiGet('/users/'+STATE.user.id+'/emails').then(function(emails){
        STATE.userEmailsCache=STATE.userEmailsCache||{};
        STATE.userEmailsCache[STATE.user.id]=emails||[];
        var primary=(emails||[]).find(function(e){return e.is_primary;})||(emails||[])[0];
        if(primary){
          if(!STATE.sigEmailId)STATE.sigEmailId=primary.id;
          if(!STATE.planFromEmailId)STATE.planFromEmailId=primary.id;
          loadMailboxSignature(STATE.user.id,STATE.sigEmailId||primary.id);
        }
      }).catch(function(){});
    }
    // Load team assignments for admin/bd_lead
    if(STATE.user&&userHasAnyRole(STATE.user,'admin','bd_lead','ra_lead')){
      apiGet('/team-assignments').then(function(d){STATE.teamAssignments=d||[];render();}).catch(function(){});
      // Pre-load email IDs for all users
      apiGet('/users').then(function(users){
        (users||[]).forEach(function(u){
          apiGet('/users/'+u.id+'/emails').then(function(emails){
            STATE.userEmailsCache=STATE.userEmailsCache||{};
            STATE.userEmailsCache[u.id]=emails||[];
          }).catch(function(){});
        });
      }).catch(function(){});
    }
    STATE.loading=false;render();
    // Auto-start progress poll for BD/BD_Lead so bar appears without any button click
    if(STATE.user&&userHasAnyRole(STATE.user,'bd','bd_lead','admin')){startProgressPoll();}
    // Start background polling to keep UI in sync (every 30s)
    startBackgroundPoll();
  }).catch(function(err){
    STATE.loading=false;STATE.user=null;STATE.token=null;
    sessionStorage.removeItem('fg_token');sessionStorage.removeItem('fg_user');
    showToast('Could not connect: '+err.message,'error');render();
  });
}
function refreshJobs(){return apiGet('/jobs').then(function(raw){var p=STATE._pendingStageChanges||{};STATE.jobs=raw.map(normaliseJob).map(function(j){if(p[j.id])j.stage=p[j.id];return j;});STATE.contacts=flattenContacts(raw);scheduleRender();});}

// ── Background polling — keeps UI in sync ──────
var _bgPollTimer=null;
function startBackgroundPoll(){
  if(_bgPollTimer)return;
  _bgPollTimer=setInterval(function(){
    if(!STATE.user||!STATE.token)return;
    var pg=STATE.page;
    // Always refresh jobs (stage changes, new leads, assignments)
    apiGet('/jobs').then(function(raw){
      var p=STATE._pendingStageChanges||{};
      STATE.jobs=raw.map(normaliseJob).map(function(j){if(p[j.id])j.stage=p[j.id];return j;});
      STATE.contacts=flattenContacts(raw);
      scheduleRender();
    }).catch(function(){});
    // Refresh emails when on email page
    if(pg==='email'){loadEmailsForCurrentUser();}
    // Refresh pool stats when on assign page
    if(pg==='assign'&&STATE.user&&userHasAnyRole(STATE.user,'ra_lead','admin')){
      apiGet('/distribute/pool-stats').then(function(d){STATE.distributePoolStats=d;scheduleRender();}).catch(function(){});
    }
    // Refresh reminders when on reminders or dashboard page
    if(pg==='reminders'||pg==='dashboard'){
      apiGet('/reminders').then(function(d){STATE.reminders=d||[];scheduleRender();}).catch(function(){});
    }
  },30000);
}
function stopBackgroundPoll(){
  if(_bgPollTimer){clearInterval(_bgPollTimer);_bgPollTimer=null;}
}

// ── Auth ───────────────────────────────────────
window.guestSwitchRole=function(role){
  if(!STATE.user||!STATE.user.isGuest)return;
  var roleMap={bd:{role:'bd',roles:['bd'],av:'G',avc:'av-bd',desig:'BD Manager'},ra:{role:'ra',roles:['ra'],av:'G',avc:'av-ra',desig:'Research Analyst'},ra_lead:{role:'ra_lead',roles:['ra_lead'],av:'G',avc:'av-admin',desig:'RA Lead'}};
  var r=roleMap[role];if(!r)return;
  Object.assign(STATE.user,r);
  STATE.page='dashboard';
  sessionStorage.setItem('fg_user',JSON.stringify(STATE.user));
  showToast('Switched to '+r.desig+' view','info');
  render();
};

window.doGuestLogin=function(){
  STATE.loading=false;
  // Seed demo users
  var demoUsers=[
    {id:'guest',name:'Guest User',email:'guest@futeglobal.com',role:'bd',roles:['bd'],av:'G',avc:'av-bd',empId:'GUEST',desig:'BD Manager',isGuest:true},
    {id:'demo-ra',name:'Demo Analyst',email:'analyst@futeglobal.com',role:'ra',roles:['ra'],av:'DA',avc:'av-ra',empId:'FG-D01',desig:'Research Analyst',isGuest:true},
    {id:'demo-bd2',name:'Alex Rivera',email:'alex@futeglobal.com',role:'bd',roles:['bd'],av:'AR',avc:'av-bd',empId:'FG-D02',desig:'BD Manager',isGuest:true},
  ];
  // Seed demo jobs
  var demoJobs=[
    {id:'dj1',company_name:'Apex Construction Group',company_id:'dc1',position:'Project Manager',industry:'Architecture, Construction & Building Materials',location:'Dallas, TX',timezone:'CST',stage:'Assigned',assigned_to_bd:'guest',assigned_bd_name:'Guest User',created_by:'demo-ra',created_date:'2026-04-29',created_at:'2026-04-29T08:00:00Z',is_duplicate:false,freshness:'New'},
    {id:'dj2',company_name:'Meridian Financial',company_id:'dc2',position:'VP Finance',industry:'Banking & Financial Services',location:'New York, NY',timezone:'EST',stage:'Connected',assigned_to_bd:'guest',assigned_bd_name:'Guest User',created_by:'demo-ra',created_date:'2026-04-28',created_at:'2026-04-28T09:00:00Z',is_duplicate:false,freshness:'New'},
    {id:'dj3',company_name:'TechNova Solutions',company_id:'dc3',position:'Head of Engineering',industry:'Computer Hardware & Software',location:'San Francisco, CA',timezone:'PST',stage:'Unassigned',assigned_to_bd:null,assigned_bd_name:null,created_by:'demo-ra',created_date:'2026-04-29',created_at:'2026-04-29T10:00:00Z',is_duplicate:false,freshness:'New'},
    {id:'dj4',company_name:'GreenPath Energy',company_id:'dc4',position:'Operations Director',industry:'Energy, Utilities, Oil & Petroleum',location:'Houston, TX',timezone:'CST',stage:'Unassigned',assigned_to_bd:null,assigned_bd_name:null,created_by:'demo-ra',created_date:'2026-04-29',created_at:'2026-04-29T11:00:00Z',is_duplicate:false,freshness:'New'},
    {id:'dj5',company_name:'Coastal Legal Partners',company_id:'dc5',position:'Managing Partner',industry:'Law Enforcement, Legal & Security',location:'Miami, FL',timezone:'EST',stage:'Future',assigned_to_bd:'guest',assigned_bd_name:'Guest User',created_by:'demo-ra',created_date:'2026-04-27',created_at:'2026-04-27T08:00:00Z',is_duplicate:false,freshness:'Normal'},
  ];
  var demoContacts=[
    {id:'dc1',job_id:'dj1',first_name:'Karen',last_name:'Hadley',designation:'Project Manager',email:'khadley@apexconstruction.com',phone:'',linkedin:'',email_status:'valid',phone_type:'office'},
    {id:'dc2',job_id:'dj2',first_name:'Robert',last_name:'Chen',designation:'VP Finance',email:'rchen@meridianfinancial.com',phone:'',linkedin:'',email_status:'valid',phone_type:'office'},
    {id:'dc3',job_id:'dj3',first_name:'Sarah',last_name:'Kim',designation:'Head of Engineering',email:'skim@technova.io',phone:'',linkedin:'',email_status:'valid',phone_type:'personal'},
    {id:'dc4',job_id:'dj4',first_name:'Marcus',last_name:'Webb',designation:'Operations Director',email:'mwebb@greenpathenergy.com',phone:'',linkedin:'',email_status:'valid',phone_type:'office'},
    {id:'dc5',job_id:'dj5',first_name:'Diana',last_name:'Torres',designation:'Managing Partner',email:'dtorres@coastallegal.com',phone:'',linkedin:'',email_status:'out_of_office',phone_type:'office'},
  ];
  var demoPending=[
    {id:'de1',job_id:'dj1',contact_id:'dc1',to_email:'khadley@apexconstruction.com',subject:'Project Manager opportunity at Apex Construction Group',body:'Hi Karen,\n\nI came across Apex Construction Group and was impressed by your project portfolio.\n\nAt Fute Global, we specialize in connecting organizations with top-tier talent. Given your role, I believe we could assist with your Project Manager search.\n\nWould you be open to a quick 15-minute call?\n\nBest,\nGuest User\nFute Global LLC',status:'pending',followup_type:'initial',contact:{first_name:'Karen',last_name:'Hadley'},job:{position:'Project Manager',company:{name:'Apex Construction Group'}}},
  ];
  STATE.user=demoUsers[0];
  STATE.token='guest';
  STATE.jobs=demoJobs;
  STATE.contacts=demoContacts;
  STATE.users=demoUsers;
  STATE.companies=[
    {id:'dc1',name:'Apex Construction Group',ind:'Architecture, Construction & Building Materials',loc:'Dallas, TX'},
    {id:'dc2',name:'Meridian Financial',ind:'Banking & Financial Services',loc:'New York, NY'},
    {id:'dc3',name:'TechNova Solutions',ind:'Computer Hardware & Software',loc:'San Francisco, CA'},
  ];
  STATE.reminders=[];
  STATE.pendingEmails=demoPending;
  STATE.sentEmails=[];
  STATE.emailAccounts=[{id:'ge1',email_address:'guest@futeglobal.com',display_name:'Guest User',platform:'Gmail',is_connected:true}];
  STATE.page='dashboard';
  sessionStorage.setItem('fg_token','guest');
  sessionStorage.setItem('fg_user',JSON.stringify(STATE.user));
  render();
  showToast('Welcome! Explore the full workflow as Guest · Portfolio preview','info');
};

// ── Guest simulation layer ──────────────────────
window.guestSimulate=function(action,payload){
  if(!STATE.user||!STATE.user.isGuest)return false;
  switch(action){
    case 'addJob':
      var newJob={id:'dj'+Date.now(),company_name:payload.coName||'Demo Company',company_id:'demo',position:payload.position||'Demo Position',industry:payload.industry||'Computer Hardware & Software',location:payload.location||'New York, NY',timezone:'EST',stage:'Unassigned',assigned_to_bd:null,assigned_bd_name:null,created_by:'guest',created_date:todayIST(),created_at:new Date().toISOString(),is_duplicate:false,freshness:'New'};
      STATE.jobs.unshift(newJob);
      (payload.contacts||[]).forEach(function(c,i){STATE.contacts.push({id:'dc'+Date.now()+i,job_id:newJob.id,first_name:c.firstName||'',last_name:c.lastName||'',designation:c.designation||'',email:c.email||'',phone:c.phone||'',linkedin:c.linkedin||'',email_status:'valid',phone_type:c.phoneType||'office'});});
      STATE.modal=null;STATE.raForm=null;
      showToast('Lead added successfully (demo)','success');render();return true;
    case 'importExcel':
      [['BuildRight Inc','Site Superintendent','Architecture, Construction & Building Materials','Phoenix, AZ','MST','Tom','Bradley','tbradley@buildright.com'],
       ['Summit Healthcare','Director of Operations','Healthcare & Health Services','Chicago, IL','CST','Lisa','Monroe','lmonroe@summithealth.com'],
       ['Vector Capital','CFO','Banking & Financial Services','Boston, MA','EST','James','Whitfield','jwhitfield@vectorcap.com'],
       ['Nova Logistics','VP Supply Chain','Airline, Aviation & Transportation','Atlanta, GA','EST','Angela','Park','apark@novalogistics.com'],
       ['ClearSky Energy','Project Engineer','Energy, Utilities, Oil & Petroleum','Denver, CO','MST','Carlos','Vega','cvega@clearsky.com']
      ].forEach(function(d){var jid='dji'+Date.now()+Math.random();STATE.jobs.unshift({id:jid,company_name:d[0],company_id:jid,position:d[1],industry:d[2],location:d[3],timezone:d[4],stage:'Unassigned',assigned_to_bd:null,assigned_bd_name:null,created_by:'guest',created_date:todayIST(),created_at:new Date().toISOString(),is_duplicate:false,freshness:'New'});STATE.contacts.push({id:'dci'+Date.now()+Math.random(),job_id:jid,first_name:d[5],last_name:d[6],designation:d[1],email:d[7],phone:'',linkedin:'',email_status:'valid',phone_type:'office'});});
      STATE.modal=null;showToast('Imported 5 demo leads successfully','success');render();return true;
    case 'sendEmail':
      showToast('Email sent to '+(payload&&payload.to||'contact')+' (demo)','success');
      STATE.modal=null;STATE.mailMerge=null;render();return true;
    case 'assignLeads':
      var unassigned=STATE.jobs.filter(function(j){return j.stage==='Unassigned';});
      var n=Math.min(payload&&payload.count||3,unassigned.length);
      unassigned.slice(0,n).forEach(function(j){j.stage='Assigned';j.assigned_to_bd='guest';j.assigned_bd_name='Guest User';j.assigned_at=new Date().toISOString();});
      showToast('Assigned '+n+' leads to Guest User (demo)','success');render();return true;
    case 'connectEmail':
      STATE.emailAccounts=[{id:'ge1',email_address:'guest@futeglobal.com',display_name:'Guest User',platform:'Gmail',is_connected:true}];
      showToast('Email account connected (demo)','success');render();return true;
    case 'stageChange':
      var sj=STATE.jobs.find(function(x){return x.id===payload.id;});
      if(sj){sj.stage=payload.stage;showToast('Stage updated (demo)','success');render();}return true;
  }
  return false;
};

window.doLogin=function(){
  if(IS_FILE){showToast('Open via fute-lms-backend.onrender.com','warning');return;}
  var em=(document.getElementById('login-email')||{}).value||'';
  var pw=(document.getElementById('login-pass')||{}).value||'';
  if(!em||!pw){var e=document.getElementById('login-err');if(e){e.textContent='Enter email and password';e.style.display='block';}return;}
  // Clear any guest session before attempting real login
  STATE.token=null;STATE.user=null;
  sessionStorage.removeItem('fg_token');sessionStorage.removeItem('fg_user');
  STATE.loading=true;render();
  apiPost('/auth/login',{email:em,password:pw}).then(function(d){
    STATE.token=d.token;STATE.user=normaliseUser(d.user);
    sessionStorage.setItem('fg_token',d.token);sessionStorage.setItem('fg_user',JSON.stringify(STATE.user));
    STATE.page='dashboard';loadAppData();
  }).catch(function(err){
    STATE.loading=false;render();
    var e=document.getElementById('login-err');if(e){e.textContent=err.message||'Invalid credentials';e.style.display='block';}
  });
};
window.loginAs=function(){showToast('Use email + password to log in','warning');};
window.doLogout=function(){STATE.user=null;STATE.token=null;sessionStorage.removeItem('fg_token');sessionStorage.removeItem('fg_user');STATE.jobs=[];STATE.contacts=[];STATE.page='login';render();};

// ── Jobs (wired) ───────────────────────────────
window.changeJobStage=function(jid,st){
  var j=jobById(jid);if(!j)return;
  if(j.stage===st)return;
  if(STATE.user&&STATE.user.isGuest){guestSimulate('stageChange',{id:jid,stage:st});return;}
  var old=j.stage;j.stage=st;
  if(!STATE._pendingStageChanges)STATE._pendingStageChanges={};
  STATE._pendingStageChanges[jid]=st;
  render();
  apiPut('/jobs/'+jid,{stage:st}).then(function(){
    if(STATE._pendingStageChanges)delete STATE._pendingStageChanges[jid];
    showToast('Stage updated','success');
  }).catch(function(e){
    if(STATE._pendingStageChanges)delete STATE._pendingStageChanges[jid];
    j.stage=old;showToast('Failed: '+e.message,'error');render();
  });
};
window.saveJobNotes=function(jid,val){
  var j=jobById(jid);if(!j||j.notes===val)return;var old=j.notes;j.notes=val;
  apiPut('/jobs/'+jid,{notes:val}).then(function(){showToast('Notes saved','success');}).catch(function(e){j.notes=old;showToast('Failed: '+e.message,'error');render();});
};
window.deleteJob=function(jid){
  if(!confirm('Delete this job and all its contacts?'))return;
  apiDelete('/jobs/'+jid).then(function(){STATE.modal=null;STATE.detailJob=null;showToast('Job deleted','success');return refreshJobs();}).catch(function(e){showToast('Failed: '+e.message,'error');});
};
window.submitAddJob=function(){
  var co=document.getElementById('aj-co').value;
  var pos=document.getElementById('aj-pos').value.trim();
  var fn=document.getElementById('aj-fn').value.trim();
  if(!co){showToast('Pick a company','error');return;}
  if(!pos){showToast('Position is required','error');return;}
  if(!fn){showToast('First contact name is required','error');return;}
  var payload={company_id:co,position:pos,
    location:document.getElementById('aj-loc').value.trim(),
    source:document.getElementById('aj-src').value.trim()||'LinkedIn',
    job_url:document.getElementById('aj-url').value.trim(),
    stage:'Active',notes:'',
    contacts:[{first_name:fn,last_name:document.getElementById('aj-ln').value.trim(),
      designation:document.getElementById('aj-desig').value.trim(),
      email:document.getElementById('aj-email').value.trim(),
      phone:document.getElementById('aj-phone').value.trim(),linkedin:''}]};
  apiPost('/jobs',payload).then(function(){STATE.modal=null;showToast('Job created','success');return refreshJobs();}).catch(function(e){showToast('Failed: '+e.message,'error');});
};
window.submitAddContact=function(jid){
  var fn=document.getElementById('ac-fn').value.trim();
  if(!fn){showToast('First name is required','error');return;}
  var existing=jobContacts(jid);
  apiPost('/contacts',{job_id:jid,first_name:fn,
    last_name:document.getElementById('ac-ln').value.trim(),
    designation:document.getElementById('ac-desig').value.trim(),
    email:document.getElementById('ac-email').value.trim(),
    phone:document.getElementById('ac-phone').value.trim(),
    linkedin:document.getElementById('ac-linkedin').value.trim(),
    is_primary:existing.length===0
  }).then(function(){showToast('Contact added','success');STATE.modal={type:'jobDetail',id:jid};return refreshJobs();}).catch(function(e){showToast('Failed: '+e.message,'error');});
};
window.deleteContact=function(cid){
  if(!confirm('Delete this contact?'))return;
  apiDelete('/contacts/'+cid).then(function(){showToast('Contact deleted','success');return refreshJobs();}).catch(function(e){showToast('Failed: '+e.message,'error');});
};


// ===== BD MANAGER / RECRUITER WORKFLOW MODULE (additive) =====

(function(){

  // ── US states ─────────────────────────────────────────────────────────────
  var US_STATES=["Alabama","Alaska","Arizona","Arkansas","California","Colorado","Connecticut","Delaware","Florida","Georgia","Hawaii","Idaho","Illinois","Indiana","Iowa","Kansas","Kentucky","Louisiana","Maine","Maryland","Massachusetts","Michigan","Minnesota","Mississippi","Missouri","Montana","Nebraska","Nevada","New Hampshire","New Jersey","New Mexico","New York","North Carolina","North Dakota","Ohio","Oklahoma","Oregon","Pennsylvania","Rhode Island","South Carolina","South Dakota","Tennessee","Texas","Utah","Vermont","Virginia","Washington","West Virginia","Wisconsin","Wyoming"];

  // ── BD namespace on STATE (no demo data, real API only) ───────────────────
  if(!STATE.bd){
    STATE.bd={
      jobOrders:[],
      candidates:[],
      submissions:[],
      assignments:[],
      loading:false,
      view:{joId:null,kanbanJoId:null},
      form:{},
      leadSel:{},
      jobFilter:{state:"",status:"",job_type:"",priority:"",remote:""},
      jobFilterOpen:false,
      _filterDocBound:false,
      _convertQueue:null
    };
  }

  var BD_STAGES=["Sourced","Screening","Submitted to BDM","Submitted to Client","Interview Scheduled","Offer","Placed","Rejected","On Hold"];
  var BDM_GATED="Submitted to Client";
  var STAGE_COLORS={"Sourced":"var(--text3)","Screening":"#6b7280","Submitted to BDM":"var(--amber)","Submitted to Client":"var(--accent)","Interview Scheduled":"#2563eb","Offer":"#7c3aed","Placed":"var(--green)","Rejected":"var(--red)","On Hold":"#9ca3af"};
  var JOB_TYPES=["Contract","Full-time","Contract-to-Hire","Part-time","1099","W2"];
  var EMP_LEVELS=["Entry","Associate","Mid-Senior","Director","Executive"];
  var WORK_AUTH=["US Citizen","Green Card","H1B","OPT/CPT","TN","Any"];
  var PRIORITIES=["Low","Normal","High","Urgent"];
  var JOB_STATUSES=["Active","On Hold","Filled","Closed"];
  var REMOTE=["No","Yes","Hybrid"];

  function isBDM(u){return userHasAnyRole(u,'admin','bd','bd_lead');}
  function isRec(u){return userHasRole(u,'recruiter');}
  function uName(id){var x=(STATE.users||[]).find(function(u){return u.id===id;});return x?x.name:"—";}
  function esc(s){return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
  function code(t){return '<span style="font-family:var(--mono);font-size:11px;color:var(--accent);font-weight:700">'+esc(t)+'</span>';}
  function badge(st){var c={Active:"var(--green)","On Hold":"var(--amber)",Filled:"var(--accent)",Closed:"var(--text3)"}[st]||"var(--text3)";return '<span style="font-size:11px;font-weight:700;color:'+c+';background:rgba(0,0,0,.04);padding:2px 8px;border-radius:10px">'+esc(st)+'</span>';}

  // ── API loaders ────────────────────────────────────────────────────────────
  function loadJobOrders(){
    STATE.bd.loading=true;render();
    return apiGet('/job-orders').then(function(d){
      STATE.bd.jobOrders=d||[];STATE.bd.loading=false;render();
    }).catch(function(e){STATE.bd.loading=false;showToast('Failed to load jobs: '+e.message,'error');render();});
  }
  function loadCandidates(q){
    return apiGet('/candidates'+(q?'?q='+encodeURIComponent(q):'')).then(function(d){return d||[];}).catch(function(){return[];});
  }
  function loadSubmissions(joId){
    return apiGet('/job-orders/'+joId+'/submissions').then(function(d){return d||[];}).catch(function(){return[];});
  }

  // ── NAV injection ──────────────────────────────────────────────────────────
  var _origRender=window.render;
  window.render=function(){
    _origRender.apply(this,arguments);
    injectBDNav();
    if(STATE.page==='leads')injectLeadsTaskbar();
    if(BD_PAGES[STATE.page])paintBDPage();
  };

  function injectBDNav(){
    var u=STATE.user; if(!u)return;
    var navWrap=document.querySelector('.sb-nav'); if(!navWrap)return;
    if(navWrap.querySelector('[data-bdnav]'))return;
    var items=[];
    if(isBDM(u))items.push({id:"bd_joborders",lbl:"Jobs",ic:"leads"});
    if(isRec(u)&&!isBDM(u))items.push({id:"bd_myjobs",lbl:"My Jobs",ic:"leads"});
    if(!items.length)return;
    var anchor=null,navEls=navWrap.querySelectorAll('.nav-item');
    for(var k=0;k<navEls.length;k++){if((navEls[k].getAttribute('onclick')||'').indexOf("goPage('leads')")>-1){anchor=navEls[k];break;}}
    items.forEach(function(n){
      var active=(STATE.page===n.id)?' active':'';
      var d=document.createElement('div');d.className='nav-item'+active;d.setAttribute('data-bdnav','1');
      d.innerHTML='<span class="nav-icon">'+icon(n.ic)+'</span>'+n.lbl;
      d.onclick=function(){goPage(n.id);};
      if(anchor&&anchor.parentNode){anchor.parentNode.insertBefore(d,anchor.nextSibling);anchor=d;}
      else{navWrap.appendChild(d);}
    });
    var titleEl=document.querySelector('.tb-title');
    var titles={bd_joborders:"Jobs",bd_myjobs:"My Jobs",bd_jodetail:"Job",bd_kanban:"Candidate Pipeline"};
    if(titleEl&&titles[STATE.page])titleEl.textContent=titles[STATE.page];
  }

  // ── Leads page task bar ────────────────────────────────────────────────────
  function injectLeadsTaskbar(){
    var u=STATE.user; if(!u||!isBDM(u))return;
    var content=document.getElementById('content'); if(!content)return;
    if(content.querySelector('[data-bd-taskbar]'))return;
    var sel=Object.keys(STATE.bd.leadSel).filter(function(id){return STATE.bd.leadSel[id];});
    var connSel=sel.filter(function(id){
      var j=(STATE.jobs||[]).find(function(x){return x.id===id;});
      return j&&j.stage==='Connected';
    });
    var bar=document.createElement('div');
    bar.setAttribute('data-bd-taskbar','1');
    bar.style.cssText='display:flex;align-items:center;gap:12px;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:10px 14px;margin:0 0 12px 0';
    bar.innerHTML=
      '<span style="font-size:12.5px;color:var(--text2)">Select connected leads to convert into jobs.</span>'+
      '<span style="font-size:12px;color:var(--text3)">'+sel.length+' selected'+(sel.length?' · '+connSel.length+' connected':'')+'</span>'+
      '<div style="margin-left:auto;display:flex;gap:8px">'+
        (sel.length?'<button class="btn btn-sm btn-outline" onclick="bdClearLeadSel()">Clear</button>':'')+
        '<button class="btn btn-sm btn-primary" '+(connSel.length?'':'disabled style="opacity:.5;cursor:not-allowed"')+' onclick="bdConvertSelected()">Convert to Job'+(connSel.length>1?' ('+connSel.length+')':'')+'</button>'+
      '</div>';
    var page=content.querySelector('.page')||content.firstElementChild;
    if(page)page.insertBefore(bar,page.firstChild);else content.insertBefore(bar,content.firstChild);
    addLeadCheckboxes();
  }

  function addLeadCheckboxes(){
    var content=document.getElementById('content'); if(!content)return;
    if(content.querySelector('[data-bd-leadpick]'))return;
    var connected=(STATE.jobs||[]).filter(function(j){return j.stage==='Connected';});
    if(!connected.length)return;
    var already=STATE.bd.jobOrders.map(function(o){return o.source_lead_id;});
    var wrap=document.createElement('div');
    wrap.setAttribute('data-bd-leadpick','1');
    wrap.style.cssText='background:var(--accent-l);border:1px solid rgba(30,122,60,.22);border-radius:10px;padding:10px 14px;margin:0 0 14px 0';
    wrap.innerHTML='<div style="font-size:12px;font-weight:700;color:var(--accent);margin-bottom:8px">Connected leads ('+connected.length+') — tick to convert</div>'+
      '<div style="display:flex;flex-wrap:wrap;gap:8px">'+
      connected.map(function(j){
        var on=STATE.bd.leadSel[j.id]?'checked':'';
        var done=already.indexOf(j.id)>-1;
        return '<label style="display:flex;align-items:center;gap:7px;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:6px 10px;font-size:12px;'+(done?'opacity:.5':'')+'">'+
          '<input type="checkbox" '+on+' '+(done?'disabled':'')+' onchange="bdToggleLead(\''+j.id+'\',this.checked)">'+
          '<span style="font-weight:600">'+esc(j.position||j.pos||'')+'</span>'+
          '<span style="color:var(--text3)">'+esc(j.company_name||'')+'</span>'+
          (done?'<span style="color:var(--green);font-weight:700">✓ converted</span>':'')+
        '</label>';
      }).join("")+'</div>';
    var taskbar=content.querySelector('[data-bd-taskbar]');
    if(taskbar&&taskbar.parentNode)taskbar.parentNode.insertBefore(wrap,taskbar.nextSibling);
  }

  window.bdToggleLead=function(id,on){STATE.bd.leadSel[id]=on;render();};
  window.bdClearLeadSel=function(){STATE.bd.leadSel={};render();};
  window.bdConvertSelected=function(){
    var ids=Object.keys(STATE.bd.leadSel).filter(function(id){return STATE.bd.leadSel[id];});
    var alreadyConverted=STATE.bd.jobOrders.map(function(o){return o.source_lead_id;});
    var conn=ids.map(function(id){return (STATE.jobs||[]).find(function(x){return x.id===id;});})
                .filter(function(j){return j&&j.stage==='Connected'&&alreadyConverted.indexOf(j.id)<0;});
    if(!conn.length){showToast('Select at least one connected lead that hasn\'t been converted','error');return;}
    STATE.bd._convertQueue=conn.slice(1).map(function(j){return j.id;});
    STATE.bd.leadSel={};
    goPage('bd_joborders');
    bdOpenNewJob(conn[0].id);
  };

  // ── Page routing ───────────────────────────────────────────────────────────
  var BD_PAGES={bd_joborders:1,bd_myjobs:1,bd_jodetail:1,bd_kanban:1};
  window.BD_PAGES=BD_PAGES;
  var _origGoPage=window.goPage;
  window.goPage=function(p){
    if(BD_PAGES[p]){
      STATE.page=p;STATE.modal=null;
      _origRender();
      if(p==='bd_joborders'||p==='bd_myjobs')loadJobOrders();
      else paintBDPage();
      injectBDNav();
      return;
    }
    return _origGoPage.apply(this,arguments);
  };

  function paintBDPage(){
    var c=document.getElementById('content'); if(!c)return;
    if(STATE.page==='bd_joborders')c.innerHTML=renderJobOrders();
    else if(STATE.page==='bd_myjobs')c.innerHTML=renderMyJobs();
    else if(STATE.page==='bd_jodetail')c.innerHTML=renderJobOrderDetail();
    else if(STATE.page==='bd_kanban')c.innerHTML=renderKanban();
    if(STATE.page==='bd_joborders'&&STATE.bd.jobFilterOpen&&!STATE.bd._filterDocBound){
      STATE.bd._filterDocBound=true;
      setTimeout(function(){
        var h=function(){STATE.bd.jobFilterOpen=false;STATE.bd._filterDocBound=false;document.removeEventListener('click',h);render();};
        document.addEventListener('click',h);
      },0);
    }
  }

  // ── helpers ────────────────────────────────────────────────────────────────
  function myJobOrders(){
    var u=STATE.user; if(!u)return[];
    if(isBDM(u))return STATE.bd.jobOrders;
    return STATE.bd.jobOrders.filter(function(j){
      return (j.recruiters||[]).some(function(r){return r.recruiter_id===u.id||r.recruiter&&r.recruiter.id===u.id;});
    });
  }
  function joById(id){return STATE.bd.jobOrders.find(function(j){return j.id===id;});}

  // ════════════════════════════════════════════════════════════════════════════
  // PAGE: Jobs list
  // ════════════════════════════════════════════════════════════════════════════
  window.renderJobOrders=function(){
    if(STATE.bd.loading)return '<div class="page"><div style="text-align:center;padding:60px;color:var(--text3)">Loading jobs…</div></div>';
    var f=STATE.bd.jobFilter;
    var rows=STATE.bd.jobOrders.filter(function(j){
      if(f.state&&(j.state||'')!==f.state)return false;
      if(f.status&&(j.status||'')!==f.status)return false;
      if(f.job_type&&(j.job_type||'')!==f.job_type)return false;
      if(f.priority&&(j.priority||'')!==f.priority)return false;
      if(f.remote&&(j.remote||'')!==f.remote)return false;
      return true;
    });
    var activeCount=['state','status','job_type','priority','remote'].filter(function(k){return f[k];}).length;
    function fopt(key,all,list){return '<select class="sel" onchange="bdSetJobFilter(\''+key+'\',this.value)"><option value="">'+all+'</option>'+list.map(function(s){return '<option value="'+esc(s)+'"'+(f[key]===s?' selected':'')+'>'+esc(s)+'</option>';}).join("")+'</select>';}
    var body=rows.map(function(j){
      var recs=j.recruiters||[];
      var recNames=recs.length?recs.map(function(r){return r.recruiter?r.recruiter.name:uName(r.recruiter_id);}).join(', '):'<span style="color:var(--text3)">Unassigned</span>';
      var loc=[j.city,j.state].filter(Boolean).join(', ');
      var pay=(j.pay_min||j.pay_max)?((j.pay_cur||'USD')+' '+(j.pay_min||'?')+'–'+(j.pay_max||'?')):'—';
      return '<tr style="border-top:1px solid var(--border);cursor:pointer" onclick="bdOpenJobOrder(\''+j.id+'\')">'+
        '<td style="padding:11px 12px">'+code(j.job_code)+'<div style="font-size:10px;color:var(--text3);margin-top:2px">'+esc(j.lead_code||'')+'</div></td>'+
        '<td style="padding:11px 12px"><div style="font-weight:600;font-size:13.5px">'+esc(j.job_title||'')+'</div></td>'+
        '<td style="padding:11px 12px;font-size:12.5px">'+esc(j.client||'—')+'</td>'+
        '<td style="padding:11px 12px;font-size:12.5px">'+esc(loc||'—')+'</td>'+
        '<td style="padding:11px 12px">'+badge(j.status)+'</td>'+
        '<td style="padding:11px 12px;font-size:12.5px">'+esc(pay)+'</td>'+
        '<td style="padding:11px 12px;font-size:12.5px">'+recNames+'</td>'+
      '</tr>';
    }).join("");
    return '<div class="page">'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'+
        '<div style="font-size:13px;color:var(--text3)">All jobs. Convert a connected lead from the Leads page, or create one here.</div>'+
        '<div style="display:flex;gap:8px;align-items:center;position:relative">'+
          '<button class="btn btn-outline btn-sm" onclick="event.stopPropagation();bdToggleFilter()" title="Filters">'+
            '<span style="display:inline-flex;align-items:center;gap:6px">'+
              '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3"></polygon></svg>'+
              'Filters'+(activeCount?' ('+activeCount+')':'')+
            '</span>'+
          '</button>'+
          '<button class="btn btn-primary" onclick="bdOpenNewJob(null)">+ New Job</button>'+
          (STATE.bd.jobFilterOpen?
            '<div onclick="event.stopPropagation()" style="position:absolute;top:40px;right:0;z-index:30;width:260px;background:var(--card);border:1px solid var(--border);border-radius:12px;box-shadow:var(--sh3);padding:14px">'+
              '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px"><div style="font-weight:700;font-size:13px">Filters</div>'+(activeCount?'<button onclick="bdClearJobFilter()" style="font-size:11.5px;color:var(--red);background:none;border:none;cursor:pointer">Clear all</button>':'')+'</div>'+
              '<div style="margin-bottom:10px"><label style="font-size:11px;color:var(--text3)">State</label>'+fopt('state','All states',US_STATES)+'</div>'+
              '<div style="margin-bottom:10px"><label style="font-size:11px;color:var(--text3)">Status</label>'+fopt('status','All statuses',JOB_STATUSES)+'</div>'+
              '<div style="margin-bottom:10px"><label style="font-size:11px;color:var(--text3)">Job Type</label>'+fopt('job_type','All types',JOB_TYPES)+'</div>'+
              '<div style="margin-bottom:10px"><label style="font-size:11px;color:var(--text3)">Priority</label>'+fopt('priority','All priorities',PRIORITIES)+'</div>'+
              '<div><label style="font-size:11px;color:var(--text3)">Remote</label>'+fopt('remote','Any',REMOTE)+'</div>'+
            '</div>':'')+
        '</div>'+
      '</div>'+
      '<div class="card" style="overflow:auto">'+
        '<table style="width:100%;border-collapse:collapse;font-size:13px;min-width:820px">'+
          '<thead><tr style="background:var(--bg);text-align:left">'+
            ['JOB CODE','JOB TITLE','CLIENT','LOCATION','STATUS','PAY RATE','RECRUITER'].map(function(h){return '<th style="padding:10px 12px;font-size:11px;color:var(--text3);font-weight:600">'+h+'</th>';}).join("")+
          '</tr></thead>'+
          '<tbody>'+(body||'<tr><td colspan="7" style="padding:40px;text-align:center;color:var(--text3)">No jobs yet. Convert a connected lead or create one.</td></tr>')+'</tbody>'+
        '</table>'+
      '</div>'+
    '</div>';
  };
  window.bdSetJobFilter=function(k,v){STATE.bd.jobFilter[k]=v;STATE.bd.jobFilterOpen=true;render();};
  window.bdClearJobFilter=function(){STATE.bd.jobFilter={state:"",status:"",job_type:"",priority:"",remote:""};render();};
  window.bdToggleFilter=function(){STATE.bd.jobFilterOpen=!STATE.bd.jobFilterOpen;render();};

  // ════════════════════════════════════════════════════════════════════════════
  // NEW JOB FORM — tabbed
  // ════════════════════════════════════════════════════════════════════════════
  window.bdOpenNewJob=function(leadId){
    var f={tab:'details',status:'Active',pay_cur:'USD',remote:'No',clearance:'No',
      job_title:'',client:'',client_job_id:'',client_manager:'',end_client:'',
      job_type:'',emp_level:'',work_auth:'',priority:'Normal',
      country:'United States',state:'',city:'',zip:'',
      pay_min:'',pay_max:'',start_date:'',end_date:'',duration:'',
      req_docs:'',placement_fee:'',primary_skills:'',secondary_skills:'',
      exp_min:'',exp_max:'',industry:'',domain:'',degree:'',languages:'',job_category:'',
      positions:'1',job_description:'',comments:'',recruiter_ids:[],
      source_lead_id:null,lead_code:null};
    if(leadId){
      var lead=(STATE.jobs||[]).find(function(j){return j.id===leadId;});
      if(lead){
        f.source_lead_id=lead.id;
        f.lead_code=lead.lead_code||lead.lead_code||'';
        f.job_title=lead.position||lead.pos||'';
        f.client=lead.company_name||'';
        f.state=lead.state||''; f.city=lead.city||'';
      }
    }
    STATE.bd.form=f;
    renderNewJobModal();
  };

  function fld(label,inner,req){return '<div style="margin-bottom:12px"><label style="font-size:11.5px;color:var(--text2);display:block;margin-bottom:3px">'+label+(req?' <span style="color:var(--red)">*</span>':'')+'</label>'+inner+'</div>';}
  function inp(key,ph){return '<input class="sel" value="'+esc(STATE.bd.form[key]||'')+'" placeholder="'+(ph||'')+'" oninput="bdFormSet(\''+key+'\',this.value)">';}
  function selF(key,opts){return '<select class="sel" onchange="bdFormSet(\''+key+'\',this.value)">'+opts.map(function(o){return '<option value="'+esc(o)+'"'+(STATE.bd.form[key]===o?' selected':'')+'>'+esc(o||'Select')+'</option>';}).join("")+'</select>';}
  function selBlank(key,opts){return selF(key,[''].concat(opts));}

  window.bdFormSet=function(k,v){STATE.bd.form[k]=v;};
  window.bdFormTab=function(t){STATE.bd.form.tab=t;renderNewJobModal();};

  function renderNewJobModal(){
    var f=STATE.bd.form;
    var tabBtn=function(id,lbl){var on=f.tab===id;return '<button onclick="bdFormTab(\''+id+'\')" style="padding:8px 14px;border:0;border-bottom:2px solid '+(on?'var(--accent)':'transparent')+';background:none;cursor:pointer;font-size:13px;font-weight:'+(on?'700':'500')+';color:'+(on?'var(--accent)':'var(--text2)')+'">'+lbl+'</button>';};
    var body='';
    if(f.tab==='details'){
      body='<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px">'+
        fld('Job Title',inp('job_title','Required'),true)+
        fld('Job Status',selF('status',JOB_STATUSES),true)+
        fld('Client',inp('client','Client company'),true)+
        fld('Client Job ID',inp('client_job_id'))+
        fld('Client Manager',inp('client_manager'))+
        fld('End Client',inp('end_client'))+
        fld('Job Type',selBlank('job_type',JOB_TYPES))+
        fld('Employment Level',selBlank('emp_level',EMP_LEVELS))+
        fld('Work Authorization',selBlank('work_auth',WORK_AUTH))+
        fld('Priority',selF('priority',PRIORITIES))+
        fld('Remote Job',selF('remote',REMOTE))+
        fld('Clearance',selF('clearance',["No","Yes"]))+
        fld('Country',inp('country'))+
        fld('State',selBlank('state',US_STATES))+
        fld('City',inp('city'))+
        fld('Zip',inp('zip'))+
        fld('Start Date','<input type="date" class="sel" value="'+esc(f.start_date)+'" onchange="bdFormSet(\'start_date\',this.value)">')+
        fld('End Date','<input type="date" class="sel" value="'+esc(f.end_date)+'" onchange="bdFormSet(\'end_date\',this.value)">')+
        fld('Duration',inp('duration','e.g. 6 months'))+
        fld('Placement Fee %',inp('placement_fee'))+
        fld('Required Documents',inp('req_docs','e.g. Resume'))+
      '</div>'+
      '<div style="margin-top:6px">'+fld('Pay Rate (Min–Max)',
        '<div style="display:flex;gap:8px"><select class="sel" style="max-width:90px" onchange="bdFormSet(\'pay_cur\',this.value)">'+['USD','CAD','GBP','EUR','INR'].map(function(c){return '<option'+(f.pay_cur===c?' selected':'')+'>'+c+'</option>';}).join("")+'</select>'+
        '<input class="sel" placeholder="Min" value="'+esc(f.pay_min)+'" oninput="bdFormSet(\'pay_min\',this.value)">'+
        '<input class="sel" placeholder="Max" value="'+esc(f.pay_max)+'" oninput="bdFormSet(\'pay_max\',this.value)"></div>')+
      '</div>';
    } else if(f.tab==='skills'){
      body='<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">'+
        fld('Primary Skills',inp('primary_skills','Required'),true)+
        fld('Secondary Skills',inp('secondary_skills'))+
        fld('Industry',inp('industry'))+
        fld('Domain',inp('domain'))+
        fld('Degree',inp('degree'))+
        fld('Languages',inp('languages'))+
        fld('Job Category',inp('job_category'))+
      '</div>'+
      '<div style="margin-top:6px">'+fld('Experience (years)',
        '<div style="display:flex;gap:8px;align-items:center">'+
          '<input class="sel" placeholder="Min" value="'+esc(f.exp_min)+'" oninput="bdFormSet(\'exp_min\',this.value)">'+
          '<span style="color:var(--text3)">to</span>'+
          '<input class="sel" placeholder="Max" value="'+esc(f.exp_max)+'" oninput="bdFormSet(\'exp_max\',this.value)">'+
          '<span style="color:var(--text3)">years</span></div>',true)+
      '</div>';
    } else {
      var assigned=(f.recruiter_ids||[]).map(function(rid){
        var u=(STATE.users||[]).find(function(x){return x.id===rid;})||{};
        return '<span style="background:var(--accent-l);border:1px solid rgba(30,122,60,.25);border-radius:14px;padding:3px 8px 3px 4px;font-size:12px;display:inline-flex;align-items:center;gap:5px">'+esc(u.name||rid)+'<span onclick="bdFormRemoveRec(\''+rid+'\')" style="cursor:pointer;color:var(--text3);font-weight:700">×</span></span>';
      }).join(' ');
      body=
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">'+
          fld('Number of Positions',inp('positions'),true)+
          fld('Comments',inp('comments'))+
        '</div>'+
        fld('Assign Recruiter(s)',
          '<input class="sel" id="bd-rec-search" placeholder="Type 3+ letters of a recruiter\'s name…" oninput="bdRecSearch(this.value)" autocomplete="off">'+
          '<div id="bd-rec-suggest" style="position:relative"></div>'+
          '<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:6px">'+(assigned||'<span style="font-size:12px;color:var(--text3)">None assigned yet.</span>')+'</div>')+
        fld('Job Description','<textarea class="sel" style="min-height:120px;resize:vertical" oninput="bdFormSet(\'job_description\',this.value)" placeholder="Required">'+esc(f.job_description)+'</textarea>',true);
    }

    var queueNote=STATE.bd._convertQueue&&STATE.bd._convertQueue.length?STATE.bd._convertQueue.length+' more lead(s) queued after this':'';
    STATE.modal='<div class="modal modal-w860" onclick="event.stopPropagation()" style="width:min(900px,95vw)">'+
      '<div style="padding:16px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">'+
        '<div style="font-weight:700;font-size:16px">New Job'+(f.source_lead_id?' — from lead '+esc(f.lead_code):'')+'</div>'+
      '</div>'+
      '<div style="padding:0 20px;border-bottom:1px solid var(--border);display:flex;gap:4px">'+tabBtn('details','Job Details')+tabBtn('skills','Skills')+tabBtn('org','Organizational')+'</div>'+
      '<div style="padding:18px 20px;max-height:62vh;overflow-y:auto">'+body+'</div>'+
      '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">'+
        '<div style="font-size:11.5px;color:var(--text3)">'+queueNote+'</div>'+
        '<div style="display:flex;gap:8px">'+
          '<button class="btn btn-outline" onclick="bdCancelNewJob()">Cancel</button>'+
          '<button class="btn btn-primary" onclick="bdSaveNewJob()">Save Job</button>'+
        '</div>'+
      '</div>'+
    '</div>';
    render();
  }

  window.bdRecSearch=function(q){
    var box=document.getElementById('bd-rec-suggest'); if(!box)return;
    q=(q||'').trim().toLowerCase();
    if(q.length<3){box.innerHTML='';return;}
    var matches=(STATE.users||[]).filter(function(u){
      return isRec(u)&&u.name.toLowerCase().indexOf(q)>-1&&(STATE.bd.form.recruiter_ids||[]).indexOf(u.id)<0;
    });
    box.innerHTML='<div style="position:absolute;top:2px;left:0;right:0;background:var(--card);border:1px solid var(--border);border-radius:8px;box-shadow:var(--sh);z-index:5;max-height:160px;overflow-y:auto">'+
      (matches.length?matches.map(function(u){
        return '<div onclick="bdFormAddRec(\''+u.id+'\')" style="padding:8px 11px;cursor:pointer;font-size:13px;display:flex;align-items:center;gap:8px" onmouseover="this.style.background=\'var(--bg)\'" onmouseout="this.style.background=\'\'">'+
          av(u,"22")+'<div><div style="font-weight:600">'+esc(u.name)+'</div><div style="font-size:11px;color:var(--text3)">'+esc(u.desig||u.role||'')+'</div></div></div>';
      }).join(""):'<div style="padding:8px 11px;font-size:12.5px;color:var(--text3)">No matching recruiter</div>')+
    '</div>';
  };
  window.bdFormAddRec=function(rid){if((STATE.bd.form.recruiter_ids||[]).indexOf(rid)<0){STATE.bd.form.recruiter_ids=STATE.bd.form.recruiter_ids||[];STATE.bd.form.recruiter_ids.push(rid);}renderNewJobModal();};
  window.bdFormRemoveRec=function(rid){STATE.bd.form.recruiter_ids=(STATE.bd.form.recruiter_ids||[]).filter(function(x){return x!==rid;});renderNewJobModal();};
  window.bdCancelNewJob=function(){STATE.bd._convertQueue=null;closeModal();};

  window.bdSaveNewJob=function(){
    var f=STATE.bd.form;
    if(!(f.job_title||'').trim()){showToast('Job Title is required','error');STATE.bd.form.tab='details';renderNewJobModal();return;}
    if(!(f.client||'').trim()){showToast('Client is required','error');STATE.bd.form.tab='details';renderNewJobModal();return;}
    var body;
    if(f.source_lead_id){
      // convert-from-lead: flat body with job fields
      body=Object.assign({},f,{recruiter_ids:undefined,tab:undefined,source_lead_id:undefined,lead_code:undefined});
      apiPost('/job-orders/from-lead/'+f.source_lead_id,body).then(function(jo){
        bdAfterSave(jo,f);
      }).catch(function(e){showToast('Failed to create job: '+e.message,'error');});
    } else {
      // direct create: { lead:{...}, job:{...} }
      var lead={position:f.job_title,company_id:null,location:f.city+' '+f.state,source:'BD Direct'};
      var job=Object.assign({},f,{recruiter_ids:undefined,tab:undefined,source_lead_id:undefined,lead_code:undefined});
      apiPost('/job-orders',{lead:lead,job:job}).then(function(jo){
        bdAfterSave(jo,f);
      }).catch(function(e){showToast('Failed to create job: '+e.message,'error');});
    }
  };

  function bdAfterSave(jo,f){
    // assign recruiters if any were selected
    var recs=f.recruiter_ids||[];
    var assignPromise=recs.length?
      apiPost('/job-orders/'+jo.id+'/recruiters',{recruiter_ids:recs}).catch(function(){})
      :Promise.resolve();
    assignPromise.then(function(){
      showToast('Job '+jo.job_code+' created','success');
      if(STATE.bd._convertQueue&&STATE.bd._convertQueue.length){
        var nextId=STATE.bd._convertQueue.shift();
        bdOpenNewJob(nextId);return;
      }
      STATE.bd._convertQueue=null;
      closeModal();
      loadJobOrders();
    });
  }

  // ════════════════════════════════════════════════════════════════════════════
  // PAGE: My Jobs (recruiter)
  // ════════════════════════════════════════════════════════════════════════════
  window.renderMyJobs=function(){
    if(STATE.bd.loading)return '<div class="page"><div style="text-align:center;padding:60px;color:var(--text3)">Loading…</div></div>';
    var jobs=myJobOrders();
    if(!jobs.length)return '<div class="page"><div class="card" style="padding:40px;text-align:center;color:var(--text3)">No jobs assigned to you yet.</div></div>';
    var u=STATE.user;
    var cards=jobs.map(function(j){
      var loc=[j.city,j.state].filter(Boolean).join(', ');
      return '<div class="card" style="padding:16px;cursor:pointer" onclick="bdOpenKanban(\''+j.id+'\')">'+
        '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px">'+code(j.job_code)+badge(j.status)+'</div>'+
        '<div style="font-weight:600;font-size:15px;margin-bottom:3px">'+esc(j.job_title||'')+'</div>'+
        '<div style="font-size:12.5px;color:var(--text3);margin-bottom:10px">'+esc(j.client||'')+' · '+esc(loc)+'</div>'+
      '</div>';
    }).join("");
    return '<div class="page"><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px">'+cards+'</div></div>';
  };

  // ════════════════════════════════════════════════════════════════════════════
  // PAGE: Job detail (BD)
  // ════════════════════════════════════════════════════════════════════════════
  window.renderJobOrderDetail=function(){
    var j=joById(STATE.bd.view.joId);
    if(!j)return '<div class="page"><div style="padding:40px;text-align:center;color:var(--text3)">Job not found or still loading.</div></div>';
    var recs=j.recruiters||[];
    var subs=STATE.bd.submissions||[];
    var pending=subs.filter(function(s){return s.job_order_id===j.id&&s.stage==='Submitted to BDM';});
    var loc=[j.city,j.state,j.zip].filter(Boolean).join(', ');
    var pay=(j.pay_min||j.pay_max)?((j.pay_cur||'USD')+' '+(j.pay_min||'?')+'–'+(j.pay_max||'?')):'—';

    var recChips=recs.map(function(r){
      var ru=r.recruiter||{name:uName(r.recruiter_id)};
      return '<span style="background:var(--bg);border:1px solid var(--border);border-radius:14px;padding:3px 10px 3px 4px;font-size:12px;display:inline-flex;align-items:center;gap:6px">'+
        esc(ru.name||'')+'<span onclick="bdUnassign(\''+j.id+'\',\''+(ru.id||r.recruiter_id)+'\')" style="cursor:pointer;color:var(--text3);font-weight:700">×</span></span>';
    }).join("");

    var approval=pending.length?'<div class="card" style="padding:14px 16px;margin-bottom:16px;background:rgba(210,140,0,.07);border-color:rgba(210,140,0,.3)">'+
      '<div style="font-weight:600;font-size:13px;color:var(--amber);margin-bottom:9px">⚑ Awaiting approval ('+pending.length+')</div>'+
      pending.map(function(s){
        var c=s.candidate||{};
        return '<div style="display:flex;justify-content:space-between;align-items:center;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:8px 12px;margin-bottom:6px">'+
          '<div><b>'+esc(c.full_name||'')+'</b> '+code(c.candidate_code||'')+'</div>'+
          '<div style="display:flex;gap:6px">'+
            '<button class="btn btn-sm btn-primary" onclick="bdApproveSub(\''+s.id+'\')">Approve → Client</button>'+
            '<button class="btn btn-sm btn-outline" onclick="bdSetStage(\''+s.id+'\',\'Rejected\')">Reject</button>'+
          '</div></div>';
      }).join("")+'</div>':'';

    function dr(lbl,val){return val?'<div style="font-size:12.5px;margin-bottom:4px"><span style="color:var(--text3)">'+lbl+': </span>'+esc(val)+'</div>':'';}

    return '<div class="page">'+
      '<div style="margin-bottom:6px"><span onclick="goPage(\'bd_joborders\')" style="cursor:pointer;font-size:12.5px;color:var(--accent)">← Jobs</span></div>'+
      '<div class="card" style="padding:18px 20px;margin-bottom:16px">'+
        '<div style="display:flex;justify-content:space-between;align-items:start">'+
          '<div>'+
            '<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px">'+code(j.job_code)+badge(j.status)+'</div>'+
            '<div style="font-size:19px;font-weight:700">'+esc(j.job_title||'')+'</div>'+
            '<div style="font-size:13px;color:var(--text3);margin-top:2px">'+esc(j.client||'')+' · '+esc(loc||'')+'</div>'+
          '</div>'+
          '<button class="btn btn-sm btn-outline" onclick="bdOpenKanban(\''+j.id+'\')">View Pipeline</button>'+
        '</div>'+
        '<div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border);display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px">'+
          dr('Pay Rate',pay)+dr('Job Type',j.job_type)+dr('Emp. Level',j.emp_level)+
          dr('Work Auth',j.work_auth)+dr('Remote',j.remote)+dr('Clearance',j.clearance)+
          dr('Priority',j.priority)+dr('Positions',j.positions)+dr('Duration',j.duration)+
          dr('Primary Skills',j.primary_skills)+dr('Experience',(j.exp_min||j.exp_max)?j.exp_min+'–'+j.exp_max+' yrs':'')+dr('Industry',j.industry)+
          dr('Lead',j.lead_code)+dr('Client Job ID',j.client_job_id)+dr('Job Category',j.job_category)+
        '</div>'+
        (j.job_description?'<div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border);font-size:13px;white-space:pre-wrap">'+esc(j.job_description)+'</div>':'')+
      '</div>'+
      approval+
      '<div class="card" style="padding:16px;margin-bottom:16px">'+
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">'+
          '<div style="font-weight:600;font-size:14px">Assigned Recruiters</div>'+
          '<button class="btn btn-sm btn-primary" onclick="bdOpenAssign(\''+j.id+'\')">+ Assign</button>'+
        '</div>'+
        '<div style="display:flex;flex-wrap:wrap;gap:8px">'+(recChips||'<span style="font-size:12.5px;color:var(--text3)">No recruiters assigned.</span>')+'</div>'+
      '</div>'+
      bdFunnelCard(j.id)+
    '</div>';
  };

  function bdFunnelCard(jid){
    var subs=(STATE.bd.submissions||[]).filter(function(s){return !jid||s.job_order_id===jid;});
    var counts={};BD_STAGES.forEach(function(s){counts[s]=0;});
    subs.forEach(function(s){if(counts[s.stage]!==undefined)counts[s.stage]++;});
    var max=Math.max(1,Math.max.apply(null,BD_STAGES.map(function(s){return counts[s];})));
    return '<div class="card" style="padding:16px"><div style="font-weight:600;font-size:14px;margin-bottom:12px">Pipeline Funnel</div>'+
      BD_STAGES.map(function(s){var w=Math.round((counts[s]/max)*100);
        return '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">'+
          '<div style="width:140px;font-size:12px;color:var(--text2);text-align:right">'+s+'</div>'+
          '<div style="flex:1;background:var(--bg);border-radius:6px;height:22px">'+
            '<div style="width:'+w+'%;background:'+STAGE_COLORS[s]+';height:100%;border-radius:6px;min-width:'+(counts[s]?'22px':'0')+'"></div>'+
          '</div>'+
          '<div style="width:30px;font-size:12.5px;font-weight:700">'+counts[s]+'</div>'+
        '</div>';
      }).join("")+'</div>';
  }

  // ════════════════════════════════════════════════════════════════════════════
  // PAGE: Kanban
  // ════════════════════════════════════════════════════════════════════════════
  window.renderKanban=function(){
    var j=joById(STATE.bd.view.kanbanJoId);
    if(!j)return '<div class="page"><div style="padding:40px;text-align:center;color:var(--text3)">Job not found.</div></div>';
    var u=STATE.user,recruiterScoped=isRec(u)&&!isBDM(u);
    var subs=STATE.bd.submissions||[];
    var jobSubs=subs.filter(function(s){return s.job_order_id===j.id;});
    var cols=["Sourced","Screening","Submitted to BDM","Submitted to Client","Interview Scheduled","Offer","Placed"];
    var backLink=isBDM(u)?'bd_jodetail':'bd_myjobs';
    var colHtml=cols.map(function(st){
      var items=jobSubs.filter(function(s){return s.stage===st;});
      var locked=(st===BDM_GATED&&recruiterScoped);
      return '<div style="min-width:210px;flex:1;background:var(--bg);border-radius:10px;padding:10px">'+
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:9px">'+
          '<div style="font-size:12px;font-weight:700;color:'+STAGE_COLORS[st]+'">'+st+'</div>'+
          '<div style="font-size:11px;color:var(--text3);font-weight:700">'+items.length+'</div>'+
        '</div>'+
        items.map(function(s){
          var c=s.candidate||{};
          var nextStages=BD_STAGES.filter(function(x){
            if(x===s.stage)return false;
            if(x===BDM_GATED&&recruiterScoped)return false;
            return true;
          });
          return '<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:9px 10px;margin-bottom:7px">'+
            '<div style="font-weight:600;font-size:12.5px">'+esc(c.full_name||'')+'</div>'+
            '<div style="font-size:10.5px;color:var(--text3);margin-bottom:6px">'+code(c.candidate_code||'')+' · '+esc(c.current_title||'')+'</div>'+
            '<select class="sel" style="font-size:11px;padding:4px 6px" onchange="bdMoveStage(\''+s.id+'\',this.value)">'+
              '<option value="">Move to…</option>'+
              nextStages.map(function(x){return '<option value="'+x+'">'+x+'</option>';}).join("")+
            '</select>'+
          '</div>';
        }).join("")+
        (locked?'<div style="font-size:10px;color:var(--text3);text-align:center;padding:4px">🔒 BDM approval required</div>':'')+
      '</div>';
    }).join("");
    return '<div class="page">'+
      '<div style="margin-bottom:6px"><span onclick="bdBackFromKanban()" style="cursor:pointer;font-size:12.5px;color:var(--accent)">← Back</span></div>'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">'+
        '<div><div style="display:flex;gap:8px;align-items:center">'+code(j.job_code)+'<span style="font-weight:700;font-size:16px">'+esc(j.job_title||'')+'</span></div>'+
        '<div style="font-size:12.5px;color:var(--text3)">'+esc(j.client||'')+'</div></div>'+
        '<button class="btn btn-primary" onclick="bdOpenAddCandidate(\''+j.id+'\')">+ Add Candidate</button>'+
      '</div>'+
      '<div style="display:flex;gap:10px;overflow-x:auto;padding-bottom:8px">'+colHtml+'</div>'+
    '</div>';
  };
  window.bdBackFromKanban=function(){
    var u=STATE.user;
    if(isBDM(u)){STATE.bd.view.joId=STATE.bd.view.kanbanJoId;goPage('bd_jodetail');}
    else goPage('bd_myjobs');
  };

  // ── job order navigation ───────────────────────────────────────────────────
  window.bdOpenJobOrder=function(id){
    STATE.bd.view.joId=id;
    // load submissions for this job before opening detail
    loadSubmissions(id).then(function(subs){
      STATE.bd.submissions=subs;
      goPage('bd_jodetail');
    });
  };
  window.bdOpenKanban=function(id){
    STATE.bd.view.kanbanJoId=id;
    loadSubmissions(id).then(function(subs){
      STATE.bd.submissions=subs;
      goPage('bd_kanban');
    });
  };

  // ── recruiter assignment ───────────────────────────────────────────────────
  window.bdOpenAssign=function(jid){
    var j=joById(jid)||{};
    var assigned=(j.recruiters||[]).map(function(r){return r.recruiter_id||(r.recruiter&&r.recruiter.id);});
    var recruiters=(STATE.users||[]).filter(function(u){return isRec(u);});
    var list=recruiters.map(function(r){
      var on=assigned.indexOf(r.id)>-1;
      return '<label style="display:flex;align-items:center;gap:10px;padding:9px 11px;border:1px solid var(--border);border-radius:8px;margin-bottom:7px;cursor:pointer">'+
        '<input type="checkbox" class="bd-rec-chk" value="'+r.id+'"'+(on?' checked':'')+'>'+
        av(r,"26")+'<div><div style="font-weight:600;font-size:13px">'+esc(r.name)+'</div><div style="font-size:11px;color:var(--text3)">'+esc(r.desig||r.role||'')+'</div></div>'+
      '</label>';
    }).join("");
    STATE.modal='<div class="modal modal-w480" onclick="event.stopPropagation()">'+
      '<div style="padding:18px 20px;border-bottom:1px solid var(--border);font-weight:700;font-size:16px">Assign Recruiters</div>'+
      '<div style="padding:18px 20px;max-height:50vh;overflow-y:auto">'+(list||'<div style="color:var(--text3)">No users with the recruiter role yet.</div>')+'</div>'+
      '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px">'+
        '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
        '<button class="btn btn-primary" onclick="bdSaveAssign(\''+jid+'\')">Save</button>'+
      '</div>'+
    '</div>';render();
  };
  window.bdSaveAssign=function(jid){
    var checks=Array.prototype.slice.call(document.querySelectorAll('.bd-rec-chk'));
    var chosen=checks.filter(function(c){return c.checked;}).map(function(c){return c.value;});
    apiPost('/job-orders/'+jid+'/recruiters',{recruiter_ids:chosen}).then(function(){
      showToast(chosen.length+' recruiter(s) assigned','success');
      closeModal();
      // refresh the job detail so recruiter chips update
      return apiGet('/job-orders/'+jid).then(function(jo){
        var idx=STATE.bd.jobOrders.findIndex(function(x){return x.id===jid;});
        if(idx>-1)STATE.bd.jobOrders[idx]=jo; else STATE.bd.jobOrders.push(jo);
        render();
      });
    }).catch(function(e){showToast('Failed: '+e.message,'error');});
  };
  window.bdUnassign=function(jid,rid){
    apiDelete('/job-orders/'+jid+'/recruiters/'+rid).then(function(){
      showToast('Recruiter unassigned','info');
      return apiGet('/job-orders/'+jid).then(function(jo){
        var idx=STATE.bd.jobOrders.findIndex(function(x){return x.id===jid;});
        if(idx>-1)STATE.bd.jobOrders[idx]=jo;
        render();
      });
    }).catch(function(e){showToast('Failed: '+e.message,'error');});
  };

  // ── add candidate to pipeline ─────────────────────────────────────────────
  window.bdOpenAddCandidate=function(jid){
    STATE.bd._addCandJob=jid;
    STATE.bd._candSearchQ='';
    loadCandidates('').then(function(pool){
      STATE.bd._candPool=pool;
      bdShowAddCandModal(jid);
    });
  };
  window.bdCandSearch=function(jid,q){
    STATE.bd._candSearchQ=q;
    loadCandidates(q).then(function(pool){
      STATE.bd._candPool=pool;
      bdShowAddCandModal(jid);
    });
  };
  function bdShowAddCandModal(jid){
    var existingCids=(STATE.bd.submissions||[]).filter(function(s){return s.job_order_id===jid;}).map(function(s){return s.candidate_id;});
    var pool=(STATE.bd._candPool||[]).filter(function(c){return existingCids.indexOf(c.id)<0;});
    var q=STATE.bd._candSearchQ||'';
    var poolHtml=pool.map(function(c){
      return '<div style="display:flex;justify-content:space-between;align-items:center;border:1px solid var(--border);border-radius:8px;padding:9px 11px;margin-bottom:6px">'+
        '<div><div style="font-weight:600;font-size:13px">'+esc(c.full_name)+' '+code(c.candidate_code||'')+'</div>'+
        '<div style="font-size:11px;color:var(--text3)">'+esc(c.current_title||'')+' · '+esc(c.skills||'')+'</div></div>'+
        '<button class="btn btn-sm btn-primary" onclick="bdAddSub(\''+jid+'\',\''+c.id+'\')">Add</button>'+
      '</div>';
    }).join("");
    STATE.modal='<div class="modal modal-w640" onclick="event.stopPropagation()">'+
      '<div style="padding:18px 20px;border-bottom:1px solid var(--border);font-weight:700;font-size:16px">Add Candidate to Pipeline</div>'+
      '<div style="padding:18px 20px">'+
        '<input class="sel" placeholder="Search by name, email, CN- code…" value="'+esc(q)+'" oninput="bdCandSearch(\''+jid+'\',this.value)" style="margin-bottom:12px">'+
        '<div style="max-height:32vh;overflow-y:auto">'+(poolHtml||'<div style="color:var(--text3);font-size:12.5px;padding:8px">No matching candidates.</div>')+'</div>'+
        '<div style="border-top:1px solid var(--border);margin-top:12px;padding-top:12px">'+
          '<div style="font-size:11px;font-weight:700;color:var(--text3);margin-bottom:8px">OR CREATE NEW</div>'+
          '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">'+
            '<input id="nc_name" class="sel" placeholder="Full name">'+
            '<input id="nc_email" class="sel" placeholder="Email">'+
            '<input id="nc_title" class="sel" placeholder="Current title">'+
            '<input id="nc_skills" class="sel" placeholder="Skills">'+
          '</div>'+
          '<button class="btn btn-primary btn-sm" style="margin-top:9px" onclick="bdCreateCandAndAdd(\''+jid+'\')">Create & Add</button>'+
        '</div>'+
      '</div>'+
      '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end">'+
        '<button class="btn btn-outline" onclick="closeModal()">Close</button>'+
      '</div>'+
    '</div>';render();
  }
  window.bdAddSub=function(jid,cid){
    apiPost('/submissions',{candidate_id:cid,job_order_id:jid}).then(function(sub){
      STATE.bd.submissions=(STATE.bd.submissions||[]).concat([sub]);
      closeModal();showToast('Candidate added to pipeline','success');
      if(STATE.page==='bd_kanban')render();
    }).catch(function(e){
      if(e.message&&e.message.indexOf('already')>-1)showToast('Candidate already in this job','error');
      else showToast('Failed: '+e.message,'error');
    });
  };
  window.bdCreateCandAndAdd=function(jid){
    var name=(document.getElementById('nc_name')||{}).value||'';
    if(!name.trim()){showToast('Name required','error');return;}
    apiPost('/candidates',{
      full_name:name,
      email:(document.getElementById('nc_email')||{}).value||'',
      current_title:(document.getElementById('nc_title')||{}).value||'',
      skills:(document.getElementById('nc_skills')||{}).value||'',
      source:'Manual'
    }).then(function(c){bdAddSub(jid,c.id);}).catch(function(e){showToast('Failed: '+e.message,'error');});
  };

  // ── stage moves + BDM gate ────────────────────────────────────────────────
  window.bdMoveStage=function(sid,stage){
    if(!stage)return;
    var u=STATE.user;
    if(stage===BDM_GATED&&!isBDM(u)){showToast('Only a BD Manager can send a candidate to the client','error');render();return;}
    apiPatch('/submissions/'+sid+'/stage',{stage:stage}).then(function(sub){
      STATE.bd.submissions=(STATE.bd.submissions||[]).map(function(s){return s.id===sid?sub:s;});
      showToast('Moved to "'+stage+'"','success');render();
    }).catch(function(e){showToast('Failed: '+e.message,'error');render();});
  };
  window.bdSetStage=function(sid,stage){bdMoveStage(sid,stage);};
  window.bdApproveSub=function(sid){bdMoveStage(sid,BDM_GATED);};

})();


// ── Boot ───────────────────────────────────────
if(STATE.token&&STATE.user){STATE.page='dashboard';loadAppData();}else{STATE.page='login';render();}

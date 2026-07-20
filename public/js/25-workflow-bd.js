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

  var BD_STAGES=["Sourced","Screening","Submitted to BDM","Submitted to Client","Interview Scheduled","Interview Completed","Offer","Confirmation","Placement","Rejected","Not Joined","On Hold"];
  var BDM_GATED="Submitted to Client";
  var STAGE_COLORS={"Sourced":"var(--text3)","Screening":"#6b7280","Submitted to BDM":"var(--amber)","Submitted to Client":"var(--accent)","Interview Scheduled":"#2563eb","Interview Completed":"#1d4ed8","Offer":"#7c3aed","Confirmation":"#0891b2","Placement":"var(--green)","Rejected":"var(--red)","Not Joined":"#b91c1c","On Hold":"#9ca3af"};
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
  function code(t){return '<span style="font-family:var(--mono);font-size:10.5px;color:var(--text3);font-weight:600">'+esc(t)+'</span>';}
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
  // per-job stage summaries for the My Jobs cards (miniature pipeline view)
  function loadJobStageCounts(jobs){
    if(STATE.bd._jobCountsLoading)return;
    STATE.bd._jobCountsLoading=true;
    Promise.all(jobs.map(function(j){
      return apiGet('/job-orders/'+j.id+'/submissions').then(function(subs){return {id:j.id,subs:subs||[]};}).catch(function(){return {id:j.id,subs:[]};});
    })).then(function(results){
      var m={};
      results.forEach(function(r){
        var counts={},names={};
        r.subs.forEach(function(s){
          counts[s.stage]=(counts[s.stage]||0)+1;
          (names[s.stage]=names[s.stage]||[]).push((s.candidate&&s.candidate.full_name)||'');
        });
        m[r.id]={counts:counts,names:names,total:r.subs.length};
      });
      STATE.bd._jobStageCounts=m; STATE.bd._jobCountsLoading=false; render();
    });
  }
  window.renderMyJobs=function(){
    if(STATE.bd.loading)return '<div class="page"><div style="text-align:center;padding:60px;color:var(--text3)">Loading…</div></div>';
    var jobs=myJobOrders();
    if(!jobs.length)return '<div class="page"><div class="card" style="padding:40px;text-align:center;color:var(--text3)">No jobs assigned to you yet.</div></div>';
    if(!STATE.bd._jobStageCounts&&!STATE.bd._jobCountsLoading)loadJobStageCounts(jobs);
    var cards=jobs.map(function(j){
      var loc=[j.city,j.state].filter(Boolean).join(', ');
      var jc=(STATE.bd._jobStageCounts||{})[j.id];
      var chips=jc?BD_STAGES.filter(function(st){return jc.counts[st];}).map(function(st){
        return '<span title="'+esc((jc.names[st]||[]).join(', '))+'" style="font-size:10px;font-weight:700;color:'+(STAGE_COLORS[st]||'var(--text3)')+';background:var(--bg);padding:2px 7px;border-radius:8px;white-space:nowrap">'+esc(STAGE_ABBR[st]||st)+' '+jc.counts[st]+'</span>';
      }).join(' '):'';
      return '<div class="card" style="padding:16px;cursor:pointer" onclick="bdOpenSubmissions(\''+j.id+'\')">'+
        '<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:8px">'+code(j.job_code)+badge(j.status)+'</div>'+
        '<div style="font-weight:600;font-size:15px;margin-bottom:3px">'+esc(j.job_title||'')+'</div>'+
        '<div style="font-size:12.5px;color:var(--text3);margin-bottom:8px">'+esc(j.client||'')+' · '+esc(loc)+'</div>'+
        (jc?'<div style="display:flex;flex-wrap:wrap;gap:4px">'+(chips||'<span style="font-size:10.5px;color:var(--text3)">No candidates yet</span>')+'</div>':'')+
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
          '<div style="display:flex;gap:8px">'+
            '<button class="btn btn-sm btn-outline" onclick="bdOpenPipeline(\''+j.id+'\')">Pipeline</button>'+
            '<button class="btn btn-sm btn-outline" onclick="bdOpenSubmissions(\''+j.id+'\')">Submissions</button>'+
            '<button class="btn btn-sm btn-outline" onclick="bdOpenKanban(\''+j.id+'\')">Board</button>'+
            '<button class="btn btn-sm btn-outline" onclick="bdOpenPostingJD(\''+j.id+'\')">'+(j.posting_description?'Posting JD ✓':'Posting JD')+'</button>'+
          '</div>'+
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
      seqCandidatesCard(j.id)+
      bdFunnelCard(j.id)+
    '</div>';
  };

  // Candidates on this job with multi-select → "Start sequence" (bulk enroll).
  function seqCandidatesCard(jid){
    var subs=(STATE.bd.submissions||[]).filter(function(s){return s.job_order_id===jid;});
    var sel=STATE.bd.seqSel||[];
    var rows=subs.map(function(s){
      var c=s.candidate||{}; var on=sel.indexOf(s.id)>-1;
      var nextStages=BD_STAGES.filter(function(x){return x!==s.stage;});
      return '<div style="display:flex;align-items:center;gap:10px;padding:8px 4px;border-bottom:1px solid var(--border)">'+
        '<input type="checkbox" '+(on?'checked':'')+' onclick="bdToggleSeqSel(\''+s.id+'\')" style="cursor:pointer">'+
        '<div style="flex:1;min-width:0">'+
          '<span style="font-weight:600;font-size:13px;cursor:pointer;color:var(--accent)" onclick="bdOpenCandidate(\''+(c.id||'')+'\')">'+esc(c.full_name||'Candidate')+'</span> '+code(c.candidate_code||'')+
          (s.sub_stage?' <span style="font-size:10px;color:var(--text3)">· '+esc(s.sub_stage)+'</span>':'')+
        '</div>'+
        '<span style="font-size:11px;font-weight:700;color:'+(STAGE_COLORS[s.stage]||'var(--text3)')+'">'+esc(s.stage||'')+'</span>'+
        '<select class="sel" style="font-size:11px;padding:3px 6px;max-width:120px" onchange="bdMoveStage(\''+s.id+'\',this.value)">'+
          '<option value="">Move…</option>'+
          nextStages.map(function(x){return '<option value="'+x+'">'+x+'</option>';}).join("")+
        '</select>'+
      '</div>';
    }).join('')||'<div style="font-size:12.5px;color:var(--text3);padding:6px 2px">No candidates on this job yet.</div>';
    var allOn=subs.length&&subs.every(function(s){return sel.indexOf(s.id)>-1;});
    return '<div class="card" style="padding:16px;margin-bottom:16px">'+
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">'+
        '<div style="font-weight:600;font-size:14px">Candidates ('+subs.length+')</div>'+
        '<div style="display:flex;gap:8px;align-items:center">'+
          (subs.length?'<label style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--text2);cursor:pointer"><input type="checkbox" '+(allOn?'checked':'')+' onclick="bdToggleSeqSelAll(\''+jid+'\')" style="cursor:pointer"> All</label>':'')+
          '<button class="btn btn-sm btn-primary" '+(sel.length?'':'disabled style="opacity:.45;cursor:default"')+' onclick="bdStartSequence()">▶ Start sequence'+(sel.length?' ('+sel.length+')':'')+'</button>'+
        '</div>'+
      '</div>'+rows+
      (sel.length?'':'<div style="font-size:11.5px;color:var(--text3);margin-top:8px">Tick candidates from any stage, then Start sequence — you\'ll pick which mailbox(es) to send from (rotated across the batch).</div>')+
    '</div>';
  }
  window.bdToggleSeqSel=function(sid){ STATE.bd.seqSel=STATE.bd.seqSel||[]; var i=STATE.bd.seqSel.indexOf(sid); if(i>-1)STATE.bd.seqSel.splice(i,1); else STATE.bd.seqSel.push(sid); render(); };
  window.bdToggleSeqSelAll=function(jid){
    var subs=(STATE.bd.submissions||[]).filter(function(s){return s.job_order_id===jid;});
    var sel=STATE.bd.seqSel||[];
    var allOn=subs.length&&subs.every(function(s){return sel.indexOf(s.id)>-1;});
    if(allOn){ subs.forEach(function(s){ var i=sel.indexOf(s.id); if(i>-1)sel.splice(i,1); }); }
    else { subs.forEach(function(s){ if(sel.indexOf(s.id)<0)sel.push(s.id); }); }
    STATE.bd.seqSel=sel; render();
  };
  window.bdStartSequence=function(){
    var sel=STATE.bd.seqSel||[]; if(!sel.length)return;
    var subs=(STATE.bd.submissions||[]);
    var items=sel.map(function(sid){ var s=subs.find(function(x){return x.id===sid;})||{}; var c=s.candidate||{}; return {entity_id:sid,label:c.full_name||'Candidate'}; });
    wfStartSequence('submission',items);
  };

  // Compact vertical funnel — one thin column per stage instead of a tall
  // stack of horizontal bars.
  var STAGE_ABBR={'Sourced':'Sourced','Screening':'Screen','Submitted to BDM':'To BDM','Submitted to Client':'To Client',
    'Interview Scheduled':'Int Sched','Interview Completed':'Int Done','Offer':'Offer','Confirmation':'Confirm',
    'Placement':'Placed','Rejected':'Rejected','Not Joined':'No Join','On Hold':'Hold'};
  function bdFunnelCard(jid){
    var subs=(STATE.bd.submissions||[]).filter(function(s){return !jid||s.job_order_id===jid;});
    var counts={};BD_STAGES.forEach(function(s){counts[s]=0;});
    subs.forEach(function(s){if(counts[s.stage]!==undefined)counts[s.stage]++;});
    var max=Math.max(1,Math.max.apply(null,BD_STAGES.map(function(s){return counts[s];})));
    return '<div class="card" style="padding:14px 16px"><div style="font-weight:600;font-size:14px;margin-bottom:10px">Pipeline Funnel</div>'+
      '<div style="display:flex;align-items:flex-end;gap:6px;height:110px;overflow-x:auto">'+
      BD_STAGES.map(function(s){
        var h=counts[s]?Math.max(8,Math.round((counts[s]/max)*72)):3;
        return '<div style="flex:1;min-width:52px;text-align:center;display:flex;flex-direction:column;justify-content:flex-end;height:100%">'+
          '<div style="font-size:11px;font-weight:700;color:'+(counts[s]?'var(--text)':'var(--text3)')+'">'+counts[s]+'</div>'+
          '<div style="height:'+h+'px;background:'+(counts[s]?STAGE_COLORS[s]:'var(--border)')+';border-radius:4px 4px 0 0;margin:3px 6px 0"></div>'+
          '<div style="font-size:9px;color:var(--text3);padding-top:4px;border-top:2px solid var(--border);white-space:nowrap">'+esc(STAGE_ABBR[s]||s)+'</div>'+
        '</div>';
      }).join("")+'</div></div>';
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
    // every stage is a column, so a card can never vanish off the board
    var cols=BD_STAGES;
    var backLink=isBDM(u)?'bd_jodetail':'bd_myjobs';
    var colHtml=cols.map(function(st){
      var items=jobSubs.filter(function(s){return s.stage===st;});
      var locked=(st===BDM_GATED&&recruiterScoped);
      return '<div style="min-width:185px;flex:1;background:var(--bg);border-radius:10px;padding:10px">'+
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
            '<div style="font-weight:600;font-size:12.5px;cursor:pointer;color:var(--accent)" onclick="bdOpenCandidate(\''+(c.id||'')+'\')">'+esc(c.full_name||'')+'</div>'+
            '<div style="font-size:10.5px;color:var(--text3);margin-bottom:4px">'+code(c.candidate_code||'')+' · '+esc(c.current_title||'')+'</div>'+
            (s.sub_stage?'<div style="font-size:10px;font-weight:700;color:var(--text2);background:var(--bg);display:inline-block;padding:1px 7px;border-radius:8px;margin-bottom:5px">'+esc(s.sub_stage)+'</div>':'')+
            (s.interview_at?'<div style="font-size:10px;color:#2563eb;margin-bottom:5px">🗓 '+esc(new Date(s.interview_at).toLocaleString())+(s.interview_location?' · '+esc(s.interview_location):'')+'</div>':'')+
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
        '<div style="display:flex;gap:8px">'+
          '<button class="btn btn-outline" onclick="bdOpenPipeline(\''+j.id+'\')">Pipeline</button>'+
          '<button class="btn btn-outline" onclick="bdOpenSubmissions(\''+j.id+'\')">Submissions</button>'+
          '<button class="btn btn-primary" onclick="bdOpenAddCandidate(\''+j.id+'\')">+ Add Candidate</button>'+
        '</div>'+
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

  // ── anonymized posting JD ─────────────────────────────────────────────────
  // Rewrite the internal job description with the client identity removed so it
  // can go on job boards. Generate (AI when configured, rule-based otherwise),
  // edit, save onto the job, copy to clipboard.
  window.bdOpenPostingJD=function(jid){
    var j=joById(jid)||{};
    STATE.bd._pjdJob=jid;
    STATE.modal=
      '<div class="modal modal-w720" onclick="event.stopPropagation()">'+
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border)">'+
          '<div style="font-weight:700;font-size:15px">Posting JD — '+esc(j.job_title||'')+'</div>'+
          '<div style="font-size:11.5px;color:var(--text3);margin-top:2px">A public version of the job description with the company name and identifying details removed. Generate, review, edit, then save or copy for posting.</div>'+
        '</div>'+
        '<div style="padding:16px 20px">'+
          '<textarea id="pjd-text" class="sel" style="min-height:290px;resize:vertical;font-size:12.5px;line-height:1.45" placeholder="Click “Generate” to create an anonymized version from the internal JD, or paste/write one here.">'+esc(j.posting_description||'')+'</textarea>'+
        '</div>'+
        '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap">'+
          '<button class="btn btn-outline" onclick="bdGeneratePostingJD(\''+jid+'\')">✨ Generate from internal JD</button>'+
          '<div style="display:flex;gap:8px">'+
            '<button class="btn btn-outline" onclick="bdCopyPostingJD()">Copy</button>'+
            '<button class="btn btn-outline" onclick="closeModal()">Close</button>'+
            '<button class="btn btn-primary" onclick="bdSavePostingJD(\''+jid+'\')">Save</button>'+
          '</div>'+
        '</div>'+
      '</div>';
    render();
  };
  window.bdGeneratePostingJD=function(jid){
    showToast('Rewriting…','info');
    apiPost('/job-orders/'+jid+'/posting-jd',{}).then(function(r){
      var ta=document.getElementById('pjd-text');
      if(ta)ta.value=r.posting||'';
      showToast(r.used_ai?'AI rewrite ready — review before posting':'Sanitized (rule-based, no AI key) — review carefully before posting','success');
    }).catch(function(e){showToast('Failed: '+e.message,'error');});
  };
  window.bdSavePostingJD=function(jid){
    var ta=document.getElementById('pjd-text');
    var text=ta?ta.value:'';
    apiPut('/job-orders/'+jid,{posting_description:text}).then(function(jo){
      var idx=STATE.bd.jobOrders.findIndex(function(x){return x.id===jid;});
      if(idx>-1)STATE.bd.jobOrders[idx]=jo;
      showToast('Posting JD saved','success');closeModal();
    }).catch(function(e){showToast('Failed: '+e.message,'error');});
  };
  window.bdCopyPostingJD=function(){
    var ta=document.getElementById('pjd-text');
    if(!ta||!ta.value.trim()){showToast('Nothing to copy','error');return;}
    (navigator.clipboard&&navigator.clipboard.writeText?navigator.clipboard.writeText(ta.value):Promise.reject())
      .then(function(){showToast('Copied to clipboard','success');})
      .catch(function(){ta.select();document.execCommand('copy');showToast('Copied','success');});
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
            '<input id="nc_name" class="sel" placeholder="Full name *">'+
            '<input id="nc_email" class="sel" placeholder="Email">'+
            '<input id="nc_phone" class="sel" placeholder="Phone number">'+
            '<input id="nc_title" class="sel" placeholder="Current title">'+
            '<input id="nc_city" class="sel" placeholder="City">'+
            '<input id="nc_state" class="sel" placeholder="State">'+
          '</div>'+
          '<input id="nc_skills" class="sel" placeholder="Skills" style="margin-top:8px">'+
          '<div style="display:flex;align-items:center;gap:10px;margin-top:8px">'+
            '<label style="font-size:11.5px;color:var(--text2);white-space:nowrap">Resume:</label>'+
            '<input id="nc_resume" type="file" accept=".pdf,.doc,.docx,.rtf,.txt" style="font-size:11.5px">'+
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
    var g=function(id){return (document.getElementById(id)||{}).value||'';};
    var name=g('nc_name');
    if(!name.trim()){showToast('Name required','error');return;}
    var resumeEl=document.getElementById('nc_resume');
    apiPost('/candidates',{
      full_name:name, email:g('nc_email'), phone:g('nc_phone'),
      current_title:g('nc_title'), city:g('nc_city'), state:g('nc_state'),
      skills:g('nc_skills'), source:'Manual'
    }).then(function(c){
      var attach=(window.atsUploadResumeFile?atsUploadResumeFile(c.id,resumeEl):Promise.resolve(false));
      attach.then(function(){bdAddSub(jid,c.id);});
    }).catch(function(e){
      if(/possible_duplicate/i.test(e.message))showToast('Possible duplicate — search for the candidate above instead','error');
      else showToast('Failed: '+e.message,'error');
    });
  };

  // ── stage moves + BDM gate ────────────────────────────────────────────────
  // Every move opens the shared stage modal (sub-stage, note, interview
  // date/location, reminder). The modal enforces the client-side gate and
  // patches STATE.bd.submissions when done.
  window.bdMoveStage=function(sid,stage){
    if(!stage)return;
    openStageModal(sid,stage,function(){render();});
  };
  window.bdSetStage=function(sid,stage){bdMoveStage(sid,stage);};
  window.bdApproveSub=function(sid){bdMoveStage(sid,BDM_GATED);};

})();



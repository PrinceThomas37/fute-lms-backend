// ===== APPLICANTS / CANDIDATE DATABASE MODULE (additive) =====
// The shared candidate pool as a Ceipal-style browsable database, usable by both
// BD managers and recruiters. Adds a top-nav "Applicants" page: search + filter +
// paginate, add a new candidate (individual CN- id) with duplicate detection
// (full name + email-or-phone, warn-and-offer), edit, delete, and add-to-job.
// Slice 1 of docs/ATS_RECRUITING_PLAN.md.

(function () {

  // ── taxonomies ──────────────────────────────────────────────────────────────
  var APPLICANT_STATUSES = ['New lead','Active','Submitted','Interviewing','Placed','Do Not Call','Blacklisted','Inactive'];
  var SOURCES = ['Monster','CareerBuilder','LinkedIn','Indeed','Dice','Naukri','ZipRecruiter','Referral','Career Site','Job Board','Vendor','Manual'];
  var WORK_AUTH = ['US Citizen','Green Card','GC EAD','H1B','H4 EAD','OPT EAD','CPT','TN','L2 EAD','E3','Canada Citizen','Canada PR','Other'];
  var PAY_TYPES = ['Hourly','Yearly'];
  var AVAILABILITY = ['Immediate','1 week','2 weeks','3 weeks','1 month','Notice period'];
  var US_STATES = ["Alabama","Alaska","Arizona","Arkansas","California","Colorado","Connecticut","Delaware","Florida","Georgia","Hawaii","Idaho","Illinois","Indiana","Iowa","Kansas","Kentucky","Louisiana","Maine","Maryland","Massachusetts","Michigan","Minnesota","Mississippi","Missouri","Montana","Nebraska","Nevada","New Hampshire","New Jersey","New Mexico","New York","North Carolina","North Dakota","Ohio","Oklahoma","Oregon","Pennsylvania","Rhode Island","South Carolina","South Dakota","Tennessee","Texas","Utah","Vermont","Virginia","Washington","West Virginia","Wisconsin","Wyoming"];

  if (!STATE.ats) {
    STATE.ats = {
      loading:false, rows:[], total:0, page:1, limit:25,
      q:'', filters:{ applicant_status:'', source:'', state:'', work_authorization:'' },
      form:{}, editId:null, dupMatches:[]
    };
  }

  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
  function code(t){ return '<span style="font-family:var(--mono);font-size:11px;color:var(--accent);font-weight:700">'+esc(t)+'</span>'; }
  function canUse(u){ return userHasAnyRole(u,'admin','bd','bd_lead','recruiter'); }
  function isBDMlike(u){ return userHasAnyRole(u,'admin','bd','bd_lead'); }
  function fmtDate(s){ if(!s)return '—'; try{ var d=new Date(s); return (d.getMonth()+1)+'/'+d.getDate()+'/'+String(d.getFullYear()).slice(2); }catch(e){ return '—'; } }
  function loc(c){ return [c.city,c.state].filter(Boolean).join(', ') || c.current_location || '—'; }
  function jobTitle(c){ return c.headline || c.current_title || '—'; }
  function ownerName(c){ return (c.owner && c.owner.name) || '—'; }
  function creatorName(c){ return (c.creator && c.creator.name) || '—'; }

  // ── data ─────────────────────────────────────────────────────────────────────
  function loadApplicants(){
    STATE.ats.loading = true; paintATSPage();
    var a = STATE.ats, p = ['page='+a.page, 'limit='+a.limit];
    if (a.q) p.push('q='+encodeURIComponent(a.q));
    Object.keys(a.filters).forEach(function(k){ if(a.filters[k]) p.push(k+'='+encodeURIComponent(a.filters[k])); });
    return apiGet('/candidates?'+p.join('&')).then(function(r){
      STATE.ats.rows = (r&&r.data)||[]; STATE.ats.total = (r&&r.total)||0; STATE.ats.loading = false; paintATSPage();
    }).catch(function(e){ STATE.ats.loading=false; showToast('Failed to load applicants: '+e.message,'error'); paintATSPage(); });
  }

  // ── nav + routing (wrap, like the BD module) ─────────────────────────────────
  var _prevRender = window.render;
  window.render = function(){
    _prevRender.apply(this, arguments);
    injectATSNav();
    if (STATE.page === 'applicants') paintATSPage();
  };

  function injectATSNav(){
    var u = STATE.user; if(!u || !canUse(u)) return;
    var navWrap = document.querySelector('.sb-nav'); if(!navWrap) return;
    if (navWrap.querySelector('[data-atsnav]')) return;
    var d = document.createElement('div');
    d.className = 'nav-item' + (STATE.page==='applicants' ? ' active' : '');
    d.setAttribute('data-atsnav','1');
    d.innerHTML = '<span class="nav-icon">'+icon('profile')+'</span>Applicants';
    d.onclick = function(){ goPage('applicants'); };
    // place after any BD nav item, else at the end
    var bd = navWrap.querySelector('[data-bdnav]');
    if (bd && bd.parentNode) bd.parentNode.insertBefore(d, bd.nextSibling);
    else navWrap.appendChild(d);
    if (STATE.page==='applicants'){ var t=document.querySelector('.tb-title'); if(t) t.textContent='Applicants'; }
  }

  var _prevGoPage = window.goPage;
  window.goPage = function(p){
    if (p === 'applicants'){
      STATE.page = 'applicants'; STATE.modal = null;
      render();
      loadApplicants();
      return;
    }
    return _prevGoPage.apply(this, arguments);
  };

  function paintATSPage(){
    if (STATE.page !== 'applicants') return;
    var c = document.getElementById('content'); if(!c) return;
    c.innerHTML = renderApplicants();
  }

  // ── grid ──────────────────────────────────────────────────────────────────────
  function renderApplicants(){
    var a = STATE.ats;
    var fopt = function(key, all, list){
      return '<select class="sel" style="max-width:170px" onchange="atsSetFilter(\''+key+'\',this.value)">'+
        '<option value="">'+all+'</option>'+
        list.map(function(s){ return '<option value="'+esc(s)+'"'+(a.filters[key]===s?' selected':'')+'>'+esc(s)+'</option>'; }).join('')+
      '</select>';
    };
    var toolbar =
      '<div style="display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap">'+
        '<div><div style="font-size:18px;font-weight:700">Applicants</div>'+
        '<div style="font-size:12.5px;color:var(--text3)">'+(a.total||0)+' candidate'+(a.total===1?'':'s')+' in the database</div></div>'+
        '<button class="btn btn-primary" onclick="atsOpenNew()">+ New Applicant</button>'+
      '</div>'+
      '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px">'+
        '<input class="sel" style="max-width:280px" placeholder="Search name, email, phone, CN- code…" value="'+esc(a.q)+'" '+
          'oninput="atsSetSearch(this.value)" onkeydown="if(event.key===\'Enter\')atsApplySearch()">'+
        '<button class="btn btn-sm btn-outline" onclick="atsApplySearch()">Search</button>'+
        fopt('applicant_status','All statuses',APPLICANT_STATUSES)+
        fopt('source','All sources',SOURCES)+
        fopt('work_authorization','All work auth',WORK_AUTH)+
        fopt('state','All states',US_STATES)+
        ((a.q||a.filters.applicant_status||a.filters.source||a.filters.work_authorization||a.filters.state)?
          '<button class="btn btn-sm btn-outline" onclick="atsClearFilters()">Clear</button>':'')+
      '</div>';

    if (a.loading) return '<div class="page">'+toolbar+'<div style="text-align:center;padding:50px;color:var(--text3)">Loading applicants…</div></div>';

    var head = ['Applicant ID','Name','Email','Mobile','City','State','Source','Status','Job Title','Ownership','Work Auth','Created By','Created','']
      .map(function(h){ return '<th style="text-align:left;padding:9px 10px;font-size:11px;color:var(--text3);font-weight:700;white-space:nowrap">'+h+'</th>'; }).join('');

    var body = a.rows.map(function(c){
      return '<tr style="border-top:1px solid var(--border)">'+
        '<td style="padding:9px 10px;white-space:nowrap">'+code(c.candidate_code||'—')+'</td>'+
        '<td style="padding:9px 10px;white-space:nowrap"><span style="font-weight:600;font-size:13px;cursor:pointer;color:var(--accent)" onclick="bdOpenCandidate(\''+c.id+'\')">'+esc(c.full_name||'—')+'</span></td>'+
        '<td style="padding:9px 10px;font-size:12.5px">'+esc(c.email||'—')+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px;white-space:nowrap">'+esc(c.phone||'—')+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px">'+esc(c.city||'—')+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px;white-space:nowrap">'+esc(c.state||'—')+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px;white-space:nowrap">'+esc(c.source||'—')+'</td>'+
        '<td style="padding:9px 10px;font-size:12px;white-space:nowrap">'+statusBadge(c.applicant_status)+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px">'+esc(jobTitle(c))+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px;white-space:nowrap">'+esc(ownerName(c))+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px;white-space:nowrap">'+esc(c.work_authorization||'—')+'</td>'+
        '<td style="padding:9px 10px;font-size:12.5px;white-space:nowrap">'+esc(creatorName(c))+'</td>'+
        '<td style="padding:9px 10px;font-size:12px;color:var(--text3);white-space:nowrap">'+fmtDate(c.created_at)+'</td>'+
        '<td style="padding:9px 10px;white-space:nowrap">'+
          '<button class="btn btn-sm btn-outline" onclick="atsAddToJob(\''+c.id+'\')">Add to Job</button>'+
        '</td>'+
      '</tr>';
    }).join('');

    if (!a.rows.length) body = '<tr><td colspan="14" style="padding:40px;text-align:center;color:var(--text3)">No applicants match. '+
      '<span style="color:var(--accent);cursor:pointer" onclick="atsOpenNew()">Add the first one →</span></td></tr>';

    var totalPages = Math.max(1, Math.ceil((a.total||0)/a.limit));
    var fromN = a.total ? (a.page-1)*a.limit+1 : 0, toN = Math.min(a.page*a.limit, a.total);
    var pager =
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-top:12px;font-size:12.5px;color:var(--text3)">'+
        '<div>'+fromN+'–'+toN+' of '+(a.total||0)+'</div>'+
        '<div style="display:flex;gap:6px;align-items:center">'+
          '<button class="btn btn-sm btn-outline" '+(a.page<=1?'disabled style="opacity:.5"':'')+' onclick="atsGoPage('+(a.page-1)+')">‹ Prev</button>'+
          '<span>Page '+a.page+' / '+totalPages+'</span>'+
          '<button class="btn btn-sm btn-outline" '+(a.page>=totalPages?'disabled style="opacity:.5"':'')+' onclick="atsGoPage('+(a.page+1)+')">Next ›</button>'+
        '</div>'+
      '</div>';

    return '<div class="page">'+toolbar+
      '<div class="card" style="padding:0;overflow-x:auto"><table style="width:100%;border-collapse:collapse;min-width:1100px">'+
        '<thead><tr style="background:var(--bg)">'+head+'</tr></thead><tbody>'+body+'</tbody></table></div>'+
      pager+
    '</div>';
  }

  function statusBadge(s){
    var col = { 'New lead':'var(--text3)','Active':'var(--green)','Submitted':'var(--accent)','Interviewing':'#2563eb',
      'Placed':'var(--green)','Do Not Call':'var(--amber)','Blacklisted':'var(--red)','Inactive':'#9ca3af' }[s] || 'var(--text3)';
    return '<span style="font-weight:700;color:'+col+';background:rgba(0,0,0,.04);padding:2px 8px;border-radius:10px">'+esc(s||'—')+'</span>';
  }

  // ── search / filter / pagination handlers ────────────────────────────────────
  window.atsSetSearch = function(v){ STATE.ats.q = v; };
  window.atsApplySearch = function(){ STATE.ats.page = 1; loadApplicants(); };
  window.atsSetFilter = function(k,v){ STATE.ats.filters[k]=v; STATE.ats.page=1; loadApplicants(); };
  window.atsClearFilters = function(){ STATE.ats.q=''; STATE.ats.filters={applicant_status:'',source:'',state:'',work_authorization:''}; STATE.ats.page=1; loadApplicants(); };
  window.atsGoPage = function(p){ if(p<1)return; STATE.ats.page=p; loadApplicants(); };

  // ── add / edit modal ─────────────────────────────────────────────────────────
  window.atsOpenNew = function(){
    STATE.ats.editId = null; STATE.ats.dupMatches = [];
    STATE.ats.form = { applicant_status:'New lead', source:'Manual', pay_currency:'USD' };
    showApplicantModal();
  };
  window.atsOpenEdit = function(id){
    var c = STATE.ats.rows.find(function(x){ return x.id===id; });
    if(!c){ apiGet('/candidates/'+id).then(function(d){ STATE.ats.editId=id; STATE.ats.dupMatches=[]; STATE.ats.form=Object.assign({},d); showApplicantModal(); }).catch(function(e){ showToast('Failed: '+e.message,'error'); }); return; }
    STATE.ats.editId = id; STATE.ats.dupMatches = []; STATE.ats.form = Object.assign({}, c);
    showApplicantModal();
  };

  window.atsFormSet = function(k,v){ STATE.ats.form[k]=v; };

  function fld(label, inner, req){
    return '<div><label style="font-size:11px;color:var(--text2);display:block;margin-bottom:3px">'+label+(req?' <span style="color:var(--red)">*</span>':'')+'</label>'+inner+'</div>';
  }
  function inp(key, ph){ return '<input class="sel" value="'+esc(STATE.ats.form[key]||'')+'" placeholder="'+(ph||'')+'" oninput="atsFormSet(\''+key+'\',this.value)">'; }
  function sel(key, opts, blank){
    var list = (blank?['']:[]).concat(opts);
    return '<select class="sel" onchange="atsFormSet(\''+key+'\',this.value)">'+
      list.map(function(o){ return '<option value="'+esc(o)+'"'+(STATE.ats.form[key]===o?' selected':'')+'>'+esc(o||'Select…')+'</option>'; }).join('')+'</select>';
  }

  function showApplicantModal(){
    var f = STATE.ats.form, editing = !!STATE.ats.editId;
    var u = STATE.user;
    var ownerSel = '';
    if (isBDMlike(u)) {
      var owners = (STATE.users||[]).filter(function(x){ return userHasAnyRole(x,'admin','bd','bd_lead','recruiter'); });
      ownerSel = fld('Ownership',
        '<select class="sel" onchange="atsFormSet(\'owner_id\',this.value)">'+
          '<option value="">'+esc(u.name)+' (me)</option>'+
          owners.map(function(o){ return '<option value="'+o.id+'"'+(f.owner_id===o.id?' selected':'')+'>'+esc(o.name)+'</option>'; }).join('')+
        '</select>');
    }

    var dup = STATE.ats.dupMatches.length ? (
      '<div style="background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:12px;margin-bottom:14px">'+
        '<div style="font-weight:700;font-size:12.5px;color:#b45309;margin-bottom:8px">⚠ Possible existing candidate'+(STATE.ats.dupMatches.length>1?'s':'')+' — matched by name + email/phone</div>'+
        STATE.ats.dupMatches.map(function(m){
          return '<div style="display:flex;justify-content:space-between;align-items:center;gap:10px;background:var(--card);border:1px solid var(--border);border-radius:7px;padding:8px 10px;margin-bottom:6px">'+
            '<div style="font-size:12.5px"><b>'+esc(m.full_name)+'</b> '+code(m.candidate_code||'')+
              '<div style="font-size:11px;color:var(--text3)">'+esc(m.email||'')+(m.phone?' · '+esc(m.phone):'')+(m.current_title?' · '+esc(m.current_title):'')+'</div></div>'+
            '<button class="btn btn-sm btn-outline" onclick="atsOpenEdit(\''+m.id+'\')">Open</button>'+
          '</div>';
        }).join('')+
        '<div style="display:flex;justify-content:flex-end;gap:8px;margin-top:6px">'+
          '<button class="btn btn-sm btn-primary" onclick="atsSaveApplicant(true)">Create anyway</button>'+
        '</div>'+
      '</div>') : '';

    STATE.modal =
      '<div class="modal modal-w720" onclick="event.stopPropagation()">'+
        '<div style="padding:16px 20px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center">'+
          '<div style="font-weight:700;font-size:16px">'+(editing?'Edit Applicant':'New Applicant')+(editing&&f.candidate_code?' '+code(f.candidate_code):'')+'</div>'+
          '<span style="cursor:pointer;color:var(--text3)" onclick="closeModal()">✕</span>'+
        '</div>'+
        '<div style="padding:18px 20px;max-height:66vh;overflow-y:auto">'+
          dup+
          '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px">'+
            fld('Full Name', inp('full_name','Jane Doe'), true)+
            fld('Email', inp('email','jane@example.com'))+
            fld('Mobile', inp('phone','(555) 123-4567'))+
            fld('Work Authorization', sel('work_authorization', WORK_AUTH, true))+
            fld('Source', sel('source', SOURCES, true))+
            fld('Applicant Status', sel('applicant_status', APPLICANT_STATUSES))+
            fld('City', inp('city'))+
            fld('State', sel('state', US_STATES, true))+
            fld('Country', inp('country','United States'))+
            fld('Zip', inp('zip'))+
            fld('Current Title', inp('current_title'))+
            fld('Desired / Headline Title', inp('headline'))+
            fld('Current Employer', inp('current_employer'))+
            fld('Experience (years)', inp('experience_years','e.g. 8'))+
            fld('LinkedIn', inp('linkedin_url'))+
            fld('Availability', sel('availability', AVAILABILITY, true))+
            fld('Notice Period', inp('notice_period'))+
            fld('Current CTC', inp('current_ctc'))+
            fld('Expected CTC', inp('expected_ctc'))+
            fld('Bill Rate', inp('bill_rate'))+
            fld('Pay Rate', inp('pay_rate'))+
            fld('Pay Type', sel('pay_type', PAY_TYPES, true))+
            fld('Resume URL', inp('resume_url'))+
            ownerSel+
          '</div>'+
          '<div style="margin-top:12px">'+fld('Skills', '<textarea class="sel" style="min-height:60px;resize:vertical" placeholder="Comma-separated skills" oninput="atsFormSet(\'skills\',this.value)">'+esc(f.skills||'')+'</textarea>')+'</div>'+
        '</div>'+
        '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:'+(editing?'space-between':'flex-end')+';gap:8px;align-items:center">'+
          (editing?'<button class="btn btn-sm btn-outline" style="color:var(--red)" onclick="atsDeleteApplicant(\''+STATE.ats.editId+'\')">Delete</button>':'')+
          '<div style="display:flex;gap:8px">'+
            '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
            '<button class="btn btn-primary" onclick="atsSaveApplicant(false)">'+(editing?'Save changes':'Create applicant')+'</button>'+
          '</div>'+
        '</div>'+
      '</div>';
    render();
  }

  window.atsSaveApplicant = function(force){
    var f = STATE.ats.form;
    if (!f.full_name || !f.full_name.trim()){ showToast('Full name is required','error'); return; }
    var payload = Object.assign({}, f); if (force) payload.force = true;

    if (STATE.ats.editId){
      apiPut('/candidates/'+STATE.ats.editId, payload).then(function(){
        showToast('Applicant updated','success'); closeModal();
        if (window.bdReloadCandidateProfile) window.bdReloadCandidateProfile();
        loadApplicants();
      }).catch(function(e){ showToast('Failed: '+e.message,'error'); });
      return;
    }
    apiPost('/candidates', payload).then(function(){
      showToast('Applicant created','success'); STATE.ats.dupMatches=[]; closeModal(); STATE.ats.page=1; loadApplicants();
    }).catch(function(e){
      // 409 possible_duplicate → surface matches, keep the form open (warn-and-offer)
      if (/possible_duplicate/i.test(e.message)){
        apiGet('/candidates/check-duplicate?full_name='+encodeURIComponent(f.full_name||'')+'&email='+encodeURIComponent(f.email||'')+'&phone='+encodeURIComponent(f.phone||''))
          .then(function(r){ STATE.ats.dupMatches = (r&&r.duplicates)||[]; showApplicantModal(); showToast('Possible duplicate found — review below','info'); })
          .catch(function(){ STATE.ats.dupMatches=[{full_name:f.full_name,candidate_code:'',email:f.email,phone:f.phone}]; showApplicantModal(); });
      } else showToast('Failed: '+e.message,'error');
    });
  };

  window.atsDeleteApplicant = function(id){
    if (!confirm('Remove this applicant from the database?')) return;
    apiDelete('/candidates/'+id).then(function(){ showToast('Applicant removed','info'); closeModal(); loadApplicants(); })
      .catch(function(e){ showToast('Failed: '+e.message,'error'); });
  };

  // ── add a candidate to a job (creates a submission via the existing endpoint) ─
  window.atsAddToJob = function(cid){
    var c = STATE.ats.rows.find(function(x){ return x.id===cid; }) || {};
    apiGet('/job-orders').then(function(jobs){
      jobs = jobs || [];
      var opts = jobs.map(function(j){ return '<option value="'+j.id+'">'+esc((j.job_code?j.job_code+' · ':'')+(j.job_title||'')+(j.client?' — '+j.client:''))+'</option>'; }).join('');
      STATE.modal =
        '<div class="modal modal-w480" onclick="event.stopPropagation()">'+
          '<div style="padding:16px 20px;border-bottom:1px solid var(--border);font-weight:700;font-size:16px">Add '+esc(c.full_name||'candidate')+' to a Job</div>'+
          '<div style="padding:18px 20px">'+
            (jobs.length?
              '<label style="font-size:11.5px;color:var(--text2);display:block;margin-bottom:4px">Job order</label>'+
              '<select id="ats-job-pick" class="sel">'+opts+'</select>'+
              '<div style="font-size:11.5px;color:var(--text3);margin-top:8px">Tags the candidate into the job pipeline. Promote to a submission from the job\'s Pipeline tab.</div>'
              :'<div style="color:var(--text3);font-size:13px">No job orders available to you yet.</div>')+
          '</div>'+
          '<div style="padding:14px 20px;border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px">'+
            '<button class="btn btn-outline" onclick="closeModal()">Cancel</button>'+
            (jobs.length?'<button class="btn btn-primary" onclick="atsDoAddToJob(\''+cid+'\')">Add to Job</button>':'')+
          '</div>'+
        '</div>';
      render();
    }).catch(function(e){ showToast('Failed to load jobs: '+e.message,'error'); });
  };
  window.atsDoAddToJob = function(cid){
    var pick = document.getElementById('ats-job-pick'); if(!pick||!pick.value){ showToast('Pick a job','error'); return; }
    apiPost('/pipeline', { candidate_id:cid, job_order_id:pick.value }).then(function(){
      showToast('Tagged to job pipeline','success'); closeModal();
    }).catch(function(e){
      if (/already tagged/i.test(e.message)) showToast('Candidate already in that pipeline','error');
      else showToast('Failed: '+e.message,'error');
    });
  };

})();

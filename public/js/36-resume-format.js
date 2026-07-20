// ===== RESUME → SUBMISSION FORMAT =====
// Takes an uploaded resume (pdf / word / txt / rtf), runs it through the
// existing parse endpoint, and lays the content onto the company letterhead
// as the standard submission document — with a live preview and Word / PDF
// download. The letterhead below is a PLACEHOLDER (brand bar + footer);
// swap LETTERHEAD_* when the real letterhead asset is provided.

(function () {

  function esc(s){ return String(s==null?'':s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }

  // ── PLACEHOLDER letterhead — replace with the real brand asset ────────────
  var LETTERHEAD_TOP =
    '<div style="border-bottom:3px solid #1E7A3C;padding:18px 0 12px;display:flex;justify-content:space-between;align-items:center">'+
      '<div style="font-family:Georgia,serif;font-size:26px;font-weight:700;color:#1E7A3C">fut<span style="color:#F5C23B">é</span> <span style="font-size:15px;color:#333;font-weight:400">Global</span></div>'+
      '<div style="font-size:10px;color:#777;text-align:right">Candidate Submission<br>[letterhead placeholder]</div>'+
    '</div>';
  var LETTERHEAD_BOTTOM =
    '<div style="border-top:2px solid #1E7A3C;margin-top:26px;padding-top:8px;font-size:9.5px;color:#888;text-align:center">'+
      'futé Global · Recruiting &amp; Staffing · [address / phone / web — letterhead placeholder]'+
    '</div>';

  function docHtml(fields, text, filename){
    var f = fields || {};
    var contact = [f.email, f.phone, [f.city,f.state].filter(Boolean).join(', ')].filter(Boolean).join(' · ');
    var skills = (f.skills && f.skills.length)
      ? '<div style="margin:10px 0 2px;font-weight:700;font-size:12px;color:#1E7A3C;text-transform:uppercase;letter-spacing:.06em">Key Skills</div>'+
        '<div style="font-size:12px;line-height:1.6">'+f.skills.map(esc).join(' · ')+'</div>'
      : '';
    var exp = f.years_experience ? '<span style="font-size:12px;color:#555"> · '+esc(String(f.years_experience))+' yrs experience</span>' : '';
    return '<!doctype html><html><head><meta charset="utf-8"><title>'+esc(f.name||filename||'Submission')+'</title></head>'+
      '<body style="font-family:Calibri,Arial,sans-serif;color:#222;max-width:750px;margin:0 auto;padding:0 28px 20px">'+
        LETTERHEAD_TOP+
        '<div style="margin-top:16px">'+
          '<div style="font-size:20px;font-weight:700">'+esc(f.name||'Candidate')+exp+'</div>'+
          (contact?'<div style="font-size:12px;color:#555;margin-top:2px">'+esc(contact)+'</div>':'')+
          (f.linkedin_url?'<div style="font-size:12px;color:#555">'+esc(f.linkedin_url)+'</div>':'')+
          skills+
          '<div style="margin:14px 0 4px;font-weight:700;font-size:12px;color:#1E7A3C;text-transform:uppercase;letter-spacing:.06em">Resume</div>'+
          '<div style="font-size:12px;line-height:1.55;white-space:pre-wrap">'+esc(text||'')+'</div>'+
        '</div>'+
        LETTERHEAD_BOTTOM+
      '</body></html>';
  }

  // Format from a File object (used by the Submit-to-BDM modal and anywhere
  // else a resume file is at hand).
  window.atsFormatResumeFile = function(file){
    if (!file) return;
    if (file.size > 4.5*1024*1024) { showToast('File too large (max ~4.5 MB)','error'); return; }
    showToast('Formatting resume…','success');
    var reader = new FileReader();
    reader.onload = function(){
      apiPost('/candidates/parse-resume', { filename: file.name, data_base64: String(reader.result) })
        .then(function(r){ openPreview(docHtml((r&&r.fields)||{}, (r&&r.resume_text)||'', file.name), (r&&r.fields&&r.fields.name)||file.name); })
        .catch(function(e){ showToast('Could not parse the resume: '+e.message,'error'); });
    };
    reader.onerror = function(){ showToast('Could not read the file','error'); };
    reader.readAsDataURL(file);
  };

  function openPreview(html, name){
    var old = document.getElementById('ats-fmt-overlay'); if (old) old.remove();
    var ov = document.createElement('div');
    ov.id = 'ats-fmt-overlay';
    ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:120;display:flex;align-items:center;justify-content:center;padding:18px';
    ov.innerHTML =
      '<div style="background:var(--card);border-radius:12px;width:820px;max-width:96vw;height:88vh;display:flex;flex-direction:column;overflow:hidden">'+
        '<div style="padding:12px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px">'+
          '<div style="font-weight:700;font-size:14px;flex:1">Formatted submission — preview</div>'+
          '<button class="btn btn-sm btn-outline" id="ats-fmt-word">Download Word</button>'+
          '<button class="btn btn-sm btn-outline" id="ats-fmt-pdf">Download PDF</button>'+
          '<button class="btn btn-sm btn-outline" id="ats-fmt-close">✕</button>'+
        '</div>'+
        '<iframe id="ats-fmt-frame" style="flex:1;border:0;background:#fff"></iframe>'+
      '</div>';
    document.body.appendChild(ov);
    var frame = document.getElementById('ats-fmt-frame');
    frame.srcdoc = html;
    var base = String(name||'candidate').replace(/[^A-Za-z0-9 _-]/g,'').trim().replace(/\s+/g,'_') || 'candidate';
    document.getElementById('ats-fmt-close').onclick = function(){ ov.remove(); };
    ov.onclick = function(e){ if (e.target===ov) ov.remove(); };
    // Word: an HTML document with a .doc name opens natively in Word.
    document.getElementById('ats-fmt-word').onclick = function(){
      var blob = new Blob(['﻿', html], { type: 'application/msword' });
      var a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = base + '_Submission.doc';
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(function(){ URL.revokeObjectURL(a.href); }, 5000);
    };
    // PDF: the browser's print-to-PDF on the preview frame.
    document.getElementById('ats-fmt-pdf').onclick = function(){
      try { frame.contentWindow.focus(); frame.contentWindow.print(); }
      catch(e){ showToast('Use the browser print dialog → Save as PDF','error'); }
    };
  }

})();

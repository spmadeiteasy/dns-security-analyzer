const $ = (id) => document.getElementById(id);
const statusBox = $('status');
let lastPayload = null;

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}
function setStatus(message, kind='') { statusBox.textContent = message; statusBox.className = `status ${kind}`; }
function options() {
  return {include_records:$('records').checked, include_email:$('email').checked,
    include_rdap:$('rdap').checked, dns_server:$('dnsServer').value.trim() || null,
    record_types:['A','AAAA','MX','NS','TXT','CNAME','SOA','CAA']};
}
async function api(path, body) {
  const response = await fetch(path, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.detail || `Request failed (${response.status})`);
  return data;
}
function card(title, tag, inner, wide=false) {
  return `<article class="result-card ${wide?'wide':''}"><div class="card-title"><h3>${esc(title)}</h3><span>${esc(tag)}</span></div>${inner}</article>`;
}
function kv(key, value) { return `<div class="kv"><div class="key">${esc(key)}</div><div class="value">${value}</div></div>`; }
function rowsFromObject(obj) {
  const entries = Object.entries(obj || {});
  if (!entries.length) return '<div class="empty">No records returned.</div>';
  return entries.map(([key, values]) => {
    const list = Array.isArray(values) ? values : [values];
    return kv(key, list.length ? list.map(v=>`<div>${esc(v)}</div>`).join('') : '<span class="empty">No answer</span>');
  }).join('');
}
function gradePill(grade) { const labels={good:'GOOD',review:'REVIEW',poor:'NEEDS ATTENTION',missing:'MISSING'}; return `<span class="pill ${esc(grade)}">${labels[grade]||esc(grade)}</span>`; }
function securityItem(name, item) {
  if (!item) return '';
  const record = Array.isArray(item.record) ? item.record.join('\n') : item.record;
  return kv(name, `${gradePill(item.grade)}${esc(item.finding||'')}${record?`<span class="record">${esc(record)}</span>`:''}`);
}
function renderResult(data) {
  if (data.error) return card(data.target || 'Target', 'ERROR', `<div class="warning">${esc(data.error)}</div>`, true);
  if (data.reverse) return card(`Reverse lookup · ${data.target}`, 'PTR', data.reverse.length ? data.reverse.map(n=>kv('Hostname',esc(n))).join('') : '<div class="empty">No PTR hostname found.</div>', true);
  const ip = data.ip_addresses || {};
  let html = card(`IP addresses · ${data.domain||data.target}`, 'A / AAAA',
    kv('IPv4', ip.ipv4?.length ? ip.ipv4.map(esc).join('<br>') : '<span class="empty">No IPv4 answer</span>')+
    kv('IPv6', ip.ipv6?.length ? ip.ipv6.map(esc).join('<br>') : '<span class="empty">No IPv6 answer</span>'));
  if (data.dns_records) html += card('DNS records','RECORD DATA',rowsFromObject(data.dns_records),true);
  if (data.email_security) {
    const e=data.email_security;
    let body=securityItem('SPF',e.spf)+securityItem('DMARC',e.dmarc);
    const dkim=e.dkim||{};
    const found=Object.entries(dkim.found||{});
    body+=kv('DKIM',found.length?found.map(([s,rs])=>`<div><b>${esc(s)}</b>: ${rs.map(esc).join('<br>')}</div>`).join(''):`<span class="pill review">NOT CONFIRMED</span> No common selector returned a TXT record.`);
    body+=kv('DKIM scope',`<span class="record">${esc(dkim.note||'')}</span>`);
    html+=card('Email authentication','SPF / DKIM / DMARC',body,true);
  }
  if (data.registration) {
    const r=data.registration; let body='';
    for (const [k,label] of [['registrar','Registrar'],['created','Created'],['updated','Updated'],['expires','Expires'],['age_days','Domain age (days)'],['status','Status'],['nameservers','Nameservers']]) {
      if (r[k]!==null && r[k]!==undefined && r[k]!=='' && (!Array.isArray(r[k]) || r[k].length)) body+=kv(label,Array.isArray(r[k])?r[k].map(esc).join('<br>'):esc(r[k]));
    }
    if (!r.available) body=kv('RDAP',esc(r.note||'Not available'));
    if (r.new_domain_warning) body+=`<div class="warning">Recently registered domain (under 90 days). Newness is one signal to investigate, not proof of malicious activity.</div>`;
    if (r.note) body+=kv('Note',esc(r.note));
    html+=card('Registration intelligence','RDAP',body||'<div class="empty">No registration fields returned.</div>');
  }
  html+=`<div class="disclaimer">${esc(data.disclaimer||'Public data only. Results are not a verdict that a domain is safe or malicious.')}${data.elapsed_ms!==undefined?` · Completed in ${esc(data.elapsed_ms)} ms`:''}</div>`;
  return html;
}
function downloadFile(name, content, type='application/json') {
  const blob=new Blob([content],{type}); const url=URL.createObjectURL(blob); const a=document.createElement('a');
  a.href=url; a.download=name; a.click(); URL.revokeObjectURL(url);
}
function addExportButtons(results) {
  const existing=document.querySelector('.export-row'); if(existing) existing.remove();
  const row=document.createElement('div'); row.className='export-row'; row.style.cssText='display:flex;gap:9px;justify-content:flex-end;grid-column:1/-1;margin:0 0 2px';
  row.innerHTML='<button class="docs-link" id="jsonExport">↓ Export JSON</button><button class="docs-link" id="txtExport">↓ Export text</button>';
  $('results').prepend(row);
  $('jsonExport').onclick=()=>downloadFile('dns-analysis-report.json',JSON.stringify(results,null,2));
  $('txtExport').onclick=()=>downloadFile('dns-analysis-report.txt',results.map(r=>JSON.stringify(r,null,2)).join('\n\n'),'text/plain');
}
function display(results) { $('results').innerHTML=results.map(renderResult).join(''); $('results').classList.remove('hidden'); addExportButtons(results); }
function setBusy(busy, button) { button.disabled=busy; button.dataset.old ||= button.textContent; button.textContent=busy?'Analyzing…':button.dataset.old; }
$('lookupForm').addEventListener('submit', async event=>{
  event.preventDefault(); const button=$('lookupBtn'); const target=$('target').value.trim(); if(!target)return;
  setBusy(true,button); $('results').classList.add('hidden'); setStatus(`Querying public DNS and registration data for ${target}…`,'loading');
  try { const result=await api('/api/lookup',{target,...options()}); lastPayload=[result]; display(lastPayload); setStatus(`Analysis complete for ${target}.`); }
  catch(error){setStatus(error.message,'error');} finally{setBusy(false,button);}
});
$('batchBtn').addEventListener('click',async()=>{
  const targets=$('batchTargets').value.split(/[\s,;]+/).filter(Boolean); if(!targets.length){setStatus('Enter at least one target.','error');return;} if(targets.length>20){setStatus('Batch limit is 20 targets.','error');return;}
  const button=$('batchBtn');setBusy(true,button);$('results').classList.add('hidden');setStatus(`Analyzing ${targets.length} targets…`,'loading');
  try{const data=await api('/api/batch',{targets,...options()});lastPayload=data.results;display(lastPayload);setStatus(`Batch complete: ${data.count} targets processed.`);}catch(error){setStatus(error.message,'error');}finally{setBusy(false,button);}
});
document.querySelectorAll('.nav').forEach(button=>button.addEventListener('click',()=>{
  document.querySelectorAll('.nav').forEach(b=>b.classList.toggle('active',b===button));
  const batch=button.dataset.view==='batch';$('lookupView').classList.toggle('hidden',batch);$('batchView').classList.toggle('hidden',!batch);$('pageTitle').textContent=batch?'Batch Analysis':'DNS Lookup';$('results').classList.add('hidden');setStatus('Ready when you are.');
}));

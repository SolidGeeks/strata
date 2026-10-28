// SPDX-License-Identifier: AGPL-3.0-or-later
// Key figures for a steering committee, measured on the raw map (the documents as saved, nothing compiled), so
// that the server can measure them at any past version from its history: exposure to the Internet, the age of
// the open vulnerabilities, owner coverage and scan coverage. Pure functions, no DOM: used by the page, the
// server and the tests.
(function(root){
'use strict';

const DAY=86400000;
// Remediation deadlines by severity, in days (a common baseline; CISA BOD 22-01 asks 15 days for a KEV)
const SLA={crit:15,high:30,med:90,low:180};
const AGES=[[0,30,'Under 30 days'],[30,90,'30 to 90 days'],[90,180,'90 to 180 days'],[180,Infinity,'Over 180 days']];
const ADMIN=new Set(['tcp/22','tcp/23','tcp/135','tcp/139','tcp/445','tcp/3389','tcp/5900','tcp/5985','tcp/5986']);
// Ids in ext that mean a vulnerability scanner knows the asset
const SCANNERS=['cyberwatch','tenable','nessus','qualys','openvas','greenbone','rapid7','insightvm','defender','crowdstrike','wazuh'];
const OWNER_ROLES=new Set(['Technical owner','Business owner','Responsable technique','Responsable métier']);
const sevOf=v=>{if(v.sev&&SLA[v.sev])return v.sev;const c=+v.cvss;return !isFinite(c)||v.cvss==null||v.cvss===''?'low':c>=9?'crit':c>=7?'high':c>=4?'med':'low';};
const vkey=(aid,v)=>`${aid}|${v.id||v.title||''}`;

// When each open vulnerability was first seen, from the history of the map (oldest first). A vulnerability that
// carries its own firstSeen (from a scanner) keeps it. Those already there when the kept history starts get the
// date of its first entry, marked as a lower bound.
function firstSeen(entries){
  const seen={},since=entries.length?entries[0].at:null;
  const take=(aid,doc,at,initial)=>{(doc&&Array.isArray(doc.vulns)?doc.vulns:[]).forEach(v=>{const k=vkey(aid,v);if(!seen[k])seen[k]={at:v.firstSeen||at,before:initial&&!v.firstSeen};});};
  entries.forEach(h=>{
    if(h.kind==='assets'){take(h.id,h.before,since,true);take(h.id,h.after,h.at,false);}
    else if(h.kind==='all'){const b=(h.before&&h.before.assets)||{},a=(h.after&&h.after.assets)||{};Object.entries(b).forEach(([id,d])=>take(id,d,since,true));Object.entries(a).forEach(([id,d])=>take(id,d,h.at,false));}
  });
  return seen;
}

// The figures of a map (or of one IS: site) at a moment `at` (ms). seen: from firstSeen(), or {} (then a
// vulnerability's own firstSeen counts, else it is taken as new).
function measure(raw,at,seen,site){
  const si=raw&&raw.si||{},assets=Object.entries(raw&&raw.assets||{}).filter(([,a])=>a&&si[a.site]&&(!site||a.site===site));
  const flows=Object.entries(si).filter(([id])=>!site||id===site).flatMap(([,d])=>Array.isArray(d.flows)?d.flows:[]);
  const ids=new Set(assets.map(([id])=>id)),n=assets.length,pct=k=>n?Math.round(1000*k/n)/10:null;
  // exposure: what the Internet reaches directly
  const inbound=flows.filter(f=>f&&f.src==='internet'&&ids.has(f.dst));
  const exposed=new Set(inbound.map(f=>f.dst)),ports=new Set(inbound.map(f=>`${f.dst}|${f.port}`)),adminExposed=new Set(inbound.filter(f=>ADMIN.has(f.port)).map(f=>f.dst));
  // vulnerabilities still open, and how old they are
  const open=[];
  assets.forEach(([id,a])=>(Array.isArray(a.vulns)?a.vulns:[]).forEach(v=>{
    const s=seen&&seen[vkey(id,v)],from=Date.parse(v.firstSeen||(s&&s.at)||'')||at,days=Math.max(0,Math.floor((at-from)/DAY)),sev=sevOf(v);
    open.push({asset:id,name:a.name||id,id:v.id||'',title:v.title||'',sev,kev:v.kev===true||v.kev==='true',days,approx:!!(s&&s.before&&!v.firstSeen),late:days>SLA[sev]});
  }));
  const serious=open.filter(v=>v.sev==='crit'||v.sev==='high'),ages=serious.map(v=>v.days).sort((x,y)=>x-y);
  const median=ages.length?(ages.length%2?ages[(ages.length-1)/2]:Math.round((ages[ages.length/2-1]+ages[ages.length/2])/2)):null;
  const bySev=s=>open.filter(v=>v.sev===s).length;
  // owners and scans
  const owned=assets.filter(([,a])=>(Array.isArray(a.contacts)?a.contacts:[]).some(c=>c&&String(c.name||'').trim()&&OWNER_ROLES.has(c.role))).length;
  const critical=assets.filter(([,a])=>+a.crit===3),critOwned=critical.filter(([,a])=>(a.contacts||[]).some(c=>c&&String(c.name||'').trim()&&OWNER_ROLES.has(c.role))).length;
  const scanned=assets.filter(([,a])=>{const e=a.ext||{};return SCANNERS.some(k=>e[k]!=null&&e[k]!=='')||(a.vulns||[]).some(v=>v&&v.src)||(a.scannedAt&&at-Date.parse(a.scannedAt)<=30*DAY);}).length;
  return {at,assets:n,
    exposure:{assets:exposed.size,share:pct(exposed.size),ports:ports.size,admin:adminExposed.size,risky:flows.filter(f=>f&&f.risk).length},
    vulns:{open:open.length,crit:bySev('crit'),high:bySev('high'),med:bySev('med'),low:bySev('low'),kev:open.filter(v=>v.kev).length,
      median,ages:AGES.map(([lo,hi])=>serious.filter(v=>v.days>=lo&&v.days<hi).length),late:open.filter(v=>v.late).length,
      lateSerious:serious.filter(v=>v.late).length,approx:open.some(v=>v.approx)},
    owners:{covered:owned,share:pct(owned),critical:critical.length,criticalCovered:critOwned},
    scans:{covered:scanned,share:pct(scanned)},
    oldest:serious.slice().sort((x,y)=>y.days-x.days||(x.sev==='crit'?-1:1)).slice(0,10)};
}
// Moments to measure: the end of each period back from `now`, oldest first
function points(now,count,stepDays){return Array.from({length:count},(_,k)=>now-(count-1-k)*stepDays*DAY);}

const api={SLA,AGES,ADMIN,SCANNERS,firstSeen,measure,points,DAY};
root.StrataKpi=api;
})(typeof globalThis!=='undefined'?globalThis:this);

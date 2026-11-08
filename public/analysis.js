// SPDX-License-Identifier: AGPL-3.0-or-later
// Graph analysis of a compiled IS. Pure functions, no DOM: the page loads this file before app.js,
// and the tests run it in Node (tests/analysis.test.mjs).
(function(root){
'use strict';
const byName=(a,b)=>String(a).localeCompare(String(b),'en',{numeric:true});

/* ---- Flows through interconnection equipment ---- */
// Every flow that crosses a piece of equipment gets its own lane there, so threads that share
// a firewall or a router enter and leave it side by side instead of on top of each other.
// Returns {equipmentId: {n, idx: {flowId: lane}}}, lanes ordered by source, destination, port.
function lanes(flows){
  const by={};
  flows.forEach(f=>(f.via||[]).forEach(id=>{(by[id]=by[id]||[]).push(f);}));
  const out={};
  Object.keys(by).forEach(id=>{
    const list=by[id].slice().sort((a,b)=>byName(a.src,b.src)||byName(a.dst,b.dst)||byName(a.port,b.port)||byName(a.id,b.id));
    const idx={};list.forEach((f,i)=>{idx[f.id]=i;});
    out[id]={n:list.length,idx};
  });
  return out;
}
// One colour per flow out of a palette of n: flows that cross the same equipment never share
// a colour while the palette lasts, then the least used colour at that equipment is reused.
// Returns {flowId: colour index}.
function flowColours(flows,n){
  const used={},out={};
  const order=flows.slice().sort((a,b)=>(b.via||[]).length-(a.via||[]).length||byName(a.id,b.id));
  order.forEach(f=>{
    const via=f.via||[],count=new Array(n).fill(0);
    via.forEach(d=>(used[d]||[]).forEach(c=>count[c]++));
    let c=count.indexOf(0);
    if(c<0)c=count.indexOf(Math.min(...count));
    out[f.id]=c;
    via.forEach(d=>(used[d]=used[d]||[]).push(c));
  });
  return out;
}

/* ---- Business services ---- */
const isNet=id=>id==='internet'||String(id).startsWith('svc:');
// Log and monitoring traffic (syslog, SNMP traps, NetFlow) is not something a service needs to run
const TELEMETRY=new Set(['udp/514','tcp/514','tcp/6514','tcp/1514','udp/162','udp/2055','udp/6343']);
// What a business service relies on: its own assets; the assets they send flows to, and so on
// (an application calls its database, which calls its storage); the equipment crossed by these
// flows and by the flows that reach its own assets; the Internet services they call.
// Log and monitoring flows are left out.
// Returns {assets: {id: {direct, path, how}}, services: [svc ids]}. `path` runs from one of the
// service's own assets to this one; `how` is 'called' or 'crossed'.
function dependencies(site,b){
  const dep={},q=[],svcs=new Set(),isAsset=id=>!!site.byId[id]&&!site.byId[id].isInternet;
  (b.assets||[]).forEach(id=>{if(isAsset(id)&&!dep[id]){dep[id]={direct:true,path:[id],how:''};q.push(id);}});
  const add=(id,from,how)=>{if(!isAsset(id)||dep[id])return false;dep[id]={direct:false,path:dep[from].path.concat(id),how};return true;};
  while(q.length){
    const n=q.shift();
    site.flows.forEach(f=>{
      if(TELEMETRY.has(f.port))return;
      if(f.src===n){
        f.via.forEach(v=>add(v,n,'crossed'));
        if(isNet(f.dst)){if(f.dst!=='internet')svcs.add(f.dst);}
        else if(add(f.dst,n,'called'))q.push(f.dst);
      }
      // the way in to the service: equipment crossed by the flows that reach its own assets
      if(f.dst===n&&dep[n].direct)f.via.forEach(v=>add(v,n,'crossed'));
    });
  }
  return {assets:dep,services:[...svcs]};
}
// For every asset, the business services that rely on it, own assets first then by criticality.
// Returns {byAsset: {id: [{id, name, crit, direct, path, how}]}, byBusiness: {id: dependencies}}
function businessImpact(site){
  const byAsset={},byBusiness={};
  (site.business||[]).forEach(b=>{
    const d=byBusiness[b.id]=dependencies(site,b);
    Object.entries(d.assets).forEach(([id,x])=>(byAsset[id]=byAsset[id]||[]).push({id:b.id,name:b.name,crit:b.crit,direct:x.direct,path:x.path,how:x.how}));
  });
  Object.values(byAsset).forEach(l=>l.sort((x,y)=>(y.direct-x.direct)||(y.crit-x.crit)||byName(x.name,y.name)));
  return {byAsset,byBusiness};
}

/* ---- Application view ---- */
// One node per application (all its hosts together), Internet and its services, and for assets
// with no application on the way, the asset itself, or a group of clients (workstations of a VLAN).
// A flow arrives on the application listening on its port. It leaves from the application its
// source serves (one whose ports receive flows); a source that serves nothing is a client.
// Returns {nodes: [{key, kind, name, hosts, versions, rank, type?, vlan?, assetId?}], edges: [{from, to, flows, risk}]}
function appGraph(site){
  const nodes={},edges={},served=new Set();
  site.flows.forEach(f=>{if(!isNet(f.dst))served.add(f.dst+'|'+f.port);});
  const node=(key,o)=>nodes[key]||(nodes[key]=Object.assign({key,hosts:[],versions:[]},o));
  const host=(n,id,v)=>{if(id&&!n.hosts.includes(id))n.hosts.push(id);if(v&&!n.versions.includes(v))n.versions.push(v);return n;};
  const nodeOf=(id,port)=>{
    if(isNet(id))return node(id,{kind:'net',name:id==='internet'?'Internet':(site.svcById&&site.svcById[id]?site.svcById[id].name:id)});
    const a=site.byId[id],apps=a.apps||[];
    const x=port?apps.find(p=>p.ports.includes(port)):apps.find(p=>p.ports.some(q=>served.has(id+'|'+q)));
    if(x)return host(node('app:'+x.name.toLowerCase(),{kind:'app',name:x.name}),id,x.version);
    if(!port&&!apps.some(p=>p.ports.some(q=>served.has(id+'|'+q)))&&!site.flows.some(f=>f.dst===id))
      return host(node(`clients:${a.type}:${a.vlan}`,{kind:'clients',name:a.type,type:a.type,vlan:a.vlan}),id);
    return host(node('asset:'+id,{kind:'asset',name:a.name,assetId:id}),id);
  };
  site.flows.forEach(f=>{
    const s=nodeOf(f.src,null),d=nodeOf(f.dst,f.port);if(s===d)return;
    const k=s.key+'>'+d.key,e=edges[k]||(edges[k]={from:s.key,to:d.key,flows:[],risk:false});
    e.flows.push(f.id);e.risk=e.risk||!!f.risk;
  });
  // columns: shortest distance from a node nothing flows into (Internet, clients…)
  const list=Object.values(nodes),E=Object.values(edges),into=new Set(E.map(e=>e.to)),q=[];
  list.forEach(n=>{n.rank=into.has(n.key)?-1:0;if(n.rank===0)q.push(n.key);});
  if(!q.length&&list.length){list[0].rank=0;q.push(list[0].key);}
  while(q.length){const k=q.shift();E.forEach(e=>{if(e.from===k&&nodes[e.to].rank<0){nodes[e.to].rank=nodes[k].rank+1;q.push(e.to);}});}
  list.forEach(n=>{if(n.rank<0)n.rank=0;});
  return {nodes:list,edges:E};
}

/* ---- Addresses ---- */
// IPv4 only: '10.20.0.15' -> integer, or null
function ip4(t){const m=/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(t||'').trim());if(!m||m.slice(1).some(x=>+x>255))return null;return ((+m[1]<<24)>>>0)+(+m[2]<<16)+(+m[3]<<8)+(+m[4]);}
const ip4s=n=>[n>>>24,(n>>>16)&255,(n>>>8)&255,n&255].join('.');
// '10.20.0.0/24' -> {base, bits, first, last} (first and last usable host), or null
function cidr4(c){const m=/^\s*([\d.]+)\/(\d{1,2})\s*$/.exec(String(c||''));if(!m)return null;const b=ip4(m[1]),bits=+m[2];if(b===null||bits>32)return null;
  const size=2**(32-bits),base=b-(b%size);return {base,bits,first:bits>=31?base:base+1,last:bits>=31?base+size-1:base+size-2};}
function inCidr(ip,c){const n=ip4(ip),r=cidr4(c);return n!==null&&!!r&&n>=r.base&&n<r.base+2**(32-r.bits);}
// First host address of the range that no asset uses yet, or null when the range is full or unreadable
function nextFreeIp(c,used){const r=cidr4(c);if(!r)return null;const u=new Set([...(used||[])].map(ip4).filter(x=>x!==null));
  for(let n=r.first;n<=r.last&&n-r.first<65536;n++)if(!u.has(n))return ip4s(n);return null;}

/* ---- Risk prioritization ---- */
// One score per asset, 0 to 100, from four factors multiplied together, each between 0 and 1:
//  - vulnerabilities: for each one, severity (CVSS / 10) times likelihood of exploitation
//    (1 when it is on the CISA list of known exploited vulnerabilities, else from its EPSS,
//    else 0.3), combined over all of them as the chance that at least one gets exploited;
//  - context: the average of its exposure (Internet, other VLANs, its own VLAN, none)
//    and its reachability from the Internet along the recorded flows (fewer hops, higher);
//  - criticality: the higher of its own and that of the business services it would hit.
const SEV_SCORE={crit:0.95,high:0.8,med:0.5,low:0.2,none:0};
const EXPO_F={internet:1,inter:0.7,intra:0.45,none:0.3};
const CRIT_F=[0.5,0.5,0.75,1];
const BANDS=[[70,'crit'],[40,'high'],[20,'med'],[1,'low']];
const severityOf=v=>v.cvss!=null&&isFinite(v.cvss)?Math.max(0,Math.min(10,+v.cvss))/10:(SEV_SCORE[v.sev]||0);
const likelihoodOf=v=>v.kev?1:v.epss!=null&&isFinite(v.epss)?0.15+0.85*Math.sqrt(Math.max(0,Math.min(1,+v.epss))):0.3;
const vulnRisk=v=>severityOf(v)*likelihoodOf(v);
const bandOf=n=>(BANDS.find(([min])=>n>=min)||[0,'none'])[1];
// asset: {vulns, exp, crit}; hops: steps from the Internet (undefined: not reachable); bizCrit: 0 to 3
function riskScore(asset,hops,bizCrit){
  const vs=asset.vulns||[];
  const vuln=1-vs.reduce((p,v)=>p*(1-vulnRisk(v)),1);
  const exposure=EXPO_F[asset.exp]!=null?EXPO_F[asset.exp]:0.3;
  const reach=hops===undefined||hops===null?0.3:Math.max(0.5,1-0.1*Math.max(0,hops-1));
  const context=(exposure+reach)/2;
  const crit=Math.max(CRIT_F[asset.crit]||0.75,CRIT_F[bizCrit||0]||0);
  const score=Math.round(100*vuln*context*crit);
  return {score,band:bandOf(score),vuln,exposure,reach,context,crit,kev:vs.filter(v=>v.kev).length};
}
// Every asset of an IS with its score, highest first, and the fixes in order: each vulnerability
// scored like an asset that would carry it alone (its own severity and likelihood, in the context
// and criticality of its asset), so the most dangerous ones come first wherever they are.
// bizCrit: {assetId: highest criticality of the business services it would hit}
function riskPriorities(site,bizCrit){
  const B=bizCrit||{},assets=[],fixes=[];
  site.assets.forEach(a=>{
    const r=riskScore(a,site.expo[a.id],B[a.id]);
    if(r.score>0)assets.push(Object.assign({id:a.id},r));
    (a.vulns||[]).forEach((v,i)=>{const score=Math.round(100*vulnRisk(v)*r.context*r.crit);
      if(score>0)fixes.push({asset:a.id,index:i,vuln:v,score,assetScore:r.score,likelihood:likelihoodOf(v),severity:severityOf(v)});});
  });
  assets.sort((x,y)=>y.score-x.score||byName(x.id,y.id));
  fixes.sort((x,y)=>y.score-x.score||(y.vuln.kev?1:0)-(x.vuln.kev?1:0)||y.likelihood-x.likelihood||y.assetScore-x.assetScore||byName(x.asset,y.asset));
  return {assets,fixes};
}

/* ---- Attack paths and blast radius ---- */
// An attacker who holds an asset can open the flows that leave it, and so reach the asset at the
// other end on the flow's port. Taking that asset over is a step, with a likelihood from what
// is there, the highest of:
//  - its vulnerabilities, combined as for the risk score (severity times likelihood of
//    exploitation, the chance that at least one gets exploited), whatever the port;
//  - a remote administration port (SSH, Telnet, RPC, SMB, RDP, VNC, WinRM): 50%, for credentials
//    picked up on the way;
//  - any other service: 10%, for what the last scan did not see.
// A path counts for the product of its steps. Flows only go from their source to their
// destination: answering a flow does not let the destination reach back.
const ADMIN_PORTS=new Set(['tcp/22','tcp/23','tcp/135','tcp/139','tcp/445','tcp/3389','tcp/5900','tcp/5985','tcp/5986']);
const STEP_ADMIN=0.5,STEP_SERVICE=0.1;
function stepOdds(asset,port){
  const vuln=1-(asset.vulns||[]).reduce((p,v)=>p*(1-vulnRisk(v)),1),admin=ADMIN_PORTS.has(port)?STEP_ADMIN:0;
  const p=Math.max(vuln,admin,STEP_SERVICE);
  return {p,why:vuln>0&&p===vuln?'vuln':admin&&p===admin?'admin':'service'};
}
const isTarget=(site,id)=>!!site.byId[id]&&!site.byId[id].isInternet;
// The flows leaving each node, towards an asset
function flowsFrom(site){
  const out=new Map();
  site.flows.forEach(f=>{if(!isTarget(site,f.dst))return;if(!out.has(f.src))out.set(f.src,[]);out.get(f.src).push(f);});
  return out;
}
// Where an attack can start from the outside: the Internet, and the Internet services that send flows in
const outside=site=>['internet',...(site.services||[]).map(x=>x.id)];
const EPS=1e-12;
const better=(a,b)=>a.p>b.p+EPS||(Math.abs(a.p-b.p)<=EPS&&(a.steps<b.steps||(a.steps===b.steps&&byName(a.path.join('>'),b.path.join('>'))<0)));
// Everything an attacker holding `from` (an asset id, or several, such as outside(site)) could
// reach along the flows, each asset with its most likely way in.
// Returns Map {assetId: {p, steps, path: [node ids, start first], flows: [flow ids], port, why, step}}.
function blastRadius(site,from){
  const starts=[].concat(from),best=new Map(),done=new Set(),out=flowsFrom(site);
  starts.forEach(s=>best.set(s,{p:1,steps:0,path:[s],flows:[]}));
  for(;;){
    let n=null;
    best.forEach((v,k)=>{if(!done.has(k)&&(n===null||better(v,best.get(n))))n=k;});
    if(n===null)break;
    done.add(n);const b=best.get(n);
    (out.get(n)||[]).forEach(f=>{
      if(done.has(f.dst))return;
      const s=stepOdds(site.byId[f.dst],f.port);
      const c={p:b.p*s.p,steps:b.steps+1,path:b.path.concat(f.dst),flows:b.flows.concat(f.id),port:f.port,why:s.why,step:s.p};
      const cur=best.get(f.dst);if(!cur||better(c,cur))best.set(f.dst,c);
    });
  }
  starts.forEach(s=>best.delete(s));
  return best;
}
// Every path from `from` to each of `targets`, never through the same node twice, most likely
// first. Paths below `min` likelihood or longer than `depth` steps are left out. The search
// stops after `budget` steps, and keeps the `max` most likely paths per target: `truncated`
// says when paths may be missing.
// Returns {byTarget: {id: [{p, path, flows}]}, truncated}
function attackPaths(site,from,targets,{max=20,depth=8,min=0.001,budget=50000}={}){
  const want=new Set(targets),found=new Map(),out=flowsFrom(site),seen=new Set();
  let left=budget,truncated=false;
  want.forEach(t=>found.set(t,[]));
  const walk=(n,p,path,flows)=>{
    if(--left<0){truncated=true;return;}
    for(const f of out.get(n)||[]){
      if(seen.has(f.dst))continue;
      const q=p*stepOdds(site.byId[f.dst],f.port).p;
      if(q<min)continue;
      const P=path.concat(f.dst),F=flows.concat(f.id);
      if(want.has(f.dst))found.get(f.dst).push({p:q,path:P,flows:F});
      if(P.length-1<depth){seen.add(f.dst);walk(f.dst,q,P,F);seen.delete(f.dst);}
      if(left<0)return;
    }
  };
  [].concat(from).forEach(s=>{if(want.has(s))return;seen.add(s);walk(s,1,[s],[]);seen.delete(s);});
  const byTarget={};
  found.forEach((l,t)=>{
    l.sort((a,b)=>(b.p-a.p)||(a.path.length-b.path.length)||byName(a.path.join('>'),b.path.join('>')));
    if(l.length>max)truncated=true;
    byTarget[t]=l.slice(0,max);
  });
  return {byTarget,truncated};
}
// Where to cut: the assets an attacker goes through, and the equipment their flows cross, on the
// way to the targets. `every` lists the targets that no path reaches without it; `paths` counts
// the paths that use it, `held` those that take it over. Most targets cut off first.
// Returns [{id, kind: 'asset' (taken over on some path) | 'equipment' (only crossed), every: [target ids], paths, held}]
function chokePoints(site,byTarget){
  const flowById=new Map(site.flows.map(f=>[f.id,f])),pts=new Map(),held=new Map();
  Object.entries(byTarget).forEach(([t,list])=>{
    const count=new Map();
    list.forEach(x=>{
      const mid=x.path.slice(1,-1),on=new Set(mid);
      x.flows.forEach(id=>{const f=flowById.get(id);(f&&f.via||[]).forEach(v=>on.add(v));});
      on.delete(t);
      on.forEach(id=>count.set(id,(count.get(id)||0)+1));
      mid.forEach(id=>held.set(id,(held.get(id)||0)+1));
    });
    count.forEach((n,id)=>{
      if(!site.byId[id])return;
      if(!pts.has(id))pts.set(id,{id,kind:'equipment',every:[],paths:0,held:0});
      const p=pts.get(id);p.paths+=n;if(n===list.length)p.every.push(t);
    });
  });
  // taken over on at least one path: an asset to harden; only crossed: equipment whose rules to tighten
  pts.forEach(p=>{if(held.has(p.id)){p.kind='asset';p.held=held.get(p.id);}});
  return [...pts.values()].sort((x,y)=>y.every.length-x.every.length||y.paths-x.paths||byName(x.id,y.id));
}

/* ---- VLANs read from a file, to import some of them ---- */
// A CSV (header in English or French, separator , ; or tab), a JSON list ([{num, name, cidr, zone}] or
// {vlans: [...]}) or a Strata export (format "strata": every VLAN of every IS, with its zone and its IS).
// Returns {kind: 'csv'|'json'|'strata', items: [{num, name, cidr, zone, site, siteName, vlanId}], skipped}
// where skipped counts the lines without a valid VLAN number (1 to 4094). Throws when nothing is readable.
const VCOL={num:['vlan','vlan id','vlan_id','vlanid','vid','vlan number','num','number','numero','numéro','n°','tag'],
  name:['name','nom','vlan name','description','desc','label','libellé','libelle'],
  cidr:['cidr','subnet','network','prefix','range','réseau','reseau','sous-réseau','sous-reseau','plage','ip range','address range','prefixe','préfixe'],
  zone:['zone','group','groupe','vlan group','site','location','emplacement','tenant']};
function csvRows(text){
  const lines=String(text).replace(/^﻿/,'').split(/\r?\n/).filter(l=>l.trim());
  if(!lines.length)return [];
  const head=lines[0],sep=[';','\t',','].map(c=>[c,head.split(c).length]).sort((a,b)=>b[1]-a[1])[0][0];
  return lines.map(l=>{const out=[];let cur='',q=false;
    for(let i=0;i<l.length;i++){const ch=l[i];
      if(q){if(ch==='"'&&l[i+1]==='"'){cur+='"';i++;}else if(ch==='"')q=false;else cur+=ch;}
      else if(ch==='"')q=true;else if(ch===sep){out.push(cur.trim());cur='';}else cur+=ch;}
    out.push(cur.trim());return out;});
}
const vlanNum=v=>{const m=/\d+/.exec(String(v==null?'':v));const n=m?parseInt(m[0],10):NaN;return n>=1&&n<=4094?n:null;};
function vlansFromFile(text,fileName=''){
  const t=String(text||'').replace(/^﻿/,'').trim();
  if(!t)throw new Error('the file is empty');
  const items=[];let skipped=0,kind;
  const push=(o,extra={})=>{const num=vlanNum(o.num);if(num===null){skipped++;return;}
    items.push(Object.assign({num,name:String(o.name||'').trim().slice(0,50)||`VLAN ${num}`,cidr:String(o.cidr||'').trim().slice(0,60),zone:String(o.zone||'').trim().slice(0,40)},extra));};
  if(/^[[{]/.test(t)&&!/\.csv$/i.test(fileName)){
    let o;try{o=JSON.parse(t);}catch(e){throw new Error('this is not valid JSON');}
    if(o&&typeof o.si==='object'&&o.si&&!Array.isArray(o.si)){
      kind='strata';
      Object.entries(o.si).forEach(([sid,d])=>{if(!d||typeof d!=='object')return;
        const zones=Array.isArray(d.zones)?d.zones:[];
        (Array.isArray(d.vlans)?d.vlans:[]).forEach(v=>{if(!v||typeof v!=='object')return;const z=zones.find(x=>x&&x.id===v.zone);
          push({num:v.num,name:v.name,cidr:v.cidr,zone:z?z.name:''},{site:sid,siteName:String(d.name||sid),vlanId:String(v.id||'')});});});
    }else{
      kind='json';
      const list=Array.isArray(o)?o:Array.isArray(o&&o.vlans)?o.vlans:Array.isArray(o&&o.results)?o.results:null;
      if(!list)throw new Error('expected a list of VLANs, {"vlans": [...]}, or a Strata export');
      const pick=(x,keys)=>{for(const k of keys){const hit=Object.keys(x).find(y=>y.toLowerCase()===k);if(hit!==undefined&&x[hit]!=null&&typeof x[hit]!=='object')return x[hit];}
        // NetBox and others: {group: {name}}, {site: {name}}
        for(const k of keys){const hit=Object.keys(x).find(y=>y.toLowerCase()===k);if(hit!==undefined&&x[hit]&&typeof x[hit]==='object'&&x[hit].name)return x[hit].name;}return '';};
      list.forEach(x=>{if(!x||typeof x!=='object'){skipped++;return;}push({num:pick(x,VCOL.num),name:pick(x,VCOL.name),cidr:pick(x,VCOL.cidr),zone:pick(x,VCOL.zone)});});
    }
  }else{
    kind='csv';
    const rows=csvRows(t);
    const norm=h=>h.toLowerCase().replace(/^["']|["']$/g,'').trim();
    const head=rows[0].map(norm),col={};
    Object.entries(VCOL).forEach(([k,names])=>{const i=head.findIndex(h=>names.includes(h));if(i>=0)col[k]=i;});
    let body=rows.slice(1);
    // no header: number, name, range, zone in that order
    if(col.num===undefined){if(vlanNum(rows[0][0])===null)throw new Error('no VLAN number column (vlan, vid, num, numéro…)');Object.assign(col,{num:0,name:1,cidr:2,zone:3});body=rows;}
    body.forEach(r=>push({num:r[col.num],name:col.name!==undefined?r[col.name]:'',cidr:col.cidr!==undefined?r[col.cidr]:'',zone:col.zone!==undefined?r[col.zone]:''}));
  }
  if(!items.length)throw new Error('no VLAN with a number from 1 to 4094 in this file');
  return {kind,items,skipped};
}

/* ---- Zones suggested from the flows ---- */
// The floors of an IS, the Internet on top: each VLAN goes to the floor of its depth, the number of flow
// hops from the Internet in the direction of the traffic (1: reached straight from the Internet), and the
// VLANs never reached from it go below, by the role of their assets (servers, users, industrial,
// network and administration). Empty VLANs stay in their zone. Existing zones that hold most of the same
// VLANs are kept, with their name and id.
// input: {vlans: [{id, num, name, zone}], assets: [{id, vlan, type}], flows: [{src, dst}],
//   zones: [{id, name}] (bottom first, as stored), sources: ids that stand for the Internet (default
//   'internet' and every 'svc:…')}
// returns {zones: [{id, name, key, vlans: [ids], existing}] bottom first, byVlan: {vlanId: {zone, depth, role,
//   moved}}, depth: {vlanId: n|null}}
const ROLE_OF={server:'srv',dc:'srv',db:'srv',hypervisor:'srv',workstation:'users',phone:'users',printer:'users',ap:'users',
  plc:'ot',camera:'ot',iot:'ot',switch:'net',router:'net',firewall:'net',gateway:'net'};
const ROLE_NAME={srv:'Internal servers',users:'Users',ot:'Industrial (OT)',net:'Network and administration',other:'Other'};
// bottom to top below the floors reached from the Internet
const ROLE_ORDER=['net','ot','users','other','srv'];
function suggestZones({vlans,assets,flows,zones,sources}){
  const isNet=id=>sources?sources.includes(id):(id==='internet'||String(id).startsWith('svc:'));
  const vOf={};assets.forEach(a=>{vOf[a.id]=a.vlan;});
  // hops from the Internet, following the flows from source to destination
  const out={};flows.forEach(f=>{(out[f.src]=out[f.src]||[]).push(f.dst);});
  const dist={},q=[];
  Object.keys(out).filter(isNet).forEach(id=>{dist[id]=0;q.push(id);});
  while(q.length){const n=q.shift();(out[n]||[]).forEach(m=>{if(dist[m]===undefined&&!isNet(m)){dist[m]=dist[n]+1;q.push(m);}});}
  const depth={},role={},count={},types={};
  vlans.forEach(v=>{depth[v.id]=null;count[v.id]={};types[v.id]={};});
  assets.forEach(a=>{if(!(a.vlan in depth))return;const d=dist[a.id];if(d!==undefined&&(depth[a.vlan]===null||d<depth[a.vlan]))depth[a.vlan]=d;
    const r=ROLE_OF[a.type]||'other';count[a.vlan][r]=(count[a.vlan][r]||0)+1;types[a.vlan][a.type]=(types[a.vlan][a.type]||0)+1;});
  // the role most of its assets have; a VLAN with PLCs, cameras or sensors (a third of it, or named so) is industrial
  // (cameras and sensors alone, in a VLAN named for offices — meeting rooms, floors, VoIP, Wi-Fi — are the users')
  const OT_NAME=/(^|[^a-z])(ot|scada|ics|plc|automat\w*|industri\w*|atelier|usine|production)([^a-z]|$)/i;
  const USER_NAME=/(r[ée]union|meeting|bureau|office|[ée]tage|floor|poste|user|utilisateur|voip|t[ée]l[ée]phon|imprim|print|wi-?fi|accueil)/i;
  vlans.forEach(v=>{const C=count[v.id],c=Object.entries(C).sort((x,y)=>y[1]-x[1]||ROLE_ORDER.indexOf(y[0])-ROLE_ORDER.indexOf(x[0]));
    const n=c.reduce((t,x)=>t+x[1],0),ot=C.ot||0,name=v.name||'',plcs=types[v.id].plc||0;
    if(!n)role[v.id]=null;
    else if(plcs||(ot&&OT_NAME.test(name)))role[v.id]='ot';
    else if(USER_NAME.test(name)&&((C.users||0)+ot)*2>=n)role[v.id]='users';
    else if(ot*3>=n)role[v.id]='ot';
    else role[v.id]=c[0][0];});
  // the floors, bottom first
  const maxD=Math.max(0,...vlans.map(v=>depth[v.id]||0)),deep=Math.min(maxD,3);
  const floors=[...ROLE_ORDER.map(r=>({key:'role:'+r,name:ROLE_NAME[r]})),
    ...[3,2,1].filter(d=>d<=deep).map(d=>({key:'depth:'+d,name:d===1?'Exposed to the Internet':d===2?'Reached from the exposed zone':'Back end, 3 hops or more'}))];
  const keyOf=v=>{if(role[v.id]===null)return null;const d=depth[v.id];if(d!==null)return 'depth:'+Math.min(d,3);return 'role:'+role[v.id];};
  const want={};vlans.forEach(v=>{const k=keyOf(v);if(k)(want[k]=want[k]||[]).push(v.id);});
  // keep an existing zone for the floor that holds most of its VLANs (and at least half of the floor)
  const cur={};zones.forEach(z=>{cur[z.id]=new Set(vlans.filter(v=>v.zone===z.id).map(v=>v.id));});
  // (and that floor holds at least half of the zone's own VLANs with assets: a catch-all zone is not reused)
  const full=z=>[...cur[z]].filter(id=>role[id]!==null).length;
  const pairs=[];floors.forEach(f=>{const ids=want[f.key]||[];zones.forEach(z=>{const n=ids.filter(id=>cur[z.id].has(id)).length;if(n&&n*2>=ids.length&&n*2>=full(z.id))pairs.push({f:f.key,z:z.id,n});});});
  pairs.sort((a,b)=>b.n-a.n);
  const zoneFor={},taken=new Set();pairs.forEach(p=>{if(!zoneFor[p.f]&&!taken.has(p.z)){zoneFor[p.f]=p.z;taken.add(p.z);}});
  const usedIds=new Set(zones.map(z=>z.id));
  const newId=key=>{let id='z-'+key.replace(/[^a-z0-9]+/g,'-');for(let i=2;usedIds.has(id);i++)id='z-'+key.replace(/[^a-z0-9]+/g,'-')+'-'+i;usedIds.add(id);return id;};
  const outZones=[],byVlan={};
  floors.forEach(f=>{const ids=want[f.key]||[];if(!ids.length)return;
    const z=zoneFor[f.key],ex=z?zones.find(x=>x.id===z):null;
    outZones.push({id:ex?ex.id:newId(f.key),name:ex?ex.name:f.name,key:f.key,vlans:ids.slice(),existing:!!ex,suggested:f.name});});
  // empty VLANs keep their zone: kept zones stay where they were, below the floors
  const stay=vlans.filter(v=>role[v.id]===null);
  const kept=new Set(outZones.map(z=>z.id));
  zones.forEach(z=>{const ids=stay.filter(v=>v.zone===z.id).map(v=>v.id);if(!ids.length)return;
    const hit=outZones.find(o=>o.id===z.id);if(hit){hit.vlans.push(...ids);return;}
    outZones.unshift({id:z.id,name:z.name,key:'keep:'+z.id,vlans:ids,existing:true,suggested:z.name});kept.add(z.id);});
  stay.filter(v=>!zones.some(z=>z.id===v.zone)).forEach(v=>{const z=outZones[0];if(z)z.vlans.push(v.id);});
  outZones.forEach(z=>z.vlans.forEach(id=>{const v=vlans.find(x=>x.id===id);byVlan[id]={zone:z.id,depth:depth[id],role:role[id],moved:v.zone!==z.id};}));
  return {zones:outZones,byVlan,depth};
}

/* ---- Arranging the plates of a level on rows and columns ---- */
// plates: [{id, w, D}] in their current order; weight(a, b): how much two VLANs talk (symmetric, >= 0);
// cols: the most plates per row (0 or less: about the square root of their number, a little wider than deep);
// gap: space between plates. Filled row by row from the back, each cell takes the plate with the most
// traffic to the plates already left of it and behind it, then the busiest plate, then the current order:
// VLANs that talk sit side by side, and VLANs with no flow end up last. Returns {id: [x, z]} (plate
// centres, the grid centred on 0) and the number of columns used.
function arrangeGrid(plates,weight,cols,gap=2){
  const n=plates.length;if(!n)return {places:{},cols:0,rows:0};
  const C=Math.max(1,Math.min(n,cols>0?Math.round(cols):Math.ceil(Math.sqrt(n*1.6))));
  const w=(a,b)=>{const v=+weight(a,b);return v>0&&isFinite(v)?v:0;};
  const total={};plates.forEach(p=>{total[p.id]=plates.reduce((t,q)=>t+(q.id!==p.id?w(p.id,q.id):0),0);});
  const left=plates.map((p,i)=>({p,i})),grid=[];
  for(let k=0;k<n;k++){
    const c=k%C,nb=[];if(c>0)nb.push(grid[k-1]);if(k>=C)nb.push(grid[k-C]);
    let best=0,bs=null;
    left.forEach((e,j)=>{const s=[nb.reduce((t,q)=>t+w(e.p.id,q.id),0),total[e.p.id],-e.i];
      if(!bs||s[0]>bs[0]||(s[0]===bs[0]&&(s[1]>bs[1]||(s[1]===bs[1]&&s[2]>bs[2])))){bs=s;best=j;}});
    grid.push(left.splice(best,1)[0].p);
  }
  const R=Math.ceil(n/C),colW=Array(C).fill(0),rowD=Array(R).fill(0);
  grid.forEach((p,k)=>{colW[k%C]=Math.max(colW[k%C],p.w);rowD[Math.floor(k/C)]=Math.max(rowD[Math.floor(k/C)],p.D);});
  const sum=a=>a.reduce((t,x)=>t+x,0),W=sum(colW)+gap*(C-1),Dt=sum(rowD)+gap*(R-1);
  const places={};
  grid.forEach((p,k)=>{const c=k%C,r=Math.floor(k/C);
    const x=-W/2+sum(colW.slice(0,c))+gap*c+colW[c]/2,z=-Dt/2+sum(rowD.slice(0,r))+gap*r+rowD[r]/2;
    places[p.id]=[Math.round(x*2)/2,Math.round(z*2)/2];});
  return {places,cols:C,rows:R,order:grid.map(p=>p.id)};
}

root.StrataAnalysis={suggestZones,arrangeGrid,vlansFromFile,riskScore,riskPriorities,vulnRisk,likelihoodOf,inCidr,nextFreeIp,lanes,flowColours,dependencies,businessImpact,appGraph,
  stepOdds,blastRadius,attackPaths,chokePoints,outside};
})(typeof globalThis!=='undefined'?globalThis:this);

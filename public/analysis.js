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

root.StrataAnalysis={riskScore,riskPriorities,vulnRisk,likelihoodOf,inCidr,nextFreeIp,lanes,flowColours,dependencies,businessImpact,appGraph};
})(typeof globalThis!=='undefined'?globalThis:this);

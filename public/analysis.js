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

root.StrataAnalysis={lanes,flowColours,dependencies,businessImpact,appGraph};
})(typeof globalThis!=='undefined'?globalThis:this);

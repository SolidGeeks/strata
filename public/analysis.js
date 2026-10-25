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

root.StrataAnalysis={lanes,flowColours};
})(typeof globalThis!=='undefined'?globalThis:this);

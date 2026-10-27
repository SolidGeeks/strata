// SPDX-License-Identifier: AGPL-3.0-or-later
// Incident mode: the assets hit, who to call, which flows to cut and where, what depends on them, how a
// Muster playbook step points at the map, and the anonymised prompts for a public AI.
// Pure functions over a compiled IS, no DOM: the page loads this file before app.js,
// and the tests run it in Node (tests/incident.test.mjs).
(function(root){
'use strict';
const isNet=id=>id==='internet'||String(id).startsWith('svc:');
const STATES=['compromised','suspected','contained'];
const TYPE_LABEL={server:'Server',dc:'Domain controller',db:'Database',hypervisor:'Hypervisor / storage',firewall:'Firewall',gateway:'VPN gateway',router:'Router / L3 core',switch:'Switch / load balancer',workstation:'Workstation',printer:'Printer',phone:'IP phone',ap:'Wi-Fi access point',camera:'IP camera',plc:'PLC',iot:'IoT device'};
const SEV_RANK={none:0,low:1,med:2,high:3,crit:4};

/* ---- Incident state of one IS ---- */
// {on, marks:{assetId:state}, cuts:[flowId], run:null|{…}, log:[{at,msg,kind,by}]}
function empty(){return {on:false,marks:{},cuts:[],run:null,log:[]};}
function clean(o){
  const e=empty();if(!o||typeof o!=='object')return e;
  e.on=!!o.on;
  if(o.marks&&typeof o.marks==='object')Object.keys(o.marks).forEach(k=>{if(STATES.includes(o.marks[k]))e.marks[k]=o.marks[k];});
  if(Array.isArray(o.cuts))e.cuts=o.cuts.filter(x=>typeof x==='string');
  if(o.run&&typeof o.run==='object')e.run=o.run;
  if(Array.isArray(o.log))e.log=o.log.slice(0,500);
  return e;
}
// Assets in the given states that still exist on the map
function marked(site,inc,states){return Object.keys(inc.marks).filter(id=>site.byId[id]&&states.includes(inc.marks[id]));}
const affected=(site,inc)=>marked(site,inc,STATES);

/* ---- Along the flows ---- */
// What an attacker holding the given assets reaches by opening the flows that leave them: {id: steps}
function reach(site,from,depth=3){
  const d={},q=[];from.forEach(x=>{d[x]=0;q.push(x);});
  while(q.length){const n=q.shift();if(d[n]>=depth)continue;
    site.flows.forEach(f=>{if(f.src===n&&d[f.dst]===undefined&&!isNet(f.dst)){d[f.dst]=d[n]+1;q.push(f.dst);}});}
  from.forEach(x=>delete d[x]);return d;
}
// Assets that call the given ones: they lose a service when these are isolated
function consumers(site,ids){const set=new Set(ids);return [...new Set(site.flows.filter(f=>set.has(f.dst)&&!isNet(f.src)&&!set.has(f.src)).map(f=>f.src))];}
// Business services that run on the given assets
function business(site,ids){const set=new Set(ids);return site.business.filter(b=>b.assets.some(x=>set.has(x)));}

/* ---- Selectors: how a playbook step points at the map ----
   affected, compromised, suspected, contained, id:<asset>, type:<type>, role:<text>, vuln:<CVE>, exposed:internet,
   reach:<selector>, consumers:<selector> give assets; flows:<selector>, business:<selector>, contacts:<selector>
   and contacts:is give the other kinds. {cve} (or any {param}) is replaced by the incident's parameters. */
function fill(sel,params){return String(sel).replace(/\{(\w+)\}/g,(m,k)=>params&&params[k]!=null?String(params[k]):'');}
function selectAssets(site,inc,sel,params){
  sel=fill(sel,params);
  if(sel==='affected')return affected(site,inc);
  if(sel==='compromised')return marked(site,inc,['compromised','contained']);
  if(sel==='suspected'||sel==='contained')return marked(site,inc,[sel]);
  const i=sel.indexOf(':'),k=i<0?sel:sel.slice(0,i),rest=i<0?'':sel.slice(i+1);
  if(k==='reach'){const d=reach(site,selectAssets(site,inc,rest,params));return Object.keys(d).sort((a,b)=>d[a]-d[b]);}
  if(k==='consumers')return consumers(site,selectAssets(site,inc,rest,params));
  const A=site.assets;
  if(k==='id')return site.byId[rest]?[rest]:A.filter(a=>a.name===rest).map(a=>a.id);
  if(k==='type')return A.filter(a=>a.type===rest).map(a=>a.id);
  if(k==='role')return A.filter(a=>String(a.role||'').toLowerCase().includes(rest.toLowerCase())).map(a=>a.id);
  if(k==='vuln')return rest?A.filter(a=>a.vulns.some(v=>v.id===rest)).map(a=>a.id):[];
  if(k==='exposed')return A.filter(a=>site.flows.some(f=>isNet(f.src)&&f.dst===a.id)).map(a=>a.id);
  return [];
}
function resolve(site,inc,sel,params){
  const i=sel.indexOf(':'),k=i<0?sel:sel.slice(0,i),rest=i<0?'':sel.slice(i+1);
  if(k==='flows')return {kind:'flows',items:flowsToCut(site,inc,selectAssets(site,inc,rest,params))};
  if(k==='business')return {kind:'business',items:business(site,selectAssets(site,inc,rest,params))};
  if(k==='contacts')return {kind:'contacts',items:rest==='is'?site.contacts.map(c=>Object.assign({},c,{why:['IS contact']})):callList(site,selectAssets(site,inc,rest,params),false)};
  return {kind:'assets',items:selectAssets(site,inc,sel,params)};
}

/* ---- Flows to cut ---- */
const ADMIN=new Set(['tcp/22','tcp/23','tcp/135','tcp/139','tcp/445','tcp/3389','tcp/5900','tcp/5985','tcp/5986','tcp/389','tcp/636','tcp/88','tcp/1433','tcp/3306','tcp/5432','tcp/1521','tcp/102','tcp/502']);
// Where a flow is cut: the first firewall it crosses, else the first piece of equipment, else the host itself
function cutPoint(site,f){
  const eq=(f.via||[]).map(id=>site.byId[id]).filter(Boolean);
  const fw=eq.find(a=>a.type==='firewall')||eq.find(a=>a.type==='gateway');
  if(fw)return {id:fw.id,label:`${fw.name} (firewall rule)`};
  if(eq.length)return {id:eq[0].id,label:`${eq[0].name} (ACL)`};
  if(isNet(f.src)||isNet(f.dst))return {id:null,label:'Internet edge (no firewall recorded on the path)'};
  return {id:null,label:'On the host (EDR isolation or local firewall)'};
}
function flowsToCut(site,inc,ids){
  const set=new Set(ids),cuts=new Set(inc.cuts||[]),name=id=>isNet(id)?(id==='internet'?'the Internet':(site.svcById[id]||{}).name||id):site.byId[id].name;
  return site.flows.filter(f=>set.has(f.src)||set.has(f.dst)).map(f=>{
    const out=set.has(f.src),peer=out?f.dst:f.src,why=[];let score=0;
    const p=isNet(peer)?null:site.byId[peer];
    if(isNet(peer)){score+=50;why.push(out?'Outbound to the Internet: command and control or data theft':'Inbound from the Internet: the way in');}
    if(p&&!set.has(peer)&&(p.crit===3||(site.critIds||[]).includes(peer))){score+=30;why.push(`${out?'Reaches':'Comes from'} critical asset ${p.name}`);}
    if(p&&ADMIN.has(f.port)){score+=out?20:8;if(out)why.push('Lateral movement protocol');}
    if(p&&out&&p.vulns.some(v=>v.kev)){score+=15;why.push(`${p.name} has a known exploited vulnerability`);}
    if(f.risk){score+=15;if(f.note)why.push(f.note);}
    if(set.has(peer))score-=10;
    const iso=[f.src,f.dst].some(x=>inc.marks[x]==='contained');
    return {f,out,peer,peerName:name(peer),srcName:name(f.src),dstName:name(f.dst),score,prio:score>=50?1:score>=25?2:3,why,cut:cuts.has(f.id)||iso,iso,at:cutPoint(site,f),
      breaks:business(site,[f.src,f.dst].filter(x=>!isNet(x))).map(b=>b.name)};
  }).sort((a,b)=>a.cut-b.cut||b.score-a.score||a.f.id.localeCompare(b.f.id));
}

/* ---- Who to call ---- */
const ROLE_ORDER={'On-call':0,'Technical owner':1,'Vendor / support':2,'Business owner':3,'CISO':4};
function callList(site,ids,withIs=true){
  const m=new Map(),add=(c,why)=>{const k=(c.name||'')+'|'+(c.phone||c.email||c.role||'');if(!m.has(k))m.set(k,Object.assign({},c,{why:[]}));const e=m.get(k);if(!e.why.includes(why))e.why.push(why);};
  ids.forEach(id=>{const a=site.byId[id];if(!a)return;(a.contacts||[]).filter(c=>c.name||c.phone||c.email).forEach(c=>add(c,a.name));});
  business(site,ids).forEach(b=>{if(b.owner)add({name:b.owner,role:'Business owner',phone:'',email:'',dispo:''},b.name);});
  if(withIs&&ids.length)site.contacts.forEach(c=>add(c,'IS contact'));
  const h24=c=>/24\s*\/\s*7|24h|on-call/i.test(`${c.dispo||''} ${c.role||''}`)?0:1;
  return [...m.values()].sort((a,b)=>h24(a)-h24(b)||(ROLE_ORDER[a.role]??9)-(ROLE_ORDER[b.role]??9)||String(a.name).localeCompare(String(b.name)));
}

/* ---- Running a Muster playbook ---- */
const step=(pb,id)=>pb.steps.find(s=>s.id===id);
const nextOf=(pb,id)=>pb.edges.filter(e=>e[0]===id);
function start(sc,pb,now,by){
  const run={ref:sc.ref,name:sc.name,pb:pb.code,v:pb.v,mode:sc.mode,severity:sc.severity,assets:(sc.assets||[]).slice(),params:Object.assign({},sc.params||{}),source:sc.source||'example',
    path:[pb.steps[0].id],cur:pb.steps[0].id,answers:{},checks:{},startedAt:now,closed:false};
  const n=nextOf(pb,run.cur)[0];if(n){run.path.push(n[1]);run.cur=n[1];}
  return run;
}
// The marks a decision asks for once answered, as [[assetId,state]]: never back from compromised or contained
function effects(site,inc,s,label,params){
  const eff=s&&s.effects&&s.effects[label],out=[];
  if(eff)selectAssets(site,inc,eff[1],params).forEach(id=>{const was=inc.marks[id];if(was!=='compromised'&&was!=='contained'&&was!==eff[0])out.push([id,eff[0]]);});
  return out;
}
// Moves the run along an edge; returns the marks a decision asks for
function advance(site,inc,pb,to,label){
  const run=inc.run,s=step(pb,run.cur),changes=label?effects(site,inc,s,label,run.params):[];
  if(label)run.answers[run.cur]=label;
  run.path.push(to);run.cur=to;if(step(pb,to).type==='end')run.closed=true;
  return changes;
}

/* ---- A Muster incident, as the map runs it ---- */
// A run that points to a real Muster incident (an example has no Muster id; older ones say source:'muster')
const isMuster=r=>!!(r&&r.source==='muster'&&r.id);
// The playbook frozen in the incident, in the shape above; edges keep their Muster id
function fromGraph(m){
  const g=m.graph||{nodes:[],edges:[]};
  return {code:m.pbCode,name:m.pbName,v:m.v,severity:m.severity,
    steps:g.nodes.map(n=>({id:n.id,type:n.type,title:n.title,phase:n.phase||'',role:n.role||'',sla:n.sla||0,desc:n.desc||'',checklist:n.checklist||[],targets:Array.isArray(n.targets)?n.targets:[],effects:n.effects||null})),
    edges:g.edges.map(e=>[e.from,e.to,e.label||'',e.id])};
}
// Where the response stands: the steps taken, the answers given, the tasks ticked
function runOf(m,pb){
  const steps=m.steps||[],answers={},checks={};
  steps.forEach(st=>{const e=st.edge&&pb.edges.find(x=>x[3]===st.edge),s=step(pb,st.id);if(e&&s&&s.type==='decision')answers[st.id]=e[2];});
  Object.entries(m.checks||{}).forEach(([id,arr])=>(arr||[]).forEach((v,i)=>{if(v)checks[id+':'+i]=true;}));
  const st=m.strata||{};
  return {source:'muster',id:m.id,ref:m.ref,name:m.name,pb:m.pbCode,v:m.v,mode:m.mode,severity:m.severity,status:m.status,
    assets:st.assets||[],params:st.params||{},path:steps.map(x=>x.id),cur:steps.length?steps[steps.length-1].id:null,answers,checks,startedAt:m.startedAt,closed:m.status!=='active'};
}
// Answers given since the map last looked (in Strata or in Muster), with the marks they ask for
function newAnswers(site,inc,pb,m,seen){
  const out=[],steps=m.steps||[];
  for(let i=Math.max(0,seen||0);i<steps.length;i++){const st=steps[i],s=step(pb,st.id),e=st.edge&&pb.edges.find(x=>x[3]===st.edge);
    if(s&&e&&s.type==='decision')out.push({step:s,label:e[2],marks:effects(site,inc,s,e[2],(m.strata||{}).params)});}
  return out;
}
// Muster incidents that belong to this IS: linked to it, or naming one of its assets
function musterFor(site,list){
  const mine=[],other=[];
  (list||[]).forEach(i=>{const st=i.strata||{};
    const named=(st.assets||[]).some(a=>site.byId[a]||site.assets.some(x=>x.name===a));
    (st.site===site.id||(!st.site&&named)?mine:other).push(i);});
  return {mine,other};
}
// Asset ids from what Muster names: Strata ids, or names
const idsOf=(site,names)=>[...new Set((names||[]).map(a=>site.byId[a]?a:(site.assets.find(x=>x.name===a)||{}).id).filter(Boolean))];
// The most likely route ahead: the steps taken, then the first edge out of each step
function route(pb,run){
  const seen=new Set(run.path),r=run.path.slice();let c=run.cur;
  for(;;){const e=nextOf(pb,c)[0];if(!e||seen.has(e[1]))break;r.push(e[1]);seen.add(e[1]);c=e[1];}
  return r;
}

/* ---- Muster playbooks (Muster's own, with the `targets` and `effects` this integration adds) ---- */
const PLAYBOOKS={
  'PB-001':{code:'PB-001',name:'Ransomware',v:3,severity:'Critical',steps:[
    {id:'start',type:'start',title:'Alert received',phase:'Detection',targets:[]},
    {id:'triage',type:'action',title:'Triage the alert',phase:'Detection',role:'L1 Analyst',sla:15,desc:'Confirm ransomware activity and rule out a false positive before anyone escalates.',checklist:['Check the alert source (EDR, SIEM, user report)','List affected hosts and accounts','Open the incident ticket'],targets:['affected','contacts:affected']},
    {id:'encrypt',type:'decision',title:'Encryption in progress?',phase:'Detection',role:'L1 Analyst',sla:5,desc:'Are files being encrypted or mass-renamed right now?',targets:['compromised']},
    {id:'isolate',type:'action',title:'Isolate affected hosts',phase:'Containment',role:'L2 Analyst',sla:10,desc:'Stop the spread before any analysis. Do not power machines off: memory is evidence.',checklist:['Isolate endpoints through the EDR','Disable exposed SMB shares','Disable compromised accounts'],targets:['affected','flows:affected'],act:'isolate'},
    {id:'crisis',type:'escalation',title:'Activate the crisis cell',phase:'Containment',role:'CISO',sla:15,desc:'Escalate to leadership, the insurer and the authorities.',checklist:['Notify executive leadership','Call the cyber insurer','Assess CNIL (72 h) and ANSSI notification'],targets:['business:affected','contacts:is']},
    {id:'forensic',type:'action',title:'Forensic analysis',phase:'Eradication',role:'IR Lead',sla:240,desc:'Find the initial access vector and every persistence mechanism.',checklist:['Capture memory and disks from key hosts','Identify patient zero','Extract IOCs and block them'],targets:['affected','reach:affected']},
    {id:'backup',type:'decision',title:'Clean backups available?',phase:'Recovery',role:'Sysadmin',sla:30,desc:'Are offline backups intact and older than the compromise?',targets:['role:backup','flows:role:backup']},
    {id:'restore',type:'action',title:'Restore from backups',phase:'Recovery',role:'Sysadmin',sla:480,checklist:['Restore into an isolated network segment','Scan restored data','Return to production in batches'],targets:['compromised','consumers:compromised']},
    {id:'rebuild',type:'action',title:'Rebuild systems',phase:'Recovery',role:'Sysadmin',sla:1440,desc:'Reinstall from trusted golden images.',checklist:['Reinstall from reference images','Rotate every domain secret'],targets:['compromised','type:dc']},
    {id:'watch',type:'action',title:'Heightened monitoring',phase:'Detection',role:'L1 Analyst',sla:60,desc:'No encryption observed. Monitor closely and document.',checklist:['Create a detection rule for the IOCs','Watch the hosts for 24 h'],targets:['affected','role:SIEM']},
    {id:'review',type:'action',title:'Post-incident review',phase:'Lessons learned',role:'IR Lead',sla:120,checklist:['Write the timeline','List corrective actions','Update this playbook'],targets:[]},
    {id:'end',type:'end',title:'Incident closed',phase:'Lessons learned',targets:[]}],
    edges:[['start','triage'],['triage','encrypt'],['encrypt','isolate','Yes'],['encrypt','watch','No'],['isolate','crisis'],['crisis','forensic'],['forensic','backup'],['backup','restore','Yes'],['backup','rebuild','No'],['restore','review'],['rebuild','review'],['watch','review'],['review','end']]},
  'PB-010':{code:'PB-010',name:'Exploited critical vulnerability',v:1,severity:'Critical',steps:[
    {id:'start',type:'start',title:'Critical vulnerability exploited',phase:'Detection',targets:[]},
    {id:'exposure',type:'action',title:'Identify exposed assets',phase:'Detection',role:'L2 Analyst',sla:60,checklist:['Match the affected product and versions','Check internet exposure','List system owners'],targets:['vuln:{cve}','contacts:vuln:{cve}']},
    {id:'found',type:'decision',title:'Exposed assets found?',phase:'Detection',role:'L2 Analyst',sla:10,targets:['vuln:{cve}'],effects:{Yes:['suspected','vuln:{cve}']}},
    {id:'doc',type:'action',title:'Document and monitor',phase:'Lessons learned',role:'L1 Analyst',sla:30,checklist:['Record that no asset is affected','Watch vendor updates'],targets:[]},
    {id:'mitigate',type:'action',title:'Apply mitigation',phase:'Containment',role:'Sysadmin',sla:120,checklist:['Patch or apply the vendor workaround','Restrict access at the firewall','Enable virtual patching on WAF or IPS'],targets:['vuln:{cve}','flows:vuln:{cve}']},
    {id:'hunt',type:'action',title:'Hunt for compromise',phase:'Eradication',role:'L2 Analyst',sla:240,checklist:['Search the vendor IOCs','Review logs since disclosure','Look for web shells and new accounts'],targets:['vuln:{cve}','reach:vuln:{cve}']},
    {id:'comp',type:'decision',title:'Signs of compromise?',phase:'Eradication',role:'L2 Analyst',sla:30,targets:['vuln:{cve}'],effects:{Yes:['compromised','vuln:{cve}']}},
    {id:'major',type:'escalation',title:'Open a major incident',phase:'Eradication',role:'IR Lead',sla:30,checklist:['Start the intrusion or ransomware playbook','Preserve evidence'],targets:['business:affected','contacts:affected']},
    {id:'review',type:'action',title:'Post-incident review',phase:'Lessons learned',role:'IR Lead',sla:60,checklist:['Measure time to patch','Review asset inventory gaps'],targets:[]},
    {id:'end',type:'end',title:'Incident closed',phase:'Lessons learned',targets:[]}],
    edges:[['start','exposure'],['exposure','found'],['found','mitigate','Yes'],['found','doc','No'],['doc','end'],['mitigate','hunt'],['hunt','comp'],['comp','major','Yes'],['comp','review','No'],['major','review'],['review','end']]}
};
// Incidents a Muster server would hand over for this IS. Without a Muster server: examples built from the map.
function demoFeed(site,now){
  const out=[],A=site.assets,find=n=>A.find(a=>a.name===n);
  const fs=find('file-01')||A.filter(a=>/file/i.test(a.role||'')).sort((a,b)=>b.crit-a.crit)[0]||(site.risk&&site.risk.assets[0]&&site.byId[site.risk.assets[0].id]);
  if(fs){const ws=find('pc-acct-01')||A.find(a=>a.type==='workstation'&&site.flows.some(f=>f.src===a.id&&f.dst===fs.id));
    out.push({ref:'IR-2026-047',name:`Ransom note on ${fs.name}`,pb:'PB-001',mode:'live',severity:'Critical',assets:[fs.id].concat(ws?[ws.id]:[]),params:{},
      note:`Declared in Muster with ${ws?'two Strata assets':'one Strata asset'} attached: ${[fs].concat(ws?[ws]:[]).map(a=>a.name).join(' and ')}.`});}
  const kev=A.flatMap(a=>a.vulns.filter(v=>v.kev&&/^CVE-/.test(v.id)).map(v=>({a,v}))).sort((x,y)=>(y.a.exp==='internet')-(x.a.exp==='internet')||(y.v.epss||0)-(x.v.epss||0)||(y.v.cvss||0)-(x.v.cvss||0))[0];
  if(kev)out.push({ref:'IR-2026-048',name:`${kev.v.id} exploited in the wild`,pb:'PB-010',mode:'exercise',severity:'Critical',assets:[],params:{cve:kev.v.id},
    note:'Declared with one parameter, the CVE: Strata finds the assets that carry it.'});
  return out;
}

/* ---- Anonymised prompts for a public AI ---- */
const pad2=n=>String(n).padStart(2,'0');
function placeholders(site,id,opts){
  const map=new Map(),rev=[];
  const put=(real,ph,kind)=>{if(!map.has(real)){map.set(real,ph);rev.push({ph,real,kind});}return map.get(real);};
  put(id,'ASSET-T','asset');let n=1,sg=1,bz=1;
  const own=site.flows.filter(f=>f.src===id||f.dst===id);
  const neigh=[...new Set(own.map(f=>f.src===id?f.dst:f.src))].filter(x=>!isNet(x)&&site.byId[x]);
  const via=[...new Set(own.flatMap(f=>f.via||[]))].filter(x=>site.byId[x]&&!neigh.includes(x)&&x!==id);
  const r=reach(site,[id],2),crit=Object.keys(r).filter(x=>!neigh.includes(x)&&!via.includes(x)&&(site.byId[x].crit===3||(site.critIds||[]).includes(x)));
  [...neigh,...via,...crit].forEach(x=>put(x,'ASSET-'+pad2(n++),'asset'));
  return {map,rev,neigh,via,crit,
    seg:x=>{const v=site.vlanById[site.byId[x].vlan];return map.get('vlan:'+v.id)||put('vlan:'+v.id,'SEG-'+(sg++),'segment');},
    biz:b=>opts.biz?b.name:(map.get('biz:'+b.id)||put('biz:'+b.id,'SVC-B'+(bz++),'business')),
    ph:x=>isNet(x)?(x==='internet'?'Internet':`${(site.svcById[x]||{}).name||'Internet service'} (${(site.svcById[x]||{}).category||'Internet service'})`):map.get(x)};
}
const L={
  en:{type:'Type',role:'Role',sys:'System',apps:'Applications',crit:'Criticality',seg:'Network segment',zone:'zone',expo:'Exposure',vul:'Known vulnerabilities',none:'none recorded',in:'Inbound flows (who talks to it)',out:'Outbound flows (what it talks to)',biz:'Business services relying on it',neigh:'Neighbours mentioned above',reach:'Critical assets reachable within 2 hops',direct:'directly reachable from the Internet',hops:n=>`reachable from the Internet in ${n} hops along allowed flows`,unreach:'not reachable from the Internet along recorded flows',risky:'flagged risky',logs:'Sends logs to a SIEM',backup:'Backed up by',yes:'yes',no:'no recorded flow',via:'through',levels:['','low','medium','high'],ctx:'Context',
    defCtx:'Mid-size organisation, one site, an in-house IT team and an outsourced SOC.'},
  fr:{type:'Type',role:'Rôle',sys:'Système',apps:'Applications',crit:'Criticité',seg:'Segment réseau',zone:'zone',expo:'Exposition',vul:'Vulnérabilités connues',none:'aucune enregistrée',in:'Flux entrants (qui lui parle)',out:'Flux sortants (à qui il parle)',biz:'Services métier qui en dépendent',neigh:'Voisins cités ci-dessus',reach:'Actifs critiques atteignables en 2 sauts',direct:'directement joignable depuis Internet',hops:n=>`joignable depuis Internet en ${n} sauts via les flux autorisés`,unreach:'non joignable depuis Internet selon les flux connus',risky:'signalé à risque',logs:'Envoie ses journaux à un SIEM',backup:'Sauvegardé par',yes:'oui',no:'aucun flux enregistré',via:'via',levels:['','faible','moyenne','haute'],ctx:'Contexte',
    defCtx:'Organisation de taille moyenne, un site, une équipe informatique interne et un SOC externalisé.'}
};
const ver=(s,opts)=>opts.versions?String(s||''):String(s||'').replace(/(\d+)(\.\d+)+/g,'$1.x');
function assetBlock(site,id,P,opts){
  const a=site.byId[id],v=site.vlanById[a.vlan],T=L[opts.lang]||L.en,ty=x=>TYPE_LABEL[x]||x;
  const peer=x=>{if(isNet(x))return P.ph(x);const b=site.byId[x];return `${P.ph(x)} (${ty(b.type)}${b.role?', '+b.role:''}, ${P.seg(x)})`;};
  const thru=f=>(f.via||[]).length?` · ${T.via} ${f.via.map(x=>`${P.ph(x)} (${ty(site.byId[x].type)})`).join(' → ')}`:'';
  const fl=f=>`${f.src===id?peer(f.dst):peer(f.src)} · ${f.port} · ${f.vol} MB/h${thru(f)}${f.risk?` · ${T.risky}${f.note?': '+f.note:''}`:''}`;
  const vul=a.vulns.map(x=>{const cfg=!/^CVE-|^GHSA-/i.test(x.id);return `  - ${cfg?'Configuration':opts.cves?x.id:'Vulnerability'}: ${x.title}${x.cvss!=null?`, CVSS ${x.cvss}`:''}${x.epss!=null?`, EPSS ${Math.round(x.epss*100)}%`:''}${x.kev?', CISA KEV':''}`;});
  const siem=site.flows.some(f=>f.src===id&&site.byId[f.dst]&&/siem|log/i.test(site.byId[f.dst].role||''));
  const bk=site.flows.filter(f=>f.dst===id&&site.byId[f.src]&&/backup|sauvegarde/i.test(site.byId[f.src].role||'')).map(f=>P.ph(f.src));
  const bz=business(site,[id]),inn=site.flows.filter(f=>f.dst===id),out=site.flows.filter(f=>f.src===id),hops=site.expo[id];
  const direct=site.flows.some(f=>isNet(f.src)&&f.dst===id);
  const lines=[`## ASSET-T`,`- ${T.type}: ${ty(a.type)}`,`- ${T.role}: ${a.role||'—'}`,`- ${T.sys}: ${ver(a.os,opts)||'—'}`];
  if((a.apps||[]).length)lines.push(`- ${T.apps}: ${a.apps.map(x=>`${x.name}${x.version?' '+ver(x.version,opts):''}${x.ports.length?' ('+x.ports.join(', ')+')':''}`).join('; ')}`);
  lines.push(`- ${T.crit}: ${T.levels[a.crit]||'—'} (${a.crit}/3)`,`- ${T.seg}: ${P.seg(id)} "${v.name}", ${T.zone} "${v.zone}"`,
    `- ${T.expo}: ${direct?T.direct:hops!=null?T.hops(hops):T.unreach}`,
    `- ${T.biz}: ${bz.map(b=>`${P.biz(b)} (${T.crit.toLowerCase()} ${T.levels[b.crit]})`).join(', ')||T.none}`,
    `- ${T.logs}: ${siem?T.yes:T.no}`,`- ${T.backup}: ${bk.join(', ')||T.no}`,
    `- ${T.vul}:`,...(vul.length?vul:[`  - ${T.none}`]),
    `- ${T.in}:`,...(inn.length?inn.map(f=>'  - '+fl(f)):[`  - ${T.none}`]),
    `- ${T.out}:`,...(out.length?out.map(f=>'  - '+fl(f)):[`  - ${T.none}`]));
  if(opts.neigh){
    const nb=[...P.neigh,...P.via].map(x=>{const b=site.byId[x],k=b.vulns.filter(z=>z.kev||z.sev==='crit');
      return `  - ${P.ph(x)}: ${ty(b.type)}, ${ver(b.os,opts)||'—'}${k.length?' — '+k.map(z=>(opts.cves&&/^CVE-/i.test(z.id)?z.id+' ':'')+z.title+(z.kev?' (KEV)':'')).join('; '):''}`;});
    if(nb.length)lines.push(`- ${T.neigh}:`,...nb);
    if(P.crit.length)lines.push(`- ${T.reach}:`,...P.crit.map(x=>`  - ${P.ph(x)}: ${ty(site.byId[x].type)}, ${site.byId[x].role||''}`));
  }
  return lines.join('\n');
}
const FENCE='```';
const YAML_EXAMPLE=`schema: muster/v1
playbook: "Ransomware on ASSET-T"
id: PB-ASSET-T-01
category: "Malware"
steps:
  - id: start
    type: start
    title: "EDR alert: mass file renames on ASSET-T"
    phase: "Detection"
    next:
      - to: triage
  - id: triage
    type: action
    title: "Confirm encryption activity"
    phase: "Detection"
    owner: "L1 Analyst"
    sla_minutes: 15
    instructions: "Confirm before escalating; do not power off."
    checklist:
      - "Check the EDR process tree on ASSET-T"
      - "Count renamed files in the last 10 minutes"
    targets: ["id:ASSET-T", "contacts:id:ASSET-T"]
    next:
      - to: spread
  - id: spread
    type: decision
    title: "Spread beyond ASSET-T?"
    phase: "Containment"
    owner: "L2 Analyst"
    sla_minutes: 10
    targets: ["reach:id:ASSET-T"]
    next:
      - to: isolate_all
        when: "Yes"
      - to: isolate_one
        when: "No"
  # ... every path continues down to a step of type: end`;
function prompts(site,id,o){
  const opts=Object.assign({lang:'fr',versions:true,cves:true,biz:false,neigh:true,ctx:''},o||{});
  const fr=opts.lang==='fr',T=L[opts.lang]||L.en,P=placeholders(site,id,opts);
  const ctx=String(opts.ctx||'').trim()||T.defCtx,block=assetBlock(site,id,P,opts);
  const risk=fr?`Tu es architecte sécurité senior. Je te décris UN actif d'un système d'information, anonymisé : les noms, adresses et personnes sont remplacés par des repères (ASSET-T, ASSET-01, SEG-1…). Garde ces repères tels quels dans ta réponse.

## ${T.ctx}
${ctx}

${block}

## Ce que j'attends
1. Les 5 risques majeurs pour ASSET-T, en tableau : risque, scénario d'attaque (accès initial → impact), techniques MITRE ATT&CK, vraisemblance (1-4), impact (1-4), justification (cite les faits ci-dessus).
2. Pour les 3 premiers : mesures rapides (moins d'une semaine), mesures de fond, et signaux de détection (source de journaux + ce qu'il faut y chercher).
3. Les flux ci-dessus que tu restreindrais ou couperais en premier, et pourquoi.
4. Les questions à me poser pour affiner l'analyse.
N'invente pas de faits absents de la description ; signale chaque hypothèse.`
  :`You are a senior security architect. I am describing ONE asset of an information system, anonymised: names, addresses and people are replaced by placeholders (ASSET-T, ASSET-01, SEG-1…). Keep the placeholders as they are in your answer.

## ${T.ctx}
${ctx}

${block}

## What I need
1. The 5 major risks for ASSET-T, as a table: risk, attack scenario (initial access → impact), MITRE ATT&CK techniques, likelihood (1-4), impact (1-4), reasoning (cite the facts above).
2. For the top 3: quick mitigations (under a week), structural ones, and detection signals (log source + what to look for).
3. Which of the flows above you would restrict or cut first, and why.
4. The questions you would ask me to refine this.
Do not invent facts that are not in the description; flag every assumption.`;
  const sels='compromised, affected, id:ASSET-01, type:<type>, role:<text>, vuln:<CVE>, exposed:internet, reach:<selector>, consumers:<selector>, flows:<selector>, business:<selector>, contacts:<selector>';
  const rules=fr?`Règles du format (muster/v1) :
- phase, uniquement : Detection, Containment, Eradication, Recovery, Lessons learned
- type d'étape : start (une seule), action, decision, escalation, end (au moins une)
- chaque decision a au moins 2 entrées next, chacune avec un libellé when ("Yes" / "No" ou le choix)
- owner, uniquement : L1 Analyst, L2 Analyst, IR Lead, CISO, Sysadmin, Network team, DPO, Communications, Business owner
- sla_minutes : délai cible réaliste pour chaque action, décision et escalade
- checklist : 2 à 6 tâches concrètes et propres à cet actif (consoles, commandes, journaux à extraire), pas de conseils génériques
- targets : les actifs, flux, services ou contacts de la cartographie sur lesquels l'étape agit, avec ces sélecteurs : ${sels}
- titres, consignes et checklist en français ; clés et valeurs de phase, owner et type en anglais, comme ci-dessus
- garde les repères ; n'invente jamais de vrais noms`
  :`Format rules (muster/v1):
- phase, only: Detection, Containment, Eradication, Recovery, Lessons learned
- step type: start (exactly one), action, decision, escalation, end (at least one)
- every decision has 2 or more next entries, each with a when label ("Yes" / "No" or the choice)
- owner, only: L1 Analyst, L2 Analyst, IR Lead, CISO, Sysadmin, Network team, DPO, Communications, Business owner
- sla_minutes: a realistic target for every action, decision and escalation
- checklist: 2 to 6 concrete tasks specific to this asset (consoles, commands, logs to pull), no generic advice
- targets: the assets, flows, services or contacts of the map the step acts on, with these selectors: ${sels}
- keep the placeholders; never invent real names`;
  const play=fr?`Tu es responsable de la réponse à incident. À partir de la description anonymisée ci-dessous, conçois les playbooks de réponse aux incidents les plus plausibles sur cet actif. Garde les repères (ASSET-T, ASSET-01, SEG-1…) tels quels.

## ${T.ctx}
${ctx}

${block}

## Étape 1 — Incidents plausibles
Liste 3 à 5 incidents qui pourraient réellement toucher ASSET-T, classés par vraisemblance × impact. Pour chacun : nom, premier signal (qui le voit, dans quel outil), chemin d'attaque en 3 à 6 étapes avec les repères, techniques ATT&CK, impact métier, playbook générique le plus proche parmi PB-001 Ransomware, PB-002 Phishing, PB-003 Compte compromis, PB-005 Violation de données personnelles, PB-006 Malware sur un poste, PB-007 DDoS, PB-009 Menace interne, PB-010 Vulnérabilité critique exploitée, et ce que ce playbook générique rate pour cet actif.

## Étape 2 — Playbooks
Pour les 3 premiers incidents, écris un playbook chacun au format YAML muster/v1 ci-dessous, pour l'importer dans notre outil de réponse à incident. Un bloc YAML par playbook.

${rules}

Exemple (forme seulement) :
${FENCE}yaml
${YAML_EXAMPLE}
${FENCE}

## Étape 3 — Vérifications
Pour chaque playbook : les hypothèses à valider avec l'équipe, et un inject d'exercice sur table pour le tester (heure, signal, décision attendue).`
  :`You are an incident response lead. From the anonymised description below, design response playbooks for the incidents most plausible on this asset. Keep the placeholders (ASSET-T, ASSET-01, SEG-1…) as they are.

## ${T.ctx}
${ctx}

${block}

## Step 1 — Plausible incidents
List 3 to 5 incidents that could realistically hit ASSET-T, ranked by likelihood × impact. For each: name, first signal (who sees it, in which tool), attack path in 3 to 6 steps using the placeholders, ATT&CK techniques, business impact, the closest generic playbook among PB-001 Ransomware, PB-002 Phishing, PB-003 Compromised account, PB-005 Personal data breach, PB-006 Malware on an endpoint, PB-007 DDoS, PB-009 Insider threat, PB-010 Exploited critical vulnerability, and what that generic playbook misses for this asset.

## Step 2 — Playbooks
For the top 3 incidents, write one playbook each in the muster/v1 YAML format below, so it can be imported into our incident response tool. One YAML block per playbook.

${rules}

Example (shape only):
${FENCE}yaml
${YAML_EXAMPLE}
${FENCE}

## Step 3 — Checks
For each playbook: the assumptions to validate with the team, and one tabletop exercise inject to test it (time, signal, expected decision).`;
  return {P,risk,play};
}
// Strings that must never reach a public AI: names that identify (with a digit, dash, dot or underscore),
// addresses, subnets, phone numbers, e-mail addresses and their domains, people's names, the IS name, listed terms
function sensitive(site,never){
  const s=new Set(),add=x=>{x=String(x||'').trim();if(x.length>2)s.add(x);};
  const person=x=>/^[A-ZÀ-Ý][a-zà-ÿ'-]+(\s+[A-ZÀ-Ý][a-zà-ÿ'-]+)+$/.test(String(x||'').trim());
  const contact=c=>{add(c.phone);add(c.email);if(c.email&&c.email.includes('@'))add(c.email.split('@')[1]);if(person(c.name))add(c.name);};
  add(site.name);
  site.assets.forEach(a=>{if(/[\d._-]/.test(a.name))add(a.name);add(a.ip);(a.contacts||[]).forEach(contact);});
  site.vlans.forEach(v=>add(v.cidr));site.contacts.forEach(contact);
  site.business.forEach(b=>{if(person(b.owner))add(b.owner);});
  String(never||'').split(',').forEach(add);
  return [...s];
}
function leaks(site,text,never){const low=String(text).toLowerCase();return sensitive(site,never).filter(x=>low.includes(x.toLowerCase()));}
function reidentify(site,text,P){
  return String(text).replace(/\b(ASSET-T|ASSET-\d\d|SEG-\d+|SVC-B\d+)\b/g,ph=>{const r=P.rev.find(x=>x.ph===ph);if(!r)return ph;
    if(r.kind==='asset')return site.byId[r.real].name;
    if(r.kind==='segment'){const v=site.vlanById[r.real.slice(5)];return v?`VLAN ${v.num}`:ph;}
    const b=site.bizById[r.real.slice(4)];return b?b.name:ph;});
}
// A quick look at muster/v1 playbooks pasted back: how many, how many steps, unknown step types
function yamlCheck(text){
  const blocks=(String(text).match(/^\s*schema:\s*muster\/v1\s*$/gm)||[]).length;if(!blocks)return null;
  const types=[...String(text).matchAll(/^\s*type:\s*(\w+)/gm)].map(m=>m[1]);
  return {blocks,steps:types.length,bad:[...new Set(types.filter(t=>!['start','action','decision','escalation','end'].includes(t)))],targets:(String(text).match(/^\s*targets:/gm)||[]).length};
}

const api={STATES,empty,clean,marked,affected,reach,consumers,business,selectAssets,resolve,cutPoint,flowsToCut,callList,
  PLAYBOOKS,step,nextOf,start,effects,isMuster,advance,route,fromGraph,runOf,newAnswers,musterFor,idsOf,demoFeed,placeholders,prompts,sensitive,leaks,reidentify,yamlCheck};
root.StrataIncident=api;
})(typeof globalThis!=='undefined'?globalThis:this);

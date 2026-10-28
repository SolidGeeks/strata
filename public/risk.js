// SPDX-License-Identifier: AGPL-3.0-or-later
// Risk register: the threats that apply to an asset (its threat landscape), how likely and how serious each one is
// on this asset, where it sits in the risk matrix, and what the requirements of the chosen baselines take off.
// Pure functions over a compiled IS, no DOM: the page loads this file before app.js,
// and the tests run it in Node (tests/risk.test.mjs).
(function(root){
'use strict';

/* ---- Threat landscape: who attacks, and why (EBIOS RM, workshop 2) ----
   Couples of a risk origin and its target objective. Each IS says how relevant each couple is, 0 to 3
   (0: not retained). A threat linked to no retained couple is left out of the landscape. */
const ACTORS=[
  {id:'crime-gain',name:'Organised crime, for financial gain',origin:'Organised crime',objective:'Financial gain (ransom, fraud, resale of data)',relevance:3},
  {id:'amateur',name:'Amateur, for the challenge',origin:'Amateur / script kiddie',objective:'Challenge, recognition',relevance:2},
  {id:'activist',name:'Activist, to influence or disrupt',origin:'Ideological activist',objective:'Influence, disruption, defacement',relevance:1},
  {id:'state-spy',name:'State, for espionage',origin:'State or state-sponsored group',objective:'Espionage',relevance:1},
  {id:'state-prepo',name:'State, for strategic pre-positioning',origin:'State or state-sponsored group',objective:'Pre-positioning, sabotage',relevance:1},
  {id:'competitor',name:'Competitor, for economic intelligence',origin:'Competitor, specialised firm',objective:'Economic intelligence',relevance:1},
  {id:'insider',name:'Malicious insider, for revenge or gain',origin:'Employee, administrator',objective:'Revenge, gain, sabotage',relevance:2},
  {id:'supplier',name:'Supplier or partner, compromised or careless',origin:'Supplier, service provider, partner',objective:'None of its own: a way in for others',relevance:2}
];
// ENISA Threat Landscape prime threats: the family each threat is reported under
const ENISA=[
  {id:'ransomware',name:'Ransomware'},
  {id:'malware',name:'Malware'},
  {id:'social',name:'Social engineering'},
  {id:'data',name:'Threats against data'},
  {id:'dos',name:'Threats against availability: denial of service'},
  {id:'internet',name:'Threats against availability: Internet threats'},
  {id:'fimi',name:'Information manipulation and interference'},
  {id:'supply',name:'Supply chain attacks'}
];

/* ---- Threat catalogue ----
   when: every condition given must hold for the threat to apply to an asset
     types: asset types; exposure: lowest exposure (intra < inter < internet); critMin: lowest criticality
     (the asset's or that of a business service it would hit); ports: one of these exposed ports;
     kev: a vulnerability on the CISA KEV list; role / os: a pattern on the role or the system;
     outbound: a flow to the Internet or an Internet service; svcCat: a flow to an Internet service of these
     categories; any: true when any of the other conditions is enough (or instead of and)
   base: how common the threat is, 1 to 4; severity: how bad it is when it happens, 1 to 4
   vulns: true when the asset's vulnerabilities make it more likely
   attack: MITRE ATT&CK techniques (Enterprise, or ICS for T08xx); enisa: families; actors: who carries it out */
const WEB=['tcp/80','tcp/443','tcp/8080','tcp/8443','tcp/8000','tcp/8888'];
const ADMIN=['tcp/22','tcp/23','tcp/135','tcp/139','tcp/445','tcp/3389','tcp/5900','tcp/5985','tcp/5986'];
const REMOTE=['tcp/22','tcp/23','tcp/3389','tcp/5900','tcp/5985','tcp/5986'];
const THREATS=[
  {id:'exploit-public',name:'Exploitation of an Internet-facing service',desc:'An attacker exploits a flaw in a service published on the Internet to run code or get in.',
    when:{exposure:'internet'},base:3,severity:3,vulns:true,attack:['T1190'],enisa:['malware','ransomware'],actors:['crime-gain','amateur','state-spy','state-prepo']},
  {id:'remote-access',name:'Compromise of a remote access (VPN, RDP, SSH)',desc:'Stolen, guessed or bypassed credentials on a remote access give an attacker a session inside.',
    when:{any:true,types:['gateway'],ports:REMOTE,exposure:'internet'},base:4,severity:3,vulns:true,attack:['T1133','T1078','T1021'],enisa:['ransomware'],actors:['crime-gain','state-spy','amateur']},
  {id:'brute-force',name:'Password guessing on an exposed login',desc:'Password spraying or credential stuffing against a login reachable from the Internet.',
    when:{exposure:'internet',ports:[...REMOTE,...WEB,'tcp/25','tcp/587','tcp/993']},base:3,severity:2,attack:['T1110'],enisa:['malware'],actors:['crime-gain','amateur']},
  {id:'ransomware',name:'Ransomware: encryption and extortion',desc:'Data and systems are encrypted, often after being copied out, and a ransom is demanded.',
    when:{types:['server','db','workstation','hypervisor','dc']},base:3,severity:4,vulns:true,attack:['T1486','T1490','T1567'],enisa:['ransomware'],actors:['crime-gain']},
  {id:'hypervisor-mass',name:'Mass encryption through the hypervisor',desc:'Taking the virtualisation layer encrypts or stops every virtual machine at once.',
    when:{types:['hypervisor']},base:2,severity:4,vulns:true,attack:['T1486','T1529'],enisa:['ransomware'],actors:['crime-gain','state-prepo']},
  {id:'directory-takeover',name:'Takeover of the directory (domain admin)',desc:'An attacker reaches domain admin rights and controls every account and machine of the domain.',
    when:{types:['dc']},base:3,severity:4,vulns:true,attack:['T1003','T1558','T1484'],enisa:['ransomware','malware'],actors:['crime-gain','state-spy','state-prepo']},
  {id:'lateral-admin',name:'Lateral movement through administration protocols',desc:'From a foothold, an attacker reuses credentials over SMB, RDP, SSH or WinRM to reach this asset.',
    when:{exposure:'inter',ports:ADMIN},base:3,severity:3,attack:['T1021','T1550','T1570'],enisa:['ransomware','malware'],actors:['crime-gain','state-spy']},
  {id:'phishing',name:'Phishing and malicious attachments',desc:'A user opens a booby-trapped attachment or link, or gives away credentials.',
    when:{types:['workstation']},base:4,severity:2,vulns:true,attack:['T1566','T1204'],enisa:['social','malware'],actors:['crime-gain','state-spy','competitor']},
  {id:'bec',name:'Business email compromise and payment fraud',desc:'A mailbox is taken over or spoofed to divert payments or steal information.',
    when:{any:true,role:'mail|smtp|exchange|messag|accounting|finance|exec|payroll'},base:3,severity:3,attack:['T1534','T1114','T1566.002'],enisa:['social'],actors:['crime-gain']},
  {id:'web-app',name:'Attack on a web application (injection, access control)',desc:'Injection, broken access control or a vulnerable component in a web application exposes data or code execution.',
    when:{types:['server','db'],exposure:'inter',ports:WEB},base:3,severity:3,vulns:true,attack:['T1190','T1059'],enisa:['data','malware'],actors:['crime-gain','amateur','activist','competitor']},
  {id:'data-theft',name:'Theft of data',desc:'Sensitive data is copied out, for extortion, resale or intelligence.',
    when:{any:true,types:['db'],role:'file|data|erp|crm|hr|document|share|historian|backup'},base:3,severity:3,vulns:true,attack:['T1041','T1567','T1005'],enisa:['data','ransomware'],actors:['crime-gain','state-spy','competitor','insider']},
  {id:'data-exposure',name:'Data exposed by a misconfiguration',desc:'A database, share or bucket is left reachable without the right access control.',
    when:{types:['db','server'],exposure:'inter',ports:['tcp/445','tcp/2049','tcp/1433','tcp/3306','tcp/5432','tcp/1521','tcp/27017','tcp/6379','tcp/9200']},base:2,severity:3,attack:['T1530','T1213'],enisa:['data'],actors:['amateur','crime-gain','competitor']},
  {id:'ddos',name:'Denial of service of an Internet-facing service',desc:'A flood of traffic or requests makes a published service unavailable.',
    when:{exposure:'internet'},base:2,severity:2,attack:['T1498','T1499'],enisa:['dos'],actors:['activist','crime-gain','state-prepo']},
  {id:'internet-dependency',name:'Loss of an Internet dependency',desc:'An Internet service the asset relies on (SaaS, DNS, cloud, updates) fails or is cut.',
    when:{outbound:true,critMin:2},base:2,severity:2,attack:[],enisa:['internet'],actors:['supplier','state-prepo']},
  {id:'supply-chain',name:'Compromise through a supplier or its updates',desc:'A compromised vendor, update channel or software component brings the attacker in.',
    when:{svcCat:['Vendor cloud','Vendor support','OS updates','Antivirus / EDR','Partner']},base:2,severity:4,attack:['T1195','T1199'],enisa:['supply'],actors:['state-spy','state-prepo','crime-gain','supplier']},
  {id:'third-party-access',name:'Abuse of a third party’s access',desc:'A supplier or partner with access to the asset is compromised or misuses it.',
    when:{any:true,svcCat:['Vendor support','Partner'],role:'vendor|support|integrator|partner|remote'},base:2,severity:3,attack:['T1199','T1078'],enisa:['supply'],actors:['supplier','crime-gain','state-spy']},
  {id:'ot-manipulation',name:'Manipulation of an industrial process',desc:'An attacker changes set points, logic or commands of a controller or a supervision station.',
    when:{any:true,types:['plc'],role:'hmi|scada|supervision|plc|automate|historian|ot '},base:2,severity:4,vulns:true,attack:['T0831','T0836','T0855'],enisa:['malware'],actors:['state-prepo','activist','crime-gain']},
  {id:'it-ot-pivot',name:'Pivot from the office network to industrial systems',desc:'From the office network, an attacker reaches an industrial system through an allowed flow.',
    when:{types:['plc','workstation','server'],exposure:'inter',role:'hmi|scada|supervision|plc|automate|historian|ot '},base:2,severity:4,attack:['T0886','T0866','T1021'],enisa:['malware','ransomware'],actors:['state-prepo','crime-gain']},
  {id:'device-takeover',name:'Takeover of a connected device',desc:'A camera, printer, phone or other device is taken over to spy, pivot or join a botnet.',
    when:{types:['camera','iot','printer','phone']},base:3,severity:2,vulns:true,attack:['T1584.005','T1078.001'],enisa:['malware'],actors:['amateur','crime-gain','state-spy']},
  {id:'default-credentials',name:'Default or weak credentials',desc:'A device or service still accepts its factory password or a trivial one.',
    when:{any:true,types:['camera','iot','printer','phone','ap','plc'],vulnTitle:'default|weak password|telnet|without authentication|no authentication'},base:3,severity:3,attack:['T1078.001'],enisa:['malware'],actors:['amateur','crime-gain']},
  {id:'wifi-intrusion',name:'Intrusion through the Wi-Fi',desc:'A guessed or leaked Wi-Fi key, or a rogue access point, lets someone nearby onto the network.',
    when:{types:['ap']},base:2,severity:2,attack:['T1200','T1557'],enisa:['malware'],actors:['amateur','competitor']},
  {id:'insider-misuse',name:'Misuse by an insider or an administrator',desc:'Someone with legitimate access steals, alters or destroys what the asset holds.',
    when:{critMin:3},base:2,severity:3,attack:['T1078','T1485'],enisa:['data'],actors:['insider']},
  {id:'backup-destruction',name:'Destruction of backups',desc:'Backups are deleted or encrypted before the attack, so nothing can be restored.',
    when:{role:'backup|sauvegarde|veeam|restore'},base:3,severity:4,vulns:true,attack:['T1490','T1485'],enisa:['ransomware'],actors:['crime-gain']},
  {id:'detection-blinding',name:'Blinding of detection',desc:'Logs are erased or the security tools are stopped, so the attack goes unseen.',
    when:{role:'siem|log|edr|soc|monitor|wazuh|splunk|elastic'},base:2,severity:3,attack:['T1070','T1562'],enisa:['malware'],actors:['crime-gain','state-spy']},
  {id:'network-device',name:'Takeover of a network or security device',desc:'Taking a firewall, router, switch or VPN gateway opens every flow it filters.',
    when:{types:['firewall','gateway','router','switch']},base:2,severity:4,vulns:true,attack:['T1190','T1601','T1556'],enisa:['malware'],actors:['state-spy','state-prepo','crime-gain']},
  {id:'privilege-escalation',name:'Local privilege escalation',desc:'From a limited foothold, a local flaw gives administrator rights on the asset.',
    when:{vulnTitle:'privilege|escalation|pwnkit|dirty|sudo|kernel'},base:2,severity:3,vulns:true,attack:['T1068'],enisa:['malware'],actors:['crime-gain','state-spy','insider']},
  {id:'known-exploited',name:'Exploitation of a known exploited vulnerability',desc:'A flaw on the CISA list of known exploited vulnerabilities is used against the asset.',
    when:{kev:true},base:4,severity:3,vulns:true,attack:['T1190','T1203','T1210'],enisa:['malware','ransomware'],actors:['crime-gain','state-spy','state-prepo','amateur']},
  {id:'end-of-life',name:'Unsupported system',desc:'The system no longer gets security fixes, so every new flaw stays open.',
    when:{any:true,os:'windows (xp|7|vista|server 200[038])|centos [5-7]|debian [5-9]\\b|ubuntu 1[0-8]\\.|end of life|eol',role:'end of life|eol'},base:3,severity:3,attack:['T1190','T1210'],enisa:['malware'],actors:['crime-gain','amateur']},
  {id:'physical-access',name:'Theft or physical tampering',desc:'The device is stolen, or someone with physical access plugs in or boots from their own media.',
    when:{types:['workstation','phone','camera','iot']},base:2,severity:2,attack:['T1200','T1091'],enisa:['data'],actors:['insider','competitor','amateur']},
  {id:'defacement',name:'Defacement and information manipulation',desc:'A public site or channel is altered to spread false or hostile content.',
    when:{exposure:'internet',ports:WEB},base:2,severity:2,attack:['T1491'],enisa:['fimi'],actors:['activist','state-prepo']}
];

/* ---- Risk matrix ----
   likelihood and impact: the labels of each level, lowest first; edges: where each level starts, from 0 to 1
   (the first is 0); cells[l][i]: the risk level of each cell, an index in LEVELS; accept: the highest risk
   level that is acceptable without treatment; acceptByCrit: the same per criticality (1 to 3) of the asset or of the
   business services it would hit, where it differs. An asset can also set its own (asset.risk.accept). */
const LEVELS=['low','med','high','crit'];
const LEVEL_LBL={low:'Low',med:'Moderate',high:'High',crit:'Critical'};
function defaultMatrix(n=4,m=n){
  const L={3:['Unlikely','Likely','Very likely'],4:['Minimal','Significant','Strong','Maximal'],5:['Rare','Unlikely','Possible','Likely','Almost certain']};
  const I={3:['Limited','Serious','Critical'],4:['Minor','Significant','Serious','Critical'],5:['Negligible','Minor','Moderate','Major','Critical']};
  const edges=k=>Array.from({length:k},(_,x)=>Math.round(100*x/k)/100);
  const cells=Array.from({length:n},(_,l)=>Array.from({length:m},(_,i)=>{
    const s=(l+1)/n+(i+1)/m;return s>=1.75?3:s>=1.25?2:s>=0.9?1:0;}));
  return {likelihood:L[n]||L[4],impact:I[m]||I[4],lEdges:edges(n),iEdges:edges(m),cells,accept:1,acceptByCrit:{3:0}};
}
// A matrix read from the settings: anything missing or out of shape falls back on the default of its size
function cleanMatrix(x){
  const n=Math.min(5,Math.max(3,x&&Array.isArray(x.likelihood)?x.likelihood.length:4)),m=Math.min(5,Math.max(3,x&&Array.isArray(x.impact)?x.impact.length:4));
  const d=defaultMatrix(n,m);if(!x||typeof x!=='object')return d;
  const labels=(a,b)=>b.map((v,k)=>a&&typeof a[k]==='string'&&a[k].trim()?a[k].trim().slice(0,40):v);
  const edges=(a,b)=>Array.isArray(a)&&a.length===b.length&&a.every((v,k)=>isFinite(v)&&v>=0&&v<1&&(k===0?v===0:v>a[k-1]))?a.map(Number):b;
  const cells=Array.isArray(x.cells)&&x.cells.length===n&&x.cells.every(r=>Array.isArray(r)&&r.length===m&&r.every(c=>[0,1,2,3].includes(c)))?x.cells:d.cells;
  return {likelihood:labels(x.likelihood,d.likelihood),impact:labels(x.impact,d.impact),lEdges:edges(x.lEdges,d.lEdges),iEdges:edges(x.iEdges,d.iEdges),cells,
    accept:[0,1,2,3].includes(x.accept)?x.accept:d.accept,
    acceptByCrit:x.acceptByCrit===undefined?d.acceptByCrit:Object.fromEntries(Object.entries(x.acceptByCrit&&typeof x.acceptByCrit==='object'?x.acceptByCrit:{}).filter(([c,v])=>['1','2','3'].includes(c)&&[0,1,2,3].includes(v)))};
}
const levelOf=(v,edges)=>{let k=0;edges.forEach((e,j)=>{if(v>=e)k=j;});return k;};
// The highest level acceptable on an asset: its own, else that of its criticality, else that of the matrix
function acceptFor(M,a,bizCrit){
  const own=a&&a.risk&&a.risk.accept,crit=Math.max(+(a&&a.crit)||0,+bizCrit||0);
  if([0,1,2,3].includes(own))return {level:own,from:'asset'};
  if(M.acceptByCrit&&[0,1,2,3].includes(M.acceptByCrit[crit]))return {level:M.acceptByCrit[crit],from:'crit',crit};
  return {level:M.accept,from:'matrix'};
}
const cellOf=(M,p,i)=>{const l=levelOf(p,M.lEdges),k=levelOf(i,M.iEdges);return {l,i:k,level:LEVELS[M.cells[l][k]]};};

/* ---- Settings: the risk document shared by every IS ----
   {matrix, baselines: [enabled ids], threats: {custom: [...], disabled: [ids]}, custom: [custom baselines]} */
function settings(doc,builtinBaselines){
  const d=doc&&typeof doc==='object'?doc:{};
  const custom=(Array.isArray(d.custom)?d.custom:[]).filter(b=>b&&b.id&&b.name).map(b=>cleanBaseline(b,true));
  const ids=new Set([...(builtinBaselines||[]).map(b=>b.id),...custom.map(b=>b.id)]);
  const enabled=Array.isArray(d.baselines)?d.baselines.filter(id=>ids.has(id)):[...ids].filter(id=>id==='anssi'||custom.some(b=>b.id===id));
  const threats=d.threats&&typeof d.threats==='object'?d.threats:{};
  return {matrix:cleanMatrix(d.matrix),baselines:enabled,custom,
    customThreats:(Array.isArray(threats.custom)?threats.custom:[]).filter(t=>t&&t.id&&t.name).map(cleanThreat),
    disabled:new Set(Array.isArray(threats.disabled)?threats.disabled.filter(x=>typeof x==='string'):[])};
}
const clamp4=v=>Math.min(4,Math.max(1,Math.round(+v)||2));
function cleanThreat(t){
  const w=t.when&&typeof t.when==='object'?t.when:{};
  return {id:'custom:'+String(t.id).replace(/^custom:/,''),name:String(t.name).slice(0,120),desc:String(t.desc||'').slice(0,600),custom:true,
    when:w,base:clamp4(t.base),severity:clamp4(t.severity),vulns:!!t.vulns,
    attack:(Array.isArray(t.attack)?t.attack:[]).filter(x=>/^T\d{4}(\.\d{3})?$/.test(x)),enisa:(Array.isArray(t.enisa)?t.enisa:[]).filter(x=>ENISA.some(e=>e.id===x)),
    actors:(Array.isArray(t.actors)?t.actors:[]).filter(x=>ACTORS.some(a=>a.id===x))};
}
// A requirement reduces how likely a threat is (likelihood) or how bad it is when it happens (impact), by a share
function cleanBaseline(b,custom){
  return {id:(custom?'custom:':'')+String(b.id).replace(/^custom:/,''),name:String(b.name).slice(0,120),version:String(b.version||''),url:/^https?:\/\//.test(b.url||'')?b.url:'',
    license:String(b.license||''),custom:!!custom,
    requirements:(Array.isArray(b.requirements)?b.requirements:[]).filter(r=>r&&r.id&&r.title).map(r=>({id:String(r.id),ref:String(r.ref||r.id),title:String(r.title).slice(0,300),text:String(r.text||'').slice(0,2000),
      threats:(Array.isArray(r.threats)?r.threats:[]).map(x=>Array.isArray(x)?{id:String(x[0]),strength:Math.min(0.9,Math.max(0.05,+x[1]||0.3)),effect:x[2]==='impact'?'impact':'likelihood'}:null).filter(Boolean)}))};
}

/* ---- The landscape of one asset ---- */
const EXPO_RANK={none:0,intra:1,inter:2,internet:3};
const EXPO_F={internet:1,inter:0.7,intra:0.45,none:0.3};
const re=s=>{try{return new RegExp(s,'i');}catch(e){return null;}};
// Why a threat applies to an asset: the list of conditions met, or null when it does not apply
function matches(site,a,t,bizCrit,labels){
  const w=t.when||{},why=[],tests=[];
  const crit=Math.max(a.crit||0,bizCrit||0),flows=site.flows.filter(f=>f.src===a.id);
  if(w.types)tests.push(w.types.includes(a.type)&&String((labels&&labels[a.type])||a.type).toLowerCase());
  // with any, an exposure next to ports only says how exposed those ports must be
  if(w.exposure&&!(w.any&&w.ports))tests.push(EXPO_RANK[a.exp||'none']>=EXPO_RANK[w.exposure]&&`exposed (${a.exp})`);
  if(w.critMin)tests.push(crit>=w.critMin&&`criticality ${crit}`);
  if(w.ports){const p=(a.ports||[]).filter(x=>w.ports.includes(x.port)&&(!w.exposure||EXPO_RANK[x.level]>=EXPO_RANK[w.exposure])).map(x=>x.port);tests.push(p.length>0&&`listens on ${p.join(', ')}`);}
  if(w.kev){const k=(a.vulns||[]).filter(v=>v.kev).map(v=>v.id);tests.push(k.length>0&&`known exploited: ${k.join(', ')}`);}
  if(w.vulnTitle){const r=re(w.vulnTitle),k=r?(a.vulns||[]).filter(v=>r.test(`${v.id} ${v.title}`)).map(v=>v.title):[];tests.push(k.length>0&&`${k[0]}`);}
  if(w.role){const r=re(w.role);tests.push(!!r&&r.test(`${a.role||''} ${a.name||''}`)&&`role "${a.role||a.name}"`);}
  if(w.os){const r=re(w.os);tests.push(!!r&&r.test(a.os||'')&&`system ${a.os}`);}
  if(w.outbound)tests.push(flows.some(f=>f.dst==='internet'||String(f.dst).startsWith('svc:'))&&'talks to the Internet');
  if(w.svcCat){const c=flows.map(f=>(site.svcById||{})[f.dst]).filter(s=>s&&w.svcCat.includes(s.category)).map(s=>s.name);tests.push(c.length>0&&`uses ${c.join(', ')}`);}
  if(!tests.length)return null;
  const ok=w.any?tests.some(Boolean):tests.every(Boolean);
  if(!ok)return null;
  tests.filter(Boolean).forEach(x=>why.push(x));
  return why;
}
// Combined likelihood that one of the asset's vulnerabilities gets exploited, as for the risk score
const vulnP=v=>{const sev=v.cvss!=null&&isFinite(v.cvss)?Math.min(10,Math.max(0,+v.cvss))/10:({crit:0.95,high:0.8,med:0.5,low:0.2}[v.sev]||0);
  const lik=v.kev?1:v.epss!=null&&isFinite(v.epss)?0.15+0.85*Math.sqrt(Math.max(0,Math.min(1,+v.epss))):0.3;return sev*lik;};
const CRIT_F=[0.5,0.5,0.75,1];
// Every threat of the catalogue that applies to an asset, scored before and after its requirements
// opts: {settings, baselines (built-in), landscape (the IS's relevance per actor), hops, bizCrit, labels (asset type names)}
function assess(site,a,opts){
  const S=opts.settings,M=S.matrix,actors=Object.assign({},...ACTORS.map(x=>({[x.id]:x.relevance})),(opts.landscape&&opts.landscape.actors)||{});
  const catalogue=[...THREATS,...S.customThreats].filter(t=>!S.disabled.has(t.id));
  const treat=(a.risk&&typeof a.risk==='object')?a.risk:{};
  const excluded=new Set(Array.isArray(treat.excluded)?treat.excluded:[]),added=new Set(Array.isArray(treat.added)?treat.added:[]);
  const reqs=requirementsFor(S,opts.baselines),accept=acceptFor(M,a,opts.bizCrit).level;
  const vuln=1-(a.vulns||[]).reduce((p,v)=>p*(1-vulnP(v)),1);
  const exposure=EXPO_F[a.exp||'none'],hops=opts.hops,reach=hops===undefined||hops===null?0.3:Math.max(0.5,1-0.1*Math.max(0,hops-1));
  const crit=Math.max(CRIT_F[a.crit]||0.75,CRIT_F[opts.bizCrit||0]||0);
  const out=[];
  catalogue.forEach(t=>{
    let why=matches(site,a,t,opts.bizCrit,opts.labels);
    if(added.has(t.id)&&!why)why=['added by hand'];
    if(!why)return;
    const rel=Math.max(0,...t.actors.map(x=>+actors[x]||0));
    const ctx=(exposure+reach)/2,vf=t.vulns?0.5+0.5*vuln:1,af=t.actors.length?[0,0.5,0.75,1][Math.min(3,rel)]:1;
    const p0=Math.min(1,(t.base/4)*(0.4+0.6*ctx)*vf*af),i0=Math.min(1,(t.severity/4)*crit);
    const st=(treat.threats&&treat.threats[t.id])||{},statuses=st.reqs||{};
    const linked=reqs.filter(r=>r.threats.some(x=>x.id===t.id)).map(r=>{const m=r.threats.find(x=>x.id===t.id);return Object.assign({},r,{strength:m.strength,effect:m.effect,status:statuses[r.key]||''});});
    const left=(st,field)=>linked.filter(r=>r.effect===field&&st.includes(r.status)).reduce((x,r)=>x*(1-r.strength),1);
    const p1=p0*left(['applied'],'likelihood'),i1=i0*left(['applied'],'impact');
    const p2=p0*left(['applied','planned'],'likelihood'),i2=i0*left(['applied','planned'],'impact');
    const inherent=cellOf(M,p0,i0),residual=cellOf(M,p1,i1),target=cellOf(M,p2,i2);
    const decision=['treat','accept','transfer','avoid'].includes(st.decision)?st.decision:'treat';
    out.push({threat:t,why,excluded:excluded.has(t.id),relevance:rel,factors:{base:t.base,context:ctx,vuln:t.vulns?vuln:null,actors:af,severity:t.severity,crit},
      p:p0,i:i0,inherent,residual,target,pResidual:p1,iResidual:i1,requirements:linked,decision,note:String(st.note||''),
      acceptable:LEVELS.indexOf(residual.level)<=accept||decision==='accept'});
  });
  return out.sort((x,y)=>(x.excluded-y.excluded)||LEVELS.indexOf(y.residual.level)-LEVELS.indexOf(x.residual.level)||y.pResidual*y.iResidual-x.pResidual*x.iResidual||x.threat.name.localeCompare(y.threat.name));
}
// The requirements of the enabled baselines, each with a key unique across baselines
function requirementsFor(S,builtin){
  const all=[...(builtin||[]).map(b=>cleanBaseline(b,false)),...S.custom];
  return all.filter(b=>S.baselines.includes(b.id)).flatMap(b=>b.requirements.map(r=>Object.assign({},r,{key:`${b.id}/${r.id}`,baseline:b.id,baselineName:b.name})));
}
// The treatment of one threat on an asset, changed: what is written back into the asset document
function setTreatment(asset,threatId,change){
  const r=JSON.parse(JSON.stringify(asset.risk||{}));r.threats=r.threats||{};
  const t=r.threats[threatId]=Object.assign({},r.threats[threatId]||{});
  if(change.req){t.reqs=Object.assign({},t.reqs||{});if(change.status)t.reqs[change.req]=change.status;else delete t.reqs[change.req];}
  if(change.decision!==undefined)t.decision=change.decision;
  if(change.note!==undefined)t.note=String(change.note).slice(0,2000);
  if(change.exclude!==undefined){const s=new Set(r.excluded||[]);change.exclude?s.add(threatId):s.delete(threatId);r.excluded=[...s];}
  if(change.add!==undefined){const s=new Set(r.added||[]);change.add?s.add(threatId):s.delete(threatId);r.added=[...s];}
  if(t.reqs&&!Object.keys(t.reqs).length)delete t.reqs;
  if(t.decision==='treat')delete t.decision;
  if(!t.note)delete t.note;
  if(!Object.keys(t).length)delete r.threats[threatId];
  if(!Object.keys(r.threats).length)delete r.threats;
  if(r.excluded&&!r.excluded.length)delete r.excluded;
  if(r.added&&!r.added.length)delete r.added;
  return Object.keys(r).length?r:undefined;
}
// The acceptance threshold of one asset, changed (null: back to that of its criticality)
function setAccept(asset,level){
  const r=JSON.parse(JSON.stringify(asset.risk||{}));
  if([0,1,2,3].includes(level))r.accept=level;else delete r.accept;
  return Object.keys(r).length?r:undefined;
}
// The register of an IS: every asset's risks, counted per cell of the matrix
function register(site,opts){
  const rows=[];
  site.assets.forEach(a=>assess(site,a,Object.assign({},opts,{hops:site.expo[a.id],bizCrit:(site.bizCrit||{})[a.id]})).forEach(r=>{if(!r.excluded)rows.push(Object.assign({asset:a},r));}));
  const M=opts.settings.matrix,grid=k=>M.cells.map(row=>row.map(()=>0));
  const inherent=grid(),residual=grid();
  rows.forEach(r=>{inherent[r.inherent.l][r.inherent.i]++;residual[r.residual.l][r.residual.i]++;});
  return {rows,inherent,residual};
}

const api={ACTORS,ENISA,THREATS,LEVELS,LEVEL_LBL,defaultMatrix,cleanMatrix,cellOf,acceptFor,setAccept,settings,cleanThreat,cleanBaseline,matches,assess,requirementsFor,setTreatment,register};
root.StrataRisk=api;
})(typeof globalThis!=='undefined'?globalThis:this);

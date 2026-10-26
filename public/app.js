// SPDX-License-Identifier: AGPL-3.0-or-later
(function(){
'use strict';
// The 3D libraries are copied into public/vendor by "npm run setup" or the Docker build
if(typeof THREE==='undefined'||!THREE.OrbitControls){
  document.body.innerHTML='<main style="max-width:560px;margin:15vh auto;padding:0 16px;font:15px/1.5 system-ui,sans-serif"><h1 style="font-size:22px">Strata cannot start</h1><p>The 3D library is missing from <code>public/vendor</code>. Run <code>npm run setup</code>, or rebuild the container with <code>docker compose up -d --build</code>, while the machine can reach the npm registry.</p></main>';
  return;
}
/* ================= Reference data ================= */
const SEV={crit:{rank:4,label:'Critical',css:'--crit'},high:{rank:3,label:'High',css:'--high'},med:{rank:2,label:'Medium',css:'--med'},low:{rank:1,label:'Low',css:'--low'},none:{rank:0,label:'None',css:'--none'}};
const SEV_KEYS=['none','low','med','high','crit'];
// Exposure of a port: where the inbound traffic comes from
const EXP={internet:{rank:3,label:'Internet',css:'--x-net'},inter:{rank:2,label:'Inter-VLAN',css:'--x-inter'},intra:{rank:1,label:'Intra-VLAN',css:'--x-intra'},none:{rank:0,label:'Not exposed',css:'--none'}};
const EXP_BY_RANK=['none','intra','inter','internet'];
const css=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const sevColor=k=>css(SEV[k].css);
const expColor=k=>css(EXP[k].css);
const sevFromCvss=s=>s>=9?'crit':s>=7?'high':s>=4?'med':s>0?'low':'none';
// Demo only: EPSS (approximate, rounded) and presence on the CISA KEV list of the CVEs the demo uses
const DEMO_EPSS={'CVE-2024-21762':0.93,'CVE-2024-21887':0.97,'CVE-2023-46805':0.96,'CVE-2020-1472':0.94,'CVE-2021-44228':0.97,'CVE-2021-34527':0.94,'CVE-2023-20198':0.93,'CVE-2021-21972':0.97,'CVE-2019-0708':0.97,'CVE-2023-23397':0.92,'CVE-2021-4034':0.86,'CVE-2022-26134':0.97,'CVE-2022-0847':0.62,'CVE-2024-3400':0.96,'CVE-2021-41773':0.97,'CVE-2021-21974':0.91,'CVE-2023-44487':0.82,'CVE-2024-6387':0.33,'CVE-2023-48795':0.6,'CVE-2023-51764':0.04};
const DEMO_KEV=new Set(['CVE-2024-21762','CVE-2024-21887','CVE-2023-46805','CVE-2020-1472','CVE-2021-44228','CVE-2021-34527','CVE-2023-20198','CVE-2021-21972','CVE-2019-0708','CVE-2023-23397','CVE-2021-4034','CVE-2022-26134','CVE-2022-0847','CVE-2024-3400','CVE-2021-41773','CVE-2021-21974','CVE-2023-44487']);
const F=(id,title,cvss,sev)=>Object.assign({id,title,cvss:cvss==null?null:cvss,sev:sev||sevFromCvss(cvss)},DEMO_EPSS[id]!=null?{epss:DEMO_EPSS[id],kev:DEMO_KEV.has(id)}:{});
const TYPE_LABEL={server:'Server',dc:'Domain controller',db:'Database',hypervisor:'Hypervisor / storage',firewall:'Firewall',gateway:'VPN gateway',router:'Router / L3 core',switch:'Switch / load balancer',workstation:'Workstation',printer:'Printer',phone:'IP phone',ap:'Wi-Fi access point',camera:'IP camera',plc:'PLC',iot:'IoT device'};
// Interconnection equipment: flows can be routed through these
const INTERCO=new Set(['firewall','router','switch','gateway']);
const SA=StrataAnalysis;
// Colours of the "Per flow" mode: --f0 to --f9 in app.css
const FLOW_PAL=10;
// Internet endpoints: the Internet as a whole, or a named service (ESET updates, Ubuntu mirrors…) as "svc:<id>"
const isNet=id=>id==='internet'||String(id).startsWith('svc:');
const SVC_CATS=['Antivirus / EDR','OS updates','SaaS','DNS / NTP','Vendor cloud','Vendor support','Partner','Other'];
const CONTACT_ROLES=['Technical owner','On-call','Business owner','Vendor / support','CISO','Other'];
const ROLE_LEGACY={'Responsable technique':'Technical owner','Astreinte':'On-call','Responsable métier':'Business owner','Prestataire / support':'Vendor / support','RSSI':'CISO','Autre':'Other'};
const roleEn=r=>ROLE_LEGACY[r]||r||'';
const CRIT_LBL=['','Low','Medium','High'];
const CRIT_CSS=['','--low','--med','--crit'];
const RISK_LBL={crit:'Critical',high:'High',med:'Medium',low:'Low',none:'None'};
const riskTag=r=>r?`<span class="tag" style="color:var(${SEV[r.band].css})"><i style="background:var(${SEV[r.band].css})"></i>${r.score} · ${RISK_LBL[r.band]}</span>`:tag('none');
const vulnChips=v=>`${v.kev?'<span class="kev" title="On the CISA list of known exploited vulnerabilities">KEV</span>':''}${v.epss!=null?`<span class="epss" title="EPSS: probability of exploitation in the next 30 days">EPSS ${Math.round(v.epss*100)}%</span>`:''}`;
const critTag=c=>`<span class="tag" style="color:var(${CRIT_CSS[c]||'--none'})"><i style="background:var(${CRIT_CSS[c]||'--none'})"></i>${CRIT_LBL[c]||'—'}</span>`;
const $=s=>document.querySelector(s);
// HTML escaping, one character at a time (a form code scanners recognise as escaping)
const esc=s=>String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const uid=p=>p+Date.now().toString(36)+Math.random().toString(36).slice(2,7);
const clone=o=>JSON.parse(JSON.stringify(o));
const pad=n=>String(n).padStart(2,'0');
const plural=(n,w)=>`${n} ${w}${n===1?'':'s'}`;

/* ================= Demo data set ================= */
const TEL=n=>`+33 1 99 00 ${pad(10+n%80)} ${pad(10+(n*7)%80)}`;
function teamOf(a){
  const p=a.pfx||'',t=a.type;
  if(['fw','sw','vpn','lb','ap'].includes(p)||['firewall','gateway','switch','ap'].includes(t))return ['Network team','network'];
  if(['plc','ihm','rf'].includes(p)||['plc','camera','iot'].includes(t))return ['Plant maintenance','maintenance'];
  if(['pc','imp','tel'].includes(p)||['workstation','printer','phone'].includes(t))return ['Service desk','servicedesk'];
  if(['app','web','rp','mx','pp','db','ipbx'].includes(p)||t==='db')return ['Application team','apps'];
  return ['Infrastructure team','infra'];
}
function demoContacts(a,code,n){
  const [team,mail]=teamOf(a);
  const c=[{name:team,role:'Technical owner',phone:TEL(n),email:`${mail}.${code}@example.com`,dispo:'Business hours'}];
  if(a.crit===3)c.push({name:'Operations on-call',role:'On-call',phone:TEL(n+40),email:`oncall.${code}@example.com`,dispo:'24/7'});
  return c;
}
// Applications running on an asset, guessed from its system and role (demo data only)
function demoApps(a){
  const os=a.os||'',role=(a.role||'').toLowerCase(),t=a.type,A=(name,version,ports)=>({name,version,ports});
  const out=[];
  if(/Nginx/.test(os))out.push(A('Nginx','1.22','tcp/443, tcp/8443'),A('Customer portal (PHP-FPM)','8.1',''));
  if(/Apache/.test(os))out.push(A('Apache httpd','2.4.57','tcp/443, tcp/8443'));
  if(/HAProxy/.test(os))out.push(A('HAProxy','2.8','tcp/443'));
  if(/Postfix/.test(os))out.push(A('Postfix','3.5','tcp/25'));
  if(/Java/.test(os)&&/erp/.test(role))out.push(A('Apache Tomcat','9.0.54','tcp/8080, tcp/443'),A('ERP suite','6.2',''),A('Log4j (library)','2.14.1',''));
  else if(/Java/.test(os))out.push(A('Apache Tomcat','10.1','tcp/8080, tcp/443'));
  if(/IIS/.test(os))out.push(A('IIS','10','tcp/443, tcp/8080'));
  if(/PostgreSQL/.test(os))out.push(A('PostgreSQL',(os.match(/PostgreSQL (\d+)/)||[,'15'])[1],'tcp/5432'));
  if(/SQL Server/.test(os))out.push(A('SQL Server','2019','tcp/1433, tcp/5432'));
  if(/Confluence/.test(os))out.push(A('Confluence','7.13','tcp/443'));
  if(/Veeam/.test(os))out.push(A('Veeam Backup & Replication','12','tcp/9392'));
  if(/Wazuh/.test(os))out.push(A('Wazuh manager','4.7','udp/514, tcp/1514'),A('OpenSearch','2.8',''));
  if(/Zabbix/.test(os))out.push(A('Zabbix server','6.4','tcp/10051, tcp/443'));
  if(/rsync/.test(os))out.push(A('rsync daemon','3.2','tcp/873'));
  if(/Asterisk/.test(os))out.push(A('Asterisk','20','udp/5060'));
  if(/OpenSSH/.test(os))out.push(A('OpenSSH','9.2','tcp/22'));
  if(/vCenter/.test(os))out.push(A('vCenter Server','6.7','tcp/443'));
  if(/ESXi/.test(os))out.push(A('ESXi host client',(os.match(/ESXi ([\d.]+)/)||[,'7.0'])[1],'tcp/443, tcp/22'));
  if(/ONTAP/.test(os))out.push(A('iSCSI target','ONTAP 9.12','tcp/3260'));
  if(/FortiOS|PAN-OS|Stormshield/.test(os))out.push(A('Firewall engine',os.replace(/^\D+/,''),''),A('Admin web UI','','tcp/443'));
  if(/Ivanti/.test(os))out.push(A('Ivanti Connect Secure','22.3','tcp/443'));
  if(/IOS XE|Aruba CX/.test(os))out.push(A('Management (SSH, web UI)','','tcp/22, tcp/443'));
  if(/BIG-IP/.test(os))out.push(A('BIG-IP LTM','16.1','tcp/443'));
  if(t==='dc')out.push(A('Active Directory DS',/2022/.test(os)?'2022':'2019','tcp/389, tcp/636'),A('Kerberos KDC','','tcp/88'),A('DNS server','','udp/53'));
  if(/file/.test(role))out.push(A('SMB file shares','3.1.1','tcp/445'),A('Print Spooler','',''));
  if(/jump host|rdp/i.test(role))out.push(A('Remote Desktop Services','','tcp/3389'));
  if(t==='workstation'&&/Windows 1/.test(os))out.push(A('Microsoft 365 Apps','2308',''),A('Microsoft Defender','',''));
  if(/Outlook 2016/.test(os))out.push(A('Outlook','2016',''));
  if(t==='workstation'&&/Ubuntu/.test(os))out.push(A('Docker Engine','24',''),A('VS Code','1.84',''));
  if(t==='workstation'&&/macOS/.test(os))out.push(A('Microsoft Office','16.78',''));
  if(t==='workstation'&&/Windows 7|LTSC/.test(os))out.push(A('SCADA HMI runtime','7.5','tcp/3389'));
  if(/historian/.test(role))out.push(A('Process historian','2018','tcp/5450'));
  if(t==='printer')out.push(A('Embedded web admin','','tcp/80'),A('JetDirect','','tcp/9100'));
  if(t==='plc')out.push(A(/Siemens/.test(os)?'S7 runtime':'Modbus/TCP server','',/Siemens/.test(os)?'tcp/102':'tcp/502'));
  if(t==='camera')out.push(A('RTSP video stream','','tcp/554'),A('Embedded web admin','','tcp/80'));
  if(t==='phone')out.push(A('SIP user agent','','udp/5060'));
  if(t==='iot'&&/Android/.test(os))out.push(A('WMS mobile client','4.2',''));
  if(t==='iot'&&/Linux/.test(os))out.push(A('Access control daemon','','tcp/23'));
  return out;
}
const LYON={
  zones:[['Industrial',[[50,'OT production','10.50.0.0/24'],[55,'Physical security','10.55.0.0/24']]],['Office',[[30,'User workstations','10.30.0.0/23'],[32,'Guest Wi-Fi','10.32.0.0/24'],[33,'IP telephony','10.33.0.0/24'],[35,'Printing','10.35.0.0/24']]],['Core IT',[[40,'Administration','10.40.0.0/24'],[20,'Servers','10.20.0.0/24'],[45,'Backup','10.45.0.0/24']]],['Exposed',[[10,'DMZ','10.10.10.0/24']]]],
  assets:[
    ['fw-edge','firewall',10,'10.10.10.1','FortiOS 7.2.4','Perimeter firewall',3,[F('CVE-2024-21762','SSL VPN out-of-bounds write (RCE)',9.8)]],
    ['vpn-gw','gateway',10,'10.10.10.20','Ivanti Connect Secure 22.3','Remote-access VPN',3,[F('CVE-2024-21887','Command injection',9.1),F('CVE-2023-46805','Authentication bypass',8.2)]],
    ['rproxy','server',10,'10.10.10.30','Debian 12 · HAProxy 2.8','Reverse proxy',2,[]],
    ['web-01','server',10,'10.10.10.11','Ubuntu 22.04 · Nginx','Customer portal',2,[F('CVE-2023-44487','HTTP/2 Rapid Reset (denial of service)',7.5)]],
    ['web-02','server',10,'10.10.10.12','Ubuntu 22.04 · Nginx','Customer portal',2,[]],
    ['mail-relay','server',10,'10.10.10.25','Debian 11 · Postfix','SMTP relay',1,[F('CVE-2023-51764','SMTP smuggling',5.3)]],
    ['dc-01','dc',20,'10.20.0.10','Windows Server 2019','Domain controller',3,[F('CVE-2020-1472','Zerologon (privilege escalation)',10)]],
    ['dc-02','dc',20,'10.20.0.11','Windows Server 2022','Domain controller',3,[]],
    ['app-erp','server',20,'10.20.0.20','RHEL 8 · Java 11','ERP application',3,[F('CVE-2021-44228','Log4Shell (RCE)',10)]],
    ['db-erp','db',20,'10.20.0.21','RHEL 8 · PostgreSQL 14','ERP database',3,[F('CVE-2022-0847','Dirty Pipe (local privilege escalation)',7.8)]],
    ['wiki','server',20,'10.20.0.30','Ubuntu 20.04 · Confluence 7.13','Internal wiki',1,[F('CVE-2022-26134','OGNL injection (RCE)',9.8)]],
    ['file-01','server',20,'10.20.0.40','Windows Server 2016','File server',2,[F('CVE-2021-34527','PrintNightmare',8.8),F('Config.','SMBv1 enabled',null,'med')]],
    ['backup-01','server',45,'10.45.0.50','Windows Server 2022 · Veeam','Backup server',3,[]],
    ['core-sw','switch',40,'10.40.0.2','Cisco IOS XE 17.6','Core switch',3,[F('CVE-2023-20198','Web UI privilege escalation',10)]],
    ['fw-int','firewall',40,'10.40.0.1','FortiOS 7.4.3','Internal firewall (core segmentation)',3,[]],
    ['bastion','server',40,'10.40.0.10','Debian 12 · OpenSSH 9.2','Admin bastion',3,[F('CVE-2024-6387','regreSSHion (RCE)',8.1)]],
    ['jump-win','server',40,'10.40.0.11','Windows Server 2008 R2','RDP jump host (end of life)',2,[F('CVE-2019-0708','BlueKeep (RDP RCE)',9.8)]],
    ['vcenter','hypervisor',40,'10.40.0.20','vCenter Server 6.7','Virtualisation',3,[F('CVE-2021-21972','File upload (RCE)',9.8)]],
    ['siem','server',40,'10.40.0.30','Ubuntu 22.04 · Wazuh 4.7','SIEM',2,[]],
    ['pc-acct-01','workstation',30,'10.30.0.21','Windows 10 22H2 · Outlook 2016','Accounting workstation',1,[F('CVE-2023-23397','Outlook NTLM hash leak',9.8)]],
    ['pc-hr-02','workstation',30,'10.30.0.34','Windows 11 23H2','HR workstation',1,[]],
    ['pc-dev-07','workstation',30,'10.30.1.7','Ubuntu 22.04','Developer workstation',1,[F('CVE-2021-4034','PwnKit (local privilege escalation)',7.8)]],
    ['pc-exec-01','workstation',30,'10.30.0.5','macOS 14','Executive workstation',2,[]],
    ['ap-lobby','ap',32,'10.32.0.11','Aruba AP-515 · 8.10','Lobby access point',1,[F('Config.','Shared WPA2 key never rotated',null,'med')]],
    ['ap-plant','ap',32,'10.32.0.12','Aruba AP-515 · 8.10','Plant access point',1,[]],
    ['ipbx','server',33,'10.33.0.5','Debian 12 · Asterisk 20','IP PBX',2,[]],
    ['tel-lobby','phone',33,'10.33.0.21','Yealink T54W','Lobby phone',1,[F('Config.','Web interface over HTTP',null,'low')]],
    ['tel-acct','phone',33,'10.33.0.22','Yealink T54W','Accounting phone',1,[]],
    ['printer-02','printer',35,'10.35.0.200','Firmware 2019','Multifunction printer',1,[F('Config.','Default admin password',null,'crit'),F('Config.','Telnet exposed',null,'high')]],
    ['plc-l1','plc',50,'10.50.0.10','Siemens S7-1200 · fw 4.2','Line 1 PLC',3,[F('Config.','S7 protocol without authentication',null,'crit')]],
    ['hmi-01','workstation',50,'10.50.0.20','Windows 7 SP1','Supervision HMI',3,[F('CVE-2019-0708','BlueKeep (RDP RCE)',9.8)]],
    ['historian','server',50,'10.50.0.30','Windows Server 2016','Historian',2,[F('CVE-2021-34527','PrintNightmare',8.8)]],
    ['cam-04','camera',55,'10.55.0.104','Firmware 5.1 (2018)','Plant IP camera',1,[F('Config.','Outdated firmware',null,'med'),F('Config.','TLS 1.0 enabled',null,'low')]],
    ['badge-ctrl','iot',55,'10.55.0.120','Embedded Linux','Badge access controller',2,[F('Config.','Telnet exposed',null,'high')]]
  ],
  business:[
    ['Customer portal',3,'E-commerce manager',['rproxy','web-01','web-02']],
    ['ERP & accounting',3,'Finance director',['app-erp','db-erp']],
    ['Production line 1',3,'Plant manager',['plc-l1','hmi-01','historian']],
    ['Email',2,'IT manager',['mail-relay']],
    ['Remote access',2,'IT manager',['vpn-gw']],
    ['Telephony',1,'Facilities manager',['ipbx']],
    ['Internal wiki',1,'Knowledge manager',['wiki']]
  ],
  flows:[
    ['internet','fw-edge','tcp/443',820],['internet','vpn-gw','tcp/443',140],['internet','mail-relay','tcp/25',60],
    ['fw-edge','rproxy','tcp/443',780],['rproxy','web-01','tcp/8443',390],['rproxy','web-02','tcp/8443',380],
    ['web-01','app-erp','tcp/8080',210],['web-02','app-erp','tcp/8080',205],['app-erp','db-erp','tcp/5432',960],
    ['vpn-gw','dc-01','tcp/389',30],['vpn-gw','bastion','tcp/22',25],
    ['bastion','core-sw','tcp/22',4],['bastion','vcenter','tcp/443',18],['bastion','db-erp','tcp/5432',12],
    ['jump-win','dc-01','tcp/3389',9],['jump-win','file-01','tcp/445',40],
    ['dc-01','siem','udp/514',75],['fw-edge','siem','udp/514',160],['core-sw','siem','udp/514',22],['app-erp','siem','udp/514',48],
    ['backup-01','file-01','tcp/445',1400],['backup-01','db-erp','tcp/5432',900],['backup-01','vcenter','tcp/443',300],
    ['pc-acct-01','file-01','tcp/445',55],['pc-acct-01','app-erp','tcp/443',35],['pc-acct-01','dc-01','tcp/88',3],
    ['pc-hr-02','file-01','tcp/445',28],['pc-hr-02','dc-02','tcp/88',3],['pc-exec-01','wiki','tcp/443',8],['pc-dev-07','wiki','tcp/443',14],
    ['pc-acct-01','printer-02','tcp/9100',6],['pc-hr-02','pc-acct-01','tcp/445',2,true,'Workstation-to-workstation SMB inside the user VLAN'],
    ['tel-lobby','ipbx','udp/5060',10],['tel-acct','ipbx','udp/5060',9],['ap-lobby','fw-edge','tcp/443',70],['ap-plant','fw-edge','tcp/443',45],
    ['pc-dev-07','db-erp','tcp/5432',45,true,'User workstation connecting straight to the ERP database'],
    ['pc-dev-07','hmi-01','tcp/3389',5,true,'RDP from IT to OT without the bastion'],
    ['hmi-01','plc-l1','tcp/102',12],['historian','plc-l1','tcp/102',20],
    ['historian','db-erp','tcp/5432',15,true,'Direct IT/OT bridge, no industrial DMZ'],
    ['cam-04','svc:svc-lyo-camcloud','tcp/443',90,true,'OT device calling the Internet (vendor cloud)'],
    ['siem','svc:svc-ubuntu','tcp/443',30],['web-01','svc:svc-ubuntu','tcp/443',12],['bastion','svc:svc-ubuntu','tcp/80',6],
    ['pc-acct-01','svc:svc-eset','tcp/443',4],['pc-hr-02','svc:svc-eset','tcp/443',4],['file-01','svc:svc-wu','tcp/443',80],
    ['dc-01','svc:svc-ntp','udp/123',1],['pc-acct-01','svc:svc-m365','tcp/443',40],['pc-exec-01','svc:svc-m365','tcp/443',25],
    ['badge-ctrl','dc-01','tcp/389',2,true,'Cleartext LDAP from the physical security VLAN'],
    ['internet','jump-win','tcp/3389',3,true,'RDP published to the Internet']
  ]
};
function rngOf(seed){return function(){seed|=0;seed=seed+0x6D2B79F5|0;let t=Math.imul(seed^seed>>>15,1|seed);t=t+Math.imul(t^t>>>7,61|t)^t;return((t^t>>>14)>>>0)/4294967296;};}
const POOL={
  winsrv:[['CVE-2021-34527','PrintNightmare',8.8],['Config.','SMBv1 enabled',null,'med'],['Config.','SMB signing not required',null,'med']],
  dc:[['CVE-2020-1472','Zerologon (privilege escalation)',10],['Config.','LDAP signing not required',null,'med']],
  linux:[['CVE-2024-6387','regreSSHion (RCE)',8.1],['CVE-2021-4034','PwnKit (local privilege escalation)',7.8],['CVE-2023-48795','Terrapin (SSH)',5.9]],
  web:[['CVE-2021-44228','Log4Shell (RCE)',10],['CVE-2023-44487','HTTP/2 Rapid Reset (denial of service)',7.5],['CVE-2021-41773','Apache path traversal',7.5]],
  fortinet:[['CVE-2024-21762','SSL VPN out-of-bounds write (RCE)',9.8]],
  panos:[['CVE-2024-3400','GlobalProtect command injection',10]],
  fw:[['Config.','Management interface exposed',null,'high']],
  vpn:[['CVE-2024-21887','Command injection',9.1],['CVE-2023-46805','Authentication bypass',8.2]],
  db:[['Config.','Default account enabled',null,'high'],['Config.','Unencrypted connections',null,'med']],
  iosxe:[['CVE-2023-20198','Web UI privilege escalation',10]],
  sw:[['Config.','SNMP v2c with default community',null,'med']],
  esxi:[['CVE-2021-21974','OpenSLP heap overflow (RCE)',8.8],['Config.','SSH permanently enabled',null,'low']],
  ws:[['CVE-2023-23397','Outlook NTLM hash leak',9.8],['Config.','Antivirus out of date',null,'med'],['Config.','BitLocker disabled',null,'low']],
  ap:[['Config.','Shared WPA2 key never rotated',null,'med'],['Config.','Outdated firmware',null,'med']],
  phone:[['Config.','Default admin password',null,'crit'],['Config.','Web interface over HTTP',null,'low']],
  printer:[['Config.','Default admin password',null,'crit'],['Config.','Telnet exposed',null,'high']],
  plc:[['Config.','Modbus without authentication',null,'crit']],
  rf:[['Config.','Android without security patches',null,'high']],
  sto:[['Config.','NFSv3 without Kerberos',null,'med']]
};
const OSMAP={
  fw:[['FortiOS 7.2.4',['fortinet','fw']],['PAN-OS 11.1.0',['panos','fw']],['Stormshield SNS 4.7',['fw']]],
  vpn:[['Ivanti Connect Secure 22.3',['vpn']]],
  web:[['Ubuntu 22.04 · Nginx',['linux','web']],['Debian 12 · Apache 2.4',['linux','web']]],
  rp:[['Debian 12 · HAProxy 2.8',['linux']]], mx:[['Debian 12 · Postfix',['linux']]],
  dc:[['Windows Server 2019',['dc','winsrv']],['Windows Server 2022',['dc']]],
  app:[['RHEL 8 · Java 11',['linux','web']],['Windows Server 2019 · IIS',['winsrv']]],
  fs:[['Windows Server 2016',['winsrv']],['Windows Server 2022',['winsrv']]],
  db:[['RHEL 8 · PostgreSQL 15',['db','linux']],['Windows Server 2019 · SQL Server 2019',['db','winsrv']]],
  sw:[['Cisco IOS XE 17.6',['iosxe','sw']],['Aruba CX 10.12',['sw']]],
  bast:[['Debian 12 · OpenSSH 9.2',['linux']]], hv:[['VMware ESXi 7.0',['esxi']],['VMware ESXi 8.0',['esxi']]],
  bkp:[['Windows Server 2022 · Veeam',['winsrv']]], pc:[['Windows 11 23H2',['ws']],['Windows 10 22H2',['ws']]],
  ap:[['Aruba AP-515 · 8.10',['ap']]], tel:[['Yealink T54W',['phone']]], ipbx:[['Debian 12 · Asterisk 20',['linux']]],
  imp:[['Firmware 2020',['printer']]], plc:[['Schneider M580 · fw 4.1',['plc']]], ihm:[['Windows 10 LTSC',['ws']]],
  rf:[['Zebra TC52 · Android 11',['rf']]], lb:[['F5 BIG-IP 16.1',['fw']]], pp:[['RHEL 8 · Java 17',['linux','web']]],
  sup:[['Ubuntu 22.04 · Zabbix 6.4',['linux']]], sto:[['NetApp ONTAP 9.12',['sto']]], rep:[['RHEL 9 · rsync',['linux']]]
};
const CRIT3=new Set(['dc','db','fw','bkp','hv','sw','sto','lb','vpn','plc']),CRIT1=new Set(['pc','ap','tel','imp','rf']);
const OFFICE=[
  ['Office',[[30,'User workstations',[['workstation','pc',[4,5],'User workstation']]],[32,'Guest Wi-Fi',[['ap','ap',[2,3],'Wi-Fi access point']]],[33,'IP telephony',[['phone','tel',[2,3],'IP phone'],['server','ipbx',1,'IP PBX']]],[35,'Printing',[['printer','imp',[1,2],'Multifunction printer']]]]],
  ['Core IT',[[20,'Servers',[['dc','dc',2,'Domain controller'],['server','app',[1,2],'Application server'],['server','fs',1,'File server']]],[21,'Databases',[['db','db',[1,2],'Database']]],[40,'Administration',[['switch','sw',1,'Core switch'],['server','bast',1,'Admin bastion'],['hypervisor','hv',[1,2],'Hypervisor']]],[45,'Backup',[['server','bkp',1,'Backup server']]]]],
  ['Exposed',[[10,'Web DMZ',[['firewall','fw',1,'Perimeter firewall'],['server','rp',1,'Reverse proxy'],['server','web',[1,2],'Web server']]],[11,'Access DMZ',[['gateway','vpn',1,'VPN gateway'],['server','mx',1,'SMTP relay']]]]]
];
const WAREHOUSE=[
  ['Industrial',[[50,'Conveyor PLCs',[['plc','plc',[2,3],'Conveyor PLC'],['workstation','ihm',1,'Conveyor HMI']]],[55,'RF handhelds',[['iot','rf',[2,3],'RF handheld']]]]],
  ['Office',[[30,'User workstations',[['workstation','pc',[2,3],'User workstation']]],[32,'Guest Wi-Fi',[['ap','ap',[1,2],'Wi-Fi access point']]],[35,'Printing',[['printer','imp',1,'Multifunction printer']]]]],
  ['Core IT',[[20,'Servers',[['dc','dc',1,'Domain controller'],['server','app',1,'WMS server'],['server','fs',1,'File server']]],[21,'WMS database',[['db','db',1,'WMS database']]],[40,'Administration',[['switch','sw',1,'Core switch'],['hypervisor','hv',1,'Hypervisor'],['server','bkp',1,'Backup server']]]]],
  ['Exposed',[[10,'DMZ',[['firewall','fw',1,'Perimeter firewall']]],[11,'VPN access',[['gateway','vpn',1,'VPN gateway']]]]]
];
const DATACENTER=[
  ['Data',[[45,'Backup',[['server','bkp',[2,3],'Backup server']]],[46,'Storage',[['hypervisor','sto',2,'Storage array']]],[47,'Replication',[['server','rep',[1,2],'Inter-site replication']]]]],
  ['Infrastructure',[[40,'Administration',[['switch','sw',[1,2],'Core switch'],['server','bast',1,'Admin bastion'],['hypervisor','hv',[2,3],'Hypervisor']]],[41,'Monitoring',[['server','sup',[1,2],'Monitoring']]]]],
  ['Production',[[20,'Applications',[['server','app',[3,4],'Application server'],['dc','dc',2,'Domain controller']]],[21,'Databases',[['db','db',[2,3],'Database']]],[22,'Pre-production',[['server','pp',[2,3],'Pre-production server']]]]],
  ['Exposed',[[10,'Hosting DMZ',[['firewall','fw',[1,2],'Perimeter firewall'],['server','web',[2,3],'Web server']]],[11,'Load balancing',[['switch','lb',[1,2],'Load balancer']]]]]
];
const RULES=[
  ['internet','fw','tcp/443',800],['internet','vpn','tcp/443',120],['internet','mx','tcp/25',50],
  ['fw','rp','tcp/443',700],['fw','lb','tcp/443',900],['rp','web','tcp/8443',350],['lb','web','tcp/8443',600],
  ['web','app','tcp/8080',200],['app','db','tcp/5432',800],['pp','app','tcp/8080',40],
  ['vpn','dc','tcp/389',30],['vpn','bast','tcp/22',20],['vpn','fs','tcp/445',60],
  ['pc','fs','tcp/445',40],['pc','dc','tcp/88',3],['pc','app','tcp/443',25],['pc','imp','tcp/9100',5],
  ['tel','ipbx','udp/5060',12],['ap','fw','tcp/443',60],
  ['bast','sw','tcp/22',3],['bast','hv','tcp/443',15],['bast','db','tcp/5432',10],
  ['sup','app','tcp/443',20],['sup','sw','udp/161',4],['sup','hv','tcp/443',6],
  ['bkp','fs','tcp/445',1200],['bkp','db','tcp/5432',800],['bkp','hv','tcp/443',300],['bkp','sto','tcp/3260',900],
  ['rep','sto','tcp/3260',1500],['app','sto','tcp/3260',600],
  ['ihm','plc','tcp/502',10],['rf','app','tcp/443',30],
  ['pc','svc:svc-eset','tcp/443',4],['pc','svc:svc-wu','tcp/443',20],['web','svc:svc-ubuntu','tcp/443',10],['dc','svc:svc-ntp','udp/123',1]
];
const RISKY=[
  ['pc','db','tcp/5432',30,'User workstation connecting straight to a database'],
  ['ap','fs','tcp/445',6,'Guest Wi-Fi reaching an internal server'],
  ['tel','dc','tcp/389',2,'Cleartext LDAP from the telephony VLAN'],
  ['rf','internet','tcp/443',40,'RF handhelds calling the Internet without a proxy'],
  ['pc','plc','tcp/502',4,'Office workstation driving a PLC'],
  ['pp','db','tcp/5432',25,'Pre-production reaching the production database'],
  ['web','db','tcp/5432',60,'Exposed server connecting straight to a database'],
  ['pc','hv','tcp/443',3,'User workstation on a hypervisor management UI'],
  ['internet','bast','tcp/22',4,'SSH bastion published to the Internet']
];
// Business services of the generated IS: [name, criticality, owner, asset prefixes]
const BIZ_TPL={
  office:[['Customer portal',3,'E-commerce manager',['rp','web']],['ERP & accounting',3,'Finance director',['app','db']],['Email',2,'IT manager',['mx']],['Telephony',1,'Facilities manager',['ipbx']],['Remote access',2,'IT manager',['vpn']]],
  warehouse:[['Warehouse management (WMS)',3,'Logistics director',['app','db','rf']],['Conveyor line',3,'Plant manager',['plc','ihm']],['Remote access',2,'IT manager',['vpn']]],
  datacenter:[['Hosted applications',3,'Hosting service manager',['lb','web','app','db']],['Backup & recovery',3,'Infrastructure manager',['bkp','sto','rep']],['Monitoring',2,'Operations manager',['sup']]]
};
// Builds the demo in storage format: {si:{id:doc}, assets:{id:doc}, wan:[...]}
function buildDemo(){
  const out={si:{},assets:{},wan:[]};let n=0;
  const site=(id,code,name,kind,order,zonesSpec,assets,flows)=>{
    const zones=[],vlans=[];
    zonesSpec.forEach(([zname,vl])=>{const zid=`z-${code}-${zones.length}`;zones.push({id:zid,name:zname});vl.forEach(v=>vlans.push({id:`v-${code}-${v.num}`,num:v.num,name:v.name,cidr:v.cidr,zone:zid}));});
    out.si[id]={name,kind,order,zones,vlans,flows,contacts:[
      {name:'SOC',role:'On-call',phone:TEL(order*3),email:'soc@example.com',dispo:'24/7'},
      {name:`IT manager, ${name}`,role:'Technical owner',phone:TEL(order*3+1),email:`it.${code}@example.com`,dispo:'Business hours'},
      {name:'Group CISO',role:'CISO',phone:TEL(77),email:'ciso@example.com',dispo:'Business hours'}]};
    assets.forEach(a=>{out.assets[a.id]=Object.assign(a,{site:id,contacts:demoContacts(a,code,n++),apps:demoApps(a)});});
  };
  site('lyon','lyo','Lyon','HQ & plant',2,LYON.zones.map(([z,vl])=>[z,vl.map(([num,name,cidr])=>({num,name,cidr}))]),
    LYON.assets.map(([name,type,vnum,ip,os,role,crit,vulns])=>({id:'lyo-'+name,name,type,vlan:`v-lyo-${vnum}`,ip,os,role,crit,vulns,notes:''})),
    LYON.flows.map(([s,d,port,vol,risk,note],i)=>({id:'f-lyo-'+i,src:isNet(s)?s:'lyo-'+s,dst:isNet(d)?d:'lyo-'+d,port,vol,risk:!!risk,note:note||''})));
  out.si.lyon.business=LYON.business.map(([name,crit,owner,ids],i)=>({id:'b-lyo-'+i,name,crit,owner,notes:'',assets:ids.map(x=>'lyo-'+x)}));
  [['paris','par','Paris','Head office',OFFICE,0.32,11,17,1],['dcw','dcw','West Datacenter','Hosting',DATACENTER,0.38,51,20,3],['nantes','nte','Nantes','Logistics warehouse',WAREHOUSE,0.75,23,18,4],['bordeaux','bdx','Bordeaux','Sales branch',OFFICE,0.55,37,19,5,true]]
  .forEach(([id,code,name,kind,tpl,hyg,seed,net,order,small])=>{
    const rng=rngOf(seed),pick=a=>a[Math.floor(rng()*a.length)],cnt=c=>Array.isArray(c)?c[0]+Math.floor(rng()*(c[1]-c[0]+1)):c;
    const assets=[],seq={};
    const zs=tpl.map(([zname,vl])=>[zname,vl.map(([num,vname,gens])=>{
      let host=10;
      gens.forEach(([type,pfx,count,role])=>{
        const k=Math.max(1,cnt(count)-(small&&Array.isArray(count)?1:0));
        for(let i=0;i<k;i++){
          seq[pfx]=(seq[pfx]||0)+1;
          const [os,fams]=pick(OSMAP[pfx]),pool=[].concat(...fams.map(f=>POOL[f]||[])).filter(v=>!(v[0]==='CVE-2020-1472'&&os.includes('2022')));
          const vulns=[];
          if(pool.length&&rng()<hyg){vulns.push(F(...pick(pool)));if(rng()<hyg*0.4){const v=pick(pool);if(!vulns.some(x=>x.title===v[1]))vulns.push(F(...v));}}
          const nm=`${code}-${pfx}-${pad(seq[pfx])}`;
          assets.push({id:nm,name:nm,pfx,type,vlan:`v-${code}-${num}`,ip:`172.${net}.${num}.${host++}`,os,role,crit:CRIT3.has(pfx)?3:CRIT1.has(pfx)?1:2,vulns,notes:''});
        }
      });
      return {num,name:vname,cidr:`172.${net}.${num}.0/24`};
    })]);
    const by=p=>isNet(p)?[p]:assets.filter(a=>a.pfx===p).map(a=>a.id);
    const flows=[];let fi=0;
    RULES.forEach(([s,d,port,vol])=>{const S=by(s),Dd=by(d);if(!S.length||!Dd.length)return;
      S.slice(0,3).forEach((src,i)=>flows.push({id:`f-${code}-${fi++}`,src,dst:Dd[i%Dd.length],port,vol:Math.max(1,Math.round(vol*(0.6+rng()*0.8))),risk:false,note:''}));});
    RISKY.forEach(([s,d,port,vol,note])=>{const S=by(s),Dd=by(d);if(!S.length||!Dd.length||rng()>hyg)return;
      flows.push({id:`f-${code}-${fi++}`,src:pick(S),dst:pick(Dd),port,vol,risk:true,note});});
    site(id,code,name,kind,order,zs,assets,flows);
    out.si[id].business=BIZ_TPL[tpl===WAREHOUSE?'warehouse':tpl===DATACENTER?'datacenter':'office']
      .map(([bname,crit,owner,pfx])=>({name:bname,crit,owner,notes:'',assets:assets.filter(a=>pfx.includes(a.pfx)).map(a=>a.id)}))
      .filter(b=>b.assets.length).map((b,i)=>Object.assign({id:`b-${code}-${i}`},b));
    assets.forEach(a=>delete a.pfx);
  });
  // Internet services shared by every IS, and one that only Lyon uses
  out.services=[
    {id:'svc-eset',name:'ESET update servers',category:'Antivirus / EDR',hosts:['update.eset.com','*.eset.com'],ports:['tcp/443','tcp/80'],notes:'Signature and module updates for ESET endpoint protection'},
    {id:'svc-ubuntu',name:'Ubuntu repositories',category:'OS updates',hosts:['archive.ubuntu.com','security.ubuntu.com'],ports:['tcp/80','tcp/443'],notes:'APT mirrors for Linux servers'},
    {id:'svc-wu',name:'Microsoft Update',category:'OS updates',hosts:['*.windowsupdate.com','*.update.microsoft.com'],ports:['tcp/443','tcp/80'],notes:'Windows and Office patches'},
    {id:'svc-ntp',name:'NTP pool',category:'DNS / NTP',hosts:['pool.ntp.org'],ports:['udp/123'],notes:'Time synchronisation of the domain controllers'},
    {id:'svc-m365',name:'Microsoft 365',category:'SaaS',hosts:['outlook.office365.com','*.sharepoint.com'],ports:['tcp/443'],notes:'Mail and documents'}];
  out.si.lyon.services=[{id:'svc-lyo-camcloud',name:'Camera vendor cloud',category:'Vendor cloud',hosts:['api.camvendor.example'],ports:['tcp/443'],notes:'Remote viewing service of the IP camera vendor'}];
  out.wan=[['paris','dcw','MPLS',4200],['lyon','dcw','MPLS',2600],['nantes','dcw','MPLS',900],['bordeaux','dcw','IPsec',650],['paris','lyon','IPsec',800],
    ['nantes','lyon','IPsec IKEv1',120,true,'IKEv1 tunnel with a weak pre-shared key'],['bordeaux','paris','Direct link',60,true,'Unfiltered interconnection between the two IS']]
    .map(([a,b,tech,vol,risk,note],i)=>({id:'w-'+i,a,b,tech,vol,risk:!!risk,note:note||''}));
  return out;
}

/* ================= Storage =================
   'api'   : served by the Strata server (shared data, live updates over SSE)
   'local' : page opened on its own; data kept in this browser only */
let raw={si:{},assets:{},wan:[],services:[]};
const LS_KEY='is-map-v1'; // kept from the IS Map days, so maps saved in the browser are still found
// The live map, then what is shown: the live map, a draft applied over it, a proposal under review,
// or an older version (read-only)
let liveRaw=raw;
function overlay(base,ch){
  const o={si:Object.assign({},base.si),assets:Object.assign({},base.assets),wan:base.wan,services:base.services};
  if(!ch)return o;
  ['si','assets'].forEach(k=>Object.entries(ch[k]||{}).forEach(([id,doc])=>{if(doc==null)delete o[k][id];else o[k][id]=doc;}));
  if(ch.wan)o.wan=ch.wan;if(ch.services)o.services=ch.services;
  return o;
}
const Store={
  mode:'local',loaded:false,bulk:false,rev:0,user:'',role:'admin',me:null,features:{},
  view:null,          // null (live) | 'draft' | 'review' | 'preview'
  prop:null,          // the proposal being edited or reviewed
  preview:null,       // {rev, at, user, raw}
  batch:null,
  get liveWrite(){return this.mode==='local'||!!(this.me&&this.me.canWrite);},
  get canWrite(){return this.view==='draft'?true:this.view?false:this.liveWrite;},
  async init(){
    let me=null;
    try{const r=await fetch('api/me',{cache:'no-store',credentials:'same-origin'});if(r.ok)me=await r.json();}catch(e){}
    if(me){
      this.mode='api';this.me=me;this.user=me.user||'';this.role=me.role||'admin';
      this.features={history:true,proposals:true,accounts:!!me.auth};
      if(me.sourceUrl){const l=document.getElementById('srcLink');if(l)l.href=me.sourceUrl;}
      await this.pull();this.listen();return;
    }
    this.mode='local';
    try{const s=localStorage.getItem(LS_KEY);if(s){const o=JSON.parse(s);liveRaw={si:o.si||{},assets:o.assets||{},wan:o.wan||[],services:o.services||[]};}}catch(e){}
    this.loaded=true;this.applyView();
  },
  applyView(delay){
    raw=this.view==='preview'&&this.preview?this.preview.raw:(this.view==='draft'||this.view==='review')&&this.prop?overlay(liveRaw,this.prop.changes):liveRaw;
    computeDiff();scheduleData(delay);if(this.view)renderModeBar();
  },
  async pull(){
    try{
      const r=await fetch('api/state',{cache:'no-store',credentials:'same-origin'});
      if(!r.ok)throw new Error('HTTP '+r.status);
      const s=await r.json();
      liveRaw={si:s.si||{},assets:s.assets||{},wan:Array.isArray(s.wan)?s.wan:[],services:Array.isArray(s.services)?s.services:[]};this.rev=s.rev||0;
      this.loaded=true;this.applyView(this.bulk?null:0);
    }catch(e){toast('Could not read the saved data. Check that the server is running, then reload.',true);}
  },
  // Live updates: the server sends the new revision after every change, and a note when proposals move
  listen(){
    if(!window.EventSource)return;
    const es=new EventSource('api/events');
    es.addEventListener('change',e=>{try{const {rev}=JSON.parse(e.data);if(rev!==this.rev&&!this.bulk)this.pull();}catch(err){}});
    es.addEventListener('proposals',()=>{onProposalsChanged();});
    es.addEventListener('connectors',()=>{onConnectorsChanged();});
    let first=true;es.addEventListener('open',()=>{if(!first)this.pull();first=false;});
  },
  async api(method,url,body){
    const h={'content-type':'application/json','x-requested-with':'strata'};
    if(this.batch){h['x-batch']=this.batch.id;h['x-batch-label']=encodeURIComponent(this.batch.label);}
    const r=await fetch(url,{method,credentials:'same-origin',headers:h,body:body===undefined?undefined:JSON.stringify(body)});
    let j=null;try{j=await r.json();}catch(e){}
    if(!r.ok){const err=new Error((j&&j.error)||('HTTP '+r.status));err.status=r.status;err.body=j;throw err;}
    if(j&&j.rev)this.rev=j.rev;
    return j;
  },
  saveLocal(){try{localStorage.setItem(LS_KEY,JSON.stringify(liveRaw));}catch(e){toast('This browser refused to save the data (storage full or disabled).',true);}},
  // kind: si | assets | wan | services ; value null = delete
  async write(kind,id,value){
    if(this.view==='preview'||this.view==='review'){toast(this.view==='preview'?'You are looking at an older version: it is read-only.':'A proposal under review is read-only.',true);throw new Error('readonly');}
    if(this.view==='draft')return this.writeDraft(kind,id,value);
    if(!this.liveWrite){toast(this.features.proposals?'Your role cannot change the map directly: start a proposal (Proposals › New).':'You have read-only access.',true);throw new Error('readonly');}
    const local=()=>{
      if(kind==='si'||kind==='assets'){liveRaw[kind]=Object.assign({},liveRaw[kind]);if(value==null)delete liveRaw[kind][id];else liveRaw[kind][id]=clone(value);}
      else liveRaw[kind]=clone(value||[]);
    };
    if(this.mode==='local'){local();this.saveLocal();this.applyView(0);return;}
    const url=kind==='wan'?'api/wan':kind==='services'?'api/services':`api/${kind}/${encodeURIComponent(id)}`;
    try{
      if(value==null&&(kind==='si'||kind==='assets'))await this.api('DELETE',url);
      else await this.api('PUT',url,kind==='wan'?{links:value}:kind==='services'?{services:value}:value);
      local();this.applyView(this.bulk?null:0);
    }catch(e){
      if(e.status===403)toast(e.message||'You cannot change this.',true);
      else if(e.status===413)toast('This item is too large to save.',true);
      else toast('Could not save: '+(e.message||'error')+'.',true);
      throw e;
    }
  },
  // In a draft, changes go to the proposal (saved on the server a moment later), never to the live map
  writeDraft(kind,id,value){
    const ch=this.prop.changes;ch.si=ch.si||{};ch.assets=ch.assets||{};
    if(kind==='si'||kind==='assets'){
      // a document brought back to its live state leaves the change set
      if(JSON.stringify(liveRaw[kind][id]??null)===JSON.stringify(value??null))delete ch[kind][id];else ch[kind][id]=value==null?null:clone(value);
    }else{if(JSON.stringify(liveRaw[kind]||[])===JSON.stringify(value||[]))delete ch[kind];else ch[kind]=clone(value||[]);}
    this.applyView(this.bulk?null:0);
    clearTimeout(this._dt);this._dt=setTimeout(()=>this.saveDraft(),this.bulk?900:350);
    return Promise.resolve();
  },
  async saveDraft(){
    if(this.view!=='draft'||!this.prop)return;
    try{const j=await this.api('PUT','api/proposals/'+encodeURIComponent(this.prop.id),{changes:this.prop.changes});this.prop.base=j.proposal.base;this.prop.updatedAt=j.proposal.updatedAt;renderModeBar();}
    catch(e){toast('The draft could not be saved: '+(e.message||'error')+'.',true);}
  },
  putSite(id,d){return this.write('si',id,d);},
  delSite(id){return this.write('si',id,null);},
  putAsset(id,d){return this.write('assets',id,d);},
  delAsset(id){return this.write('assets',id,null);},
  putWan(links){return this.write('wan',null,links);},
  putServices(list){return this.write('services',null,list);},
  async many(tasks,label){
    this.bulk=true;this.batch={id:'b'+Date.now().toString(36)+Math.random().toString(36).slice(2,6),label};let done=0;const total=tasks.length;
    toast(`${label}: 0 / ${total}`,false,true);
    try{for(const t of tasks){await t();done++;if(done%5===0||done===total)toast(`${label}: ${done} / ${total}`,false,true);}toast(`${label}: done.`);}
    catch(e){toast(`${label} stopped after ${done} items.`,true);}
    finally{this.bulk=false;this.batch=null;this.applyView(0);if(this.view==='draft'){clearTimeout(this._dt);this.saveDraft();}}
  }
};
// Replace the whole map (demo, import, delete everything) in one request
async function replaceAll(data,label){
  const next={si:clone(data.si||{}),assets:clone(data.assets||{}),wan:clone(data.wan||[]),services:clone(data.services||[])};
  if(Store.view){toast('Leave the draft, review or older version first.',true);return;}
  if(!Store.liveWrite){toast('You cannot replace the map with your role.',true);return;}
  if(Store.mode==='local'){liveRaw=next;Store.saveLocal();Store.applyView(0);toast(`${label}: done.`);return;}
  toast(`${label}…`,false,true);
  Store.batch={id:'imp'+Date.now().toString(36),label};
  try{await Store.api('POST','api/import',next);liveRaw=next;Store.applyView(0);toast(`${label}: done.`);}
  catch(e){toast(`${label} failed: ${e.message||'error'}.`,true);}
  finally{Store.batch=null;}
}

/* ================= Compiling the data ================= */
let SITES=[],siteById={},WAN=[];
// Hand-placed positions of the assets on a plate: {assetId:[x,z]} in plate units from its centre
function cleanLayout(l){
  if(!l||typeof l!=='object')return null;const o={};let n=0;
  Object.entries(l).forEach(([id,p])=>{if(Array.isArray(p)&&isFinite(p[0])&&isFinite(p[1])){o[id]=[+p[0],+p[1]];n++;}});
  return n?o:null;
}
const svcHosts=v=>(Array.isArray(v)?v:String(v||'').split(/[\s,;]+/)).map(h=>String(h).trim()).filter(Boolean);
// "tcp/443, udp/53" -> ['tcp/443','udp/53']
function parsePorts(v){
  const arr=Array.isArray(v)?v:String(v||'').split(/[\s,;]+/);
  return arr.map(p=>String(p).trim().toLowerCase()).filter(Boolean).map(p=>/^\d+$/.test(p)?'tcp/'+p:p);
}
// Edge firewall (Internet side) and core L3 device (between internal VLANs) of an IS
function topology(s){
  const zoneOf=a=>s.vlanById[a.vlan]?s.zones.findIndex(z=>z.id===s.vlanById[a.vlan].zoneId):0;
  const fromNet=a=>s.flows.filter(f=>isNet(f.src)&&f.dst===a.id).length;
  const rank=(list,score)=>list.slice().sort((a,b)=>score(b)-score(a))[0]||null;
  const fws=s.assets.filter(a=>a.type==='firewall'),routers=s.assets.filter(a=>a.type==='router');
  const edge=rank(fws,a=>zoneOf(a)*100+fromNet(a)*10+(/edge|perim|front|internet|wan/i.test(a.name+' '+a.role)?5:0))||rank(routers,a=>zoneOf(a));
  const inner=fws.filter(a=>a!==edge);
  const core=rank(inner,a=>(/core|intern|segment/i.test(a.name+' '+a.role)?50:0)-zoneOf(a))
    ||rank(routers.filter(a=>a!==edge),a=>(/core|l3/i.test(a.name+' '+a.role)?50:0))
    ||rank(s.assets.filter(a=>a.type==='switch'&&/core|l3|backbone|router/i.test(a.name+' '+a.role)),a=>-zoneOf(a))
    ||null;
  return {edge,core,zoneOf};
}
function autoVia(s,net,f){
  const {edge,core,zoneOf}=net,E=edge&&edge.id,Cc=core&&core.id;
  if(isNet(f.src)&&isNet(f.dst))return [];
  const ez=edge?zoneOf(edge):-1,inEdge=id=>!isNet(id)&&edge&&zoneOf(s.byId[id])===ez;
  if(isNet(f.src))return [E,inEdge(f.dst)?null:Cc];
  if(isNet(f.dst))return [inEdge(f.src)?null:Cc,E];
  if(f.level==='intra')return [];
  const se=inEdge(f.src),de=inEdge(f.dst);
  if(edge&&se&&de)return [E];
  if(edge&&se)return [E,Cc];
  if(edge&&de)return [Cc,E];
  return [Cc||E];
}
function bfs(flows,from){const starts=[].concat(from),d={},q=starts.slice();starts.forEach(x=>d[x]=0);while(q.length){const n=q.shift();flows.forEach(f=>{if(f.src===n&&d[f.dst]===undefined){d[f.dst]=d[n]+1;q.push(f.dst);}});}return d;}
const maxExp=(a,b)=>EXP[a].rank>=EXP[b].rank?a:b;
// EPSS: a probability from 0 to 1; a percentage (above 1) is read as such
const epssOf=v=>{if(v==null||v==='')return null;const n=parseFloat(String(v).trim().replace(/,/g,'.'));return isFinite(n)&&n>=0?(n>1?Math.min(1,n/100):n):null;};
function compile(){
  const list=Object.entries(raw.si).map(([id,d])=>({id,d})).sort((a,b)=>(a.d.order||0)-(b.d.order||0)||String(a.d.name).localeCompare(String(b.d.name)));
  SITES=list.map(({id,d},si)=>{
    const s={id,name:d.name||'Untitled IS',kind:d.kind||'',order:d.order||0,planche:pad(si+1),contacts:(d.contacts||[]).map(c=>Object.assign({},c,{role:roleEn(c.role)})),raw:d};
    s.zones=(d.zones&&d.zones.length?d.zones:[{id:'z-def',name:'Main zone'}]).map(z=>({id:z.id,name:z.name,vlans:[]}));
    (d.vlans||[]).forEach(v=>{const z=s.zones.find(z=>z.id===v.zone)||s.zones[0];z.vlans.push({id:v.id,num:v.num,name:v.name,cidr:v.cidr||'',zone:z.name,zoneId:z.id,pos:Number.isFinite(+v.pos)&&v.pos!==''&&v.pos!=null?+v.pos:null,layout:cleanLayout(v.layout),place:Array.isArray(v.place)&&isFinite(v.place[0])&&isFinite(v.place[1])?[+v.place[0],+v.place[1]]:null});});
    // Left-to-right order inside a zone: saved position first, then VLAN number
    s.zones.forEach((z,zi)=>{z.idx=zi;z.vlans.sort((a,b)=>(a.pos==null?1e9:a.pos)-(b.pos==null?1e9:b.pos)||a.num-b.num);});
    s.vlans=[];s.zones.forEach(z=>z.vlans.forEach(v=>s.vlans.push(v)));
    // Colours follow the VLAN number, so moving a plate (even to another zone) keeps its colour
    s.vlans.slice().sort((a,b)=>a.num-b.num).forEach((v,i)=>v.ci=i%10);
    s.vlanById={};s.vlans.forEach(v=>s.vlanById[v.id]=v);
    s.assets=Object.entries(raw.assets).filter(([,a])=>a.site===id&&s.vlanById[a.vlan]).map(([aid,a])=>{
      const o=clone(a);o.id=aid;o.vulns=(o.vulns||[]).map(v=>({id:v.id||'',title:v.title||'',cvss:v.cvss==null||v.cvss===''?null:+v.cvss,sev:v.sev||sevFromCvss(+v.cvss),epss:epssOf(v.epss),kev:v.kev===true||v.kev==='true'||v.kev===1,src:v.src||''}));
      o.contacts=(o.contacts||[]).map(c=>Object.assign({},c,{role:roleEn(c.role)}));o.crit=+o.crit||2;
      o.apps=(Array.isArray(o.apps)?o.apps:[]).filter(x=>x&&x.name).map(x=>({name:String(x.name),version:String(x.version||''),ports:parsePorts(x.ports)}));o.type=TYPE_LABEL[o.type]?o.type:'server';
      o.sev=o.vulns.reduce((m,v)=>SEV[v.sev]&&SEV[v.sev].rank>SEV[m].rank?v.sev:m,'none');return o;})
      .sort((a,b)=>String(a.name).localeCompare(String(b.name),'en',{numeric:true}));
    s.byId={};s.assets.forEach(a=>s.byId[a.id]=a);
    // Internet services this IS can use: the shared catalogue plus its own
    const svc=(list,scope)=>(Array.isArray(list)?list:[]).filter(x=>x&&x.id&&x.name).map(x=>({id:'svc:'+x.id,key:x.id,name:String(x.name),category:x.category||'Other',hosts:svcHosts(x.hosts),ports:parsePorts(x.ports),notes:x.notes||'',scope}));
    s.services=[...svc(raw.services,'global'),...svc(d.services,'site')];
    s.svcById={};s.services.forEach(x=>s.svcById[x.id]=x);
    const valid=id=>id==='internet'||!!s.svcById[id]||!!s.byId[id];
    s.flows=(d.flows||[]).filter(f=>valid(f.src)&&valid(f.dst)&&f.src!==f.dst&&!(isNet(f.src)&&isNet(f.dst))).map(f=>{
      const o=Object.assign(clone(f),{vol:+f.vol||1,risk:!!f.risk});
      o.level=(isNet(o.src)||isNet(o.dst))?'internet':(s.byId[o.src].vlan!==s.byId[o.dst].vlan?'inter':'intra');
      return o;});
    // Interconnection equipment crossed by each flow: saved list, or suggested from the topology
    const net=topology(s);
    s.flows.forEach(f=>{
      const manual=Array.isArray(f.via);
      f.viaAuto=!manual;
      f.via=(manual?f.via:autoVia(s,net,f)).filter((id,i,arr)=>s.byId[id]&&id!==f.src&&id!==f.dst&&arr.indexOf(id)===i);
      f.hops=[f.src,...f.via,f.dst];
    });
    s.lanes=SA.lanes(s.flows);s.fcol=SA.flowColours(s.flows,FLOW_PAL);
    // Business services: what the organisation does, and the assets it runs on
    s.business=(Array.isArray(d.business)?d.business:[]).filter(b=>b&&b.id&&b.name).map(b=>({id:String(b.id),name:String(b.name),crit:[1,2,3].includes(+b.crit)?+b.crit:2,owner:String(b.owner||''),notes:String(b.notes||''),
      assets:(Array.isArray(b.assets)?b.assets:[]).filter((id,i,arr)=>s.byId[id]&&arr.indexOf(id)===i)})).sort((a,b)=>b.crit-a.crit||a.name.localeCompare(b.name));
    s.bizById={};s.business.forEach(b=>s.bizById[b.id]=b);
    s.impact=SA.businessImpact(s);
    // Exposed ports: grouped inbound flows per destination port
    s.assets.forEach(a=>{a.ports=[];a.exp='none';});
    s.flows.forEach(f=>{
      if(isNet(f.dst))return;const a=s.byId[f.dst];
      let p=a.ports.find(x=>x.port===f.port);if(!p){p={port:f.port,level:'none',from:[]};a.ports.push(p);}
      p.level=maxExp(p.level,f.level);if(!p.from.includes(f.src))p.from.push(f.src);a.exp=maxExp(a.exp,f.level);
    });
    s.assets.forEach(a=>a.ports.sort((x,y)=>EXP[y.level].rank-EXP[x.level].rank||x.port.localeCompare(y.port,'en',{numeric:true})));
    s.expo=bfs(s.flows,['internet',...s.services.map(x=>x.id)]);
    // Risk: one score per asset and the fixes in order, once exposure and reachability are known
    const bizCrit={};Object.entries(s.impact.byAsset).forEach(([id,l])=>bizCrit[id]=Math.max(...l.map(x=>x.crit)));
    s.risk=SA.riskPriorities(s,bizCrit);s.riskById={};s.risk.assets.forEach(r=>s.riskById[r.id]=r);
    // Attack paths: the critical assets (their own criticality, or that of a business service they
    // would hit) and what an attacker coming from the Internet could reach
    s.bizCrit=bizCrit;s.critIds=s.assets.filter(a=>a.crit===3||bizCrit[a.id]===3).map(a=>a.id);s.atkOut=SA.blastRadius(s,SA.outside(s));
    s.usedSvc=new Set(s.flows.flatMap(f=>[f.src,f.dst]).filter(id=>id!=='internet'&&isNet(id)));
    const cnt=k=>s.assets.filter(a=>a.exp===k).length;
    s.stats={vlans:s.vlans.length,assets:s.assets.length,crit:s.assets.reduce((n,a)=>n+a.vulns.filter(v=>v.sev==='crit').length,0),
      high:s.assets.reduce((n,a)=>n+a.vulns.filter(v=>v.sev==='high').length,0),risk:s.flows.filter(f=>f.risk).length,
      reach:s.assets.filter(a=>s.expo[a.id]!==undefined).length,xNet:cnt('internet'),xInter:cnt('inter'),xIntra:cnt('intra'),
      ports:s.assets.reduce((n,a)=>n+a.ports.length,0),business:s.business.length};
    return s;
  });
  siteById={};SITES.forEach(s=>siteById[s.id]=s);
  WAN=(raw.wan||[]).filter(w=>siteById[w.a]&&siteById[w.b]&&w.a!==w.b).map(w=>Object.assign(clone(w),{vol:+w.vol||1,risk:!!w.risk}));
}

/* ---- Current IS ---- */
let SITE=null,VLANS=[],ZONES=[],ASSETS=[],FLOWS=[],byId={},vlanById={},EXPO={},SVC={};
function setSite(s){SITE=s;VLANS=s.vlans;ZONES=s.zones;ASSETS=s.assets;FLOWS=s.flows;byId=s.byId;vlanById=s.vlanById;EXPO=s.expo;SVC=s.svcById;}
const neighborsOf=id=>{const s=new Set();FLOWS.forEach(f=>{if(f.hops.includes(id))f.hops.forEach(h=>s.add(h));});s.delete(id);return s;};
const nameOf=id=>id==='internet'?'Internet':SVC[id]?SVC[id].name:(byId[id]&&!byId[id].isInternet?byId[id].name:'?');
// Internet services shown in this IS: those its flows use, and its own
const siteServices=()=>SITE?SITE.services.filter(x=>x.scope==='site'||SITE.usedSvc.has(x.id)):[];
const vnum=a=>{const v=vlanById[a.vlan];return v?v.num:'?';};

const state={attack:{from:'internet'},attackHl:null,hoverFlow:null,lens:'physical',biz:null,view:'overview',siteId:null,ovSelId:null,selId:null,mode:'zones',hidden:new Set(),minSev:0,minExp:0,dir:'all',color:'risk',flows:true,riskOnly:false,labels:true,ports:false,rotate:false,gap:8,path:false,panel:null,posts:'off',compact:true,arrange:false,flat:false,tool:'move'};
const reduceMotion=matchMedia('(prefers-reduced-motion: reduce)').matches;
// saved theme applied before the first frame, so the page does not flash
try{const t=localStorage.getItem('strata-theme');if(t==='light'||t==='dark')document.documentElement.dataset.theme=t;}catch(e){}
const selAsset=()=>state.selId&&byId[state.selId]||null;
const ovSel=()=>state.ovSelId&&siteById[state.ovSelId]||null;
// Does a flow pass the direction filter? Relative to the selected asset, otherwise to the Internet boundary
function dirOk(f,sel){
  if(sel&&f.via.includes(sel.id))return true;
  if(state.dir==='all')return sel?(f.src===sel.id||f.dst===sel.id):true;
  if(sel)return state.dir==='in'?f.dst===sel.id:f.src===sel.id;
  return state.dir==='in'?isNet(f.src):isNet(f.dst);
}

/* ================= Messages ================= */
let toastT=null;
function toast(msg,err,sticky){const t=$('#toast');t.textContent=msg;t.className='panel'+(err?' err':'');t.hidden=false;clearTimeout(toastT);if(!sticky)toastT=setTimeout(()=>t.hidden=true,err?5000:2200);}

/* ================= Title block and lists ================= */
const nums=arr=>`<div class="nums">${arr.map(([n,l,c])=>`<div class="${c||''}"><b>${n}</b><span class="cap">${l}</span></div>`).join('')}</div>`;
function storeBadge(){return Store.mode==='api'?`<span class="store"><i></i><b>Server${Store.user?' · '+esc(Store.user)+' ('+esc(Store.role)+')':''}</b></span>`:`<span class="store local"><i></i><b>This browser only</b></span>`;}
function renderCart(){
  const c=$('#cart');
  if(state.view==='overview'){
    const T=k=>SITES.reduce((n,s)=>n+s.stats[k],0);
    c.innerHTML=`<div class="t"><h1>Strata</h1><span class="cap">Overview</span></div><div class="pl"><span class="cap">Sheet</span><b>00</b></div>
    <div class="meta"><span>Scope <b>${plural(SITES.length,'IS').replace('ISs','IS')} · ${plural(T('vlans'),'VLAN')}</b></span><span>Storage ${storeBadge()}</span></div>
    ${nums([[T('assets'),'assets'],[T('xNet'),'internet-facing','net'],[T('crit'),'critical vulns','alert'],[T('risk')+WAN.filter(w=>w.risk).length,'risky flows','alert']])}`;
  }else{
    const s=SITE.stats;
    c.innerHTML=`<div class="t"><button class="back" data-back>← Overview</button><h1>IS ${esc(SITE.name)}</h1><span class="cap">${esc(SITE.kind||'Information system')}</span></div><div class="pl"><span class="cap">Sheet</span><b>${SITE.planche}</b></div>
    <div class="meta"><span>Zones <b>${ZONES.length}</b></span><span>Scale <b>1 plate = 1 VLAN</b></span><span>Storage ${storeBadge()}</span></div>
    ${nums([[s.assets,'assets'],[s.xNet,'internet-facing','net'],[s.crit,'critical vulns','alert'],[s.risk,'risky flows','alert']])}`;
  }
  placeCtl();
}
function placeCtl(){
  const ctl=$('#ctl');
  if(innerWidth<=760){ctl.style.top='';ctl.style.maxHeight='';return;}
  const b=Math.round($('#cart').getBoundingClientRect().bottom);ctl.style.top=(b+10)+'px';ctl.style.maxHeight=`calc(100% - ${b+36}px)`;
}
addEventListener('resize',placeCtl);
function renderSiteList(){
  $('#siteList').innerHTML=SITES.length?SITES.map(s=>`<button class="site" data-site="${esc(s.id)}" aria-pressed="${state.ovSelId===s.id}"><b>${esc(s.name)}</b><span class="c" title="Critical vulnerabilities">${s.stats.crit} crit.</span><small>${esc(s.kind||'IS')} · ${plural(s.stats.vlans,'VLAN')} · ${plural(s.stats.assets,'asset')}</small></button>`).join(''):'<p class="empty">No information system yet.</p>';
}
function renderVlanList(){
  // By zone: listed left to right as on the level. One VLAN per floor: listed top to bottom.
  const zm=state.mode==='zones',L=zm?['←','→','Move left','Move right']:['↑','↓','Move up','Move down'];
  $('#vlans').innerHTML=ZONES.slice().reverse().filter(z=>z.vlans.length).map(z=>{const vs=zm?z.vlans:z.vlans.slice().reverse();return `<div class="zone-h">${esc(z.name.toUpperCase())}${zm&&z.vlans.some(v=>v.place)?` <button class="ibtn mvbox-r edit-only" data-reset-zone="${esc(z.id)}" title="Line the plates of this level up again">Line up</button>`:zm&&vs.length>1?' <span>left → right</span>':''}</div>`+vs.map((v,i)=>{
    const first=i===0,last=i===vs.length-1,dA=zm?-1:1,dB=zm?1:-1;
    return `<div class="vrow"><label class="vlan" for="vl-${v.id}"><input type="checkbox" id="vl-${v.id}" data-vlan="${esc(v.id)}" ${state.hidden.has(v.id)?'':'checked'}>
    <span class="nm"><b><i class="sw" style="background:var(--c${v.ci})"></i>VLAN ${esc(v.num)} · ${esc(v.name)}</b><small>${esc(v.cidr||'—')}</small></span><span class="ct">${ASSETS.filter(a=>a.vlan===v.id).length}</span></label>
    <span class="mvbox edit-only"><button class="ibtn mvb" data-mv="${esc(v.id)}" data-d="${dA}" aria-label="${L[2]} VLAN ${esc(v.num)}" ${first?'disabled':''}>${L[0]}</button><button class="ibtn mvb" data-mv="${esc(v.id)}" data-d="${dB}" aria-label="${L[3]} VLAN ${esc(v.num)}" ${last?'disabled':''}>${L[1]}</button></span>
    <button class="ibtn edit-only" data-edit-vlan="${esc(v.id)}" aria-label="Edit VLAN ${esc(v.num)}">Edit</button></div>`;}).join('');}).join('')||'<p class="empty">No VLAN yet.</p>';
  $('#assetList').innerHTML=ASSETS.map(a=>`<option value="${esc(a.name)}">${esc(a.ip||'')}</option>`).join('');
  $('#pathCount').textContent=SITE.stats.reach;
  $('#portsCount').textContent=SITE.stats.ports;
  $('#riskCount').textContent=SITE.risk.assets.length?SITE.risk.assets[0].score:'';
  const atkN=SITE.critIds.filter(id=>SITE.atkOut.has(id)).length;$('#atkCount').textContent=SITE.critIds.length?`${atkN}/${SITE.critIds.length}`:'';
}
function renderLegend(){
  const sev=['crit','high','med','low'].map(k=>`<span><i class="pin" style="background:var(${SEV[k].css})"></i>${SEV[k].label}</span>`).join('')+`<span class="wide">Pin: worst vulnerability. Flag: critical.</span>`;
  const flows=state.view==='site'&&state.color==='flow'
    ?`<span class="wide"><i class="ln" style="background:var(--f0)"></i><i class="ln" style="background:var(--f1)"></i><i class="ln" style="background:var(--f2)"></i><i class="ln" style="background:var(--f3)"></i> One colour per flow: flows crossing the same equipment never share one (up to ${FLOW_PAL}). Risky flows are dashed in the 2D diagram.</span>`
    :state.view==='site'&&state.color==='exp'
    ?['internet','inter','intra'].map(k=>`<span><i class="ln" style="background:var(${EXP[k].css})"></i>${EXP[k].label}</span>`).join('')+`<span class="wide">Flow colour: where the traffic crosses (Internet, between VLANs, inside a VLAN).</span>`
    :`<span><i class="ln" style="background:var(--thread)"></i>Observed flow</span><span><i class="ln" style="background:var(--crit)"></i>Risky flow</span>`;
  $('#legend').innerHTML=sev+flows+`<span class="wide">Thread thickness: volume (MB/h). Beads and cones: direction of travel, from the source. A thread bends through each firewall, router or switch it crosses, in its own lane.</span>`;
}
function renderDirNote(){
  const sel=selAsset(),n=$('#dirNote');
  if(state.view!=='site'){n.textContent='';return;}
  n.textContent=sel?`Relative to ${sel.name}.`:(state.dir==='all'?'Select an asset to see its own flows.':`No asset selected: ${state.dir==='in'?'traffic coming in from':'traffic going out to'} the Internet.`);
}
function syncUI(){
  const flat=state.flat&&state.view==='site';
  document.querySelectorAll('#ctl [data-view],#ctl [data-only3d]').forEach(el=>el.hidden=(el.dataset.view&&el.dataset.view!==state.view)||(el.hasAttribute('data-only3d')&&flat));
  $('#hint').textContent=flat?(state.tool==='flow'?'Draw a flow: press on the source asset and release on the destination':state.tool==='asset'?'Add an asset: click on a VLAN plate where it should go':'Drag the background to pan · scroll to zoom · drag an asset, or a plate by its header (anywhere on its level, or onto another level)'):state.view==='overview'?'Drag to orbit · middle or right button to move the view · click a plinth for its summary · click again to open it':state.arrange?'Arrange mode · drag a plate anywhere on its level (left, right, front, back) · click “Arrange plates” again to finish':'Drag to orbit · middle or right button to move the view · scroll to zoom · click an asset or a flow';
  document.querySelectorAll('#siteList .site').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.site===state.ovSelId)));
  document.body.classList.toggle('readonly',!Store.canWrite);
  $('#portsBtn').setAttribute('aria-pressed',String(state.panel==='ports'));
  $('#riskBtn').setAttribute('aria-pressed',String(state.panel==='risk'));
  $('#atkBtn').setAttribute('aria-pressed',String(state.panel==='attack'));
  renderLegend();renderDirNote();
}
function renderEmpty(){
  const e=$('#empty');
  if(!Store.loaded){e.innerHTML='<h2>Loading…</h2><p>Reading the saved map.</p>';e.hidden=false;return;}
  if(state.panel==='form'){e.hidden=true;return;}
  if(state.view==='overview'&&!SITES.length){
    e.innerHTML=`<h2>Your map is empty</h2><p>Create your first information system, then add its zones, VLANs, assets and flows. You can also load the demo (5 fictional IS) to explore the tool.</p>
    ${Store.canWrite?`<div class="btns"><button class="btn primary" data-act="new-site">Create an IS</button><button class="btn" data-act="demo"><span>Load the demo</span></button><button class="btn" data-act="import"><span>Import a JSON file</span></button></div>`:'<p>You have read-only access.</p>'}`;
    e.hidden=false;return;
  }
  if(state.view==='site'&&!VLANS.length){
    e.innerHTML=`<h2>IS ${esc(SITE.name)} has no VLAN</h2><p>Each VLAN becomes a plate on the model. Add one, then place your assets on it.</p>${Store.canWrite?'<div class="btns"><button class="btn primary" data-act="new-vlan">Add a VLAN</button><button class="btn" data-act="edit-site"><span>Edit zones</span></button></div>':''}`;
    e.hidden=false;return;
  }
  if(state.view==='site'&&!ASSETS.length){
    e.innerHTML=`<h2>Add your assets</h2><p>The VLANs are in place. Add a first asset with its vulnerabilities and incident contacts.</p>${Store.canWrite?'<div class="btns"><button class="btn primary" data-act="new-asset">Add an asset</button></div>':''}`;
    e.hidden=!!state.panel;return;
  }
  e.hidden=true;
}
$('#sevSeg').innerHTML=SEV_KEYS.map((k,i)=>`<button data-sev="${i}" aria-pressed="${i===0}" title="${i===0?'Show everything':'From '+SEV[k].label+' upwards'}">${['All','Low','Med','High','Crit'][i]}</button>`).join('');

/* ================= Three.js ================= */
const renderer=new THREE.WebGLRenderer({antialias:true});
renderer.setPixelRatio(Math.min(devicePixelRatio,2));
renderer.shadowMap.enabled=true;renderer.shadowMap.type=THREE.PCFSoftShadowMap;
$('#scene').appendChild(renderer.domElement);
const scene=new THREE.Scene();
const camera=new THREE.PerspectiveCamera(42,1,0.1,700);
const controls=new THREE.OrbitControls(camera,renderer.domElement);
controls.enableDamping=true;controls.dampingFactor=0.08;controls.maxPolarAngle=Math.PI*0.47;controls.minDistance=8;controls.maxDistance=260;controls.autoRotateSpeed=0.45;
// Left button orbits; the middle button (or the right one) moves the view across the screen, left, right,
// up and down, so the model need not stay centred on one point. The wheel zooms; on a touch screen,
// two fingers zoom and move.
controls.enablePan=true;controls.screenSpacePanning=true;
controls.mouseButtons={LEFT:THREE.MOUSE.ROTATE,MIDDLE:THREE.MOUSE.PAN,RIGHT:THREE.MOUSE.PAN};
controls.touches={ONE:THREE.TOUCH.ROTATE,TWO:THREE.TOUCH.DOLLY_PAN};
// No browser autoscroll on a middle click in the 3D view
renderer.domElement.addEventListener('mousedown',e=>{if(e.button===1)e.preventDefault();});

const W=34,D=21,SLAB=0.3,TABLE_Y=-2;
let floors={},pickables=[],cloud=null,selRing=null,sun=null,levelTags=[],extent=W,nLevels=0,ANIM=[],OV={spanX:60,spanZ:40,ex:14,sites:{}};
const pGeo=new THREE.SphereGeometry(0.12,10,8);

function roundRect(ctx,x,y,w,h,r){ctx.beginPath();ctx.moveTo(x+r,y);ctx.arcTo(x+w,y,x+w,y+h,r);ctx.arcTo(x+w,y+h,x,y+h,r);ctx.arcTo(x,y+h,x,y,r);ctx.arcTo(x,y,x+w,y,r);ctx.closePath();}
function tagLabel(text,dot,size=0.58,weight=500,border){
  const px=40,pd=14,dotW=dot?28:0,c=document.createElement('canvas'),ctx=c.getContext('2d'),font=`${weight} ${px}px "IBM Plex Mono", ui-monospace, monospace`;
  ctx.font=font;const w=Math.ceil(ctx.measureText(text).width)+pd*2+dotW,h=Math.round(px*1.5);
  c.width=w;c.height=h;ctx.font=font;
  ctx.fillStyle=css('--panel');roundRect(ctx,0,0,w,h,6);ctx.fill();
  ctx.strokeStyle=border||css('--line');ctx.lineWidth=border?5:3;roundRect(ctx,2,2,w-4,h-4,5);ctx.stroke();
  if(dot){ctx.fillStyle=dot;ctx.beginPath();ctx.arc(pd+9,h/2,9,0,Math.PI*2);ctx.fill();}
  ctx.fillStyle=css('--fg');ctx.textBaseline='middle';ctx.fillText(text,pd+dotW,h/2+2);
  const tex=new THREE.CanvasTexture(c);tex.minFilter=THREE.LinearFilter;
  const s=new THREE.Sprite(new THREE.SpriteMaterial({map:tex,transparent:true,depthTest:false,depthWrite:false}));
  s.scale.set(size*w/h,size,1);s.renderOrder=20;return s;
}
function placard(v,col){
  const c=document.createElement('canvas');c.width=1024;c.height=256;const ctx=c.getContext('2d');
  ctx.fillStyle=css('--card');ctx.fillRect(0,0,1024,256);ctx.fillStyle=col;ctx.fillRect(0,0,22,256);
  ctx.fillStyle='#1b2125';
  const title=`VLAN ${v.num}  ${String(v.name).toUpperCase()}`;
  ctx.font='700 104px "Archivo Narrow", "Arial Narrow", sans-serif';
  const fs=Math.min(104,Math.floor(104*930/Math.max(1,ctx.measureText(title).width)));
  ctx.font=`700 ${fs}px "Archivo Narrow", "Arial Narrow", sans-serif`;ctx.textBaseline='alphabetic';ctx.fillText(title,58,128);
  ctx.font='500 58px "IBM Plex Mono", monospace';ctx.fillStyle='#4a5359';ctx.fillText(v.cidr||'',60,210);
  const tex=new THREE.CanvasTexture(c);tex.anisotropy=4;
  const side=new THREE.MeshStandardMaterial({color:new THREE.Color(css('--card')),roughness:0.9});
  const face=new THREE.MeshStandardMaterial({map:tex,roughness:0.9});
  const m=new THREE.Mesh(new THREE.BoxGeometry(8,2,0.1),[side,side,side,side,face,side]);m.castShadow=true;return m;
}

/* ---- Low-poly models ---- */
const B=(g,w,h,d,m,x,y,z)=>{const o=new THREE.Mesh(new THREE.BoxGeometry(w,h,d),m);o.position.set(x,y,z);g.add(o);return o;};
const C=(g,rt,rb,h,seg,m,x,y,z)=>{const o=new THREE.Mesh(new THREE.CylinderGeometry(rt,rb,h,seg),m);o.position.set(x,y,z);g.add(o);return o;};
function rack(g,w,h,d,c,k,y0=0){
  B(g,w,h,d,c,0,y0+h/2,0);B(g,w+0.1,0.08,d+0.1,k,0,y0+h+0.04,0);
  const n=Math.max(1,Math.floor((h-0.3)/0.24));for(let i=0;i<n;i++)B(g,w*0.72,0.065,0.03,k,0,y0+0.24+i*0.24,d/2+0.016);
  return y0+h+0.08;
}
const MODELS={
  server:(g,c,k)=>rack(g,1.2,2,1.2,c,k),
  dc:(g,c,k)=>{const h=rack(g,1.35,2.5,1.35,c,k);const r=C(g,0,0.62,0.5,4,c,0,h+0.25,0);r.rotation.y=Math.PI/4;return h+0.5;},
  hypervisor:(g,c,k)=>{rack(g,1.9,0.8,1.3,c,k);return rack(g,1.9,0.8,1.3,c,k,0.9);},
  db:(g,c,k)=>{for(let i=0;i<3;i++){C(g,0.8,0.8,0.42,12,c,0,0.21+i*0.5,0);if(i<2)C(g,0.72,0.72,0.08,12,k,0,0.46+i*0.5,0);}return 1.42;},
  firewall:(g,c,k)=>{B(g,2.7,0.08,0.6,k,0,0.04,0);for(let r=0;r<4;r++)for(let i=0;i<4;i++)B(g,0.56,0.28,0.5,c,(i-1.5)*0.62+(r%2?0.31:0)-0.15,0.22+r*0.31,0);return 1.37;},
  gateway:(g,c,k)=>{B(g,1.7,0.6,1.05,c,0,0.3,0);B(g,1.3,0.22,0.02,k,0,0.34,0.535);[-0.6,0.6].forEach(x=>{C(g,0.035,0.035,0.85,6,k,x,1.02,-0.35);const s=new THREE.Mesh(new THREE.SphereGeometry(0.07,8,6),k);s.position.set(x,1.45,-0.35);g.add(s);});return 1.5;},
  switch:(g,c,k)=>{B(g,2.5,0.42,1.2,c,0,0.21,0);for(let r=0;r<2;r++)for(let i=0;i<10;i++)B(g,0.15,0.1,0.03,k,(i-4.5)*0.2,0.14+r*0.15,0.6);return 0.42;},
  workstation:(g,c,k)=>{B(g,0.55,0.05,0.38,c,0,0.025,-0.1);B(g,0.09,0.5,0.09,c,0,0.3,-0.15);B(g,1.45,0.88,0.08,c,0,0.98,-0.1);B(g,1.3,0.74,0.02,k,0,0.98,-0.05);B(g,1.05,0.05,0.34,c,0,0.025,0.48);return 1.42;},
  printer:(g,c,k)=>{B(g,1.6,0.75,1.2,c,0,0.375,0);B(g,1.5,0.12,1.1,c,0,0.81,0);B(g,1.1,0.05,0.04,k,0,0.6,0.61);B(g,0.95,0.03,0.5,c,0,0.5,0.82);return 0.87;},
  plc:(g,c,k)=>{B(g,2.1,0.12,0.1,k,0,0.62,-0.33);[1.1,1.0,1.0,0.85,0.85].forEach((h,i)=>{const x=(i-2)*0.4;B(g,0.36,h,0.6,c,x,h/2,0);B(g,0.22,0.12,0.02,k,x,h-0.2,0.31);});return 1.1;},
  camera:(g,c,k)=>{C(g,0.06,0.08,1.15,6,k,0,0.575,0);B(g,0.22,0.12,0.22,k,0,1.18,0);const b=B(g,0.4,0.36,0.88,c,0,1.32,0.22);b.rotation.x=-0.22;const l=C(g,0.13,0.13,0.1,10,k,0,1.24,0.68);l.rotation.x=Math.PI/2-0.22;return 1.55;},
  iot:(g,c,k)=>{C(g,0.1,0.15,0.9,8,c,0,0.45,0);B(g,0.62,0.88,0.14,c,0,1.32,0);B(g,0.36,0.36,0.02,k,0,1.42,0.08);B(g,0.36,0.08,0.02,k,0,1.08,0.08);return 1.76;},
  ap:(g,c,k)=>{C(g,0.05,0.05,0.9,6,k,0,0.45,0);C(g,0.55,0.62,0.16,14,c,0,0.98,0);C(g,0.06,0.06,0.02,8,k,0,1.07,0.3);return 1.06;},
  phone:(g,c,k)=>{B(g,0.95,0.1,0.75,c,0,0.05,0);const b=B(g,0.95,0.32,0.6,c,0,0.26,0.02);b.rotation.x=-0.35;const s=B(g,0.5,0.02,0.24,k,0.12,0.43,0.05);s.rotation.x=-0.35;B(g,0.2,0.14,0.72,c,-0.33,0.5,0);return 0.6;}
};
const MINI_H={dc:1.2,server:0.95,hypervisor:0.8,db:0.8,firewall:0.6,gateway:0.55,switch:0.3,workstation:0.55,printer:0.45,plc:0.6,camera:0.6,iot:0.7,ap:0.55,phone:0.3};

function buildBase(spanX,spanZ){
  while(scene.children.length)scene.remove(scene.children[0]);
  pickables=[];ANIM=[];
  const BG=css('--bg');scene.background=new THREE.Color(BG);scene.fog=new THREE.Fog(BG,Math.max(90,spanX*1.3),Math.max(200,spanX*3));
  scene.add(new THREE.HemisphereLight(0xffffff,0x8a8f8c,parseFloat(css('--sky'))||0.6));
  sun=new THREE.DirectionalLight(0xffffff,parseFloat(css('--sun'))||1);
  sun.position.set(-26,80,34);sun.castShadow=true;sun.shadow.mapSize.set(2048,2048);
  const sb=Math.max(42,Math.max(spanX,spanZ)/2+12);
  Object.assign(sun.shadow.camera,{left:-sb,right:sb,top:sb,bottom:-sb,near:1,far:280});sun.shadow.bias=-0.0006;sun.shadow.normalBias=0.02;
  scene.add(sun);scene.add(sun.target);
  const table=new THREE.Mesh(new THREE.PlaneGeometry(800,800),new THREE.MeshStandardMaterial({color:new THREE.Color(css('--table')),roughness:1}));
  table.rotation.x=-Math.PI/2;table.position.y=TABLE_Y-0.12;table.receiveShadow=true;scene.add(table);
  const MW=Math.ceil(Math.max(58,spanX+16)/2)*2,MD=Math.ceil(Math.max(42,spanZ+12)/2)*2;
  const mat=new THREE.Mesh(new THREE.BoxGeometry(MW,0.12,MD),new THREE.MeshStandardMaterial({color:new THREE.Color(css('--mat')),roughness:0.95}));
  mat.position.y=TABLE_Y-0.06;mat.receiveShadow=true;scene.add(mat);
  const pts=[],maj=[];
  for(let x=-MW/2+2;x<MW/2;x+=2)(Math.round(x)%10===0?maj:pts).push(x,0,-MD/2+1.5,x,0,MD/2-1.5);
  for(let z=-MD/2+2;z<MD/2;z+=2)(Math.round(z)%10===0?maj:pts).push(-MW/2+1.5,0,z,MW/2-1.5,0,z);
  const lc=new THREE.Color(css('--matline'));
  [[pts,0.45],[maj,0.9]].forEach(([p,o])=>{const g=new THREE.BufferGeometry();g.setAttribute('position',new THREE.Float32BufferAttribute(p,3));
    const l=new THREE.LineSegments(g,new THREE.LineBasicMaterial({color:lc,transparent:true,opacity:o}));l.position.y=TABLE_Y+0.005;scene.add(l);});
  selRing=new THREE.Mesh(new THREE.RingGeometry(1,1.08,64).rotateX(-Math.PI/2),new THREE.MeshBasicMaterial({color:new THREE.Color(css('--fg')),depthWrite:false}));
  selRing.visible=false;scene.add(selRing);
  return {steel:new THREE.MeshStandardMaterial({color:0xb9bec2,metalness:0.6,roughness:0.35}),card:new THREE.Color(css('--card')),detail:new THREE.Color(css('--detail'))};
}
function thread(curve,vol,colorVar,nseg=1){
  const col=new THREE.Color(css(colorVar));
  const mat=new THREE.MeshStandardMaterial({color:col,roughness:0.8,transparent:true});
  const tube=new THREE.Mesh(new THREE.TubeGeometry(curve,48*nseg,0.022+Math.log10(1+vol)*0.022,5,false),mat);tube.castShadow=true;scene.add(tube);
  const pm=new THREE.MeshStandardMaterial({color:col,roughness:0.4}),n=Math.min(4,1+Math.round(Math.log10(1+vol)))*nseg,parts=[];
  for(let i=0;i<n;i++){const p=new THREE.Mesh(pGeo,pm);p.userData.t=i/n;p.position.copy(curve.getPoint(i/n));scene.add(p);parts.push(p);}
  const o={curve,tube,mat,parts,speed:(0.06+Math.log10(1+vol)*0.04)/Math.sqrt(nseg)};ANIM.push(o);return o;
}

/* ================= Overview ================= */
const MINI={slab:0.18,D:4.6,lg:3.1,sp:1.05,gap:0.8};
function miniPlan(s){
  let ext=0;const lv=s.zones.filter(z=>z.vlans.length).map((z,li)=>{
    const vs=z.vlans.map(v=>{const n=s.assets.filter(a=>a.vlan===v.id).length;return {v,n,w:Math.max(3.4,n*MINI.sp+1.4)};});
    const tot=vs.reduce((t,x)=>t+x.w,0)+(vs.length-1)*MINI.gap;let cx=-tot/2;vs.forEach(x=>{x.x0=cx+x.w/2;cx+=x.w+MINI.gap;});
    ext=Math.max(ext,tot);return {li,vs};});
  return {lv,ext:Math.max(ext,8)};
}
function buildOverview(){
  const plans=SITES.map(miniPlan),ex=Math.max(14,...plans.map(p=>p.ext));
  const n=SITES.length,cols=Math.max(1,Math.ceil(Math.sqrt(n))),rows=Math.max(1,Math.ceil(n/cols)),cellW=ex+9,cellD=18;
  OV={spanX:cols*cellW,spanZ:rows*cellD,ex,sites:{}};
  const base=buildBase(OV.spanX,OV.spanZ);
  SITES.forEach((s,i)=>{
    const r=Math.floor(i/cols),c=i%cols,inRow=r<rows-1?cols:n-cols*(rows-1);
    const px=(c-(inRow-1)/2)*cellW,pz=(r-(rows-1)/2)*cellD;
    const p=plans[i],g=new THREE.Group();g.position.set(px,TABLE_Y,pz);
    const mats=[];const M=o=>{const m=new THREE.MeshStandardMaterial(Object.assign({roughness:0.88,transparent:true},o));mats.push(m);return m;};
    const card=M({color:base.card,flatShading:true}),dark=M({color:base.detail}),steel=M({color:0xb9bec2,metalness:0.6,roughness:0.35});
    const plinth=new THREE.Mesh(new THREE.BoxGeometry(p.ext+2.4,0.5,MINI.D+2.6),card);plinth.position.y=0.25;g.add(plinth);
    const edge=new THREE.Mesh(new THREE.BoxGeometry(p.ext+2.42,0.08,MINI.D+2.62),dark);edge.position.y=0.04;g.add(edge);
    p.lv.forEach(({li,vs})=>{
      const y=1.5+li*MINI.lg;
      vs.forEach(({v,n:cnt,w,x0})=>{
        const slab=new THREE.Mesh(new THREE.BoxGeometry(w,MINI.slab,MINI.D),M({color:new THREE.Color(css('--c'+v.ci))}));slab.position.set(x0,y,0);g.add(slab);
        [-1,1].forEach(sx=>[-1,1].forEach(sz=>{const len=y-MINI.slab/2-0.5;const post=new THREE.Mesh(new THREE.CylinderGeometry(0.07,0.07,len,6),steel);post.position.set(x0+sx*(w/2-0.3),0.5+len/2,sz*(MINI.D/2-0.3));post.visible=state.posts!=='off';if(state.posts==='thin')post.scale.set(0.5,1,0.5);g.add(post);}));
        s.assets.filter(a=>a.vlan===v.id).forEach((a,j)=>{
          const h=MINI_H[a.type]||0.6,ax=x0+(j-(cnt-1)/2)*MINI.sp,ay=y+MINI.slab/2;
          const geo=a.type==='db'?new THREE.CylinderGeometry(0.32,0.32,h,10):new THREE.BoxGeometry(a.type==='firewall'||a.type==='switch'?0.9:0.6,h,0.6);
          const m=new THREE.Mesh(geo,card);m.position.set(ax,ay+h/2,0);g.add(m);
          if(a.sev!=='none'){const sc=new THREE.Color(sevColor(a.sev)),sm=M({color:sc,emissive:sc,emissiveIntensity:0.15});
            const ph=h+0.25+SEV[a.sev].rank*0.12;
            const nd=new THREE.Mesh(new THREE.CylinderGeometry(0.02,0.02,ph,4),steel);nd.position.set(ax+0.3,ay+ph/2,0.15);g.add(nd);
            const hd=new THREE.Mesh(new THREE.SphereGeometry(0.14,10,8),sm);hd.position.set(ax+0.3,ay+ph,0.15);g.add(hd);}
        });
      });
    });
    const top=1.5+Math.max(0,p.lv.length-1)*MINI.lg+2.2;
    const lab=tagLabel(`${s.name.toUpperCase()} · ${s.stats.crit} CRIT.`,s.stats.crit?sevColor('crit'):null,0.95,600);lab.position.set(0,top+1.0,0);g.add(lab);
    g.traverse(o=>{if(o.isMesh){o.castShadow=true;o.receiveShadow=true;o.userData.site=s;pickables.push(o);}});
    scene.add(g);
    OV.sites[s.id]={group:g,mats,label:lab,top,ext:p.ext,anchor:new THREE.Vector3(px,TABLE_Y+top-0.6,pz)};
  });
  WAN.forEach(w=>{
    const a=OV.sites[w.a].anchor,b=OV.sites[w.b].anchor,mid=a.clone().add(b).multiplyScalar(0.5);mid.y=Math.max(a.y,b.y)+4+a.distanceTo(b)*0.18;
    Object.assign(w,thread(new THREE.QuadraticBezierCurve3(a,mid,b),w.vol,w.risk?'--crit':'--thread'));
  });
  sun.target.position.set(0,TABLE_Y,0);
}
function refreshOverview(){
  const sel=ovSel();
  SITES.forEach(s=>{const o=OV.sites[s.id];if(!o)return;const op=sel&&sel!==s?0.22:1;o.mats.forEach(m=>{m.opacity=op;m.depthWrite=op>0.5;});o.label.material.opacity=op>0.5?1:0.45;});
  WAN.forEach(w=>{if(!w.tube)return;const vis=state.flows&&(!state.riskOnly||w.risk);let op=w.risk?0.95:0.85;if(sel)op=(w.a===sel.id||w.b===sel.id)?1:0.08;
    w.mat.opacity=op;w.mat.depthWrite=op>0.5;w.tube.visible=vis;w.parts.forEach(p=>p.visible=vis&&op>0.5);});
  if(sel&&OV.sites[sel.id]){const o=OV.sites[sel.id];selRing.scale.set((o.ext+5)/2,1,(MINI.D+5)/2);selRing.position.set(o.group.position.x,TABLE_Y+0.02,o.group.position.z);selRing.visible=true;}
  else selRing.visible=false;
  syncUI();
}

/* ================= Detailed model ================= */
const portText=a=>{const ps=a.ports.map(p=>p.port.startsWith('tcp/')?p.port.slice(4):p.port.replace(/^(\w+)\/(.*)$/,'$2/$1'));return 'IN '+(ps.length>4?ps.slice(0,4).join(' ')+` +${ps.length-4}`:ps.join(' '));};
// Footprint of each model on a plate (width along x)
const FOOT={server:1.2,dc:1.35,hypervisor:1.9,db:1.6,firewall:2.6,gateway:1.7,router:1.8,switch:2.5,workstation:1.45,printer:1.6,plc:2.1,camera:0.9,iot:0.8,ap:1.25,phone:1.0};
// Packs the assets of one VLAN in rows; returns the plate size and each asset's spot
function packVlan(list,compact){
  const gap=compact?1.3:3.4,rowD=compact?3.3:5.4,margin=compact?1.4:2.6,front=2.6,back=compact?1.1:2;
  const n=list.length,cols=n?Math.max(1,Math.min(n,Math.ceil(Math.sqrt(n*(compact?2.6:3.2))))):1;
  const rows=[];for(let i=0;i<n;i+=cols)rows.push(list.slice(i,i+cols));
  const fw=a=>(FOOT[a.type]||1.2)+(a.sev!=='none'?0.5:0);
  const rowW=r=>r.reduce((t,a)=>t+fw(a),0)+(r.length-1)*gap;
  const inner=Math.max(0,...rows.map(rowW));
  const w=Math.max(compact?8:14,inner+margin*2),D=Math.max(compact?6.5:10,rows.length*rowD+front+back);
  const pos={};
  rows.forEach((r,ri)=>{let x=-rowW(r)/2;r.forEach((a,ci)=>{const f=fw(a);pos[a.id]={x:x+(FOOT[a.type]||1.2)/2,ri,ci,zr:ri};x+=f+gap;});});
  return {w,D,pos,rows:rows.length,rowD,back};
}
const footW=a=>(FOOT[a.type]||1.2)+(a.sev!=='none'?0.5:0);
// Where each asset sits on its plate: hand-placed (2D diagram) or packed automatically
function plateLayout(id,compact){
  const v=vlanById[id],list=ASSETS.filter(a=>a.vlan===id),pk=packVlan(list,compact),man=v.layout,spots={};
  const autoZ=ri=>-pk.D/2+pk.back+pk.rowD*(ri+0.5);
  const manual=!!(man&&list.some(a=>man[a.id]));
  if(!manual)list.forEach(a=>{const sp=pk.pos[a.id];spots[a.id]={x:sp.x,z:autoZ(sp.ri),ci:sp.ci};});
  else{
    let maxX=-Infinity,firstZ=null;
    list.forEach(a=>{const p=man[a.id];if(!p)return;spots[a.id]={x:p[0],z:p[1],ci:0};maxX=Math.max(maxX,p[0]+footW(a)/2);if(firstZ===null||p[1]<firstZ)firstZ=p[1];});
    // assets added since the plate was arranged by hand go to its right
    list.forEach(a=>{if(spots[a.id])return;const f=footW(a);spots[a.id]={x:maxX+1.3+f/2,z:firstZ,ci:0};maxX+=1.3+f;});
    Object.values(spots).sort((p,q)=>p.x-q.x).forEach((sp,i)=>sp.ci=i);
  }
  const minW=compact?8:14,minD=compact?6.5:10,margin=compact?1.4:2.6;
  let hx=0,zb=0,zf=0;
  list.forEach(a=>{const sp=spots[a.id];hx=Math.max(hx,Math.abs(sp.x)+footW(a)/2);zb=Math.max(zb,-sp.z+1.1);zf=Math.max(zf,sp.z+1.1);});
  const w=manual?Math.max(minW,2*hx+2*margin):pk.w,Dv=manual?Math.max(minD,2*Math.max(zb+(compact?0.6:1),zf+2.6)):pk.D;
  return {id,list,w,D:Dv,spots,manual};
}
// Levels and plates, the same for the 3D model and the 2D diagram
function computeLayout(){
  const zm=state.mode==='zones',compact=state.compact,zonesUsed=ZONES.filter(z=>z.vlans.length);
  const levels=zm?zonesUsed.map(z=>({name:z.name,zoneId:z.id,ids:z.vlans.map(v=>v.id)})):VLANS.map(v=>({name:`VLAN ${v.num} · ${v.zone}`,zoneId:v.zoneId,ids:[v.id]}));
  let ext=0,maxD=0;const plan=[];
  levels.forEach((lv,li)=>{
    const infos=lv.ids.map(id=>Object.assign(plateLayout(id,compact),{level:li})),g=compact?2:3;
    const free=zm&&lv.ids.some(id=>vlanById[id].place);
    if(!free){
      const lvD=Math.max(...infos.map(i=>i.D));if(zm)infos.forEach(i=>i.D=lvD);
      const total=infos.reduce((t,i)=>t+i.w,0)+(infos.length-1)*g;let cx=-total/2;
      infos.forEach(inf=>{inf.x0=cx+inf.w/2;inf.z0=0;cx+=inf.w+g;});
    }else{
      // plates placed by hand keep their spot; the others line up to their right
      let maxX=-Infinity;
      infos.forEach(i=>{const p=vlanById[i.id].place;if(p){i.x0=p[0];i.z0=p[1];maxX=Math.max(maxX,i.x0+i.w/2);}});
      infos.forEach(i=>{if(i.x0===undefined){i.x0=(maxX===-Infinity?0:maxX+g)+i.w/2;i.z0=0;maxX=i.x0+i.w/2;}});
    }
    const minX=Math.min(...infos.map(i=>i.x0-i.w/2)),maxXX=Math.max(...infos.map(i=>i.x0+i.w/2));
    const minZ=Math.min(...infos.map(i=>i.z0-i.D/2)),maxZ=Math.max(...infos.map(i=>i.z0+i.D/2));
    infos.forEach(inf=>{plan.push(inf);maxD=Math.max(maxD,inf.D);});
    Object.assign(lv,{li,free,D:maxZ-minZ,minZ,minX,total:maxXX-minX,plates:infos});
    ext=Math.max(ext,2*Math.max(Math.abs(minX),Math.abs(maxXX)));maxD=Math.max(maxD,2*Math.max(Math.abs(minZ),Math.abs(maxZ)));
  });
  return {zm,compact,levels,plan,extent:ext,maxD};
}
function buildScene(){
  const L=computeLayout(),zm=L.zm,compact=L.compact,plan=L.plan;
  nLevels=L.levels.length;extent=L.extent;floors={};
  levelTags=zm?L.levels.map(lv=>({li:lv.li,name:lv.name})):[];
  const DD=L.maxD||D;
  const base=buildBase(Math.max(extent,30),DD),steel=base.steel;
  const postMat=steel.clone();postMat.transparent=true;
  plan.forEach(inf=>{
    const v=vlanById[inf.id],Wv=inf.w,Dv=inf.D,vc=css('--c'+v.ci);
    const g=new THREE.Group(),col=new THREE.Color(vc);g.position.x=inf.x0;
    const slab=new THREE.Mesh(new THREE.BoxGeometry(Wv,SLAB,Dv),new THREE.MeshStandardMaterial({color:col,roughness:0.92,transparent:true}));
    slab.castShadow=slab.receiveShadow=true;slab.userData.plate=v.id;g.add(slab);pickables.push(slab);
    const pl=placard(v,vc),pk0=compact?0.72:1;pl.scale.setScalar(pk0);pl.position.set(-Wv/2+0.6+4*pk0,SLAB/2+pk0,Dv/2-0.9);g.add(pl);
    const posts=[];
    [[-1,-1],[1,-1],[-1,1],[1,1]].forEach(([sx,sz])=>{const p=new THREE.Mesh(new THREE.CylinderGeometry(0.22,0.22,1,10),postMat);p.position.set(sx*(Wv/2-0.9),0,sz*(Dv/2-0.9));p.castShadow=true;g.add(p);posts.push(p);});
    scene.add(g);floors[v.id]={group:g,posts,postMat,slab,level:inf.level,x0:inf.x0,z0:inf.z0||0,w:Wv,D:Dv};
    inf.list.forEach(a=>{
      const sp=inf.spots[a.id],x=sp.x,z=sp.z;
      const ag=new THREE.Group();ag.position.set(x,SLAB/2,z);
      const c=new THREE.MeshStandardMaterial({color:base.card,roughness:0.85,flatShading:true,transparent:true});
      const k=new THREE.MeshStandardMaterial({color:base.detail,roughness:0.6,flatShading:true,transparent:true});
      const model=new THREE.Group();const h=(MODELS[a.type]||MODELS.server)(model,c,k);ag.add(model);
      const box=new THREE.Box3().setFromObject(model),sz=box.getSize(new THREE.Vector3());
      const mats=[c,k];let pinTop=h;
      if(a.sev!=='none'){
        const sc=new THREE.Color(sevColor(a.sev));
        const sm=new THREE.MeshStandardMaterial({color:sc,roughness:0.5,transparent:true,emissive:sc,emissiveIntensity:0.12});mats.push(sm);
        const tape=new THREE.Mesh(new THREE.BoxGeometry(sz.x+0.5,0.04,sz.z+0.5),sm);tape.position.y=0.02;ag.add(tape);
        const ph=h+0.55+SEV[a.sev].rank*0.28,px=box.max.x+0.35,pz=-0.2;
        const needle=new THREE.Mesh(new THREE.CylinderGeometry(0.03,0.03,ph,6),steel);needle.position.set(px,ph/2,pz);ag.add(needle);
        const head=new THREE.Mesh(new THREE.SphereGeometry(0.21,14,10),sm);head.position.set(px,ph,pz);ag.add(head);
        if(a.sev==='crit'){const fl=new THREE.Mesh(new THREE.BoxGeometry(0.6,0.36,0.025),sm);fl.position.set(px+0.32,ph-0.42,pz);ag.add(fl);}
        pinTop=ph;
      }
      ag.traverse(o=>{if(o.isMesh){o.castShadow=true;o.receiveShadow=true;o.userData.asset=a;pickables.push(o);}});
      if(DIFF&&DIFF.A[a.id]){const r=new THREE.Mesh(new THREE.RingGeometry(1.2,1.42,40).rotateX(-Math.PI/2),new THREE.MeshBasicMaterial({color:new THREE.Color(css(DIFF_COL[DIFF.A[a.id]])),depthWrite:false}));r.position.y=0.05;ag.add(r);}
      const top=Math.max(h,pinTop);
      const lift=compact&&sp.ci%2?0.62:0;
      const label=tagLabel(a.name,a.sev==='none'?null:sevColor(a.sev));label.position.set(0,top+0.7+lift,0);ag.add(label);
      let portLabel=null;
      if(a.ports.length){portLabel=tagLabel(portText(a),expColor(a.exp),0.5,600,expColor(a.exp));portLabel.position.set(0,top+1.35+lift,0);ag.add(portLabel);}
      g.add(ag);Object.assign(a,{group:ag,mats,label,portLabel,h});
    });
  });
  levelTags.forEach(t=>{t.sprite=tagLabel(`LEVEL ${t.li} · ${t.name.toUpperCase()}`,null,0.87);t.sprite.center.set(1,0.5);scene.add(t.sprite);});
  const cg=new THREE.Group(),cm=new THREE.MeshStandardMaterial({color:base.card,roughness:0.8,flatShading:true});
  [[0,0,0,1.6],[1.5,-0.3,0.2,1.15],[-1.5,-0.35,0,1.2],[0.6,0.7,-0.2,1.1],[-0.7,0.5,0.4,1.0],[2.6,-0.6,0,0.75],[-2.6,-0.6,0.1,0.8]]
    .forEach(([x,y,z,r])=>{const s=new THREE.Mesh(new THREE.IcosahedronGeometry(r,0),cm);s.position.set(x,y,z);s.castShadow=true;cg.add(s);});
  const rod=new THREE.Mesh(new THREE.CylinderGeometry(0.08,0.08,1,8),steel);rod.castShadow=true;scene.add(rod);
  const il=tagLabel('INTERNET',null);il.position.y=2.6;cg.add(il);
  scene.add(cg);cloud=cg;cloud.rod=rod;
  byId.internet={id:'internet',name:'Internet',group:cg,h:0,isInternet:true};
  // Named Internet services hang in a row next to the cloud
  const sm=new THREE.MeshStandardMaterial({color:new THREE.Color(css('--x-net')),roughness:0.6,flatShading:true});
  cloud.svcs=siteServices().map(x=>{const g=new THREE.Group(),m=new THREE.Mesh(new THREE.OctahedronGeometry(0.62,0),sm);m.castShadow=true;m.userData.svc=x;g.add(m);pickables.push(m);
    const lb=tagLabel(x.name,css('--x-net'),0.5);lb.position.y=1.15;g.add(lb);scene.add(g);byId[x.id]={id:x.id,name:x.name,group:g,h:0,isInternet:true,isSvc:true};return g;});
}
function anchor(id){const a=byId[id],p=new THREE.Vector3();a.group.getWorldPosition(p);if(!a.isInternet)p.y+=a.h*0.55;else if(!a.isSvc)p.y-=0.6;return p;}
function flowColorVar(f){if(DIFF&&DIFF.F[f.id])return DIFF_COL[DIFF.F[f.id]];return state.color==='exp'?EXP[f.level].css:state.color==='flow'?'--f'+(SITE.fcol[f.id]||0):(f.risk?'--crit':'--thread');}
// A flow is drawn hop by hop: source -> each interconnection device -> destination,
// with an arrowhead at the end of every hop so the direction and the origin read at a glance
const coneGeo=new THREE.ConeGeometry(0.2,0.55,10).rotateX(Math.PI/2),pickMat=new THREE.MeshBasicMaterial({colorWrite:false,depthWrite:false});
// Lane of a flow on a piece of equipment it crosses: -0.5 to 0.5 across the device, 0 when alone
function laneOf(f,id){const L=SITE.lanes[id];return L&&L.n>1&&L.idx[f.id]!==undefined?{k:L.idx[f.id],n:L.n,t:L.idx[f.id]/(L.n-1)-0.5}:null;}
function flowCurve(f){
  const path=new THREE.CurvePath(),segs=[],last=f.hops.length-1;
  // Flows sharing a device are spread across its top, and each lane arches a little higher than the previous one
  const lift=f.hops.map((id,i)=>{const l=i>0&&i<last?laneOf(f,id):null;return l?Math.min(0.16*l.k,2.4*(l.t+0.5)):0;});
  const pts=f.hops.map((id,i)=>{const p=anchor(id),l=i>0&&i<last?laneOf(f,id):null;if(l)p.x+=l.t*Math.min(0.3*l.n,footW(byId[id])+0.6);return p;});
  for(let i=0;i<pts.length-1;i++){
    const a=pts[i],b=pts[i+1],mid=a.clone().add(b).multiplyScalar(0.5);mid.y=Math.max(a.y,b.y)+1.2+a.distanceTo(b)*0.09+Math.max(lift[i],lift[i+1]);
    const c=new THREE.QuadraticBezierCurve3(a,mid,b);path.add(c);segs.push(c);
  }
  return {path,segs};
}
function buildFlows(){
  scene.updateMatrixWorld(true);
  ANIM=ANIM.filter(o=>!o.owner);
  FLOWS.forEach(f=>{
    if(f.tube){scene.remove(f.tube);f.tube.geometry.dispose();f.parts.forEach(p=>scene.remove(p));(f.extras||[]).forEach(x=>{scene.remove(x);if(x.geometry!==coneGeo)x.geometry.dispose();});pickables=pickables.filter(o=>o!==f.pick);}
    const {path,segs}=flowCurve(f);
    const o=thread(path,f.vol,flowColorVar(f),segs.length);o.owner=f;
    const extras=segs.map(c=>{const m=new THREE.Mesh(coneGeo,o.mat);const t=Math.max(0.5,1-1.1/Math.max(1,c.getLength()));m.position.copy(c.getPoint(t));m.lookAt(c.getPoint(t).add(c.getTangent(t)));
      const k=0.75+Math.log10(1+f.vol)*0.18;m.scale.set(k,k,k);m.castShadow=true;scene.add(m);return m;});
    const pick=new THREE.Mesh(new THREE.TubeGeometry(path,24*segs.length,0.32,4,false),pickMat);pick.userData.flow=f;scene.add(pick);pickables.push(pick);
    extras.push(pick);
    Object.assign(f,{tube:o.tube,mat:o.mat,parts:o.parts,extras,cones:extras.slice(0,-1),pick});
  });
}
function postLen(level,wx,y,wz=0){
  for(let l=level-1;l>=0;l--){if(Object.values(floors).some(f=>f.level===l&&Math.abs(wx-f.x0)<=f.w/2-0.3&&Math.abs(wz-f.z0)<=f.D/2-0.3))return (level-l)*state.gap-SLAB;}
  return y-SLAB/2-TABLE_Y;
}
function layout(){
  const pv=state.posts,thick=pv==='full'?1:0.32;
  Object.values(floors).forEach(fl=>{const y=fl.level*state.gap;fl.group.position.set(fl.x0,y,fl.z0);
    fl.postMat.opacity=pv==='full'?1:0.55;fl.postMat.depthWrite=pv==='full';
    fl.posts.forEach(p=>{p.visible=pv!=='off';const len=postLen(fl.level,fl.x0+p.position.x,y,fl.z0+p.position.z);p.scale.set(thick,len,thick);p.position.y=-SLAB/2-len/2;p.castShadow=pv==='full';});});
  levelTags.forEach(t=>t.sprite.position.set(-extent/2-1.2,t.li*state.gap+0.2,0));
  const top=Object.values(floors).filter(f=>f.level===nLevels-1)[0];
  const topY=top?top.level*state.gap+SLAB/2:TABLE_Y,cy=topY+5.2,cx=top?top.x0-top.w/2+5:0,cz=top?top.z0-top.D/2+3:0;
  cloud.position.set(cx,cy,cz);
  (cloud.svcs||[]).forEach((g,i)=>g.position.set(cx+4.6+(i%6)*3.6,cy-0.6-Math.floor(i/6)*2.6,cz+0.5));cloud.rod.visible=state.posts!=='off';cloud.rod.scale.y=cy-topY-1;cloud.rod.position.set(cx,topY+(cy-topY-1)/2,cz);
  sun.target.position.copy(center());
  buildFlows();placeSelRing();
}
function center(){return state.view==='overview'?new THREE.Vector3(0,TABLE_Y+3,0):new THREE.Vector3(0,Math.max(0,nLevels-1)*state.gap/2,0);}
// Moving the view stops when the point it looks at reaches the edge of the model, so the model cannot be
// lost off screen (Reset view centres it again). The camera follows that point, so the angle and the
// distance stay as they were.
function keepInView(){
  const c=center(),ov=state.view==='overview';
  const rx=ov?OV.spanX/2:extent/2,rz=ov?OV.spanZ/2:extent/2,ry=ov?6:Math.max(1,nLevels)*state.gap/2+4;
  const t=controls.target,clamp=(v,o,r)=>Math.max(o-r,Math.min(o+r,v));
  const dx=clamp(t.x,c.x,rx)-t.x,dy=clamp(t.y,c.y,ry)-t.y,dz=clamp(t.z,c.z,rz)-t.z;
  if(dx||dy||dz){t.x+=dx;t.y+=dy;t.z+=dz;camera.position.x+=dx;camera.position.y+=dy;camera.position.z+=dz;}
}
// Opacity of every asset and flow under the current filters and selection (3D model and 2D diagram)
function computeVis(){
  const sel=selAsset(),nb=sel?neighborsOf(sel.id):null,fsel=(state.hoverFlow&&FLOWS.find(x=>x.id===state.hoverFlow))||(state.panel==='flow'?FLOWS.find(x=>x.id===state.flowId):null);
  const dirPeers=sel&&state.dir!=='all'?new Set(FLOWS.filter(f=>dirOk(f,sel)).flatMap(f=>f.hops)):null;
  const aOp={},fv={},bdep=state.biz&&SITE.impact.byBusiness[state.biz]?SITE.impact.byBusiness[state.biz].assets:null;
  const atk=state.panel==='attack'?attackData():null,ahl=atk&&state.attackHl?atk.hl.get(state.attackHl):null,aon=atk&&(ahl||atk);
  ASSETS.forEach(a=>{let op=1;
    if(SEV[a.sev].rank<state.minSev)op=0.15;
    if(EXP[a.exp].rank<state.minExp)op=Math.min(op,0.15);
    if(sel&&sel!==a&&!(dirPeers?dirPeers.has(a.id):nb.has(a.id)))op=Math.min(op,0.18);
    if(state.path&&EXPO[a.id]===undefined)op=Math.min(op,0.15);
    if(fsel&&!fsel.hops.includes(a.id))op=Math.min(op,0.18);
    if(bdep&&!bdep[a.id])op=Math.min(op,0.15);
    if(aon&&!aon.nodes.has(a.id))op=Math.min(op,0.12);
    aOp[a.id]=op;});
  const shown=id=>isNet(id)||(byId[id]&&!state.hidden.has(byId[id].vlan));
  FLOWS.forEach(f=>{
    let vis=state.flows&&shown(f.src)&&shown(f.dst);if(state.riskOnly&&!f.risk)vis=false;
    if(!sel&&state.dir!=='all'&&!dirOk(f,null))vis=false;
    if(EXP[f.level].rank<state.minExp)vis=false;
    let op=f.risk?0.95:0.8;
    if(sel)op=dirOk(f,sel)?1:0.07;
    if(state.path)op=(EXPO[f.src]!==undefined&&EXPO[f.dst]===EXPO[f.src]+1)?1:0.07;
    if(aon)op=aon.flows.has(f.id)?1:0.05;
    if(fsel)op=f===fsel?1:0.06;
    else if(bdep)op=(bdep[f.src]||isNet(f.src))&&(bdep[f.dst]||isNet(f.dst))?1:0.06;
    const dimEnd=id=>!isNet(id)&&SEV[byId[id].sev].rank<state.minSev;
    if(state.minSev>0&&dimEnd(f.src)&&dimEnd(f.dst))op=Math.min(op,0.07);
    fv[f.id]={vis,op};});
  return {sel,fsel,aOp,fv};
}
function refresh(){
  const V=computeVis(),sel=V.sel;
  VLANS.forEach(v=>{if(floors[v.id])floors[v.id].group.visible=!state.hidden.has(v.id);});
  ASSETS.forEach(a=>{
    if(!a.mats)return;
    const op=V.aOp[a.id];
    a.mats.forEach(m=>{m.opacity=op;m.depthWrite=op>0.5;});
    a.label.visible=(state.labels&&op>0.5)||sel===a;
    if(a.portLabel)a.portLabel.visible=(state.ports&&op>0.5)||(sel===a&&state.ports);
  });
  FLOWS.forEach(f=>{
    if(!f.tube)return;
    const {vis,op}=V.fv[f.id];
    f.mat.opacity=op;f.mat.depthWrite=op>0.5;f.tube.visible=vis;f.tube.castShadow=op>0.5;
    f.parts.forEach(p=>p.visible=vis&&op>0.5);f.cones.forEach(c=>c.visible=vis);f.pick.visible=vis&&op>0.5;
  });
  placeSelRing();renderDirNote();
  if(state.flat)renderFlat();
  if(state.lens!=='physical')renderLens();
}
function placeSelRing(){
  const a=state.view==='site'?selAsset():null;
  if(!a||!a.group||!a.group.parent.visible){if(state.view==='site')selRing.visible=false;return;}
  const p=new THREE.Vector3();a.group.getWorldPosition(p);selRing.scale.set(1.75,1,1.75);selRing.position.copy(p);selRing.position.y+=0.06;selRing.visible=true;
}

/* ================= Read panels ================= */
const det=$('#det');
const tag=k=>`<span class="tag" style="color:var(${SEV[k].css})"><i style="background:var(${SEV[k].css})"></i>${SEV[k].label}</span>`;
const xtag=k=>`<span class="xtag" style="color:var(${EXP[k].css})">${EXP[k].label}</span>`;
function openDet(html,panel){det.innerHTML=html;det.hidden=false;det.scrollTop=0;document.body.classList.add('has-det');const wasAtk=state.panel==='attack'&&panel!=='attack';state.panel=panel;renderEmpty();syncUI();placeLens();if(wasAtk&&state.view==='site')refresh();}
function closeDet(){const wasFlow=state.panel==='flow'||state.panel==='attack';det.hidden=true;document.body.classList.remove('has-det');state.panel=null;state.attackHl=null;renderEmpty();syncUI();placeLens();if(wasFlow&&state.view==='site')refresh();}
function contactsHtml(list){
  return `<ul class="list">${list.map(c=>`<li class="contact"><div class="who"><b>${esc(c.name||'Contact')}</b><span>${esc(c.role||'')}${c.dispo?' · '+esc(c.dispo):''}</span></div>
    ${c.phone?`<div class="line"><span>${esc(c.phone)}</span><button class="copy" data-copy="${esc(c.phone)}">Copy</button></div>`:''}
    ${c.email?`<div class="line"><span>${esc(c.email)}</span><button class="copy" data-copy="${esc(c.email)}">Copy</button></div>`:''}</li>`).join('')}</ul>`;
}
const viaHtml=f=>f.via.length?`<span class="via">via ${f.via.map(id=>`<button data-goto="${esc(id)}">${esc(nameOf(id))}</button>`).join(' → ')}${f.viaAuto?' <i>(suggested)</i>':''}</span>`:'';
function flowRow(f,dir){
  const peer=dir==='out'?f.dst:f.src;
  return `<li class="flow${f.risk?' risk':''}" data-hl-flow="${esc(f.id)}"><button class="peer" data-goto="${esc(peer)}"><i class="fsw" style="background:var(${flowColorVar(f)})"></i>${dir==='out'?'→':'←'} ${esc(nameOf(peer))}</button><span class="meta">${esc(f.port)}</span><span class="meta">${f.vol} MB/h</span><button class="ibtn" data-show-flow="${esc(f.id)}" aria-label="Show this flow">Path</button>${viaHtml(f)}${f.note?`<span class="note">${esc(f.note)}</span>`:''}</li>`;
}
// Which application listens on a port
const appOn=(a,port)=>(a.apps||[]).find(x=>x.ports.includes(port));
function portsHtml(a){
  return a.ports.length?`<ul class="list">${a.ports.map(p=>{const ap=appOn(a,p.port);return `<li class="port"><b>${esc(p.port)}</b><span class="from">from ${p.from.map(id=>esc(nameOf(id))).join(', ')}${ap?`<br><span class="app-on">→ ${esc(ap.name)}${ap.version?' '+esc(ap.version):''}</span>`:''}</span>${xtag(p.level)}</li>`;}).join('')}</ul>`:'<p class="empty">No inbound flow reaches this asset.</p>';
}
// The asset opened: hardware, operating system and the applications running on it
function insideHtml(a){
  const apps=a.apps||[];
  return `<div class="inside"><div class="in-apps">${apps.length?apps.map(x=>`<div class="in-app"><b>${esc(x.name)}</b><span>${esc(x.version||'')}</span>${x.ports.length?`<span class="chips">${x.ports.map(p=>`<span class="chip${a.ports.some(q=>q.port===p)?' on':''}">${esc(p)}</span>`).join('')}</span>`:''}</div>`).join(''):'<p class="empty">No application recorded. Add them with Edit.</p>'}</div>
  <div class="in-os"><span class="cap">System</span><b>${esc(a.os||'Unknown')}</b></div>
  <div class="in-hw"><span class="cap">${esc(TYPE_LABEL[a.type])}</span><span>${esc(a.ip||'No IP')} · VLAN ${esc(vnum(a))}</span></div></div>`;
}
// The business services that stop or degrade when this asset fails or is compromised
const impactOf=a=>SITE.impact.byAsset[a.id]||[];
const chain=ids=>ids.map(id=>esc(nameOf(id))).join(' → ');
function impactHtml(a){
  const l=impactOf(a);
  if(!l.length)return `<p class="empty">No business service relies on this asset${SITE.business.length?'':', because none is recorded yet for this IS. Add them in the Business view'}.</p>`;
  return `<ul class="list">${l.map(x=>`<li class="biz"><button data-biz="${esc(x.id)}"><b>${esc(x.name)}</b><small>${x.direct?'Runs on this asset':x.how==='crossed'?`Its flows cross this equipment: ${chain(x.path)}`:`Relies on it: ${chain(x.path)}`}</small></button>${critTag(x.crit)}</li>`).join('')}</ul>`;
}
function showFlow(f){
  state.flowId=f.id;
  const lvl=EXP[f.level];
  openDet(`<div class="d-head"><div><span class="cap">Flow · ${esc(f.port)}</span><h2>${esc(nameOf(f.src))} → ${esc(nameOf(f.dst))}</h2><p>${f.vol} MB/h · ${lvl.label}${f.risk?' · risky':''}</p></div><button class="close" data-close-flow aria-label="Close the flow">×</button></div>
  <div class="d-body">
  <div class="actions edit-only"><button class="btn small" data-edit-flow="${esc(f.id)}">Edit the flow</button></div>
  <h3 class="cap">Path · ${plural(f.hops.length-1,'hop')}</h3>
  <ol class="hops">${f.hops.map((id,i)=>{const a=byId[id],role=i===0?'Source':i===f.hops.length-1?'Destination':'Crossed';
    return `<li class="${i===0?'src':i===f.hops.length-1?'dst':'thru'}"><span class="cap">${role}</span>${id==='internet'?'<b>Internet</b>':SVC[id]?`<button data-svc="${esc(id)}"><b>${esc(SVC[id].name)}</b><small>Internet service · ${esc(SVC[id].hosts.join(', ')||'no host recorded')}</small></button>`:`<button data-goto="${esc(id)}"><b>${esc(a.name)}</b><small>${esc(TYPE_LABEL[a.type])} · ${esc(a.ip||'')} · VLAN ${esc(vnum(a))}</small></button>`}</li>`;}).join('')}</ol>
  <p class="fhint">${f.via.length?(f.viaAuto?'Equipment suggested from the topology (edge firewall, core firewall or router). Edit the flow to set it yourself.':'Equipment set by hand on this flow.'):'Direct flow: no interconnection equipment on the path.'}</p>
  <dl class="kv"><dt>Service</dt><dd>${esc(f.port)}</dd><dt>Exposure</dt><dd>${xtag(f.level)}</dd><dt>Volume</dt><dd>${f.vol} MB/h</dd>${!isNet(f.dst)&&appOn(byId[f.dst],f.port)?`<dt>Application</dt><dd>${esc(appOn(byId[f.dst],f.port).name)} on ${esc(nameOf(f.dst))}</dd>`:''}${f.note?`<dt>Note</dt><dd style="color:var(--crit)">${esc(f.note)}</dd>`:''}</dl>
  </div>`,'flow');
  if(state.view==='site')refresh();
}
function showAsset(a){
  const v=vlanById[a.vlan],out=FLOWS.filter(f=>f.src===a.id),inn=FLOWS.filter(f=>f.dst===a.id),thru=FLOWS.filter(f=>f.via.includes(a.id)),hops=EXPO[a.id];
  const own=a.contacts.filter(c=>c.name||c.phone||c.email);
  const contacts=own.length?contactsHtml(own):(SITE.contacts.length?`<p class="inherit">No contact on this asset. IS contacts:</p>${contactsHtml(SITE.contacts)}`:'<p class="empty">No contact recorded.</p>');
  const showIn=state.dir!=='out',showOut=state.dir!=='in';
  openDet(`<div class="d-head"><div><span class="cap">${esc(TYPE_LABEL[a.type])}</span><h2>${esc(a.name)}</h2><p>${esc(a.ip||'No IP address')}</p></div><button class="close" data-close aria-label="Close the asset sheet">×</button></div>
  <div class="d-body">
  <div class="actions edit-only"><button class="btn small" data-edit-asset="${esc(a.id)}">Edit</button><button class="btn small" data-new-flow-to="${esc(a.id)}">+ Inbound flow</button><button class="btn small" data-new-flow-from="${esc(a.id)}">+ Outbound flow</button></div>
  <div class="actions docs"><button class="btn small" data-plan-asset="${esc(a.id)}">2D plan</button><button class="btn small" data-csv-flows="${esc(a.id)}">Flow matrix (CSV)</button><button class="btn small" data-csv-fw="${esc(a.id)}">Firewall rules (CSV)</button><button class="btn small" data-blast="${esc(a.id)}">Blast radius</button></div>
  <dl class="kv">
    <dt>IS</dt><dd>${esc(SITE.name)}</dd>
    <dt>VLAN</dt><dd><i class="sw" style="display:inline-block;background:var(--c${v.ci});margin-right:7px"></i>${esc(v.num)} · ${esc(v.name)}</dd>
    <dt>Zone</dt><dd>${esc(v.zone)}</dd>
    <dt>System</dt><dd>${esc(a.os||'—')}</dd>
    <dt>Role</dt><dd>${esc(a.role||'—')}</dd>
    <dt>Business criticality</dt><dd>${CRIT_LBL[a.crit]||'—'}</dd>
    <dt>Exposure</dt><dd>${xtag(a.exp)}</dd>
    <dt>From Internet</dt><dd>${hops===undefined?'Not reachable':`Reachable in ${plural(hops,'hop')}`}</dd>
    <dt>Risk score</dt><dd>${riskTag(SITE.riskById[a.id])}${SITE.riskById[a.id]?` <button class="linkbtn" data-risk-why="${esc(a.id)}">Why?</button>`:''}</dd>
    <dt>Blast radius</dt><dd>${blastLine(a)}</dd>
  </dl>
  <div id="riskWhy" hidden></div>
  <h3 class="cap">Business services impacted · ${impactOf(a).length}</h3>${impactHtml(a)}
  <h3 class="cap">Inside · ${plural((a.apps||[]).length,'application')}</h3>${insideHtml(a)}
  <h3 class="cap">Incident contacts</h3>${contacts}
  ${a.notes?`<h3 class="cap">Notes</h3><p style="margin:0;white-space:pre-wrap">${esc(a.notes)}</p>`:''}
  <h3 class="cap">Exposed ports · ${a.ports.length}</h3>${portsHtml(a)}
  <h3 class="cap">Vulnerabilities · ${a.vulns.length}</h3>
  ${a.vulns.length?`<ul class="list">${a.vulns.map(x=>`<li class="vuln"><b>${esc(x.id||'—')}</b><span class="score" style="color:var(${SEV[x.sev].css})">${x.cvss!=null&&!isNaN(x.cvss)?'CVSS '+(+x.cvss).toFixed(1):tag(x.sev)}</span><span class="t">${esc(x.title)}${x.kev||x.epss!=null?`<span class="vchips">${vulnChips(x)}</span>`:''}</span></li>`).join('')}</ul>`:'<p class="empty">No vulnerability in the last scan.</p>'}
  ${showIn?`<h3 class="cap">Inbound flows · ${inn.length}</h3>${inn.length?`<ul class="list">${inn.map(f=>flowRow(f,'in')).join('')}</ul>`:'<p class="empty">No inbound flow.</p>'}`:''}
  ${showOut?`<h3 class="cap">Outbound flows · ${out.length}</h3>${out.length?`<ul class="list">${out.map(f=>flowRow(f,'out')).join('')}</ul>`:'<p class="empty">No outbound flow.</p>'}`:''}
  ${thru.length?`<h3 class="cap">Flows crossing this ${INTERCO.has(a.type)?'equipment':'asset'} · ${thru.length}</h3>${state.color!=='flow'&&thru.length>1?`<p class="fhint">Hover a flow to pick it out, or <button class="linkbtn" data-col-flow>give each flow its own colour</button>.</p>`:''}<ul class="list">${thru.slice().sort((x,y)=>(SITE.lanes[a.id].idx[x.id])-(SITE.lanes[a.id].idx[y.id])).map(f=>`<li class="flow${f.risk?' risk':''}" data-hl-flow="${esc(f.id)}"><button class="peer" data-show-flow="${esc(f.id)}"><i class="fsw" style="background:var(${flowColorVar(f)})"></i>${esc(nameOf(f.src))} → ${esc(nameOf(f.dst))}</button><span class="meta">${esc(f.port)}</span><span class="meta">${f.vol} MB/h</span><span></span></li>`).join('')}</ul>`:''}
  ${state.dir!=='all'?`<p class="dirnote">Showing ${state.dir==='in'?'inbound':'outbound'} flows only. Change it under Flows › Direction.</p>`:''}
  </div>`,'asset');
}
// A business service: its own assets, what they call, the equipment crossed, the Internet services used
function bizGroups(b){
  const d=SITE.impact.byBusiness[b.id],L=Object.entries(d.assets).map(([id,x])=>Object.assign({a:byId[id]},x));
  const by=k=>L.filter(k).sort((x,y)=>SEV[y.a.sev].rank-SEV[x.a.sev].rank||x.a.name.localeCompare(y.a.name));
  return [['Runs on',by(x=>x.direct)],['Calls',by(x=>!x.direct&&x.how==='called')],['Flows cross',by(x=>!x.direct&&x.how==='crossed')],['Internet services',d.services.map(id=>({svc:SVC[id]})).filter(x=>x.svc)]];
}
function showBusiness(b){
  state.bizPanel=b.id;
  const g=bizGroups(b),worst=Object.keys(SITE.impact.byBusiness[b.id].assets).reduce((m,id)=>SEV[byId[id].sev].rank>SEV[m].rank?byId[id].sev:m,'none');
  openDet(`<div class="d-head"><div><span class="cap">Business service</span><h2>${esc(b.name)}</h2><p>${b.owner?esc(b.owner)+' · ':''}${CRIT_LBL[b.crit]} criticality</p></div><button class="close" data-close-biz aria-label="Close the business service">×</button></div>
  <div class="d-body">
  <div class="actions"><button class="btn small" data-biz-hl="${esc(b.id)}" aria-pressed="${state.biz===b.id}">${state.biz===b.id?'Shown on the model':'Show on the model'}</button><button class="btn small edit-only" data-edit-biz="${esc(b.id)}">Edit</button></div>
  <dl class="kv"><dt>Criticality</dt><dd>${critTag(b.crit)}</dd><dt>Owner</dt><dd>${esc(b.owner||'—')}</dd><dt>Worst vulnerability</dt><dd>${tag(worst)}</dd><dt>Assets involved</dt><dd>${Object.keys(SITE.impact.byBusiness[b.id].assets).length}</dd></dl>
  ${b.notes?`<p style="white-space:pre-wrap">${esc(b.notes)}</p>`:''}
  ${g.map(([t,l],i)=>`<h3 class="cap">${t} · ${l.length}</h3>${l.length?`<ul class="list">${l.map(x=>x.svc?`<li class="reach"><button data-svc="${esc(x.svc.id)}">${esc(x.svc.name)}<small>${esc(x.svc.hosts.join(', '))}</small></button></li>`:`<li class="reach"><button data-goto="${esc(x.a.id)}">${esc(x.a.name)}<small>${x.direct?esc(x.a.role||TYPE_LABEL[x.a.type]):chain(x.path)}</small></button>${tag(x.a.sev)}</li>`).join('')}</ul>`:`<p class="empty">${['No asset recorded. Edit the service to add some.','Its assets call no other asset.','No equipment crossed.','No Internet service used.'][i]}</p>`}`).join('')}
  <p class="fhint">Strata works out the dependencies from the flows: what the service's assets call, and so on, the equipment these flows cross, and the equipment in front of its assets. Log and monitoring flows (syslog, SNMP traps, NetFlow) are left out.</p>
  </div>`,'business');
}
function businessForm(b,preset){
  const d=b?clone((SITE.raw.business||[]).find(x=>x.id===b.id)||b):{name:'',crit:2,owner:'',notes:'',assets:preset?[preset]:[]};
  const on=new Set(d.assets||[]);
  openForm(b?b.name:'New business service',`IS ${SITE.name}`,`
    ${fIn('fName','Name *',d.name,'required maxlength="80" placeholder="e.g. Online sales, Payroll, Production line 1"')}
    <div class="f2">${fSel('fCrit','Criticality',[[1,'Low'],[2,'Medium'],[3,'High']],d.crit)}${fIn('fOwner','Owner',d.owner,'maxlength="80" placeholder="e.g. Finance director"')}</div>
    <fieldset><legend>Assets it runs on</legend><span class="fhint">Only the assets of the service itself (its servers, databases, PLCs). Strata adds what they depend on from the flows.</span>
      <div class="bizpick">${ZONES.slice().reverse().flatMap(z=>z.vlans).filter(v=>ASSETS.some(a=>a.vlan===v.id)).map(v=>`<div class="bp-v"><span class="cap">VLAN ${esc(v.num)} · ${esc(v.name)}</span>${ASSETS.filter(a=>a.vlan===v.id).map(a=>`<label class="chk plain"><input type="checkbox" data-biz-asset="${esc(a.id)}"${on.has(a.id)?' checked':''}>${esc(a.name)}<small>${esc(a.role||'')}</small></label>`).join('')}</div>`).join('')}</div></fieldset>
    <div class="f"><label for="fNotes">Notes</label><textarea id="fNotes" maxlength="2000" placeholder="Hours of service, maximum outage, continuity plan…">${esc(d.notes)}</textarea></div>`,
  async()=>{
    const name=$('#fName').value.trim();if(!name)return formErr('The name is required.','fName');
    const doc={id:b?b.id:uid('b'),name,crit:+$('#fCrit').value,owner:$('#fOwner').value.trim(),notes:$('#fNotes').value.trim(),assets:[...det.querySelectorAll('[data-biz-asset]:checked')].map(x=>x.dataset.bizAsset)};
    const sd=clone(SITE.raw);sd.business=(sd.business||[]).filter(x=>x.id!==doc.id);sd.business.push(doc);
    await Store.putSite(SITE.id,sd);toast(b?'Business service saved.':'Business service added.');
    afterSave(()=>{const nb=SITE.bizById[doc.id];if(nb)showBusiness(nb);else restorePanel();});
  },{del:b?{label:'Delete the business service',run:async()=>{const sd=clone(SITE.raw);sd.business=(sd.business||[]).filter(x=>x.id!==b.id);if(state.biz===b.id)state.biz=null;await Store.putSite(SITE.id,sd);toast('Business service deleted.');closeDet();}}:null});
}
function setBizHighlight(id){state.biz=id;if(id)state.selId=null;if(id&&state.lens!=='physical')setLens('physical');refresh();}
// How the score of an asset is made, factor by factor
function riskWhyHtml(a){
  const r=SITE.riskById[a.id];if(!r)return '';
  const pct=x=>Math.round(x*100)+'%';
  return `<dl class="kv riskwhy"><dt>Vulnerabilities</dt><dd>${pct(r.vuln)} chance one is exploited${r.kev?` · ${plural(r.kev,'known exploited (KEV)')}`:''}</dd>
  <dt>Exposure</dt><dd>${xtag(a.exp)} → ${pct(r.exposure)}</dd><dt>Reachability</dt><dd>${EXPO[a.id]===undefined?'not reachable from the Internet':`${plural(EXPO[a.id],'hop')} from the Internet`} → ${pct(r.reach)}</dd>
  <dt>Criticality</dt><dd>${pct(r.crit)}${impactOf(a).length?` (asset or business services it would hit)`:''}</dd>
  <dt>Score</dt><dd>100 × ${pct(r.vuln)} × ${pct(r.context)} context × ${pct(r.crit)} = <b>${r.score}</b></dd></dl>`;
}
function showRisk(){
  const R=SITE.risk,top=R.fixes.slice(0,40),kev=R.fixes.filter(x=>x.vuln.kev).length,hi=R.assets.filter(x=>x.score>=40).length;
  openDet(`<div class="d-head"><div><span class="cap">Analysis · IS ${esc(SITE.name)}</span><h2>Risk priorities</h2><p>What to fix first, from CVSS, EPSS, known exploitation, exposure, reachability and criticality</p></div><button class="close" data-close aria-label="Close the analysis">×</button></div>
  <div class="d-body">
  <p class="summary"><b style="color:var(--crit)">${hi}</b> ${hi===1?'asset':'assets'} at high or critical risk · <b>${kev}</b> known exploited ${kev===1?'vulnerability':'vulnerabilities'} (CISA KEV) to fix.</p>
  <div class="actions"><button class="btn small" data-csv-risk>Remediation list (CSV)</button></div>
  <h3 class="cap">Fix in this order · ${R.fixes.length}</h3>
  ${top.length?`<ol class="list fixes">${top.map((x,i)=>{const a=byId[x.asset];return `<li class="fix"><span class="rk">${i+1}</span><button data-goto="${esc(a.id)}"><b>${esc(x.vuln.id||'—')}</b> on ${esc(a.name)}<small>${esc(x.vuln.title)}</small><span class="vchips">${vulnChips(x.vuln)}${x.vuln.cvss!=null?`<span class="cv">CVSS ${(+x.vuln.cvss).toFixed(1)}</span>`:''}${xtag(a.exp)}</span></button><span class="fscore" style="color:var(${SEV[SA_band(x.score)].css})">${x.score}</span></li>`;}).join('')}</ol>${R.fixes.length>top.length?`<p class="fhint">${R.fixes.length-top.length} more in the CSV.</p>`:''}`:'<p class="empty">No vulnerability recorded on this IS.</p>'}
  <h3 class="cap">Assets by risk · ${R.assets.length}</h3>
  ${R.assets.length?`<ul class="list">${R.assets.slice(0,30).map(r=>{const a=byId[r.id];return `<li class="reach"><button data-goto="${esc(a.id)}">${esc(a.name)}<small>${esc(a.role||TYPE_LABEL[a.type])} · VLAN ${esc(vnum(a))}</small><span class="rbar"><i style="width:${r.score}%;background:var(${SEV[r.band].css})"></i></span></button>${riskTag(r)}</li>`;}).join('')}</ul>`:'<p class="empty">No asset at risk.</p>'}
  <p class="fhint">Each vulnerability counts for its severity (CVSS) times its likelihood of exploitation: certain when it is on the CISA list of known exploited vulnerabilities, otherwise from its EPSS, otherwise 30%. That is weighed by the exposure and the reachability of its asset from the Internet, and by the criticality of the asset or of the business services it would hit. Open an asset and click “Why?” for the detail.</p>
  </div>`,'risk');
}
const SA_band=n=>n>=70?'crit':n>=40?'high':n>=20?'med':n>0?'low':'none';
function exportRisk(){
  const rows=[['Rank','Vulnerability','Title','Asset','IP','VLAN','Exposure','From Internet (hops)','Asset criticality','CVSS','EPSS','CISA KEV','Fix priority (0-100)','Asset risk score (0-100)']];
  SITE.risk.fixes.forEach((x,i)=>{const a=byId[x.asset];rows.push([i+1,x.vuln.id,x.vuln.title,a.name,a.ip||'',vnum(a),EXP[a.exp].label,EXPO[a.id]===undefined?'':EXPO[a.id],CRIT_LBL[a.crit]||'',x.vuln.cvss==null?'':x.vuln.cvss,x.vuln.epss==null?'':x.vuln.epss,x.vuln.kev?'yes':'no',x.score,x.assetScore]);});
  if(rows.length===1){toast('No vulnerability recorded on this IS.',true);return;}
  saveFile(`remediation_${fileStem(SITE.name)}_${today()}.csv`,'text/csv;charset=utf-8',csv(rows));
}
function showPorts(){
  const groups=['internet','inter','intra'].map(k=>({k,list:ASSETS.filter(a=>a.exp===k).sort((a,b)=>SEV[b.sev].rank-SEV[a.sev].rank)}));
  openDet(`<div class="d-head"><div><span class="cap">Analysis · IS ${esc(SITE.name)}</span><h2>Exposed ports</h2><p>Ports that receive at least one inbound flow</p></div><button class="close" data-close aria-label="Close the analysis">×</button></div>
  <div class="d-body"><p class="summary"><b style="color:var(--x-net)">${SITE.stats.xNet}</b> internet-facing, <b style="color:var(--x-inter)">${SITE.stats.xInter}</b> exposed to other VLANs, <b>${SITE.stats.xIntra}</b> exposed inside their VLAN only.</p>
  ${groups.map(g=>`<div class="hopgrp"><h4>${xtag(g.k)} ${plural(g.list.length,'asset')}</h4>${g.list.length?`<ul class="list">${g.list.map(a=>`<li class="reach"><button data-goto="${esc(a.id)}">${esc(a.name)}<small>${esc(a.role||'')} · VLAN ${esc(vnum(a))}</small><span class="chips">${a.ports.map(p=>`<span class="chip" style="border-color:var(${EXP[p.level].css})">${esc(p.port)}</span>`).join('')}</span></button>${tag(a.sev)}</li>`).join('')}</ul>`:'<p class="empty">None.</p>'}</div>`).join('')}
  </div>`,'ports');
}
function showPath(){
  const reach=ASSETS.filter(a=>EXPO[a.id]!==undefined).sort((a,b)=>EXPO[a.id]-EXPO[b.id]||SEV[b.sev].rank-SEV[a.sev].rank);
  const critN=reach.filter(a=>a.sev==='crit').length,groups={};
  reach.forEach(a=>{(groups[EXPO[a.id]]=groups[EXPO[a.id]]||[]).push(a);});
  openDet(`<div class="d-head"><div><span class="cap">Analysis · IS ${esc(SITE.name)}</span><h2>Reachable from Internet</h2><p>Paths that follow the recorded flows, hop by hop</p></div><button class="close" data-close aria-label="Close the analysis">×</button></div>
  <div class="d-body"><p class="summary"><b>${reach.length}</b> assets can be reached from the Internet, <b style="color:var(--crit)">${critN}</b> of them with a critical vulnerability.</p>
  ${reach.length?Object.keys(groups).map(h=>`<div class="hopgrp"><h4>${plural(+h,'hop')}</h4><ul class="list">${groups[h].map(a=>`<li class="reach"><button data-goto="${esc(a.id)}">${esc(a.name)}<small>${esc(a.role||'')} · VLAN ${esc(vnum(a))}</small></button>${tag(a.sev)}</li>`).join('')}</ul></div>`).join(''):'<p class="empty">No flow starts from the Internet. Add a flow with Internet as its source.</p>'}</div>`,'path');
}
/* ---- Attack paths and blast radius ---- */
const pct=p=>p>=0.995?'100%':p<0.01?'<1%':Math.round(p*100)+'%';
const oddsBand=p=>p>=0.5?'crit':p>=0.2?'high':p>=0.05?'med':'low';
const oddsTag=p=>`<span class="tag" style="color:var(${SEV[oddsBand(p)].css})" title="Likelihood of getting there"><i style="background:var(${SEV[oddsBand(p)].css})"></i>${pct(p)}</span>`;
const WHY={vuln:'vulnerable',admin:'remote admin',service:'service'};
// The steps of a path: each asset taken over, with the port of the flow that reaches it
function stepsHtml(x){const fl=x.flows.map(id=>FLOWS.find(f=>f.id===id));
  return x.path.map((id,i)=>i?`<span class="ap-s">${esc(nameOf(id))}<i>${esc(fl[i-1]?fl[i-1].port:'')}</i></span>`:`<span class="ap-s from">${esc(nameOf(id))}</span>`).join('<span class="ap-ar">→</span>');}
function blastLine(a){
  const r=SA.blastRadius(SITE,a.id),crit=SITE.critIds.filter(id=>r.has(id)).length;
  return r.size?`${plural(r.size,'asset')}${crit?` · <b style="color:var(--crit)">${crit} critical</b>`:''} <button class="linkbtn" data-blast="${esc(a.id)}">Show</button>`:'Reaches no other asset';
}
// What the panel draws on the model, worked out once per IS and starting point
let ATK=null;
function attackData(){
  if(!state.attack.from||(state.attack.from!=='internet'&&!byId[state.attack.from]))state.attack.from='internet';
  const from=state.attack.from;
  if(ATK&&ATK.site===SITE&&ATK.from===from)return ATK;
  const d={site:SITE,from,nodes:new Set(),flows:new Set(),hl:new Map()};
  const mark=(key,x)=>{const n=new Set(x.path),fl=new Set(x.flows);x.flows.forEach(id=>{const f=FLOWS.find(y=>y.id===id);if(f)f.via.forEach(v=>n.add(v));});
    n.forEach(v=>d.nodes.add(v));fl.forEach(v=>d.flows.add(v));d.hl.set(key,{nodes:n,flows:fl});};
  if(from==='internet'){
    const P=SA.attackPaths(SITE,SA.outside(SITE),SITE.critIds);
    d.truncated=P.truncated;d.cut=SA.chokePoints(SITE,P.byTarget);
    // every critical asset in reach, with its paths; below the search floor, its most likely one
    d.targets=SITE.critIds.filter(id=>SITE.atkOut.has(id)).map(id=>({id,best:SITE.atkOut.get(id),paths:P.byTarget[id]&&P.byTarget[id].length?P.byTarget[id]:[SITE.atkOut.get(id)]}))
      .sort((x,y)=>y.best.p-x.best.p||byId[y.id].crit-byId[x.id].crit||byId[x.id].name.localeCompare(byId[y.id].name));
    d.out=SITE.critIds.filter(id=>!SITE.atkOut.has(id));
    d.targets.forEach(t=>t.paths.forEach((x,i)=>mark(`${t.id}|${i}`,x)));
  }else{
    d.reach=[...SA.blastRadius(SITE,from).entries()].map(([id,x])=>Object.assign({id},x)).sort((x,y)=>y.p-x.p||x.steps-y.steps||byId[x.id].name.localeCompare(byId[y.id].name));
    d.nodes.add(from);d.reach.forEach(x=>mark(x.id,x));
    const hit=new Map();[from,...d.reach.map(x=>x.id)].forEach(id=>impactOf(byId[id]).forEach(b=>{if(!hit.has(b.id))hit.set(b.id,b);}));
    d.biz=[...hit.values()].sort((x,y)=>y.crit-x.crit||x.name.localeCompare(y.name));
  }
  return ATK=d;
}
function setAttack(from){state.attack.from=from;state.attackHl=null;if(state.path)setPath(false);state.selId=null;state.biz=null;if(state.lens!=='physical')setLens('physical');showAttack();refresh();}
function showAttack(){
  const d=attackData(),from=d.from,src=byId[from];
  const opts=`<option value="internet"${from==='internet'?' selected':''}>The Internet: every path to the critical assets</option>`+ZONES.slice().reverse().flatMap(z=>z.vlans).filter(v=>ASSETS.some(a=>a.vlan===v.id))
    .map(v=>`<optgroup label="VLAN ${esc(v.num)} · ${esc(v.name)}">${ASSETS.filter(a=>a.vlan===v.id).map(a=>`<option value="${esc(a.id)}"${a.id===from?' selected':''}>${esc(a.name)}</option>`).join('')}</optgroup>`).join('');
  const row=(key,x,title,right)=>`<li class="atk" data-hl-path="${esc(key)}"><div class="atk-h">${title}${right}</div><div class="atk-p">${stepsHtml(x)}</div></li>`;
  let body;
  if(from==='internet'){
    const T=d.targets,n=SITE.critIds.length,np=T.reduce((k,t)=>k+t.paths.length,0);
    body=!n?`<p class="empty">No critical asset on this IS. Set an asset's business criticality to High, or record a business service of High criticality in the Business view.</p>`
    :`<p class="summary"><b style="color:var(${T.length?'--crit':'--fg'})">${T.length}</b> of ${plural(n,'critical asset')} can be reached from the Internet${T.length?`, along ${d.truncated?'at least ':''}${plural(np,'path')}`:''}.</p>
    <div class="actions"><button class="btn small" data-csv-attack>Attack paths (CSV)</button></div>
    ${T.length?`<h3 class="cap">Critical assets in reach · ${T.length}</h3>${T.map(t=>{const a=byId[t.id];return `<div class="atk-t"><div class="reach"><button data-goto="${esc(a.id)}">${esc(a.name)}<small>${esc(a.role||TYPE_LABEL[a.type])} · VLAN ${esc(vnum(a))} · ${plural(t.paths.length,'path')}</small></button>${oddsTag(t.best.p)}</div>
      <ol class="list">${t.paths.slice(0,5).map((x,i)=>row(`${t.id}|${i}`,x,`<span class="cap">Path ${i+1} · ${plural(x.path.length-1,'step')}</span>`,oddsTag(x.p))).join('')}</ol>${t.paths.length>5?`<p class="fhint">${t.paths.length-5} more in the CSV.</p>`:''}</div>`;}).join('')}`:''}
    ${d.cut.length?`<h3 class="cap">Where to cut · ${Math.min(d.cut.length,8)}</h3><ul class="list">${d.cut.slice(0,8).map(c=>{const a=byId[c.id];return `<li class="reach"><button data-goto="${esc(a.id)}">${esc(a.name)}<small>${c.kind==='equipment'?'Crossed: tighten its rules':c.held<c.paths?'Crossed, and taken over on some paths: harden it, tighten its rules':'Taken over on the way: harden it'} · ${c.every.length?`on every path to ${c.every.map(id=>esc(byId[id].name)).join(', ')}`:`on ${plural(c.paths,'path')}`}</small></button>${c.every.length?`<span class="tag" style="color:var(--crit)"><i style="background:var(--crit)"></i>${c.every.length} cut off</span>`:''}</li>`;}).join('')}</ul>`:''}
    ${d.out.length?`<h3 class="cap">Out of reach from the Internet · ${d.out.length}</h3><p class="chips">${d.out.map(id=>`<button class="chip" data-goto="${esc(id)}">${esc(byId[id].name)}</button>`).join('')}</p>`:''}
    ${d.truncated?'<p class="fhint">The search kept the most likely paths: there are more, all less likely.</p>':''}`;
  }else{
    const R=d.reach,likely=R.filter(x=>x.p>=0.2).length,crit=R.filter(x=>SITE.critIds.includes(x.id)).length;
    body=!R.length?`<p class="empty">No flow leaves ${esc(src.name)} towards another asset: an attacker holding it reaches nothing else along the recorded flows.</p>`
    :`<p class="summary">An attacker holding <b>${esc(src.name)}</b> reaches <b>${plural(R.length,'asset')}</b>, <b style="color:var(--crit)">${likely}</b> of them likely taken over (20% or more), <b style="color:var(--crit)">${crit}</b> critical.</p>
    <div class="actions"><button class="btn small" data-csv-attack>Blast radius (CSV)</button></div>
    ${d.biz.length?`<h3 class="cap">Business services hit · ${d.biz.length}</h3><ul class="list">${d.biz.map(b=>`<li class="biz"><button data-biz="${esc(b.id)}"><b>${esc(b.name)}</b></button>${critTag(b.crit)}</li>`).join('')}</ul>`:''}
    <h3 class="cap">Reached · ${R.length}</h3><ol class="list">${R.map(x=>{const a=byId[x.id];return row(x.id,x,`<button data-goto="${esc(a.id)}">${esc(a.name)}${SITE.critIds.includes(a.id)?' <span class="crit-dot" title="Critical asset">●</span>':''}<small>${plural(x.steps,'step')} · last one ${esc(x.port)}, ${WHY[x.why]}</small></button>`,oddsTag(x.p));}).join('')}</ol>`;
  }
  openDet(`<div class="d-head"><div><span class="cap">Analysis · IS ${esc(SITE.name)}</span><h2>${from==='internet'?'Attack paths':'Blast radius'}</h2><p>${from==='internet'?'Every way in from the Internet to the critical assets, along the allowed flows':`Everything an attacker could reach from ${esc(src.name)}, along the allowed flows`}</p></div><button class="close" data-close aria-label="Close the analysis">×</button></div>
  <div class="d-body">
  <div class="f"><label for="atkFrom">Attacker starts from</label><select id="atkFrom" data-atk-from>${opts}</select></div>
  ${body}
  <p class="fhint">Hover a path to pick it out on the model. An attacker who holds an asset can open the flows that leave it. Taking the next asset over counts for the highest of: its vulnerabilities (CVSS times likelihood of exploitation, as for the risk score), 50% on a remote administration port (SSH, RDP, SMB, WinRM, VNC, Telnet, RPC) for credentials picked up on the way, 10% on any other service. A path counts for the product of its steps. Flows run one way: answering a flow does not let the destination reach back.</p>
  </div>`,'attack');
}
function exportAttack(){
  const d=attackData(),ports=x=>x.flows.map(id=>{const f=FLOWS.find(y=>y.id===id);return f?f.port:'';}).join(' > '),names=x=>x.path.map(nameOf).join(' > ');
  let rows,name;
  if(d.from==='internet'){
    rows=[['Critical asset','IP','VLAN','Path','Likelihood (%)','Steps','Path through','Ports']];
    d.targets.forEach(t=>{const a=byId[t.id];t.paths.forEach((x,i)=>rows.push([a.name,a.ip||'',vnum(a),i+1,Math.round(x.p*1000)/10,x.path.length-1,names(x),ports(x)]));});
    name=`attack-paths_${fileStem(SITE.name)}_${today()}.csv`;
  }else{
    rows=[['Asset','IP','VLAN','Critical','Likelihood (%)','Steps','Path through','Ports','Last step']];
    d.reach.forEach(x=>{const a=byId[x.id];rows.push([a.name,a.ip||'',vnum(a),SITE.critIds.includes(a.id)?'yes':'no',Math.round(x.p*1000)/10,x.steps,names(x),ports(x),WHY[x.why]]);});
    name=`blast-radius_${fileStem(byId[d.from].name)}_${today()}.csv`;
  }
  if(rows.length===1){toast('Nothing to export.',true);return;}
  saveFile(name,'text/csv;charset=utf-8',csv(rows));
}
function showSite(s){
  const links=WAN.filter(w=>w.a===s.id||w.b===s.id);
  const top=s.assets.filter(a=>a.sev==='crit'||a.sev==='high').sort((a,b)=>SEV[b.sev].rank-SEV[a.sev].rank||EXP[b.exp].rank-EXP[a.exp].rank||b.crit-a.crit).slice(0,5);
  openDet(`<div class="d-head"><div><span class="cap">${esc(s.kind||'Information system')}</span><h2>IS ${esc(s.name)}</h2><p>${plural(s.stats.vlans,'VLAN')} · ${plural(s.stats.assets,'asset')}</p></div><button class="close" data-close aria-label="Close the summary">×</button></div>
  <div class="d-body">
  <div class="actions"><button class="btn small primary" data-open="${esc(s.id)}">Open the model</button><button class="btn small edit-only" data-edit-site="${esc(s.id)}">Edit</button><button class="btn small" data-export-site="${esc(s.id)}">Export this IS (JSON)</button><button class="btn small" data-arch-site="${esc(s.id)}">Architecture file</button></div>
  <dl class="kv">
    <dt>Zones</dt><dd>${s.zones.map(z=>esc(z.name)).join(' · ')}</dd>
    <dt>Exposure</dt><dd><b style="color:var(--x-net)">${s.stats.xNet}</b> internet-facing · <b style="color:var(--x-inter)">${s.stats.xInter}</b> inter-VLAN · ${s.stats.xIntra} intra-VLAN</dd>
    <dt>From Internet</dt><dd>${plural(s.stats.reach,'asset')} reachable</dd>
    <dt>Vulnerabilities</dt><dd><b style="color:var(--crit)">${s.stats.crit}</b> critical · <b style="color:var(--high)">${s.stats.high}</b> high</dd>
    <dt>Risky flows</dt><dd>${s.stats.risk}</dd>
  </dl>
  <h3 class="cap">IS contacts</h3>${s.contacts.length?contactsHtml(s.contacts):'<p class="empty">No contact recorded.</p>'}
  <h3 class="cap">Watch list</h3>
  ${top.length?`<ul class="list">${top.map(a=>`<li class="reach"><span class="nm">${esc(a.name)}<small>${esc(a.role||'')} · VLAN ${esc(s.vlanById[a.vlan].num)} · ${EXP[a.exp].label}</small></span>${tag(a.sev)}</li>`).join('')}</ul>`:'<p class="empty">No critical or high vulnerability.</p>'}
  <h3 class="cap"><span>Inter-IS links · ${links.length}</span><button class="ibtn edit-only" data-new-wan="${esc(s.id)}">+ Add</button></h3>
  ${links.length?`<ul class="list">${links.map(w=>{const peer=siteById[w.a===s.id?w.b:w.a];return `<li class="flow${w.risk?' risk':''}"><button class="peer" data-site="${esc(peer.id)}">↔ ${esc(peer.name)}</button><span class="meta">${esc(w.tech)}</span><span class="meta">${esc(w.vol)} MB/h</span><button class="ibtn edit-only" data-edit-wan="${esc(w.id)}" aria-label="Edit this link">Edit</button>${w.note?`<span class="note">${esc(w.note)}</span>`:''}</li>`;}).join('')}</ul>`:'<p class="empty">No link to another IS.</p>'}
  </div>`,'site');
}

/* ================= Architecture file ================= */
// One document per IS, in the order audits and security accreditation files follow: document
// control and sign-off, summary, scope, architecture, inventory, flows and filtering, exposure,
// vulnerabilities and attack paths, plans of the exposed and critical assets, contacts, history,
// method. Built from the map as it is shown; a standalone HTML file, printable to PDF.
const ARCH_CSS=`
:root,:host{color-scheme:light;--ink:#1d2321;--muted:#3d4744;--line:#d5dbd7;--soft:#f2f5f3;--accent:#1f5f8b;--crit:#b3261e;--high:#c25e00;--med:#8a6d00;--low:#2f6f3e;--net:#7a2fa0;--inter:#1f5f8b}
*{box-sizing:border-box}
.af{font-family:"Archivo",system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink);background:#fff;font-size:10.5pt;line-height:1.45;max-width:210mm;margin:0 auto;padding:18mm 16mm}
.af h1,.af h2,.af h3{font-family:"Archivo Narrow","Archivo",system-ui,sans-serif;line-height:1.2;text-wrap:balance;margin:0}
.af h2{font-size:17pt;margin:26pt 0 8pt;padding-top:8pt;border-top:2px solid var(--ink);break-before:page}
.af h3{font-size:12.5pt;margin:16pt 0 6pt}
.af p{margin:0 0 7pt;max-width:68ch}
.af .mono,.af code,.af td.m{font-family:"IBM Plex Mono",ui-monospace,Menlo,Consolas,monospace;font-size:9pt}
.af .muted{color:var(--muted)}
.af table{width:100%;border-collapse:collapse;margin:4pt 0 10pt;font-size:9pt;font-variant-numeric:tabular-nums}
.af th{text-align:left;font-weight:600;background:var(--soft);border-bottom:1px solid var(--ink);padding:4pt 5pt;vertical-align:bottom}
.af td{border-bottom:1px solid var(--line);padding:3.5pt 5pt;vertical-align:top;overflow-wrap:anywhere}
.af thead{display:table-header-group}.af tr{break-inside:avoid}
.af .num{text-align:right}
.af .cover{min-height:150mm;display:flex;flex-direction:column;gap:14pt;break-after:page}
.af .cover .kind{font-size:10pt;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.af .cover h1{font-size:34pt}
.af .cover .is{font-size:22pt;font-weight:600}
.af .mark{border:2px solid var(--crit);color:var(--crit);padding:6pt 9pt;font-weight:600;font-size:9.5pt;max-width:120mm}
.af .meta{display:grid;grid-template-columns:42mm 1fr;gap:3pt 10pt;font-size:10pt;margin-top:auto}
.af .meta dt{color:var(--muted)}.af .meta dd{margin:0}
.af .sign td{height:16mm}
.af .toc{columns:2;column-gap:12mm;padding:0;list-style:none;font-size:10pt}
.af .toc li{margin:0 0 3pt}.af .toc a{color:var(--ink);text-decoration:none}
.af .figs{display:grid;grid-template-columns:repeat(4,1fr);gap:6pt;margin:6pt 0 12pt}
.af .fig{border:1px solid var(--line);padding:6pt 8pt}
.af .fig b{display:block;font-size:17pt;font-family:"Archivo Narrow","Archivo",sans-serif}
.af .fig span{font-size:8.5pt;color:var(--muted)}
.af .t{display:inline-block;font-size:8pt;font-weight:600;padding:0 4pt;border:1px solid currentColor;border-radius:2px;white-space:nowrap}
.af .crit{color:var(--crit)}.af .high{color:var(--high)}.af .med{color:var(--med)}.af .low{color:var(--low)}.af .none{color:var(--muted)}
.af .x-internet{color:var(--net)}.af .x-inter{color:var(--inter)}.af .x-intra,.af .x-none{color:var(--muted)}
.af .kev{background:var(--crit);color:#fff;border-color:var(--crit)}
.af figure{margin:6pt 0 12pt;break-inside:avoid}
.af figure svg{width:100%;height:auto;display:block;border:1px solid var(--line)}
.af figcaption{font-size:8.5pt;color:var(--muted);margin-top:3pt}
.af .path{font-family:"IBM Plex Mono",ui-monospace,monospace;font-size:8.5pt}
.af .path i{font-style:normal;color:var(--crit)}
.af .note{border-left:3px solid var(--line);padding:2pt 0 2pt 8pt;color:var(--muted);font-size:9pt}
@page{size:A4;margin:14mm 12mm}
@media print{.af{padding:0;max-width:none}.af h2{margin-top:0}.af .cover{min-height:250mm}}
.af .ip{white-space:nowrap}
@media (max-width:640px){.af figure{overflow-x:auto}.af figure svg{width:760px;max-width:none}.af figure.net svg{width:1100px}.af{padding:18px 16px;font-size:15px}.af table{font-size:12.5px}.af .mono,.af code,.af td.m,.af .path{font-size:12px}.af figcaption,.af .note,.af .fig span{font-size:12.5px}.af .t{font-size:11px}.af .figs{grid-template-columns:repeat(2,1fr)}.af .toc{columns:1}.af .meta{grid-template-columns:1fr}.af .scroll{overflow-x:auto}}
`;
// class names from fixed tables, never from the data
const AF_CLS={crit:'crit',high:'high',med:'med',low:'low',none:'none',internet:'internet',inter:'inter',intra:'intra'};
const afSev=k=>`<span class="t ${AF_CLS[k]||'none'}">${esc(SEV[k]?SEV[k].label:k)}</span>`;
const afExp=k=>`<span class="t x-${AF_CLS[k]||'none'}">${esc(EXP[k]?EXP[k].label:k)}</span>`;
const afTable=(head,rows,cls='')=>rows.length?`<div class="scroll"><table${cls?` class="${cls}"`:''}><thead><tr>${head.map(h=>`<th${/^(#|Rule|CVSS|EPSS|Score|MB\/h|Assets|Flows|Steps|Paths|Hops|Likelihood)/.test(h)?' class="num"':''}>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r=>`<tr>${r.map((c,i)=>`<td${typeof c==='number'?' class="num"':''}>${typeof c==='number'?c:c==null?'':c}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`:'<p class="muted">None.</p>';
// The SVG of a drawing, sized to the page width
const afFit=svg=>svg.replace(/<svg([^>]*?)\swidth="[^"]*"\sheight="[^"]*"/,'<svg$1');
// The light theme of app.css, for drawings on paper: fixed values, whatever the theme on screen
// (the greys a shade darker, for print)
const PAPER={'--mat':'#5e7d6c','--matline':'#86a291','--fg':'#1b2125','--panel':'#f7f7f3','--muted':'#454e53','--detail':'#3a4148','--card':'#f0eee8','--line':'#c2c6c0','--accent':'#2b5884',
  '--thread':'#4b5a68','--crit':'#c4313d','--high':'#cc6a22','--med':'#b38d14','--low':'#3a8763','--none':'#6a747a','--x-net':'#8a3fbf','--x-inter':'#2a7fa6','--x-intra':'#5f6a72',
  '--c0':'#d2a198','--c1':'#9db9a3','--c2':'#d5b671','--c3':'#97acc3','--c4':'#aea8c9','--c5':'#b8c39e','--c6':'#c6a9b9','--c7':'#a9c4c0','--c8':'#d8b49a','--c9':'#b3b8a6',
  '--f0':'#2f63c8','--f1':'#d97a0f','--f2':'#13917f','--f3':'#8549c9','--f4':'#4a8f1f','--f5':'#c93f8f','--f6':'#a88200','--f7':'#1688b8','--f8':'#8c5a36','--f9':'#55657d'};
// The 2D diagram of the whole IS, every plate and flow shown, coloured by exposure, on paper colours
function afDiagram(){
  const keep={hidden:state.hidden,color:state.color,ports:state.ports};
  Object.assign(state,{hidden:new Set(),color:'exp',ports:false});
  try{
    const G=flatGeometry(),V={sel:null,aOp:{},fv:{}};
    ASSETS.forEach(a=>V.aOp[a.id]=1);FLOWS.forEach(f=>V.fv[f.id]={vis:true,op:f.risk?0.95:0.8});
    return afFit(flatSvgMarkup(G,V,true,n=>PAPER[n]||PAPER['--fg']));
  }finally{Object.assign(state,keep);}
}
async function afHistory(){
  if(!Store.features.history)return null;
  try{const j=await Store.api('GET','api/history?limit=500');return (j.entries||[]).filter(h=>h.site===SITE.id).slice(0,60);}catch(e){return null;}
}
async function buildArchFile(){
  const s=SITE,now=new Date(),date=now.toISOString().slice(0,10);
  const crit=a=>`<span class="t ${['none','low','med','crit'][a.crit]||'none'}">${CRIT_LBL[a.crit]||'—'}</span>`;
  const vl=a=>{const v=vlanById[a.vlan];return v?`${esc(v.num)} · ${esc(v.name)}`:'';};
  const vulns=ASSETS.flatMap(a=>a.vulns.map(v=>({a,v}))).sort((x,y)=>SEV[y.v.sev].rank-SEV[x.v.sev].rank||(y.v.kev?1:0)-(x.v.kev?1:0)||(+y.v.cvss||0)-(+x.v.cvss||0));
  const kev=vulns.filter(x=>x.v.kev).length,P=SA.attackPaths(s,SA.outside(s),s.critIds),cut=SA.chokePoints(s,P.byTarget).filter(c=>c.every.length);
  const inReach=s.critIds.filter(id=>s.atkOut.has(id)).sort((x,y)=>s.atkOut.get(y).p-s.atkOut.get(x).p);
  const fws=ASSETS.filter(a=>a.type==='firewall'),inter=ASSETS.filter(a=>INTERCO.has(a.type));
  const unfiltered=FLOWS.filter(f=>f.level!=='intra'&&!f.via.some(id=>byId[id].type==='firewall'));
  const plans=ASSETS.filter(a=>!INTERCO.has(a.type)&&(a.exp==='internet'||s.critIds.includes(a.id))).sort((x,y)=>EXP[y.exp].rank-EXP[x.exp].rank||y.crit-x.crit||x.name.localeCompare(y.name)).slice(0,12);
  const hist=await afHistory();
  const pathHtml=x=>x.path.map((id,i)=>{const f=i?FLOWS.find(y=>y.id===x.flows[i-1]):null;return esc(nameOf(id))+(f?` <span class="muted">${esc(f.port)}</span>`:'');}).join(' <i>→</i> ');
  const S=[['summary','Summary'],
    ['scope','Scope and context'],['arch','Architecture'],['inv','Asset inventory'],['flows','Flows and filtering'],['expo','Exposure'],
    ['vuln','Vulnerabilities and risk'],['attack','Attack paths'],['plans','Plans of the exposed and critical assets'],['contacts','Incident contacts'],['hist','Change history'],['method','Method and limits']];
  let n=0;const H=(id)=>{n++;return `<h2 id="${id}">${n}. ${esc(S.find(x=>x[0]===id)[1])}</h2>`;};
  const body=`<div class="af">
<section class="cover">
  <span class="kind">${esc(s.kind||'Information system')}</span>
  <h1>Architecture file</h1>
  <div class="is">IS ${esc(s.name)}</div>
  <p class="mark">Restricted. This document describes the weak spots of the information system: share it on a need-to-know basis, and keep it with the accreditation file.</p>
  <dl class="meta">
    <dt>Date</dt><dd>${esc(date)}</dd>
    <dt>Map version</dt><dd>${Store.mode==='api'?`v${esc(Store.rev)}`:'Copy kept in a browser (no version number)'}${Store.view==='preview'&&Store.preview?` · shown as of version ${esc(Store.preview.rev)}`:Store.view==='draft'?' · including a draft not yet approved':''}</dd>
    <dt>Generated by</dt><dd>Strata${Store.user?`, for ${esc(Store.user)}`:''}</dd>
    <dt>Status</dt><dd>Generated from the map. To be reviewed and signed by the IS owner.</dd>
  </dl>
</section>
<h3>Document control</h3>
${afTable(['Version','Date','Author','Change'],[[Store.mode==='api'?`v${esc(Store.rev)}`:'—',esc(date),esc(Store.user||'—'),'Generated from the Strata map']])}
<h3>Approval</h3>
${afTable(['Role','Name','Date','Signature'],[['IS owner','','',''],['Security officer (CISO)','','',''],['Accreditation authority','','','']],'sign')}
<h3>Contents</h3>
<ol class="toc">${S.map(([id,t])=>`<li><a href="#${id}">${esc(t)}</a></li>`).join('')}</ol>
${H('summary')}
<div class="figs">
  <div class="fig"><b>${s.stats.assets}</b><span>assets in ${plural(s.stats.vlans,'VLAN')}</span></div>
  <div class="fig"><b class="x-internet">${s.stats.xNet}</b><span>internet-facing assets</span></div>
  <div class="fig"><b class="crit">${s.stats.crit}</b><span>critical vulnerabilities${kev?`, ${kev} known exploited`:''}</span></div>
  <div class="fig"><b class="crit">${inReach.length}/${s.critIds.length}</b><span>critical assets reachable from the Internet</span></div>
</div>
<p>The IS counts ${plural(s.stats.assets,'asset')} in ${plural(s.zones.length,'zone')} and ${plural(s.stats.vlans,'VLAN')}, linked by ${plural(FLOWS.length,'recorded flow')}${s.stats.risk?`, ${s.stats.risk} of them marked risky`:''}. ${plural(s.stats.reach,'asset')} can be reached from the Internet along these flows. ${s.business.length?`It runs ${plural(s.business.length,'business service')}.`:''}</p>
<h3>Fix first</h3>
${afTable(['#','Vulnerability','Asset','Exposure','Score'],s.risk.fixes.slice(0,8).map((x,i)=>[i+1,`<b>${esc(x.vuln.id||'—')}</b> ${esc(x.vuln.title)}${x.vuln.kev?' <span class="t kev">KEV</span>':''}`,esc(byId[x.asset].name),afExp(byId[x.asset].exp),x.score]))}
${inReach.length?`<h3>Critical assets reachable from the Internet</h3>${afTable(['Asset','Most likely path','Likelihood'],inReach.slice(0,8).map(id=>[esc(byId[id].name),`<span class="path">${pathHtml(s.atkOut.get(id))}</span>`,`${Math.round(s.atkOut.get(id).p*100)}%`]))}`:''}

${H('scope')}
<p>${esc(s.kind||'Information system')} ${esc(s.name)}: ${s.zones.map(z=>esc(z.name)).join(', ')}.</p>
<h3>Business services</h3>
${afTable(['Service','Criticality','Owner','Runs on','Assets involved'],s.business.map(b=>[`<b>${esc(b.name)}</b>${b.notes?`<br><span class="muted">${esc(b.notes)}</span>`:''}`,`<span class="t ${['none','low','med','crit'][b.crit]}">${CRIT_LBL[b.crit]}</span>`,esc(b.owner||'—'),b.assets.map(id=>esc(byId[id].name)).join(', '),Object.keys(s.impact.byBusiness[b.id].assets).length]))}
<h3>Links to other information systems</h3>
${afTable(['With','Technology','MB/h','Note'],WAN.filter(w=>w.a===s.id||w.b===s.id).map(w=>[esc(siteById[w.a===s.id?w.b:w.a].name),esc(w.tech||''),w.vol,`${w.risk?'<span class="t crit">Risky</span> ':''}${esc(w.note||'')}`]))}
<h3>Internet services used</h3>
${afTable(['Service','Category','Hosts','Ports'],siteServices().map(x=>[esc(x.name),esc(x.category),`<span class="mono">${esc(x.hosts.join(', '))}</span>`,`<span class="mono">${esc(x.ports.join(' '))}</span>`]))}

${H('arch')}
<h3>Network diagram</h3>
<figure class="net">${afDiagram()}<figcaption>IS ${esc(s.name)}: zones as bands, VLANs as plates, flows coloured by exposure (Internet, between VLANs, inside a VLAN), through the equipment they cross. Dashed: risky flows.</figcaption></figure>
<h3>Zones and VLANs</h3>
${afTable(['Zone','VLAN','Name','Range','Assets'],s.zones.slice().reverse().flatMap(z=>z.vlans.map(v=>[esc(z.name),`<span class="mono">${esc(v.num)}</span>`,esc(v.name),`<span class="mono">${esc(v.cidr||'—')}</span>`,ASSETS.filter(a=>a.vlan===v.id).length])))}
<h3>Interconnection equipment</h3>
${afTable(['Equipment','Type','IP','VLAN','Flows crossing'],inter.map(a=>[`<b>${esc(a.name)}</b>`,esc(TYPE_LABEL[a.type]),`<span class="mono ip">${esc(a.ip||'')}</span>`,vl(a),FLOWS.filter(f=>f.via.includes(a.id)).length]))}
<h3>Applications</h3>
${afTable(['Application','Version','Runs on','Listening ports'],Object.values(ASSETS.flatMap(a=>a.apps.map(x=>({x,a}))).reduce((m,{x,a})=>{const k=x.name.toLowerCase();(m[k]=m[k]||{name:x.name,v:new Set(),on:[],ports:new Set()});if(x.version)m[k].v.add(x.version);m[k].on.push(a.name);x.ports.forEach(p=>m[k].ports.add(p));return m;},{})).sort((x,y)=>x.name.localeCompare(y.name)).map(x=>[`<b>${esc(x.name)}</b>`,esc([...x.v].join(', ')),esc(x.on.join(', ')),`<span class="mono">${esc([...x.ports].join(' '))}</span>`]))}

${H('inv')}
${afTable(['Asset','Type','IP','VLAN','System','Role','Criticality','Exposure','Worst vuln.','Risk'],s.zones.slice().reverse().flatMap(z=>z.vlans).flatMap(v=>ASSETS.filter(a=>a.vlan===v.id)).map(a=>[`<b>${esc(a.name)}</b>`,esc(TYPE_LABEL[a.type]),`<span class="mono ip">${esc(a.ip||'')}</span>`,vl(a),esc(a.os||''),esc(a.role||''),crit(a),afExp(a.exp),a.sev==='none'?'':afSev(a.sev),s.riskById[a.id]?s.riskById[a.id].score:'']))}

${H('flows')}
<h3>Flow matrix</h3>
${afTable(['#','Source','Destination','Port','Path','Exposure','MB/h','Note'],FLOWS.slice().sort((x,y)=>EXP[y.level].rank-EXP[x.level].rank||nameOf(x.src).localeCompare(nameOf(y.src))||nameOf(x.dst).localeCompare(nameOf(y.dst))).map((f,i)=>[i+1,esc(nameOf(f.src)),esc(nameOf(f.dst)),`<span class="mono">${esc(f.port)}</span>`,f.via.length?esc(f.via.map(nameOf).join(' › '))+(f.viaAuto?' <span class="muted">(suggested)</span>':''):'<span class="muted">direct</span>',afExp(f.level),f.vol,`${f.risk?'<span class="t crit">Risky</span> ':''}${esc(f.note||'')}`]))}
<h3>Filtering: rules each firewall needs</h3>
<p class="note">One allow rule per flow and per firewall crossed, then the default deny. Addresses and zones are those of the map: map them to the objects of each firewall before comparing with its configuration.</p>
${fws.length?fws.map(fw=>{const R=fwRules(fw).rules.filter(r=>r.fw===fw.name);return `<h3>${esc(fw.name)} <span class="muted">${esc(fw.ip||'')}</span></h3>${afTable(['Rule','Source','Destination','Service','Action','Comment'],[...R.map(r=>[r.n,`${esc(r.src)}<br><span class="mono muted">${esc(r.srcAddr)} · ${esc(r.srcZone)}</span>`,`${esc(r.dst)}<br><span class="mono muted">${esc(r.dstAddr)} · ${esc(r.dstZone)}</span>`,`<span class="mono">${esc(r.service)}</span>`,'accept',esc(r.comment)]),[R.length+1,'any','any','any','<b>deny</b>','Default rule']])}`;}).join(''):'<p class="muted">No firewall recorded on this IS.</p>'}
<h3>Flows between VLANs or with the Internet that cross no firewall</h3>
${afTable(['Source','Destination','Port','Exposure','Path'],unfiltered.map(f=>[esc(nameOf(f.src)),esc(nameOf(f.dst)),`<span class="mono">${esc(f.port)}</span>`,afExp(f.level),f.via.length?esc(f.via.map(nameOf).join(' › ')):'direct']))}

${H('expo')}
<h3>Exposed ports</h3>
${afTable(['Asset','VLAN','Port','Exposure','Application','Reached from'],ASSETS.flatMap(a=>a.ports.map(p=>({a,p}))).sort((x,y)=>EXP[y.p.level].rank-EXP[x.p.level].rank||x.a.name.localeCompare(y.a.name)).map(({a,p})=>{const ap=appOn(a,p.port);return [`<b>${esc(a.name)}</b>`,vl(a),`<span class="mono">${esc(p.port)}</span>`,afExp(p.level),ap?esc(`${ap.name} ${ap.version}`.trim()):'',esc(p.from.map(nameOf).join(', '))];}))}
<h3>Reachable from the Internet</h3>
${afTable(['Hops','Asset','VLAN','Worst vuln.'],ASSETS.filter(a=>EXPO[a.id]!==undefined).sort((a,b)=>EXPO[a.id]-EXPO[b.id]||a.name.localeCompare(b.name)).map(a=>[EXPO[a.id],`<b>${esc(a.name)}</b>`,vl(a),a.sev==='none'?'':afSev(a.sev)]))}
<h3>Flows marked risky</h3>
${afTable(['Source','Destination','Port','Note'],FLOWS.filter(f=>f.risk).map(f=>[esc(nameOf(f.src)),esc(nameOf(f.dst)),`<span class="mono">${esc(f.port)}</span>`,esc(f.note||'')]))}

${H('vuln')}
<h3>Remediation order</h3>
${afTable(['#','Vulnerability','Asset','CVSS','EPSS','Exposure','Score'],s.risk.fixes.slice(0,40).map((x,i)=>[i+1,`<b>${esc(x.vuln.id||'—')}</b> ${esc(x.vuln.title)}${x.vuln.kev?' <span class="t kev">KEV</span>':''}`,esc(byId[x.asset].name),x.vuln.cvss==null?'':(+x.vuln.cvss).toFixed(1),x.vuln.epss==null?'':`${(x.vuln.epss*100).toFixed(1)}%`,afExp(byId[x.asset].exp),x.score]))}
${s.risk.fixes.length>40?`<p class="muted">${s.risk.fixes.length-40} more in the remediation list (CSV), from Analysis › Risk priorities.</p>`:''}
<h3>Assets by risk score</h3>
${afTable(['Asset','VLAN','Criticality','Exposure','Score'],s.risk.assets.map(r=>{const a=byId[r.id];return [`<b>${esc(a.name)}</b>`,vl(a),crit(a),afExp(a.exp),`<span class="${AF_CLS[r.band]||'none'}">${r.score}</span>`];}))}
<h3>All vulnerabilities</h3>
${afTable(['Reference','Title','Asset','Severity','CVSS','EPSS','Source'],vulns.map(({a,v})=>[`<span class="mono">${esc(v.id||'—')}</span>${v.kev?' <span class="t kev">KEV</span>':''}`,esc(v.title),esc(a.name),afSev(v.sev),v.cvss==null?'':(+v.cvss).toFixed(1),v.epss==null?'':`${(v.epss*100).toFixed(1)}%`,esc(v.src||'entered by hand')]))}

${H('attack')}
<p>${s.critIds.length?`${inReach.length} of the ${plural(s.critIds.length,'critical asset')} can be reached from the Internet along the allowed flows.`:'No asset is marked critical on this IS (criticality High, of its own or through a business service).'}</p>
${inReach.length?afTable(['Critical asset','Path','Steps','Likelihood'],inReach.flatMap(id=>{const l=(P.byTarget[id]&&P.byTarget[id].length?P.byTarget[id]:[s.atkOut.get(id)]).slice(0,3);return l.map((x,i)=>[i?'':`<b>${esc(byId[id].name)}</b>`,`<span class="path">${pathHtml(x)}</span>`,x.path.length-1,`${x.p<0.01?'<1':Math.round(x.p*100)}%`]);})):''}
${cut.length?`<h3>Where to cut</h3><p>Every path to these critical assets goes through:</p>${afTable(['Asset or equipment','Role on the paths','Cuts off'],cut.slice(0,10).map(c=>[`<b>${esc(byId[c.id].name)}</b>`,c.kind==='equipment'?'Crossed: tighten its rules':c.held<c.paths?'Crossed, and taken over on some paths':'Taken over on the way: harden it',esc(c.every.map(id=>byId[id].name).join(', '))]))}`:''}
${s.critIds.filter(id=>!s.atkOut.has(id)).length?`<p class="muted">Out of reach from the Internet: ${esc(s.critIds.filter(id=>!s.atkOut.has(id)).map(id=>byId[id].name).join(', '))}.</p>`:''}

${H('plans')}
<p>The direct flows of the internet-facing and critical assets${plans.length===12?' (the first twelve)':''}, with the equipment they cross.</p>
${plans.map(a=>`<figure>${afFit(buildPlanSvg(a,false,false,{dir:'all',lv:['internet','inter','intra']}).svg)}<figcaption>${esc(a.name)} · ${esc(TYPE_LABEL[a.type])} · ${esc(a.ip||'')} · VLAN ${vl(a)}</figcaption></figure>`).join('')||'<p class="muted">None.</p>'}

${H('contacts')}
<h3>IS contacts</h3>
${afTable(['Name','Role','Phone','Email','Availability'],s.contacts.map(c=>[esc(c.name),esc(c.role),`<span class="mono">${esc(c.phone||'')}</span>`,esc(c.email||''),esc(c.dispo||'')]))}
<h3>Asset contacts</h3>
${afTable(['Asset','Name','Role','Phone','Email','Availability'],ASSETS.flatMap(a=>a.contacts.filter(c=>c.name||c.phone||c.email).map((c,i)=>[i?'':`<b>${esc(a.name)}</b>`,esc(c.name),esc(c.role),`<span class="mono">${esc(c.phone||'')}</span>`,esc(c.email||''),esc(c.dispo||'')])))}

${H('hist')}
${hist?afTable(['Version','Date','By','Change'],hist.map(h=>[`<span class="mono">v${esc(h.rev)}</span>`,esc(new Date(h.at).toLocaleString()),esc(h.user||'—'),esc(h.label||`${{si:'IS',assets:'asset',wan:'inter-IS links',services:'Internet services',all:'whole map'}[h.kind]||h.kind} ${h.name?'“'+h.name+'” ':''}${h.op||''}`)])):'<p class="muted">No history: this map is kept in a browser only. On a Strata server, every change is recorded with its author and date, and listed here.</p>'}

${H('method')}
<p><b>Source.</b> Everything in this file comes from the Strata map of the IS: entered by hand, imported, or read by the connectors (Cyberwatch, GLPI, phpIPAM, Palo Alto) and approved before publication. A flow missing from the map is missing here.</p>
<p><b>Exposure.</b> An asset is exposed at the widest level of the flows it receives: from the Internet, from another VLAN, or from its own VLAN.</p>
<p><b>Risk score.</b> 0 to 100 per asset: each vulnerability counts for its severity (CVSS) times its likelihood of exploitation (certain on the CISA list of known exploited vulnerabilities, otherwise from its EPSS, otherwise 30%), weighed by the exposure of the asset, its reachability from the Internet, and its criticality or that of the business services it would hit.</p>
<p><b>Attack paths.</b> An attacker who holds an asset can open the flows that leave it. Taking the next asset over counts for the highest of its vulnerabilities, 50% on a remote administration port (SSH, RDP, SMB, WinRM, VNC, Telnet, RPC), 10% on any other service; a path for the product of its steps. These likelihoods rank paths; they are not measured probabilities.</p>
<p><b>Firewall rules.</b> Derived from the flows and the equipment they cross, as a generic table: they are what the architecture needs, to compare with the configuration in place.</p>
</div>`;
  return {body,html:`<!doctype html>\n<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Architecture file · IS ${esc(s.name)} · ${esc(date)}</title><style>${ARCH_CSS}</style></head><body style="margin:0;background:#fff">${body}</body></html>`,date};
}
let ARCHF=null;
async function openArchFile(){
  if(!SITE)return;
  const host=$('#archView');host.innerHTML='<p class="archwait">Building the architecture file…</p>';$('#archf').hidden=false;document.body.classList.add('has-plan');
  $('#archTitle').textContent=`IS ${SITE.name}`;
  try{ARCHF=await buildArchFile();}catch(e){host.innerHTML='';closeArchFile();toast('The architecture file could not be built: '+e.message,true);return;}
  host.innerHTML='';const root=host.shadowRoot||host.attachShadow({mode:'open'});
  root.innerHTML=`<style>${ARCH_CSS}:host{display:block}.af{box-shadow:0 1px 6px rgba(0,0,0,.25);margin:0 auto 24px}</style>${ARCHF.body}`;
  root.querySelectorAll('.toc a').forEach(a=>a.addEventListener('click',e=>{e.preventDefault();const t=root.getElementById(a.getAttribute('href').slice(1));if(t)t.scrollIntoView({behavior:reduceMotion?'auto':'smooth'});}));
  host.scrollTop=0;
}
function closeArchFile(){$('#archf').hidden=true;if($('#plan').hidden)document.body.classList.remove('has-plan');const h=$('#archView');if(h.shadowRoot)h.shadowRoot.innerHTML='';ARCHF=null;}

/* ================= Forms ================= */
let onSave=null,onCancel=null;
const fIn=(id,label,val,attrs='',hint='')=>`<div class="f"><label for="${esc(id)}">${label}</label><input id="${esc(id)}" value="${esc(val)}" ${attrs}>${hint?`<span class="hint">${hint}</span>`:''}</div>`;
const fSel=(id,label,opts,val)=>`<div class="f"><label for="${esc(id)}">${label}</label><select id="${esc(id)}">${opts.map(o=>o.group?`<optgroup label="${esc(o.group)}">${o.items.map(([v,t])=>`<option value="${esc(v)}"${String(v)===String(val)?' selected':''}>${esc(t)}</option>`).join('')}</optgroup>`:`<option value="${esc(o[0])}"${String(o[0])===String(val)?' selected':''}>${esc(o[1])}</option>`).join('')}</select></div>`;
const roleOpts=v=>CONTACT_ROLES.map(r=>`<option${r===v?' selected':''}>${esc(r)}</option>`).join('');
const REP={
  contact:(c={})=>`<div class="rep" data-rep="contact"><div class="rep-grid">
    <input data-k="name" aria-label="Name or team" placeholder="Name or team" value="${esc(c.name)}">
    <select data-k="role" aria-label="Role">${roleOpts(roleEn(c.role)||'Technical owner')}</select>
    <input data-k="phone" aria-label="Phone" placeholder="Phone" inputmode="tel" value="${esc(c.phone)}">
    <input data-k="email" aria-label="Email" placeholder="Email" type="email" value="${esc(c.email)}">
    <input class="full" data-k="dispo" aria-label="Availability" placeholder="Availability (e.g. 24/7, business hours)" value="${esc(c.dispo)}">
    </div><div class="rep-foot"><button type="button" class="rm" data-rm>Remove this contact</button></div></div>`,
  vuln:(v={})=>`<div class="rep" data-rep="vuln"><div class="rep-grid">
    <input data-k="id" aria-label="Reference" placeholder="CVE-2024-… or Config." value="${esc(v.id)}">
    <input data-k="cvss" aria-label="CVSS score" placeholder="CVSS (0 to 10)" type="number" min="0" max="10" step="0.1" value="${v.cvss==null?'':esc(v.cvss)}">
    <input class="full" data-k="title" aria-label="Title" placeholder="Title" value="${esc(v.title)}">
    <select class="full" data-k="sev" aria-label="Severity"><option value="">Severity from CVSS</option>${['crit','high','med','low'].map(k=>`<option value="${k}"${v.sev===k&&v.cvss==null?' selected':''}>${SEV[k].label}</option>`).join('')}</select>
    <input data-k="epss" aria-label="EPSS" placeholder="EPSS (0 to 1, or %)" inputmode="decimal" value="${v.epss==null?'':esc(v.epss)}">
    <label class="chk plain"><input type="checkbox" data-k="kev"${v.kev?' checked':''}>Known exploited (CISA KEV)</label>
    <input type="hidden" data-k="src" value="${esc(v.src||'')}">
    </div><div class="rep-foot"><button type="button" class="rm" data-rm>Remove</button></div></div>`,
  app:(x={})=>`<div class="rep" data-rep="app"><div class="rep-grid">
    <input data-k="name" aria-label="Application" placeholder="Application (e.g. Apache Tomcat)" value="${esc(x.name)}">
    <input data-k="version" aria-label="Version" placeholder="Version" value="${esc(x.version)}">
    <input class="full" data-k="ports" aria-label="Listening ports" placeholder="Listening ports, e.g. tcp/8080, tcp/443" value="${esc(Array.isArray(x.ports)?x.ports.join(', '):x.ports)}">
    </div><div class="rep-foot"><button type="button" class="rm" data-rm>Remove</button></div></div>`
};
function readRep(form,kind){return [...form.querySelectorAll(`[data-rep="${kind}"]`)].map(r=>{const o={};r.querySelectorAll('[data-k]').forEach(i=>o[i.dataset.k]=i.type==='checkbox'?i.checked:i.value.trim());return o;});}
function openForm(title,sub,body,save,{del,cancel}={}){
  onSave=save;onCancel=cancel||null;
  openDet(`<div class="d-head"><div><span class="cap">${esc(sub)}</span><h2>${esc(title)}</h2></div><button class="close" data-cancel aria-label="Cancel">×</button></div>
  <form class="frm" id="frm" novalidate>${body}<p class="form-err" id="ferr" hidden></p>
  <div class="form-foot"><button type="button" class="btn small" data-cancel>Cancel</button><button type="submit" class="btn small primary">Save</button></div>
  ${del?`<button type="button" class="btn small danger" data-del>${esc(del.label)}</button>`:''}</form>`,'form');
  det._del=del||null;
  const first=det.querySelector('input,select');if(first&&innerWidth>760)first.focus();
}
function formErr(msg,fieldId){const e=$('#ferr');e.textContent=msg;e.hidden=false;if(fieldId){const f=$('#'+fieldId);if(f){f.closest('.f')&&f.closest('.f').classList.add('err');f.focus();}}}
function cancelForm(){const c=onCancel;onSave=null;onCancel=null;if(c)c();else restorePanel();}
function restorePanel(){
  if(state.view==='overview'){const s=ovSel();if(s)showSite(s);else closeDet();return;}
  const f=state.panel==='flow'||state.flowId?FLOWS.find(x=>x.id===state.flowId):null;
  const a=selAsset();if(f&&!a)showFlow(f);else if(a)showAsset(a);else if(state.path)showPath();else closeDet();
}

function siteForm(s){
  const d=s?clone(s.raw):{name:'',kind:'',zones:[{id:uid('z'),name:'Office'},{id:uid('z'),name:'Core IT'},{id:uid('z'),name:'Exposed'}],vlans:[],flows:[],contacts:[]};
  if(!d.zones||!d.zones.length)d.zones=[{id:uid('z'),name:'Main zone'}];
  const zRow=z=>`<div class="zrow" data-zone="${esc(z.id)}"><input aria-label="Zone name" value="${esc(z.name)}"><button type="button" class="mv" data-up aria-label="Move up">↑</button><button type="button" class="mv" data-down aria-label="Move down">↓</button><button type="button" class="rm" data-rmzone>Remove</button></div>`;
  openForm(s?`IS ${s.name}`:'New IS',s?'Edit the IS':'Create an information system',`
    ${fIn('fName','IS name *',d.name,'required maxlength="60" placeholder="e.g. Lyon, West Datacenter"')}
    ${fIn('fKind','Site type',d.kind,'maxlength="60" placeholder="e.g. Head office, Warehouse"')}
    <fieldset><legend>Zones, top to bottom</legend><span class="fhint">One zone = one level of the model. The first zone in the list sits at the top.</span>
      <div id="zones" class="btns">${d.zones.slice().reverse().map(zRow).join('')}</div>
      <button type="button" class="add" data-addzone>+ Add a zone</button></fieldset>
    <fieldset><legend>IS contacts</legend><span class="fhint">Shown on assets that have no contact of their own.</span>
      <div id="repContact" class="btns">${(d.contacts||[]).map(c=>REP.contact(c)).join('')}</div>
      <button type="button" class="add" data-add="contact" data-into="repContact">+ Add a contact</button></fieldset>`,
  async()=>{
    const name=$('#fName').value.trim();if(!name)return formErr('The IS name is required.','fName');
    const zones=[...det.querySelectorAll('#zones .zrow')].map(r=>({id:r.dataset.zone,name:r.querySelector('input').value.trim()||'Zone'})).reverse();
    if(!zones.length)return formErr('Keep at least one zone.');
    const zIds=new Set(zones.map(z=>z.id));
    const vlans=(d.vlans||[]).map(v=>zIds.has(v.zone)?v:Object.assign({},v,{zone:zones[0].id}));
    // fields this form does not show (site services, business services…) are kept as they are
    const doc=Object.assign({},d,{name,kind:$('#fKind').value.trim(),order:s?(d.order||0):(SITES.reduce((m,x)=>Math.max(m,x.order||0),0)+1),zones,vlans,flows:d.flows||[],contacts:readRep(det,'contact').filter(c=>c.name||c.phone||c.email)});
    const id=s?s.id:uid('si-');
    await Store.putSite(id,doc);toast(s?'IS saved.':'IS created.');
    if(!s){state.ovSelId=id;afterSave(()=>{const ns=siteById[id];if(ns&&state.view==='overview')showSite(ns);else restorePanel();});}
    else afterSave(()=>restorePanel());
  },{del:s?{label:`Delete the IS and its ${plural(s.stats.assets,'asset')}`,run:async()=>{
    await Store.many([...Object.keys(raw.assets).filter(id=>raw.assets[id].site===s.id).map(id=>()=>Store.delAsset(id)),()=>Store.delSite(s.id),()=>Store.putWan((raw.wan||[]).filter(w=>w.a!==s.id&&w.b!==s.id))],'Deleting the IS');
    state.ovSelId=null;if(state.view==='site')backToOverview();else closeDet();
  }}:null});
  det._zRow=zRow;
}
function vlanForm(v){
  const zones=SITE.raw.zones&&SITE.raw.zones.length?SITE.raw.zones:[{id:'z-def',name:'Main zone'}];
  const used=ASSETS.filter(a=>v&&a.vlan===v.id);
  openForm(v?`VLAN ${v.num}`:'New VLAN',`IS ${SITE.name}`,`
    <div class="f2">${fIn('fNum','Number *',v?v.num:'','type="number" min="1" max="4094" required')}${fIn('fCidr','Address range',v?v.cidr:'','placeholder="10.20.0.0/24"')}</div>
    ${fIn('fName','Name *',v?v.name:'','required maxlength="50" placeholder="e.g. Servers, Guest Wi-Fi"')}
    ${fSel('fZone','Zone',[...zones.slice().reverse().map(z=>[z.id,z.name]),['__new','New zone…']],v?v.zoneId:zones[zones.length-1].id)}
    <div class="f" id="newZoneBox" hidden><label for="fNewZone">New zone name (placed at the top)</label><input id="fNewZone" maxlength="40"></div>`,
  async()=>{
    const num=parseInt($('#fNum').value,10),name=$('#fName').value.trim();
    if(!(num>=1&&num<=4094))return formErr('The VLAN number must be between 1 and 4094.','fNum');
    if(!name)return formErr('The VLAN name is required.','fName');
    const d=clone(SITE.raw);d.zones=d.zones&&d.zones.length?d.zones:clone(zones);d.vlans=d.vlans||[];
    if(d.vlans.some(x=>x.num===num&&(!v||x.id!==v.id)))return formErr(`VLAN ${num} already exists in this IS.`,'fNum');
    let zone=$('#fZone').value;
    if(zone==='__new'){const zn=$('#fNewZone').value.trim();if(!zn)return formErr('Name the new zone.','fNewZone');zone=uid('z');d.zones.push({id:zone,name:zn});}
    const doc={id:v?v.id:uid('v'),num,name,cidr:$('#fCidr').value.trim(),zone};
    if(v)d.vlans=d.vlans.map(x=>x.id===v.id?doc:x);else d.vlans.push(doc);
    await Store.putSite(SITE.id,d);toast(v?'VLAN saved.':'VLAN added.');afterSave(()=>restorePanel());
  },{del:v?{label:used.length?`Delete the VLAN and its ${plural(used.length,'asset')}`:'Delete the VLAN',run:async()=>{
    const d=clone(SITE.raw);d.vlans=(d.vlans||[]).filter(x=>x.id!==v.id);
    const gone=new Set(used.map(a=>a.id));d.flows=(d.flows||[]).filter(f=>!gone.has(f.src)&&!gone.has(f.dst));
    if(gone.has(state.selId))state.selId=null;
    await Store.many([...used.map(a=>()=>Store.delAsset(a.id)),()=>Store.putSite(SITE.id,d)],'Deleting the VLAN');
    closeDet();
  }}:null});
  $('#fZone').addEventListener('change',e=>{$('#newZoneBox').hidden=e.target.value!=='__new';});
}
function assetForm(a,presetVlan,opts={}){
  if(!VLANS.length){toast('Add a VLAN to this IS first.',true);return vlanForm(null);}
  const vOpts=ZONES.slice().reverse().filter(z=>z.vlans.length).map(z=>({group:z.name,items:z.vlans.map(v=>[v.id,`VLAN ${v.num} · ${v.name}`])}));
  const d=a?clone(raw.assets[a.id]):{name:'',type:'server',vlan:presetVlan||VLANS[VLANS.length-1].id,ip:'',os:'',role:'',crit:2,vulns:[],contacts:[],apps:[],notes:''};
  openForm(a?a.name:'New asset',`IS ${SITE.name}`,`
    ${fIn('fName','Name *',d.name,'required maxlength="60" placeholder="e.g. srv-erp-01"')}
    <div class="f2">${fSel('fType','Type',Object.entries(TYPE_LABEL),d.type)}${fSel('fCrit','Business criticality',[[1,'Low'],[2,'Medium'],[3,'High']],d.crit)}</div>
    ${fSel('fVlan','VLAN *',vOpts,d.vlan)}
    <div class="f2">${fIn('fIp','IP address',d.ip,'placeholder="10.20.0.15" inputmode="decimal"')}${fIn('fOs','System / version',d.os,'placeholder="Windows Server 2022"')}</div>
    ${fIn('fRole','Role',d.role,'maxlength="80" placeholder="e.g. File server"')}
    <fieldset><legend>Applications</legend>
      <span class="fhint">What runs on the system. A flow that reaches one of these ports is shown arriving on that application in the 2D plan.</span>
      <div id="repApp" class="btns">${(d.apps||[]).map(x=>REP.app(x)).join('')}</div>
      <button type="button" class="add" data-add="app" data-into="repApp">+ Add an application</button></fieldset>
    <fieldset><legend>Incident contacts</legend>
      <span class="fhint">With no contact here, the sheet shows the IS contacts.</span>
      <div id="repContact" class="btns">${(d.contacts||[]).map(c=>REP.contact(c)).join('')}</div>
      <button type="button" class="add" data-add="contact" data-into="repContact">+ Add a contact</button></fieldset>
    <fieldset><legend>Vulnerabilities</legend>
      <div id="repVuln" class="btns">${(d.vulns||[]).map(v=>REP.vuln(v)).join('')}</div>
      <button type="button" class="add" data-add="vuln" data-into="repVuln">+ Add a vulnerability</button></fieldset>
    ${SITE.business.length?`<fieldset><legend>Business services it runs</legend><span class="fhint">Services that rely on it through the flows are worked out on their own.</span>
      <div class="btns">${SITE.business.map(b=>`<label class="chk plain"><input type="checkbox" data-asset-biz="${esc(b.id)}"${a&&b.assets.includes(a.id)?' checked':''}>${esc(b.name)}</label>`).join('')}</div></fieldset>`:''}
    <div class="f"><label for="fNotes">Notes</label><textarea id="fNotes" maxlength="2000" placeholder="Restart procedure, dependencies…">${esc(d.notes)}</textarea></div>
    <p class="fhint">Exposed ports come from the inbound flows. Add them from the asset sheet with “+ Inbound flow”.</p>`,
  async()=>{
    const name=$('#fName').value.trim();if(!name)return formErr('The asset name is required.','fName');
    const ip=$('#fIp').value.trim();
    if(ip&&!/^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/.test(ip))return formErr('Invalid IP address (expected format: 10.20.0.15).','fIp');
    const vulns=[];
    for(const v of readRep(det,'vuln')){if(!v.id&&!v.title)continue;
      const cv=v.cvss===''?null:parseFloat(v.cvss.replace(',','.'));
      if(cv!=null&&!(cv>=0&&cv<=10))return formErr('The CVSS score must be between 0 and 10.');
      if(cv==null&&!v.sev)return formErr(`Give a CVSS score or a severity for “${v.title||v.id}”.`);
      const ep=epssOf(v.epss);if(v.epss&&ep==null)return formErr(`Give the EPSS of “${v.title||v.id}” as a number from 0 to 1, or a percentage.`);
      const nv={id:v.id||'Config.',title:v.title||v.id,cvss:cv,sev:cv!=null?sevFromCvss(cv):v.sev};
      if(ep!=null)nv.epss=ep;if(v.kev)nv.kev=true;if(v.src)nv.src=v.src;
      vulns.push(nv);}
    const id=a?a.id:uid('a-');
    const doc={site:SITE.id,name,type:$('#fType').value,vlan:$('#fVlan').value,ip,os:$('#fOs').value.trim(),role:$('#fRole').value.trim(),crit:+$('#fCrit').value,vulns,
      contacts:readRep(det,'contact').filter(c=>c.name||c.phone||c.email),notes:$('#fNotes').value.trim()};
    const apps=[];
    for(const x of readRep(det,'app')){if(!x.name)continue;const ports=parsePorts(x.ports);
      if(ports.some(p=>!/^(tcp|udp|icmp|any)(\/[\d-]+)?$/.test(p)))return formErr(`Write the ports of “${x.name}” as protocol/number, e.g. tcp/8080.`);
      apps.push({name:x.name,version:x.version,ports});}
    doc.apps=apps;
    // business services it runs: saved on the IS, only when the ticks changed
    const want=new Set([...det.querySelectorAll('[data-asset-biz]:checked')].map(x=>x.dataset.assetBiz));
    const sd=clone(SITE.raw);let bizChanged=false;
    (sd.business||[]).forEach(b=>{const has=(b.assets||[]).includes(id);if(has!==want.has(b.id)){bizChanged=true;b.assets=has?b.assets.filter(x=>x!==id):[...(b.assets||[]),id];}});
    if(bizChanged)await Store.many([()=>Store.putAsset(id,doc),()=>Store.putSite(SITE.id,sd)],'Saving');else await Store.putAsset(id,doc);
    toast(a?'Asset saved.':'Asset added.');
    // placed by clicking in the 2D diagram: keep that spot (the plate's other assets stay where they are)
    if(!a&&opts.pos&&FL&&doc.vlan===presetVlan){const l=frozen(doc.vlan);l[id]=opts.pos;try{await saveLayouts({[doc.vlan]:l});}catch(e){}}
    state.selId=id;afterSave(()=>{const na=byId[id];if(na){state.hidden.delete(na.vlan);showAsset(na);refresh();}else closeDet();});
  },{del:a?{label:'Delete the asset',run:async()=>{
    const d=clone(SITE.raw);d.flows=(d.flows||[]).filter(f=>f.src!==a.id&&f.dst!==a.id);
    state.selId=null;await Store.many([()=>Store.delAsset(a.id),()=>Store.putSite(SITE.id,d)],'Deleting');closeDet();
  }}:null});
  ipFromVlan(a);
}
// The IP field follows the VLAN range: a new asset starts on the first free address of its VLAN,
// and an address outside the range of the VLAN picked is pointed out, with the free one to use instead
function ipFromVlan(a){
  const ipIn=$('#fIp'),vSel=$('#fVlan'),hint=document.createElement('span');hint.className='hint';hint.id='ipHint';ipIn.after(hint);
  const used=()=>ASSETS.filter(x=>!a||x.id!==a.id).map(x=>x.ip).filter(Boolean);
  let auto=null;
  const sync=fromVlan=>{
    const v=vlanById[vSel.value],cidr=v&&v.cidr,cur=ipIn.value.trim();
    const free=cidr?SA.nextFreeIp(cidr,used()):null;
    if(!a&&fromVlan&&(cur===''||cur===auto)){auto=free;ipIn.value=free||'';}
    const ip=ipIn.value.trim();
    if(!cidr)hint.innerHTML=ip?'':'This VLAN has no address range: give the IP by hand.';
    else if(ip&&/^[\d.]+$/.test(ip)&&!SA.inCidr(ip,cidr))hint.innerHTML=`<span class="warn">Outside VLAN ${esc(v.num)} (${esc(cidr)}).</span>${free?` <button type="button" class="linkbtn" data-use-ip="${esc(free)}">Use ${esc(free)}</button>`:''}`;
    else if(ip&&ip===auto)hint.innerHTML=`First free address in ${esc(cidr)}.`;
    else if(!ip&&!free)hint.innerHTML=`No free address left in ${esc(cidr)}.`;
    else hint.innerHTML='';
  };
  vSel.addEventListener('change',()=>sync(true));
  ipIn.addEventListener('input',()=>sync(false));
  hint.addEventListener('click',e=>{const b=e.target.closest('[data-use-ip]');if(b){ipIn.value=auto=b.dataset.useIp;sync(false);}});
  sync(true);
}
// preset: {src} for an outbound flow, {dst} for an inbound flow
function flowForm(f,preset={}){
  if(!ASSETS.length){toast('Add some assets first.',true);return;}
  const svcOpts=SITE.services.length?[{group:'Internet services',items:SITE.services.map(x=>[x.id,`${x.name}${x.scope==='site'?' (this IS)':''}`])}]:[];
  const opts=[['internet','Internet (any address)'],...svcOpts,...ZONES.slice().reverse().flatMap(z=>z.vlans.slice().reverse().flatMap(v=>ASSETS.filter(a=>a.vlan===v.id).map(a=>[a.id,`${a.name} · VLAN ${v.num}`])))];
  const d=f?{id:f.id,src:f.src,dst:f.dst,port:f.port,vol:f.vol,risk:f.risk,note:f.note||'',via:f.via.slice(),viaAuto:f.viaAuto}:{src:preset.src||(preset.dst?'internet':ASSETS[0].id),dst:preset.dst||(preset.src?'internet':ASSETS[0].id),port:'tcp/443',vol:10,risk:false,note:''};
  if(!f&&d.src===d.dst)d.dst='internet';
  const title=f?'Flow':preset.src&&preset.dst?'New flow':preset.dst?`Inbound flow to ${nameOf(preset.dst)}`:preset.src?`Outbound flow from ${nameOf(preset.src)}`:'New flow';
  openForm(title,`IS ${SITE.name}`,`
    <div class="swapRow">${fSel('fSrc','Source *',opts,d.src)}<button type="button" class="swap" data-swap aria-label="Swap source and destination">⇄</button>${fSel('fDst','Destination *',opts,d.dst)}</div>
    <p class="levelPreview" id="levelPreview"></p>
    <div class="f2">${fIn('fPort','Destination port',d.port,'placeholder="tcp/443"','Protocol/port, e.g. tcp/443 or udp/53')}${fIn('fVol','Volume (MB/h)',d.vol,'type="number" min="1" step="1"')}</div>
    <fieldset><legend>Path through the network</legend>
      <label class="chk plain" for="fViaAuto"><input type="checkbox" id="fViaAuto" ${d.viaAuto!==false?'checked':''}>Suggest the equipment from the topology</label>
      <div id="viaList" class="btns"></div>
      <button type="button" class="add" data-addvia>+ Add equipment crossed</button>
      <span class="fhint" id="viaHint"></span></fieldset>
    <label class="chk" for="fRisk"><input type="checkbox" id="fRisk" ${d.risk?'checked':''}>Risky flow</label>
    ${fIn('fNote','Why this flow is risky',d.note,'maxlength="140" placeholder="e.g. direct RDP without the bastion"')}`,
  async()=>{
    const src=$('#fSrc').value,dst=$('#fDst').value;
    if(src===dst)return formErr('Source and destination must be different.','fDst');
    if(isNet(src)&&isNet(dst))return formErr('One side of the flow must be an asset of this IS.','fDst');
    let port=$('#fPort').value.trim().toLowerCase().replace(/\s+/g,'');
    if(/^\d+$/.test(port))port='tcp/'+port;
    if(port&&!/^(tcp|udp|icmp|any)(\/[\d-]+)?$/.test(port))return formErr('Write the port as protocol/number, e.g. tcp/443.','fPort');
    const doc={id:f?f.id:uid('f'),src,dst,port:port||'tcp/?',vol:Math.max(1,parseInt($('#fVol').value,10)||1),risk:$('#fRisk').checked,note:$('#fNote').value.trim()};
    if(!$('#fViaAuto').checked)doc.via=[...det.querySelectorAll('#viaList select')].map(x=>x.value).filter((id,i,arr)=>id&&id!==src&&id!==dst&&arr.indexOf(id)===i);
    const sd=clone(SITE.raw);sd.flows=sd.flows||[];
    if(f)sd.flows=sd.flows.map(x=>x.id===f.id?doc:x);else sd.flows.push(doc);
    await Store.putSite(SITE.id,sd);toast(f?'Flow saved.':'Flow added.');afterSave(()=>restorePanel());
  },{del:f?{label:'Delete the flow',run:async()=>{const sd=clone(SITE.raw);sd.flows=(sd.flows||[]).filter(x=>x.id!==f.id);await Store.putSite(SITE.id,sd);toast('Flow deleted.');afterSave(()=>restorePanel());}}:null});
  const preview=()=>{
    const s=$('#fSrc').value,t=$('#fDst').value,el=$('#levelPreview');
    if(s===t){el.textContent='';return;}
    if(isNet(s)&&isNet(t)){el.textContent='Pick an asset on one side.';return;}
    const lvl=(isNet(s)||isNet(t))?'internet':(byId[s].vlan!==byId[t].vlan?'inter':'intra');
    el.innerHTML=isNet(t)?`Outbound to ${t==='internet'?'the Internet':esc(nameOf(t))}. Exposure level: ${xtag('internet')}`:`Opens a port on <b>${esc(nameOf(t))}</b>. Exposure level: ${xtag(lvl)}`;
  };
  // Equipment crossed: suggested list (read-only) or a list edited by hand
  const devOpts=()=>{const dev=ASSETS.filter(a=>INTERCO.has(a.type)),other=ASSETS.filter(a=>!INTERCO.has(a.type));
    return [{group:'Interconnection equipment',items:dev.map(a=>[a.id,`${a.name} · ${TYPE_LABEL[a.type]}`])},{group:'Other assets (proxy, bastion…)',items:other.map(a=>[a.id,`${a.name} · VLAN ${vnum(a)}`])}].filter(g=>g.items.length);};
  const viaRow=id=>`<div class="viarow"><select aria-label="Equipment crossed">${devOpts().map(g=>`<optgroup label="${esc(g.group)}">${g.items.map(([v,t])=>`<option value="${esc(v)}"${v===id?' selected':''}>${esc(t)}</option>`).join('')}</optgroup>`).join('')}</select><button type="button" class="mv" data-viaup aria-label="Move up">↑</button><button type="button" class="mv" data-viadown aria-label="Move down">↓</button><button type="button" class="rm" data-viarm>Remove</button></div>`;
  const suggest=()=>{const s=$('#fSrc').value,t=$('#fDst').value;if(s===t)return [];
    if(isNet(s)&&isNet(t))return [];
    const lvl=(isNet(s)||isNet(t))?'internet':(byId[s].vlan!==byId[t].vlan?'inter':'intra');
    return autoVia(SITE,topology(SITE),{src:s,dst:t,level:lvl}).filter((id,i,arr)=>id&&byId[id]&&id!==s&&id!==t&&arr.indexOf(id)===i);};
  const viaSync=(fill)=>{const auto=$('#fViaAuto').checked,list=$('#viaList');
    if(auto||fill)list.innerHTML=(auto?suggest():fill).map(viaRow).join('');
    list.querySelectorAll('select,button').forEach(x=>x.disabled=auto);det.querySelector('[data-addvia]').hidden=auto;
    const n=list.children.length;
    $('#viaHint').textContent=auto?(n?'Suggested: the edge firewall for Internet traffic, the core firewall or router between internal VLANs. Untick to change it.':'Suggested: direct (same VLAN, or no firewall or router recorded in this IS).'):'Listed in the order the traffic crosses them, from the source to the destination.';};
  det._viaRow=viaRow;det._viaSync=viaSync;
  $('#fViaAuto').addEventListener('change',e=>viaSync(e.target.checked?null:[...det.querySelectorAll('#viaList select')].map(x=>x.value)));
  viaSync(d.viaAuto===false?d.via:null);
  const onEnds=()=>{preview();if($('#fViaAuto').checked)viaSync();};
  $('#fSrc').addEventListener('change',onEnds);$('#fDst').addEventListener('change',onEnds);preview();
  det._preview=onEnds;
}
function wanForm(w,presetA){
  if(SITES.length<2){toast('You need at least two IS to create a link.',true);return;}
  const opts=SITES.map(s=>[s.id,s.name]);
  const d=w?clone(w):{a:presetA||SITES[0].id,b:(SITES.find(s=>s.id!==(presetA||SITES[0].id))||SITES[1]).id,tech:'MPLS',vol:500,risk:false,note:''};
  openForm(w?'Inter-IS link':'New inter-IS link','Overview',`
    <div class="f2">${fSel('fA','IS A *',opts,d.a)}${fSel('fB','IS B *',opts,d.b)}</div>
    <div class="f2">${fIn('fTech','Technology',d.tech,'placeholder="MPLS, IPsec, SD-WAN…"')}${fIn('fVol','Volume (MB/h)',d.vol,'type="number" min="1" step="1"')}</div>
    <label class="chk" for="fRisk"><input type="checkbox" id="fRisk" ${d.risk?'checked':''}>Risky link</label>
    ${fIn('fNote','Why this link is risky',d.note,'maxlength="140"')}`,
  async()=>{
    const a=$('#fA').value,b=$('#fB').value;if(a===b)return formErr('Pick two different IS.','fB');
    const doc={id:w?w.id:uid('w'),a,b,tech:$('#fTech').value.trim()||'WAN',vol:Math.max(1,parseInt($('#fVol').value,10)||1),risk:$('#fRisk').checked,note:$('#fNote').value.trim()};
    const links=(raw.wan||[]).filter(x=>!w||x.id!==w.id);links.push(doc);
    await Store.putWan(links);toast('Link saved.');afterSave(()=>restorePanel());
  },{del:w?{label:'Delete the link',run:async()=>{await Store.putWan((raw.wan||[]).filter(x=>x.id!==w.id));toast('Link deleted.');afterSave(()=>restorePanel());}}:null});
}

/* ---- Panel interactions ---- */
det.addEventListener('submit',async e=>{
  e.preventDefault();if(!onSave)return;
  det.querySelectorAll('.f.err').forEach(x=>x.classList.remove('err'));$('#ferr').hidden=true;
  const btn=det.querySelector('button[type=submit]');btn.disabled=true;
  try{await onSave();}catch(err){}finally{if(btn.isConnected)btn.disabled=false;}
});
det.addEventListener('click',async e=>{
  const t=e.target;const q=s=>t.closest(s);
  if(q('[data-copy]')){const v=q('[data-copy]').dataset.copy;try{await navigator.clipboard.writeText(v);toast('Copied: '+v);}catch(err){const sp=q('.line')&&q('.line').querySelector('span');if(sp){const r=document.createRange();r.selectNodeContents(sp);const s=getSelection();s.removeAllRanges();s.addRange(r);}toast('Text selected: copy it with Ctrl+C.');}return;}
  if(q('[data-add]')){const b=q('[data-add]');$('#'+b.dataset.into).insertAdjacentHTML('beforeend',REP[b.dataset.add]());const last=$('#'+b.dataset.into).lastElementChild.querySelector('input');if(last)last.focus();return;}
  if(q('[data-rm]')){q('.rep').remove();return;}
  if(q('[data-addvia]')){$('#viaList').insertAdjacentHTML('beforeend',det._viaRow(''));$('#viaList').lastElementChild.querySelector('select').focus();det._viaSync([...det.querySelectorAll('#viaList select')].map(x=>x.value));return;}
  if(q('[data-viarm]')){q('.viarow').remove();return;}
  if(q('[data-viaup]')){const r=q('.viarow');if(r.previousElementSibling)r.parentNode.insertBefore(r,r.previousElementSibling);return;}
  if(q('[data-viadown]')){const r=q('.viarow');if(r.nextElementSibling)r.parentNode.insertBefore(r.nextElementSibling,r);return;}
  if(q('[data-swap]')){const s=$('#fSrc'),d=$('#fDst'),v=s.value;s.value=d.value;d.value=v;if(det._preview)det._preview();return;}
  if(q('[data-addzone]')){$('#zones').insertAdjacentHTML('afterbegin',det._zRow({id:uid('z'),name:''}));$('#zones input').focus();return;}
  if(q('[data-rmzone]')){const rows=det.querySelectorAll('#zones .zrow');if(rows.length<=1){formErr('Keep at least one zone.');return;}q('.zrow').remove();return;}
  if(q('[data-up]')){const r=q('.zrow');if(r.previousElementSibling)r.parentNode.insertBefore(r,r.previousElementSibling);return;}
  if(q('[data-down]')){const r=q('.zrow');if(r.nextElementSibling)r.parentNode.insertBefore(r.nextElementSibling,r);return;}
  if(q('[data-cancel]')){cancelForm();return;}
  if(q('[data-del]')){const b=q('[data-del]');if(!b.classList.contains('armed')){b.classList.add('armed');b.textContent='Confirm deletion';return;}
    b.disabled=true;const del=det._del;onSave=null;try{await del.run();}catch(err){b.disabled=false;}return;}
  if(q('[data-open]')){enterSite(siteById[q('[data-open]').dataset.open]);return;}
  if(q('[data-export-site]')){exportSite(siteById[q('[data-export-site]').dataset.exportSite]);return;}
  if(q('[data-arch-site]')){const s=siteById[q('[data-arch-site]').dataset.archSite];if(s){enterSite(s);openArchFile();}return;}
  if(q('[data-edit-site]')){siteForm(siteById[q('[data-edit-site]').dataset.editSite]);return;}
  if(q('[data-new-wan]')){wanForm(null,q('[data-new-wan]').dataset.newWan);return;}
  if(q('[data-edit-wan]')){wanForm(WAN.find(w=>w.id===q('[data-edit-wan]').dataset.editWan));return;}
  if(q('[data-edit-asset]')){assetForm(byId[q('[data-edit-asset]').dataset.editAsset]);return;}
  if(q('[data-new-flow-from]')){flowForm(null,{src:q('[data-new-flow-from]').dataset.newFlowFrom});return;}
  if(q('[data-new-flow-to]')){flowForm(null,{dst:q('[data-new-flow-to]').dataset.newFlowTo});return;}
  if(q('[data-edit-flow]')){flowForm(FLOWS.find(f=>f.id===q('[data-edit-flow]').dataset.editFlow));return;}
  if(q('[data-risk-why]')){const w=$('#riskWhy');if(w.hidden){w.innerHTML=riskWhyHtml(byId[q('[data-risk-why]').dataset.riskWhy]);w.hidden=false;}else w.hidden=true;return;}
  if(q('[data-csv-risk]')){exportRisk();return;}
  if(q('[data-blast]')){setAttack(q('[data-blast]').dataset.blast);closeCtlMobile(true);return;}
  if(q('[data-csv-attack]')){exportAttack();return;}
  if(q('[data-biz]')){const b=SITE&&SITE.bizById[q('[data-biz]').dataset.biz];if(b)showBusiness(b);return;}
  if(q('[data-biz-hl]')){const id=q('[data-biz-hl]').dataset.bizHl;setBizHighlight(state.biz===id?null:id);showBusiness(SITE.bizById[id]);return;}
  if(q('[data-edit-biz]')){businessForm(SITE.bizById[q('[data-edit-biz]').dataset.editBiz]);return;}
  if(q('[data-close-biz]')){state.biz=null;closeDet();refresh();return;}
  if(q('[data-app-node]')){showAppNode(q('[data-app-node]').dataset.appNode);return;}
  if(q('[data-col-flow]')){setColour('flow');if(selAsset())showAsset(selAsset());return;}
  if(q('[data-show-flow]')){const f=FLOWS.find(x=>x.id===q('[data-show-flow]').dataset.showFlow);if(f)showFlow(f);return;}
  if(q('[data-close-flow]')){state.flowId=null;const a=selAsset();if(a)showAsset(a);else closeDet();refresh();return;}
  if(q('[data-plan-asset]')){openPlan(byId[q('[data-plan-asset]').dataset.planAsset]);return;}
  if(q('[data-csv-flows]')){exportFlowMatrix(byId[q('[data-csv-flows]').dataset.csvFlows]);return;}
  if(q('[data-csv-fw]')){exportFwRules(byId[q('[data-csv-fw]').dataset.csvFw]);return;}
  if(q('[data-site]')){selectSite(siteById[q('[data-site]').dataset.site],true);return;}
  if(q('[data-goto]')){const id=q('[data-goto]').dataset.goto;if(SVC[id]){showService(SVC[id]);return;}if(!isNet(id)&&byId[id])select(byId[id],true);return;}
  if(q('[data-svc]')){const id=q('[data-svc]').dataset.svc,x=SVC[id]||(state.view==='overview'?globalServices().find(y=>y.id===id):null);if(x)showService(x);return;}
  if(q('[data-edit-svc]')){const id=q('[data-edit-svc]').dataset.editSvc;serviceForm(allServices().find(y=>y.id===id));return;}
  if(q('[data-new-svc]')){serviceForm(null,q('[data-new-svc]').dataset.newSvc);return;}
  if(q('[data-close]')){if(state.view==='overview'){selectSite(null);return;}if(state.path)setPath(false);if(state.panel==='ports'||state.panel==='risk'||state.panel==='attack'){closeDet();return;}select(null);}
});

/* ================= Global actions ================= */
async function act(name){
  if(name==='new-site')return siteForm(null);
  if(name==='new-wan')return wanForm(null,state.ovSelId);
  if(name==='new-asset')return assetForm(null,selAsset()&&selAsset().vlan);
  if(name==='new-flow')return flowForm(null,selAsset()?{dst:selAsset().id}:{});
  if(name==='new-vlan')return vlanForm(null);
  if(name==='edit-site')return siteForm(SITE);
  if(name==='new-biz')return businessForm(null);
  if(name==='demo'){if(SITES.length&&!confirmArm('demo'))return;await replaceAll(buildDemo(),'Loading the demo');return;}
  if(name==='wipe'){if(!confirmArm('wipe'))return;await replaceAll({si:{},assets:{},wan:[]},'Deleting');state.ovSelId=null;closeDet();return;}
  if(name==='export')return exportJson();
  if(name==='import'){$('#io').value='';$('#io').click();return;}
}
// Destructive actions need a second click on the same button
const armed={};
function confirmArm(key){
  const btns=document.querySelectorAll(`[data-act="${key}"]`);
  if(armed[key]){armed[key]=false;btns.forEach(b=>{b.classList.remove('armed');if(key!=='wipe')b.classList.remove('danger');b.replaceChildren(...(b._label||[]));});return true;}
  armed[key]=true;
  btns.forEach(b=>{b._label=[...b.childNodes].map(n=>n.cloneNode(true));b.classList.add('armed','danger');b.textContent=key==='wipe'?'Confirm: delete everything':'Confirm: replace with the demo';});
  setTimeout(()=>{if(armed[key]){armed[key]=false;btns.forEach(b=>{b.classList.remove('armed');if(key!=='wipe')b.classList.remove('danger');b.replaceChildren(...(b._label||[]));});}},5000);
  return false;
}
document.addEventListener('click',e=>{const b=e.target.closest('[data-act]');if(b&&!b.closest('#det'))act(b.dataset.act);});
async function exportJson(){
  const data=JSON.stringify({format:'strata',version:3,exportedAt:new Date().toISOString(),si:raw.si,assets:raw.assets,wan:raw.wan,services:raw.services||[]},null,2);
  await saveFile(`strata-${today()}.json`,'application/json',data);
}
$('#io').addEventListener('change',e=>{
  const f=e.target.files&&e.target.files[0];if(!f)return;
  const r=new FileReader();
  r.onload=async()=>{
    let o;try{o=JSON.parse(r.result);}catch(err){toast('This file is not valid JSON.',true);return;}
    if(!o||typeof o.si!=='object'||typeof o.assets!=='object'){toast('Unexpected format: an export needs the “si” and “assets” keys.',true);return;}
    if(o.scope==='si'){
      // one IS: replace only that IS and its assets
      const ch=changesFromFile(o),tasks=[];
      Object.entries(ch.si).forEach(([id,d])=>tasks.push(()=>Store.putSite(id,d)));
      Object.entries(ch.assets).forEach(([id,d])=>tasks.push(()=>d?Store.putAsset(id,d):Store.delAsset(id)));
      if(ch.services)tasks.push(()=>Store.putServices(ch.services));
      if(!tasks.length){toast('This file is identical to the map.');return;}
      await Store.many(tasks,`Import of IS ${Object.values(o.si)[0].name||''}`);return;
    }
    await replaceAll({si:o.si,assets:o.assets,wan:Array.isArray(o.wan)?o.wan:[],services:Array.isArray(o.services)?o.services:[]},'Import');
  };
  r.readAsText(f);
});

/* ================= Files for documentation ================= */
// Saves a file on the user's computer
// Saves a file on the user's computer.
// Text files (JSON, CSV, SVG) go out as a percent-encoded data: URL; it only feeds an <a download>,
// so the browser saves the file and never renders it as a page.
async function saveFile(name,mime,text){
  const a=document.createElement('a');
  a.href='data:'+String(mime).replace(/[^\w/+.;=-]/g,'')+','+encodeURIComponent(String(text));
  a.download=name;document.body.appendChild(a);a.click();a.remove();
  toast(`${name} downloaded.`);
}
// Binary files drawn by the app itself (PNG plans)
async function saveBlob(name,blob){
  const url=URL.createObjectURL(blob),a=document.createElement('a');
  a.href=url;a.download=name;document.body.appendChild(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),2000);
  toast(`${name} downloaded.`);
}
const fileStem=s=>String(s||'export').normalize('NFD').replace(/[̀-ͯ]/g,'').replace(/[^A-Za-z0-9._-]+/g,'-').replace(/^-+|-+$/g,'').slice(0,60)||'export';
const today=()=>new Date().toISOString().slice(0,10);
// CSV for spreadsheets: semicolon separator and UTF-8 mark, so Excel in French opens it in columns
function csv(rows){
  const cell=v=>{v=v==null?'':String(v);return /[;"\r\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v;};
  return '﻿'+rows.map(r=>r.map(cell).join(';')).join('\r\n')+'\r\n';
}
const nodeInfo=id=>{
  if(id==='internet')return {name:'Internet',ip:'any',vlan:'',cidr:'0.0.0.0/0',zone:'Internet'};
  if(SVC[id])return {name:SVC[id].name,ip:SVC[id].hosts.join(', '),vlan:'',cidr:SVC[id].hosts.join(', '),zone:'Internet',svc:true};
  const a=byId[id],v=vlanById[a.vlan];return {name:a.name,ip:a.ip||'',vlan:v?`VLAN ${v.num} ${v.name}`:'',cidr:v?v.cidr:'',zone:v?v.zone:''};
};
const splitPort=p=>{const m=/^(\w+)(?:\/(.*))?$/.exec(p||'')||[];return [m[1]||'',m[2]||''];};
function exportFlowMatrix(a){
  const list=FLOWS.filter(f=>f.src===a.id||f.dst===a.id||f.via.includes(a.id));
  const rows=[['Direction','Source','Source IP','Source VLAN','Source zone','Destination','Destination IP','Destination VLAN','Destination zone','Protocol','Port','Application','Path','Firewalls crossed','Path set','Exposure','Volume (MB/h)','Risky','Note']];
  const dirOf=f=>f.src===a.id?'Outbound':f.dst===a.id?'Inbound':'Crossing';
  list.sort((x,y)=>dirOf(x).localeCompare(dirOf(y))||x.port.localeCompare(y.port,'en',{numeric:true}));
  list.forEach(f=>{const S=nodeInfo(f.src),T=nodeInfo(f.dst),[proto,port]=splitPort(f.port),ap=!isNet(f.dst)?appOn(byId[f.dst],f.port):null;
    rows.push([dirOf(f),S.name,S.ip,S.vlan,S.zone,T.name,T.ip,T.vlan,T.zone,proto,port,ap?`${ap.name} ${ap.version}`.trim():'',f.hops.map(nameOf).join(' > '),
      f.via.filter(id=>byId[id].type==='firewall').map(nameOf).join(', ')||'none',f.via.length?(f.viaAuto?'suggested':'manual'):'direct',EXP[f.level].label,f.vol,f.risk?'yes':'no',f.note||'']);});
  if(rows.length===1){toast('No flow recorded for this asset.',true);return;}
  saveFile(`flow-matrix_${fileStem(SITE.name)}_${fileStem(a.name)}_${today()}.csv`,'text/csv;charset=utf-8',csv(rows));
}
// Firewall rules: one allow rule per flow and per firewall crossed. For a firewall, its own rule base.
// Returns {rules: [...], unfiltered: [...]}, rules grouped by firewall in rule order; shared by the CSV export and the plan.
function fwRules(a){
  const isFw=a.type==='firewall';
  const list=FLOWS.filter(f=>isFw?(f.via.includes(a.id)||f.dst===a.id||f.src===a.id):(f.src===a.id||f.dst===a.id));
  const n={},addr=id=>{const i=nodeInfo(id);return id==='internet'?'all':i.svc?(i.ip||i.name):(i.ip?i.ip+'/32':i.name);};
  const zoneOf=id=>{const i=nodeInfo(id);return isNet(id)?'Internet':[i.zone,i.vlan].filter(Boolean).join(' / ');};
  const rules=[],unfiltered=[];
  list.forEach(f=>{
    let fws=f.via.filter(id=>byId[id].type==='firewall');
    if(isFw)fws=f.via.includes(a.id)?[a.id]:[];
    const dir=f.src===a.id?'Outbound':f.dst===a.id?'Inbound':'Crossing';
    const S=Object.assign(nodeInfo(f.src),{zone:zoneOf(f.src)}),T=Object.assign(nodeInfo(f.dst),{zone:zoneOf(f.dst)}),[proto,port]=splitPort(f.port);
    const comment=[f.risk?'RISKY: '+(f.note||'review this flow'):f.note,f.via.length&&f.viaAuto?'path suggested by Strata':''].filter(Boolean).join(' · ');
    const r={flow:f,name:`${fileStem(S.name)}_to_${fileStem(T.name)}_${proto}${port}`.slice(0,63),src:S.name,srcAddr:addr(f.src),srcZone:S.zone,dst:T.name,dstAddr:addr(f.dst),dstZone:T.zone,proto,port,service:f.port,dir};
    if(isFw&&!fws.length){
      // Traffic to or from the firewall itself (management, logs, VPN)
      rules.push(Object.assign(r,{fw:a.name,n:(n[a.id]=(n[a.id]||0)+1),action:'accept',comment:['local traffic (to or from the firewall)',comment].filter(Boolean).join(' · ')}));return;}
    if(!fws.length){unfiltered.push(Object.assign(r,{fw:'(no firewall on the path)',n:'',action:'—',dir:f.src===a.id?'Outbound':'Inbound',
      comment:['not filtered by a firewall: '+(f.level==='intra'?'same VLAN':'check the path'),f.risk?'RISKY: '+(f.note||''):''].filter(Boolean).join(' · ')}));return;}
    fws.forEach(fw=>rules.push(Object.assign({},r,{fw:nameOf(fw),n:(n[fw]=(n[fw]||0)+1),action:'accept',comment})));
  });
  rules.sort((x,y)=>String(x.fw).localeCompare(String(y.fw),'en',{numeric:true})||x.n-y.n);
  return {rules,unfiltered,count:list.length};
}
function exportFwRules(a){
  const R=fwRules(a);
  if(R.count===0){toast('No flow recorded for this asset.',true);return;}
  const row=r=>[r.fw,r.n,r.name,r.src,r.srcAddr,r.srcZone,r.dst,r.dstAddr,r.dstZone,r.proto,r.port,r.service,r.action,r.action==='accept'?'yes':'',r.dir,r.comment];
  const rows=[['Firewall','Rule','Name','Source','Source address','Source zone','Destination','Destination address','Destination zone','Protocol','Port','Service','Action','Log','Flow direction (for '+a.name+')','Comment'],...R.rules.map(row),...R.unfiltered.map(row)];
  rows.push([]);rows.push(['Default rule','','deny_all','any','all','','any','all','','any','','','deny','yes','','Implicit last rule on every firewall listed above']);
  saveFile(`firewall-rules_${fileStem(SITE.name)}_${fileStem(a.name)}_${today()}.csv`,'text/csv;charset=utf-8',csv(rows));
  if(R.unfiltered.length)toast(`${R.unfiltered.length===1?'1 flow crosses':R.unfiltered.length+' flows cross'} no firewall: listed at the end of the file.`);
}

/* ================= 2D architecture plan ================= */
const PF={d:"'Archivo Narrow','Arial Narrow',Arial,sans-serif",b:"Archivo,Arial,Helvetica,sans-serif",m:"'IBM Plex Mono',Consolas,'Courier New',monospace"};
// Per-flow colours on paper: the light values of --f0 to --f9
const PC_FLOW=['#2f63c8','#d97a0f','#13917f','#8549c9','#4a8f1f','#c93f8f','#a88200','#1688b8','#8c5a36','#55657d'];
const PC={ink:'#1b2125',muted:'#454e53',line:'#c2c6c0',panel:'#ffffff',paper:'#f7f7f3',zone:'#ecece6',dev:'#2b3238',devText:'#f0eee8',net:'#8a3fbf',inter:'#2a7fa6',intra:'#5f6a72',crit:'#c4313d',high:'#cc6a22',med:'#b38d14',low:'#3a8763',none:'#6a747a',accent:'#2b5884',
  vlan:['#d2a198','#9db9a3','#d5b671','#97acc3','#aea8c9','#b8c39e','#c6a9b9','#a9c4c0','#d8b49a','#b3b8a6']};
const measureCtx=document.createElement('canvas').getContext('2d');
// Width of a text in px: a number, never the text (the drawings place their shapes with it)
const tw=(t,size,weight,fam)=>{measureCtx.font=`${weight} ${size}px ${fam}`;return Math.max(0,Number(measureCtx.measureText(String(t)).width)||0);};
function clip(t,size,weight,fam,max){t=String(t||'');if(tw(t,size,weight,fam)<=max)return t;while(t.length>1&&tw(t+'…',size,weight,fam)>max)t=t.slice(0,-1);return t+'…';}
// Which flows and assets the plan of an asset shows: its own flows, the equipment they cross,
// and every recorded path from the Internet to it and from it to the Internet
function planScope(a,full){
  const succ={},pred={};FLOWS.forEach(f=>{(succ[f.src]=succ[f.src]||[]).push(f);(pred[f.dst]=pred[f.dst]||[]).push(f);});
  const reach=(start,adj,key)=>{const st=[].concat(start),d={},q=st.slice();st.forEach(x=>d[x]=0);while(q.length){const x=q.shift();(adj[x]||[]).forEach(f=>{const m=f[key];if(d[m]===undefined){d[m]=d[x]+1;q.push(m);}});}return d;};
  const NET=['internet',...SITE.services.map(x=>x.id)];
  const fromNet=reach(NET,succ,'dst'),toSel=reach(a.id,pred,'src'),fromSel=reach(a.id,succ,'dst'),toNet=reach(NET,pred,'src');
  const pick=short=>{const set=new Set();FLOWS.forEach(f=>{
    const own=f.src===a.id||f.dst===a.id||f.via.includes(a.id);
    const inP=fromNet[a.id]!==undefined&&fromNet[f.src]!==undefined&&toSel[f.dst]!==undefined&&(!short||fromNet[f.src]+1+toSel[f.dst]===fromNet[a.id]);
    const outP=toNet[a.id]!==undefined&&fromSel[f.src]!==undefined&&toNet[f.dst]!==undefined&&(!short||fromSel[f.src]+1+toNet[f.dst]===toNet[a.id]);
    if(own||inP||outP)set.add(f);});return set;};
  if(!full){const own=FLOWS.filter(f=>f.src===a.id||f.dst===a.id||f.via.includes(a.id)),nodes=new Set([a.id]);own.forEach(f=>f.hops.forEach(h=>nodes.add(h)));
    return {flows:own,nodes,short:false,full:false,inbound:fromNet[a.id],outbound:toNet[a.id]};}
  let flows=pick(false),short=false;
  const count=fs=>new Set([a.id,...[...fs].flatMap(f=>f.hops)]).size;
  if(count(flows)>36){flows=pick(true);short=true;}
  const nodes=new Set([a.id]);flows.forEach(f=>f.hops.forEach(h=>nodes.add(h)));
  return {flows:[...flows],nodes,short,full:true,inbound:fromNet[a.id],outbound:toNet[a.id]};
}
// Plan filters: direction relative to the asset, and where the traffic crosses.
// A flow is inbound when it leads to the asset (directly or further along the path drawn), outbound when it leaves from it.
const PLAN_DIR={all:'All',in:'Inbound',out:'Outbound',thru:'Crossing'};
function planFilter(a,sc,flt){
  const lv=new Set(flt.lv),up=new Set(),down=new Set(),fl=sc.flows;
  for(let ch=true;ch;){ch=false;fl.forEach(f=>{if((f.dst===a.id||up.has(f.dst))&&!up.has(f.src)&&f.src!==a.id){up.add(f.src);ch=true;}if((f.src===a.id||down.has(f.src))&&!down.has(f.dst)&&f.dst!==a.id){down.add(f.dst);ch=true;}});}
  const dirOk=f=>flt.dir==='all'||(flt.dir==='in'?f.dst===a.id||up.has(f.dst):flt.dir==='out'?f.src===a.id||down.has(f.src):f.via.includes(a.id));
  const flows=fl.filter(f=>lv.has(f.level)&&dirOk(f)),nodes=new Set([a.id]);flows.forEach(f=>f.hops.forEach(h=>nodes.add(h)));
  const on=flt.dir!=='all'||lv.size<3;
  return Object.assign({},sc,{flows,nodes,total:fl.length,filtered:on,
    label:on?[flt.dir!=='all'?PLAN_DIR[flt.dir]:'',lv.size<3?['internet','inter','intra'].filter(k=>lv.has(k)).map(k=>EXP[k].label).join(', '):''].filter(Boolean).join(' · '):''});
}
function buildPlanSvg(a,perFlow,full,flt){
  const sc=planFilter(a,planScope(a,full),flt),STEP=8,M=40,GAP=16,PAD=14,VH=30,BANDGAP=96,CARD_W=196,CARD_H=74;
  const appsOf=a.apps||[],APP_W=150,APP_H=48,apCols=Math.min(3,Math.max(2,appsOf.length>4?3:2));
  const selW=Math.max(340,apCols*APP_W+(apCols+1)*10),apRows=Math.max(1,Math.ceil(appsOf.length/apCols));
  const selH=66+apRows*(APP_H+10)+10+34;
  const box={};// id -> {x,y,w,h}
  const sizeOf=id=>id===a.id?[selW,selH]:id==='internet'?[180,64]:SVC[id]?[210,70]:[CARD_W,CARD_H];
  // Bands: Internet at the top, then the zones from the top level down
  const bands=[];
  const netIds=[...sc.nodes].filter(isNet).sort((x,y)=>(x!=='internet')-(y!=='internet')||nameOf(x).localeCompare(nameOf(y)));
  if(netIds.length)bands.push({name:'INTERNET',net:true,vlans:[{net:true,ids:netIds}]});
  ZONES.slice().reverse().forEach(z=>{const vl=z.vlans.map(v=>({v,ids:ASSETS.filter(x=>x.vlan===v.id&&sc.nodes.has(x.id)).map(x=>x.id)})).filter(x=>x.ids.length);
    if(vl.length)bands.push({name:'ZONE · '+z.name.toUpperCase(),vlans:vl});});
  // Size every VLAN box (cards in rows of up to 4)
  bands.forEach(b=>{b.vlans.forEach(vb=>{
    const ids=vb.ids.slice().sort((x,y)=>(y===a.id)-(x===a.id)||(INTERCO.has(byId[y]&&byId[y].type)-INTERCO.has(byId[x]&&byId[x].type))||nameOf(x).localeCompare(nameOf(y),'en',{numeric:true}));
    const rows=[];let row=[];const per=vb.net?6:4;ids.forEach(id=>{if(row.length>=per){rows.push(row);row=[];}row.push(id);});if(row.length)rows.push(row);
    vb.rows=rows.map(r=>({ids:r,w:r.reduce((t,id)=>t+sizeOf(id)[0],0)+(r.length-1)*GAP,h:Math.max(...r.map(id=>sizeOf(id)[1]))}));
    const pad=vb.net?0:PAD,head=vb.net?0:VH;
    vb.w=Math.max(vb.net?0:Math.max(220,tw(`VLAN ${vb.v.num} · ${vb.v.name}`,13.5,700,PF.d)+(vb.v.cidr?tw(vb.v.cidr,11,400,PF.m):0)+44),...vb.rows.map(r=>r.w))+pad*2;vb.h=head+vb.rows.reduce((t,r)=>t+r.h,0)+(vb.rows.length-1)*GAP+pad*(vb.net?0:2);
  });b.w=b.vlans.reduce((t,v)=>t+v.w,0)+(b.vlans.length-1)*40;b.h=Math.max(...b.vlans.map(v=>v.h));});
  // Flows of the plan, numbered: into the asset, through it, out of it, then the paths beyond
  const grp=f=>f.dst===a.id?0:f.via.includes(a.id)?1:f.src===a.id?2:3;
  const FLS=sc.flows.slice().sort((x,y)=>grp(x)-grp(y)||nameOf(x.src).localeCompare(nameOf(y.src),'en',{numeric:true})||nameOf(x.dst).localeCompare(nameOf(y.dst),'en',{numeric:true})||String(x.port).localeCompare(String(y.port)));
  const num={};FLS.forEach((f,i)=>num[f.id]=i+1);
  const pcol=perFlow?SA.flowColours(FLS.map(f=>({id:f.id,via:f.hops})),PC_FLOW.length):{};
  const colOf=f=>perFlow?PC_FLOW[pcol[f.id]||0]:f.risk?PC.crit:f.level==='internet'?PC.net:f.level==='inter'?PC.inter:PC.intra;
  // One segment per flow and hop
  const bandOf={};bands.forEach((b,bi)=>b.vlans.forEach(vb=>vb.ids.forEach(id=>bandOf[id]=bi)));
  const list=[];
  FLS.forEach(f=>f.hops.forEach((p,i)=>{if(i===f.hops.length-1)return;const q=f.hops[i+1],last=i===f.hops.length-2;
    list.push({f,n:num[f.id],p,q,last,c:colOf(f),app:last&&q===a.id?appsOf.findIndex(x=>x.ports.includes(f.port)):-1,A:bandOf[p],B:bandOf[q]});}));
  // Lines run at right angles: out of a card, along the corridor under or over its zone, into the other card.
  // Between zones that are not next to each other, they go round by the left-hand corridor.
  const gapUse={},corr=[];
  list.forEach(s=>{const {A,B}=s;
    s.gaps=A===B?[A]:B===A+1?[A]:B===A-1?[B]:B>A?[A,B-1]:[A-1,B];
    s.corr=Math.abs(B-A)>1;if(s.corr)corr.push(s);
    s.gaps.forEach(g=>(gapUse[g]=gapUse[g]||[]).push(s));});
  const gapH=g=>Math.max(BANDGAP,40+((gapUse[g]||[]).length)*STEP);
  const CORR=corr.length?corr.length*STEP+28:0;
  // the rules of the flows shown
  const FW0=fwRules(a),shown=new Set(sc.flows.map(f=>f.id)),FW={rules:FW0.rules.filter(r=>shown.has(r.flow.id)),unfiltered:FW0.unfiltered.filter(r=>shown.has(r.flow.id))},FWROWS=[...FW.rules,...FW.unfiltered],FROW=34;
  const TITLE=118,LEG=96,ROW=22,TAB=FLS.length?56+FLS.length*ROW:0,FWTAB=FWROWS.length?40+56+FWROWS.length*FROW+FROW:0;
  // wider when the rules table is there, so its comments have room
  const W=Math.max(FWROWS.length?1280:1100,...bands.map(b=>b.w+M*2+40+CORR*2));
  let y=M+TITLE;
  bands.forEach((b,bi)=>{b.y=y;const label=b.net?0:24;b.x=(W-b.w)/2;let x=b.x;
    b.vlans.forEach(vb=>{vb.x=x;vb.y=y+label;x+=vb.w+40;
      let ry=vb.y+(vb.net?0:VH+PAD);vb.rows.forEach(r=>{let cx=vb.x+(vb.w-r.w)/2;r.ids.forEach(id=>{const [w,h]=sizeOf(id);box[id]={x:cx,y:ry+(r.h-h)/2,w,h,band:bi};cx+=w+GAP;});ry+=r.h+GAP;});});
    b.h+=label;y+=b.h+gapH(bi);});
  const lastB=bands.length-1;
  if(!(gapUse[lastB]||[]).length)y-=gapH(lastB)-40;
  const tabY=y,fwY=tabY+TAB,H=fwY+FWTAB+LEG+M+30;
  const cy=id=>box[id].y+box[id].h/2,cx=id=>box[id].x+box[id].w/2;
  const side=(s,end)=>{const me=end?s.q:s.p,other=end?s.p:s.q;
    if(s.A===s.B)return 'bottom';return cy(other)>cy(me)?'bottom':'top';};
  // Spread the attachment points along each side: on equipment, in the order of the flow lanes,
  // so a flow enters and leaves at the same rank; elsewhere, by where the other end is
  const slots={};list.forEach(s=>{[[s.p,0],[s.q,1]].forEach(([id,end])=>{const sd=side(s,end),k=id+'|'+sd;(slots[k]=slots[k]||[]).push({s,end});});});
  const laneAt=(id,s)=>{const L=SITE.lanes[id];return L&&L.idx[s.f.id]!==undefined?L.idx[s.f.id]:null;};
  Object.entries(slots).forEach(([k,arr])=>{const [id,sd]=k.split('|'),b=box[id];
    arr.sort((u,v)=>{const lu=laneAt(id,u.s),lv=laneAt(id,v.s);return lu!=null&&lv!=null?lu-lv:cx(u.end?u.s.p:u.s.q)-cx(v.end?v.s.p:v.s.q)||u.s.n-v.s.n;});
    arr.forEach((o,i)=>{let x=b.x+b.w*(i+1)/(arr.length+1);
      if(o.end&&id===a.id&&o.s.app>=0){const ai=o.s.app,col=ai%apCols;x=b.x+10+col*(APP_W+10)+APP_W/2+((i%3)-1)*6;}
      o.s[o.end?'q2':'p2']={x,y:sd==='top'?b.y:b.y+b.h,sd,rank:i};});});
  // Tracks: each segment gets its own height in each corridor it uses, and its own x in the left one
  Object.entries(gapUse).forEach(([g,arr])=>{const top=bands[g].y+bands[g].h;
    arr.slice().sort((u,v)=>((u.p2.x+u.q2.x)/2)-((v.p2.x+v.q2.x)/2)||u.n-v.n).forEach((s,i)=>{(s.ty=s.ty||{})[g]=top+22+i*STEP;});});
  const minX=Math.min(...bands.map(b=>b.x));
  corr.forEach((s,i)=>s.cx=minX-18-i*STEP);
  list.forEach(s=>{const p=s.p2,q=s.q2;if(!p||!q)return;const t=s.gaps.map(g=>s.ty[g]);
    s.pts=s.corr?[[p.x,p.y],[p.x,t[0]],[s.cx,t[0]],[s.cx,t[1]],[q.x,t[1]],[q.x,q.y]]:[[p.x,p.y],[p.x,t[0]],[q.x,t[0]],[q.x,q.y]];});
  // A polyline with rounded corners
  const orth=(pts,r=7)=>{let d=`M${pts[0][0]},${pts[0][1]}`;
    for(let i=1;i<pts.length-1;i++){const [x0,y0]=pts[i-1],[x1,y1]=pts[i],[x2,y2]=pts[i+1];
      const r1=Math.min(r,Math.hypot(x1-x0,y1-y0)/2,Math.hypot(x2-x1,y2-y1)/2);
      const ux=Math.sign(x1-x0),uy=Math.sign(y1-y0),vx=Math.sign(x2-x1),vy=Math.sign(y2-y1);
      d+=` L${x1-ux*r1},${y1-uy*r1} Q${x1},${y1} ${x1+vx*r1},${y1+vy*r1}`;}
    const e=pts[pts.length-1];return d+` L${e[0]},${e[1]}`;};
  const X=t=>esc(t);
  let out='';
  // Title block
  const v=vlanById[a.vlan];
  out+=`<rect x="0" y="0" width="${W}" height="${H}" fill="${PC.paper}"/>`;
  out+=`<text x="${M}" y="${M+12}" font-family="${PF.d}" font-weight="700" font-size="12" letter-spacing="1.6" fill="${PC.muted}">ARCHITECTURE PLAN · IS ${X(SITE.name.toUpperCase())}</text>`;
  out+=`<text x="${M}" y="${M+50}" font-family="${PF.d}" font-weight="700" font-size="36" fill="${PC.ink}">${X(a.name)}</text>`;
  out+=`<text x="${M}" y="${M+76}" font-family="${PF.m}" font-size="13" fill="${PC.muted}">${X([TYPE_LABEL[a.type],a.role,a.ip,v?`VLAN ${v.num} ${v.name}`:'',v?v.cidr:''].filter(Boolean).join(' · '))}</text>`;
  const reachTxt=[sc.inbound!==undefined?`reachable from the Internet in ${plural(sc.inbound,'hop')}`:'not reachable from the Internet',sc.outbound!==undefined?`reaches the Internet in ${plural(sc.outbound,'hop')}`:''].filter(Boolean).join(' · ');
  out+=`<text x="${M}" y="${M+96}" font-family="${PF.b}" font-size="12.5" fill="${a.sev==='crit'?PC.crit:PC.ink}">${X(reachTxt)}${a.vulns.length?X(` · ${plural(a.vulns.length,'vulnerability').replace('vulnerabilitys','vulnerabilities')} (worst: ${SEV[a.sev].label})`):''}</text>`;
  out+=`<text x="${W-M}" y="${M+12}" text-anchor="end" font-family="${PF.m}" font-size="11.5" fill="${PC.muted}">${X(today())} · Strata</text>`;
  out+=`<line x1="${M}" y1="${M+TITLE-14}" x2="${W-M}" y2="${M+TITLE-14}" stroke="${PC.line}" stroke-width="1"/>`;
  // Bands and VLAN boxes
  let vlanLabels='';
  bands.forEach(b=>{if(!b.net)vlanLabels+=`<text x="${b.x}" y="${b.y+12}" font-family="${PF.d}" font-weight="700" font-size="12" letter-spacing="1.4" fill="${PC.muted}" stroke="${PC.paper}" stroke-width="4" stroke-linejoin="round" paint-order="stroke">${X(b.name)}</text>`;
    b.vlans.forEach(vb=>{if(vb.net)return;const c=PC.vlan[vb.v.ci%10];
      out+=`<rect x="${vb.x}" y="${vb.y}" width="${vb.w}" height="${vb.h}" rx="6" fill="${c}" fill-opacity="0.28" stroke="${c}" stroke-width="1.5"/>`;
      out+=`<rect x="${vb.x}" y="${vb.y}" width="6" height="${vb.h}" rx="3" fill="${c}"/>`;
      // names go on top of the lines, with a halo, so a line crossing the header does not hide them
      vlanLabels+=`<text x="${vb.x+16}" y="${vb.y+20}" font-family="${PF.d}" font-weight="700" font-size="13.5" fill="${PC.ink}" stroke="${PC.paper}" stroke-width="4" stroke-linejoin="round" paint-order="stroke">${X(clip(`VLAN ${vb.v.num} · ${vb.v.name}`,13.5,700,PF.d,vb.w-130))}</text>`;
      vlanLabels+=`<text x="${vb.x+vb.w-12}" y="${vb.y+20}" text-anchor="end" font-family="${PF.m}" font-size="11" fill="${PC.muted}" stroke="${PC.paper}" stroke-width="4" stroke-linejoin="round" paint-order="stroke">${X(vb.v.cidr||'')}</text>`;});});
  // Flows, under the cards; a white casing keeps crossing lines apart
  const marks=new Set();
  list.forEach(s=>{if(!s.pts)return;s.d=orth(s.pts);marks.add(s.c);
    out+=`<path d="${s.d}" fill="none" stroke="${PC.paper}" stroke-width="5.5" stroke-linejoin="round"/>`;
    out+=`<path d="${s.d}" fill="none" stroke="${s.c}" stroke-width="${s.f.risk?2.2:1.8}" ${s.f.risk?'stroke-dasharray="7 4"':''} stroke-linejoin="round" marker-end="url(#a${s.c.slice(1)})"/>`;});
  out+=vlanLabels;
  // Cards
  const card=id=>{const b=box[id];
    if(SVC[id]){const x=SVC[id];return `<g><rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="10" fill="${PC.panel}" stroke="${PC.net}" stroke-width="1.6"/><text x="${b.x+12}" y="${b.y+17}" font-family="${PF.d}" font-weight="700" font-size="10" letter-spacing="1.2" fill="${PC.net}">${X(clip(('INTERNET · '+x.category).toUpperCase(),10,700,PF.d,b.w-24))}</text><text x="${b.x+12}" y="${b.y+38}" font-family="${PF.d}" font-weight="700" font-size="16" fill="${PC.ink}">${X(clip(x.name,16,700,PF.d,b.w-24))}</text><text x="${b.x+12}" y="${b.y+56}" font-family="${PF.m}" font-size="10.5" fill="${PC.muted}">${X(clip(x.hosts.join(', '),10.5,400,PF.m,b.w-24))}</text></g>`;}
    if(id==='internet'){return `<g><rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="32" fill="${PC.panel}" stroke="${PC.net}" stroke-width="2"/><text x="${b.x+b.w/2}" y="${b.y+28}" text-anchor="middle" font-family="${PF.d}" font-weight="700" font-size="18" fill="${PC.ink}">Internet</text><text x="${b.x+b.w/2}" y="${b.y+46}" text-anchor="middle" font-family="${PF.m}" font-size="11" fill="${PC.muted}">0.0.0.0/0</text></g>`;}
    const x=byId[id],dev=INTERCO.has(x.type),sel=id===a.id,sev=PC[x.sev]||PC.none;
    if(sel){let g=`<g><rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="6" fill="${PC.panel}" stroke="${PC.ink}" stroke-width="2.5"/>`;
      g+=`<text x="${b.x+14}" y="${b.y+20}" font-family="${PF.d}" font-weight="700" font-size="11" letter-spacing="1.3" fill="${PC.muted}">${X((TYPE_LABEL[x.type]+' · '+(x.ip||'no IP')).toUpperCase())}</text>`;
      g+=`<text x="${b.x+14}" y="${b.y+46}" font-family="${PF.d}" font-weight="700" font-size="24" fill="${PC.ink}">${X(clip(x.name,24,700,PF.d,b.w-40))}</text>`;
      if(x.sev!=='none')g+=`<circle cx="${b.x+b.w-18}" cy="${b.y+18}" r="7" fill="${sev}"/>`;
      appsOf.forEach((ap,i)=>{const col=i%apCols,row=Math.floor(i/apCols),ax=b.x+10+col*(APP_W+10),ay=b.y+62+row*(APP_H+10);
        const hit=a.ports.some(p=>ap.ports.includes(p.port));
        g+=`<rect x="${ax}" y="${ay}" width="${APP_W}" height="${APP_H}" rx="4" fill="${hit?'#eef3f8':PC.paper}" stroke="${hit?PC.accent:PC.line}" stroke-width="${hit?1.6:1}"/>`;
        g+=`<text x="${ax+9}" y="${ay+19}" font-family="${PF.b}" font-weight="600" font-size="12" fill="${PC.ink}">${X(clip(ap.name,12,600,PF.b,APP_W-18))}</text>`;
        g+=`<text x="${ax+9}" y="${ay+36}" font-family="${PF.m}" font-size="10.5" fill="${PC.muted}">${X(clip([ap.version,ap.ports.join(' ')].filter(Boolean).join(' · '),10.5,400,PF.m,APP_W-18))}</text>`;});
      if(!appsOf.length)g+=`<text x="${b.x+14}" y="${b.y+86}" font-family="${PF.b}" font-size="12" fill="${PC.muted}">No application recorded</text>`;
      const oy=b.y+b.h-34;
      g+=`<rect x="${b.x+10}" y="${oy}" width="${b.w-20}" height="26" rx="3" fill="${PC.ink}"/><text x="${b.x+20}" y="${oy+17}" font-family="${PF.m}" font-size="11.5" fill="${PC.devText}">${X(clip('OS · '+(x.os||'unknown'),11.5,400,PF.m,b.w-40))}</text>`;
      return g+'</g>';}
    const fill=dev?PC.dev:PC.panel,ink=dev?PC.devText:PC.ink,mut=dev?'#aeb6bb':PC.muted;
    let g=`<g><rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" rx="5" fill="${fill}" stroke="${dev?PC.dev:PC.line}" stroke-width="1.2"/>`;
    if(x.sev!=='none')g+=`<rect x="${b.x}" y="${b.y+b.h-4}" width="${b.w}" height="4" fill="${sev}"/><circle cx="${b.x+b.w-14}" cy="${b.y+15}" r="5" fill="${sev}"/>`;
    g+=`<text x="${b.x+11}" y="${b.y+17}" font-family="${PF.d}" font-weight="700" font-size="10" letter-spacing="1.2" fill="${mut}">${X(clip(TYPE_LABEL[x.type].toUpperCase(),10,700,PF.d,b.w-36))}</text>`;
    g+=`<text x="${b.x+11}" y="${b.y+38}" font-family="${PF.d}" font-weight="700" font-size="16" fill="${ink}">${X(clip(x.name,16,700,PF.d,b.w-22))}</text>`;
    g+=`<text x="${b.x+11}" y="${b.y+55}" font-family="${PF.m}" font-size="10.5" fill="${mut}">${X(clip(x.ip||'',10.5,400,PF.m,b.w-22))}</text>`;
    g+=`<text x="${b.x+11}" y="${b.y+68}" font-family="${PF.m}" font-size="10" fill="${mut}">${X(clip(x.os||'',10,400,PF.m,b.w-22))}</text>`;
    return g+'</g>';};
  Object.keys(box).forEach(id=>out+=card(id));
  // Badges, on top: number and port where a flow arrives, number alone where it reaches equipment it crosses.
  // Neighbouring badges are staggered so they do not overlap.
  list.forEach(s=>{if(!s.q2)return;const q=s.q2,out1=q.sd==='top'?-1:1,lvl=q.rank%3,by=q.y+out1*(15+lvl*17);
    if(s.last){const txt=`${s.n} · ${s.f.port}`,w=tw(txt,10.5,600,PF.m)+14;
      out+=`<rect x="${q.x-w/2}" y="${by-8.5}" width="${w}" height="17" rx="8.5" fill="${PC.panel}" stroke="${s.c}" stroke-width="1.3"/><text x="${q.x}" y="${by+3.6}" text-anchor="middle" font-family="${PF.m}" font-size="10.5" font-weight="600" fill="${s.c}">${X(txt)}</text>`;}
    else out+=`<circle cx="${q.x}" cy="${by}" r="8" fill="${PC.panel}" stroke="${s.c}" stroke-width="1.3"/><text x="${q.x}" y="${by+3.5}" text-anchor="middle" font-family="${PF.m}" font-size="10" font-weight="600" fill="${s.c}">${s.n}</text>`;});
  // Table of the flows
  if(FLS.length){
    const ty=tabY,C1=M,C2=M+40,C3=W-M-380,C4=W-M-290,C5=W-M-200,C6=W-M-110;
    out+=`<line x1="${M}" y1="${ty}" x2="${W-M}" y2="${ty}" stroke="${PC.line}" stroke-width="1"/>`;
    out+=`<text x="${M}" y="${ty+24}" font-family="${PF.d}" font-weight="700" font-size="12" letter-spacing="1.4" fill="${PC.muted}">FLOWS ON THIS PLAN · ${FLS.length}${sc.filtered?` OF ${sc.total} · FILTER: ${X(sc.label.toUpperCase())}`:''}</text>`;
    [['Path',C2],['Port',C3],['Volume',C4],['Exposure',C5],['Note',C6]].forEach(([t,x])=>out+=`<text x="${x}" y="${ty+44}" font-family="${PF.d}" font-weight="700" font-size="10.5" letter-spacing="1.1" fill="${PC.muted}">${t.toUpperCase()}</text>`);
    FLS.forEach((f,i)=>{const ry=ty+64+i*ROW,c=colOf(f);
      if(i%2)out+=`<rect x="${M-6}" y="${ry-15}" width="${W-M*2+12}" height="${ROW}" fill="${PC.zone}" opacity="0.55"/>`;
      out+=`<circle cx="${C1+10}" cy="${ry-4}" r="9" fill="${PC.panel}" stroke="${c}" stroke-width="1.5"/><text x="${C1+10}" y="${ry}" text-anchor="middle" font-family="${PF.m}" font-size="10.5" font-weight="600" fill="${c}">${num[f.id]}</text>`;
      out+=`<text x="${C2}" y="${ry}" font-family="${PF.b}" font-size="12" fill="${PC.ink}" ${f.src===a.id||f.dst===a.id?'font-weight="600"':''}>${X(clip(f.hops.map(nameOf).join(' → '),12,400,PF.b,C3-C2-16))}</text>`;
      out+=`<text x="${C3}" y="${ry}" font-family="${PF.m}" font-size="11" fill="${PC.ink}">${X(f.port)}</text>`;
      out+=`<text x="${C4}" y="${ry}" font-family="${PF.m}" font-size="11" fill="${PC.muted}">${f.vol} MB/h</text>`;
      out+=`<text x="${C5}" y="${ry}" font-family="${PF.b}" font-size="11.5" fill="${f.level==='internet'?PC.net:f.level==='inter'?PC.inter:PC.muted}">${X(EXP[f.level].label)}</text>`;
      out+=`<text x="${C6}" y="${ry}" font-family="${PF.b}" font-size="11.5" fill="${PC.crit}">${f.risk?X(clip(f.note||'Risky',11.5,400,PF.b,W-M-C6)):''}</text>`;});
  }
  // Firewall rules for this asset: one allow rule per flow and firewall crossed, then the default deny
  if(FWROWS.length){
    const ty=fwY+40,cols=[['Rule',M],['Firewall',M+48],['Source',M+196],['Destination',M+436],['Service',M+676],['Action',M+770],['Flow',M+836]],CM=M+884;
    out+=`<line x1="${M}" y1="${ty}" x2="${W-M}" y2="${ty}" stroke="${PC.line}" stroke-width="1"/>`;
    out+=`<text x="${M}" y="${ty+24}" font-family="${PF.d}" font-weight="700" font-size="12" letter-spacing="1.4" fill="${PC.muted}">FIREWALL RULES FOR ${X(a.name.toUpperCase())} · ${FW.rules.length}${FW.unfiltered.length?` · ${FW.unfiltered.length} UNFILTERED`:''}</text>`;
    [...cols,['Comment',CM]].forEach(([t,x])=>out+=`<text x="${x}" y="${ty+44}" font-family="${PF.d}" font-weight="700" font-size="10.5" letter-spacing="1.1" fill="${PC.muted}">${t.toUpperCase()}</text>`);
    const cell=(x,y,top,sub,w,o={})=>`<text x="${x}" y="${y}" font-family="${o.mono?PF.m:PF.b}" font-size="${o.mono?11:12}" ${o.bold?'font-weight="600"':''} fill="${o.c||PC.ink}">${X(clip(top,o.mono?11:12,o.bold?600:400,o.mono?PF.m:PF.b,w))}</text>`+(sub?`<text x="${x}" y="${y+13}" font-family="${PF.m}" font-size="10" fill="${PC.muted}">${X(clip(sub,10,400,PF.m,w))}</text>`:'');
    const rowAt=(r,i,deny)=>{const ry=ty+66+i*FROW,none=r.action==='—';
      if(i%2)out+=`<rect x="${M-6}" y="${ry-15}" width="${W-M*2+12}" height="${FROW}" fill="${PC.zone}" opacity="0.55"/>`;
      out+=cell(cols[0][1],ry,String(r.n||'—'),'',40,{mono:true});
      out+=cell(cols[1][1],ry,r.fw,'',140,{bold:!none,c:none?PC.crit:PC.ink});
      out+=cell(cols[2][1],ry,r.src,r.srcAddr,226);
      out+=cell(cols[3][1],ry,r.dst,r.dstAddr,226);
      out+=cell(cols[4][1],ry,r.service,'',88,{mono:true});
      out+=cell(cols[5][1],ry,r.action,'',60,{mono:true,c:deny?PC.crit:none?PC.muted:PC.low});
      if(r.flow&&num[r.flow.id]){const c=colOf(r.flow);out+=`<circle cx="${cols[6][1]+10}" cy="${ry-4}" r="9" fill="${PC.panel}" stroke="${c}" stroke-width="1.5"/><text x="${cols[6][1]+10}" y="${ry}" text-anchor="middle" font-family="${PF.m}" font-size="10.5" font-weight="600" fill="${c}">${num[r.flow.id]}</text>`;}
      out+=cell(CM,ry,r.comment||'',r.dir,W-M-CM,{c:/RISKY|not filtered/.test(r.comment||'')?PC.crit:PC.ink});};
    FWROWS.forEach((r,i)=>rowAt(r,i,false));
    rowAt({n:'',fw:'Every firewall above',src:'any',srcAddr:'all',dst:'any',dstAddr:'all',service:'any',action:'deny',comment:'Default rule, last on each firewall',dir:''},FWROWS.length,true);
  }
  // Legend and scope note
  const ly=H-M-LEG+26;
  out+=`<line x1="${M}" y1="${ly-18}" x2="${W-M}" y2="${ly-18}" stroke="${PC.line}" stroke-width="1"/>`;
  const legend=perFlow?[[PC_FLOW[0],''],[PC_FLOW[1],''],[PC_FLOW[2],'One colour per flow'],[PC.ink,'Risky flow',true]]:[[PC.net,'Internet'],[PC.inter,'Between VLANs'],[PC.intra,'Inside a VLAN'],[PC.crit,'Risky flow',true]];
  let lx=M;legend.forEach(([c,t,dash])=>{out+=`<line x1="${lx}" y1="${ly}" x2="${lx+30}" y2="${ly}" stroke="${c}" stroke-width="2.4" ${dash?'stroke-dasharray="7 5"':''}/><text x="${lx+38}" y="${ly+4}" font-family="${PF.b}" font-size="12" fill="${PC.ink}">${t}</text>`;lx+=t?60+tw(t,12,400,PF.b)+26:40;});
  out+=`<rect x="${lx}" y="${ly-9}" width="26" height="18" rx="3" fill="${PC.dev}"/><text x="${lx+34}" y="${ly+4}" font-family="${PF.b}" font-size="12" fill="${PC.ink}">Interconnection equipment</text>`;
  out+=`<text x="${M}" y="${ly+28}" font-family="${PF.b}" font-size="12" fill="${PC.ink}">Each line is one flow, from its source to its destination. Its number refers to the table; the badge where it arrives gives the destination port.</text>`;
  if(!FLS.length)out+=`<text x="${W/2}" y="${tabY-10}" text-anchor="middle" font-family="${PF.b}" font-size="14" fill="${PC.muted}">${sc.total?'No flow of this asset matches the filters.':'No flow recorded for this asset.'}</text>`;
  out+=`<text x="${M}" y="${ly+50}" font-family="${PF.b}" font-size="11.5" fill="${PC.muted}">${X(`${sc.filtered?`Filter: ${sc.label} (${FLS.length} of ${sc.total} flows). `:''}Scope: ${a.name} and ${sc.full?`its flows, the equipment they cross and ${sc.short?'the shortest':'every'} recorded path from and to the Internet`:'its own flows, with the equipment they cross'}. ${plural(Object.keys(box).length,'node')} · ${plural(FLS.length,'flow')}.`)}</text>`;
  const defs=[...marks].map(c=>`<marker id="a${c.slice(1)}" viewBox="0 0 10 10" refX="9.5" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="${c}"/></marker>`).join('');
  const svg=`<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}" font-family="${PF.b}"><title>${X(`Architecture plan · ${a.name} · IS ${SITE.name}`)}</title><defs>${defs}</defs>${out}</svg>`;
  return {svg,w:W,h:H,nodes:Object.keys(box).length,flows:FLS.length};
}
let PLAN=null;
// The filters stay the same from one plan to the next, until changed
const planFlt={dir:'all',lv:['internet','inter','intra']};
function openPlan(a,perFlow=state.color==='flow',full=false){
  if(!a)return;
  PLAN=Object.assign(buildPlanSvg(a,perFlow,full,planFlt),{asset:a,zoom:0,perFlow,full});
  document.querySelectorAll('#planDir [data-plan-dir]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.planDir===planFlt.dir)));
  document.querySelectorAll('#planLv [data-plan-lv]').forEach(b=>b.setAttribute('aria-pressed',String(planFlt.lv.includes(b.dataset.planLv))));
  $('#planDir [data-plan-dir="thru"]').hidden=!FLOWS.some(f=>f.via.includes(a.id));
  const cb=$('#planColour');cb.textContent=perFlow?'Colour: per flow':'Colour: exposure';cb.setAttribute('aria-pressed',String(perFlow));
  const sb=$('#planScope');sb.textContent=full?'Scope: full paths':'Scope: direct flows';sb.setAttribute('aria-pressed',String(full));
  $('#planTitle').textContent=`${a.name} · IS ${SITE.name}`;
  $('#planView').innerHTML=PLAN.svg;$('#plan').hidden=false;document.body.classList.add('has-plan');planZoom(0);
}
function planZoom(z){
  if(!PLAN)return;PLAN.zoom=z;const s=$('#planView svg');if(!s)return;
  if(z===0){s.style.width='100%';s.style.maxWidth=PLAN.w+'px';s.style.height='auto';}
  else{s.style.maxWidth='none';s.style.width=Math.round(PLAN.w*z)+'px';s.style.height='auto';}
}
function closePlan(){$('#plan').hidden=true;document.body.classList.remove('has-plan');$('#planView').innerHTML='';PLAN=null;}
async function planPng(){
  const img=new Image(),url=URL.createObjectURL(new Blob([PLAN.svg],{type:'image/svg+xml'}));
  try{
    await new Promise((ok,ko)=>{img.onload=ok;img.onerror=ko;img.src=url;});
    const k=2,c=document.createElement('canvas');c.width=PLAN.w*k;c.height=PLAN.h*k;const x=c.getContext('2d');x.scale(k,k);x.drawImage(img,0,0);
    const blob=await new Promise(r=>c.toBlob(r,'image/png'));
    await saveBlob(`architecture-plan_${fileStem(PLAN.asset.name)}_${today()}.png`,blob);
  }catch(e){toast('Could not produce the PNG. Download the SVG instead.',true);}
  finally{URL.revokeObjectURL(url);}
}
$('#plan').addEventListener('click',e=>{
  const fd=e.target.closest('[data-plan-dir]'),fl=e.target.closest('[data-plan-lv]');
  if((fd||fl)&&PLAN){
    if(fd)planFlt.dir=fd.dataset.planDir;
    else{const k=fl.dataset.planLv,on=planFlt.lv.includes(k);if(on&&planFlt.lv.length===1){toast('Keep at least one kind of flow.');return;}planFlt.lv=on?planFlt.lv.filter(x=>x!==k):[...planFlt.lv,k];}
    const z=PLAN.zoom;openPlan(PLAN.asset,PLAN.perFlow,PLAN.full);planZoom(z);return;}
  const b=e.target.closest('[data-plan]');if(!b||!PLAN)return;const k=b.dataset.plan;
  if(k==='close')closePlan();
  else if(k==='colour'){const z=PLAN.zoom;openPlan(PLAN.asset,!PLAN.perFlow,PLAN.full);planZoom(z);}
  else if(k==='scope'){const z=PLAN.zoom;openPlan(PLAN.asset,PLAN.perFlow,!PLAN.full);planZoom(z);}
  else if(k==='fit')planZoom(0);
  else if(k==='zoom-in'||k==='zoom-out'){const cur=PLAN.zoom||Math.min(1,$('#planView').clientWidth/PLAN.w);planZoom(Math.max(0.25,Math.min(3,cur*(k==='zoom-in'?1.25:0.8))));}
  else if(k==='svg')saveFile(`architecture-plan_${fileStem(PLAN.asset.name)}_${today()}.svg`,'image/svg+xml','<?xml version="1.0" encoding="UTF-8"?>\n'+PLAN.svg);
  else if(k==='png')planPng();});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&PLAN)closePlan();});

/* ================= 2D diagram: the same IS, drawn flat and edited directly ================= */
// Levels become bands (top level first), plates keep their order and size, assets their spot on the plate.
// Moving an asset here moves it in the 3D model too: positions are saved per VLAN (vlans[].layout).
const flatEl=$('#flat'),flatSvg=$('#flatSvg');
let FL=null,flatView={k:28,tx:300,ty:90},flatFitFor=null,flatDrag=null,flatRaf=0;
// The diagram spreads plates horizontally a little more than the model, so names fit on the cards
const FSX=1.25,CARD_H=1.5,cardW=a=>Math.max(2.9,Math.min(3.6,footW(a)+1.1));
const snap=v=>Math.round(v*4)/4;
function flatGeometry(){
  const L=computeLayout(),G={plates:{},assets:{},bands:[],L};
  let y=4.2;
  L.levels.slice().reverse().forEach(lv=>{
    const top=y+1.25,bi=G.bands.length;
    G.bands.push({name:lv.name,zoneId:lv.zoneId,li:lv.li,y,top,D:lv.D,minZ:lv.minZ,free:lv.free,x0:lv.minX*FSX,ids:lv.ids});
    lv.plates.forEach(pl=>{const v=vlanById[pl.id],cz=top+(pl.z0-lv.minZ);
      const P=G.plates[pl.id]={id:pl.id,v,x:(pl.x0-pl.w/2)*FSX,y:cz-pl.D/2,w:pl.w*FSX,h:pl.D,cx:pl.x0*FSX,cz,manual:pl.manual,zoneId:lv.zoneId,band:bi,x0:pl.x0,z0:pl.z0,w0:pl.w};
      pl.list.forEach(a=>{const sp=pl.spots[a.id];G.assets[a.id]={a,x:P.cx+sp.x*FSX,y:P.cz+sp.z,w:cardW(a),h:CARD_H,plate:pl.id,lx:sp.x,lz:sp.z};});
    });
    y=top+lv.D+2.1;
  });
  const ps=Object.values(G.plates);
  G.minX=Math.min(0,...ps.map(p=>p.x));G.maxX=Math.max(8,...ps.map(p=>p.x+p.w));G.H=y-1.5;
  G.internet={x:G.minX+2.6,y:1.9,w:4.4,h:1.8};
  G.svc={};let sx=G.internet.x+G.internet.w/2+1.2;
  siteServices().forEach(x=>{const w=Math.max(3.6,Math.min(6,x.name.length*0.24+1.4));G.svc[x.id]={x:sx+w/2,y:1.9,w,h:1.8,s:x};sx+=w+0.8;});
  G.maxX=Math.max(G.maxX,sx);
  return G;
}
// Small top-view glyphs, drawn in a 1 x 1 box
const GLYPH={
  server:'M.25 .08h.5v.84h-.5zM.33 .25h.34M.33 .42h.34M.33 .59h.34',
  dc:'M.25 .28h.5v.64h-.5zM.25 .28L.5 .06L.75 .28M.33 .48h.34M.33 .64h.34',
  db:'M.2 .22a.3 .12 0 1 0 .6 0a.3 .12 0 1 0 -.6 0M.2 .22v.56a.3 .12 0 0 0 .6 0v-.56M.2 .5a.3 .12 0 0 0 .6 0',
  hypervisor:'M.1 .2h.8v.25h-.8zM.1 .55h.8v.25h-.8zM.2 .32h.3M.2 .67h.3',
  firewall:'M.08 .2h.84v.6h-.84zM.08 .4h.84M.08 .6h.84M.36 .2v.2M.64 .2v.2M.22 .4v.2M.5 .4v.2M.78 .4v.2M.36 .6v.2M.64 .6v.2',
  gateway:'M.12 .45h.76v.4h-.76zM.28 .45V.1M.72 .45V.1M.24 .65h.1M.4 .65h.1',
  router:'M.5 .5m-.38 0a.38 .38 0 1 0 .76 0a.38 .38 0 1 0 -.76 0M.5 .2v.6M.2 .5h.6M.5 .2l-.08 .08M.5 .2l.08 .08M.5 .8l-.08 -.08M.5 .8l.08 -.08',
  switch:'M.06 .34h.88v.32h-.88zM.16 .5h.06M.3 .5h.06M.44 .5h.06M.58 .5h.06M.72 .5h.06',
  workstation:'M.1 .12h.8v.5h-.8zM.5 .62v.14M.3 .82h.4',
  printer:'M.12 .38h.76v.36h-.76zM.28 .38V.14h.44v.24M.28 .74v.14h.44v-.14',
  phone:'M.18 .3h.64v.56h-.64zM.18 .3l.1 -.16h.44l.1 .16M.3 .5h.4',
  ap:'M.5 .58m-.08 0a.08 .08 0 1 0 .16 0a.08 .08 0 1 0 -.16 0M.3 .42a.28 .28 0 0 1 .4 0M.18 .3a.45 .45 0 0 1 .64 0',
  camera:'M.12 .3h.56v.34h-.56zM.68 .4l.2 -.1v.34l-.2 -.1M.3 .64v.22',
  plc:'M.08 .2h.18v.6h-.18zM.31 .2h.18v.6h-.18zM.54 .2h.18v.6h-.18zM.77 .25h.15v.5h-.15z',
  iot:'M.3 .1h.4v.8h-.4zM.4 .25h.2v.2h-.2zM.45 .7h.1'
};
// pal: the colour of a theme token; the current theme by default
function flatSvgMarkup(G,V,forExport,pal){
  const C=pal||css,bg=C('--mat'),line=C('--matline'),ink=C('--fg'),card=C('--panel'),muted=C('--muted'),dark=C('--detail'),devText='#eef0ec';
  const sel=V.sel,edit=Store.canWrite&&!forExport;
  const pos=id=>{
    if(id==='internet')return G.internet;
    if(G.svc[id])return G.svc[id];
    const g=G.assets[id];if(!g)return null;
    const d=flatDrag;
    if(d&&d.moved&&d.kind==='asset'&&d.id===id)return Object.assign({},g,{x:d.wx,y:d.wy});
    if(d&&d.moved&&d.kind==='plate'&&g.plate===d.id)return Object.assign({},g,{x:g.x+d.dx,y:g.y+d.dy});
    return g;};
  const F=PF.b,M=PF.m,D=PF.d;
  let o='',marks=new Set();
  // bands
  G.bands.forEach(b=>{const t=G.L.zm?`LEVEL ${b.li} · ${b.name.toUpperCase()}`:b.name.toUpperCase();o+=`<text x="${b.x0}" y="${b.top-0.4}" font-family="${D}" font-weight="700" font-size="0.62" letter-spacing="0.08" fill="${C('--card')}" opacity="0.9">${esc(t)}</text>`;
    if(b.free&&edit){const bx=b.x0+tw(t,62,700,D)/100+t.length*0.08+0.5;o+=`<g data-reset-zone="${esc(b.zoneId)}" class="fbtn"><rect x="${bx}" y="${b.top-1.05}" width="2.2" height="0.8" rx="0.15" fill="${card}"/><text x="${bx+1.1}" y="${b.top-0.5}" text-anchor="middle" font-family="${F}" font-size="0.38" fill="${ink}">Line up</text><title>Line the plates of this level up again</title></g>`;}});
  // plates
  Object.values(G.plates).forEach(P=>{
    const hid=state.hidden.has(P.id),d=flatDrag&&flatDrag.moved&&flatDrag.kind==='plate'&&flatDrag.id===P.id?flatDrag:null;
    const x=P.x+(d?d.dx:0),y=P.y+(d?d.dy:0),col=C('--c'+P.v.ci);
    o+=`<g data-plate="${esc(P.id)}" opacity="${hid?0.3:1}"><rect x="${x}" y="${y}" width="${P.w}" height="${P.h}" rx="0.25" fill="${col}" stroke="${shadeHex(col,-0.25)}" stroke-width="0.06" ${d?'stroke-dasharray="0.3 0.2"':''}/>`;
    o+=`<rect x="${x}" y="${y}" width="${P.w}" height="1.05" rx="0.25" fill="${shadeHex(col,-0.12)}" ${edit?'data-plate-handle="'+esc(P.id)+'" class="ph"':''}/>`;
    o+=`<text x="${x+0.35}" y="${y+0.72}" font-family="${D}" font-weight="700" font-size="0.52" fill="${ink}" pointer-events="none">${esc(clip(`VLAN ${P.v.num} · ${P.v.name}`,52,700,D,(P.w-(P.v.cidr?3.2:0.8)-(P.manual&&edit?1.7:0))*100))}</text>`;
    if(P.v.cidr)o+=`<text x="${x+P.w-(P.manual&&edit?2.0:0.35)}" y="${y+0.7}" text-anchor="end" font-family="${M}" font-size="0.34" fill="${ink}" opacity="0.7" pointer-events="none">${esc(P.v.cidr)}</text>`;
    if(P.manual&&edit)o+=`<g data-auto="${esc(P.id)}" class="fbtn"><rect x="${x+P.w-1.75}" y="${y+0.18}" width="1.5" height="0.7" rx="0.14" fill="${card}" stroke="${ink}" stroke-width="0.03"/><text x="${x+P.w-1.0}" y="${y+0.66}" text-anchor="middle" font-family="${F}" font-size="0.36" fill="${ink}">Auto</text><title>Arrange this plate automatically again</title></g>`;
    o+='</g>';});
  // flows, under the cards
  const clipTo=(c,t,pad)=>{const dx=t.x-c.x,dy=t.y-c.y;if(!dx&&!dy)return {x:c.x,y:c.y};const sx=dx?(c.w/2+pad)/Math.abs(dx):Infinity,sy=dy?(c.h/2+pad)/Math.abs(dy):Infinity,s=Math.min(sx,sy,1);return {x:c.x+dx*s,y:c.y+dy*s};};
  const flowEls=[];
  FLOWS.forEach((f,fi)=>{const fv=V.fv[f.id];if(!fv.vis)return;
    const last=f.hops.length-1,pts=f.hops.map((id,i)=>{const p=pos(id),l=p&&i>0&&i<last?laneOf(f,id):null;if(!l)return p;
      // a lane on the card of the device crossed: shifted centre, narrower box so the thread still stops at the card edge
      const dx=l.t*Math.min(0.42*(l.n-1),p.w-0.6);return Object.assign({},p,{x:p.x+dx,w:p.w-2*Math.abs(dx)});});
    if(pts.some(p=>!p))return;
    const col=C(flowColorVar(f)),w=(0.05+Math.log10(1+f.vol)*0.032)*(DIFF&&DIFF.F[f.id]?2.2:1),mk='m'+col.replace(/[^0-9a-z]/gi,'');marks.add(col);
    const side=(((fi*2654435761)>>>0)%2?1:-1),dash=f.risk?' stroke-dasharray="0.32 0.2"':'';let segs='',hit='';
    for(let i=0;i<pts.length-1;i++){
      const a=clipTo(pts[i],pts[i+1],0.06),b=clipTo(pts[i+1],pts[i],0.12),mx=(a.x+b.x)/2,my=(a.y+b.y)/2,len=Math.hypot(b.x-a.x,b.y-a.y)||1;
      const off=Math.min(1.6,len*0.12)*side,cx=mx-(b.y-a.y)/len*off,cy=my+(b.x-a.x)/len*off;
      const d=`M${a.x.toFixed(2)},${a.y.toFixed(2)} Q${cx.toFixed(2)},${cy.toFixed(2)} ${b.x.toFixed(2)},${b.y.toFixed(2)}`;
      segs+=`<path d="${d}" fill="none" stroke="${col}" stroke-width="${w.toFixed(3)}"${dash} stroke-linecap="round" marker-end="url(#${mk})"/>`;hit+=d+' ';}
    flowEls.push({op:fv.op,s:`<g data-flow="${esc(f.id)}" opacity="${fv.op}">${segs}${forExport?'':`<path d="${hit}" fill="none" stroke="transparent" stroke-width="0.55"/>`}</g>`});});
  flowEls.sort((a,b)=>a.op-b.op).forEach(x=>o+=x.s);
  // flows a draft or a proposal removes: dashed red, between their ends when both are still drawn
  if(DIFF&&SITE)DIFF.items.filter(it=>it.kind==='flow'&&it.op==='removed'&&it.site===SITE.id).forEach(it=>{const a=pos(it.before.src),b=pos(it.before.dst);if(!a||!b)return;
    o+=`<g opacity="0.85"><line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${C('--crit')}" stroke-width="0.09" stroke-dasharray="0.25 0.25"/><text x="${(a.x+b.x)/2}" y="${(a.y+b.y)/2-0.2}" text-anchor="middle" font-family="${D}" font-weight="700" font-size="0.34" fill="${C('--crit')}">REMOVED ${esc(it.before.port||'')}</text></g>`;});
  // Internet
  const I=G.internet;
  Object.values(G.svc).forEach(v=>{o+=`<g data-internet="${esc(v.s.id)}" data-svc="${esc(v.s.id)}" class="fa"><rect x="${v.x-v.w/2}" y="${v.y-v.h/2}" width="${v.w}" height="${v.h}" rx="0.3" fill="${card}" stroke="${C('--x-net')}" stroke-width="0.07"/><text x="${v.x-v.w/2+0.3}" y="${v.y-0.12}" font-family="${D}" font-weight="700" font-size="0.42" fill="${ink}">${esc(clip(v.s.name,42,700,D,(v.w-0.6)*100))}</text><text x="${v.x-v.w/2+0.3}" y="${v.y+0.42}" font-family="${M}" font-size="0.26" fill="${muted}">${esc(clip(v.s.hosts.join(', ')||v.s.category,26,400,M,(v.w-0.6)*100))}</text>${forExport?'':`<title>${esc(v.s.name+' · '+v.s.hosts.join(', ')+' · '+v.s.ports.join(' '))}</title>`}</g>`;});
  o+=`<g data-internet="internet"><rect x="${I.x-I.w/2}" y="${I.y-I.h/2}" width="${I.w}" height="${I.h}" rx="0.95" fill="${card}" stroke="${C('--x-net')}" stroke-width="0.09"/><text x="${I.x}" y="${I.y+0.2}" text-anchor="middle" font-family="${D}" font-weight="700" font-size="0.62" fill="${ink}">Internet</text></g>`;
  // assets
  Object.values(G.assets).forEach(g0=>{const g=pos(g0.a.id),a=g0.a;if(state.hidden.has(a.vlan))return;
    const op=V.aOp[a.id],dev=INTERCO.has(a.type),fill=dev?dark:card,tx=dev?devText:ink,mu=dev?'#aeb6bb':muted,sev=a.sev!=='none'?C(SEV[a.sev].css):null;
    const x=g.x-g.w/2,y=g.y-g.h/2,isSel=sel===a,drag=flatDrag&&flatDrag.moved&&flatDrag.kind==='asset'&&flatDrag.id===a.id;
    o+=`<g data-asset="${esc(a.id)}" opacity="${drag?0.85:op}" class="fa">`;
    if(isSel)o+=`<rect x="${x-0.16}" y="${y-0.16}" width="${g.w+0.32}" height="${g.h+0.32}" rx="0.32" fill="none" stroke="${C('--accent')}" stroke-width="0.12"/>`;
    if(DIFF&&DIFF.A[a.id])o+=`<rect x="${x-0.28}" y="${y-0.28}" width="${g.w+0.56}" height="${g.h+0.56}" rx="0.4" fill="none" stroke="${C(DIFF_COL[DIFF.A[a.id]])}" stroke-width="0.14" stroke-dasharray="${DIFF.A[a.id]==='added'?'none':'0.35 0.2'}"/><text x="${x+g.w+0.1}" y="${y-0.36}" text-anchor="end" font-family="${D}" font-weight="700" font-size="0.36" fill="${C(DIFF_COL[DIFF.A[a.id]])}">${DIFF.A[a.id]==='added'?'NEW':'CHANGED'}</text>`;
    o+=`<rect x="${x}" y="${y}" width="${g.w}" height="${g.h}" rx="0.2" fill="${fill}" stroke="${dev?fill:C('--line')}" stroke-width="0.05"/>`;
    if(sev)o+=`<rect x="${x}" y="${y+g.h-0.14}" width="${g.w}" height="0.14" fill="${sev}"/>`;
    if(a.exp!=='none'&&state.ports)o+=`<rect x="${x+g.w-0.95}" y="${y-0.42}" width="0.95" height="0.42" rx="0.08" fill="${C(EXP[a.exp].css)}"/><text x="${x+g.w-0.475}" y="${y-0.12}" text-anchor="middle" font-family="${M}" font-size="0.27" font-weight="600" fill="#fff">IN ${a.ports.length}</text>`;
    o+=`<path transform="translate(${x+0.1},${y+0.36}) scale(0.6)" d="${GLYPH[a.type]||GLYPH.server}" fill="none" stroke="${tx}" stroke-width="0.08" stroke-linejoin="round" stroke-linecap="round"/>`;
    o+=`<text x="${x+0.8}" y="${y+0.66}" font-family="${D}" font-weight="700" font-size="0.44" fill="${tx}">${esc(clip(a.name,44,700,D,(g.w-0.9)*100))}</text>`;
    o+=`<text x="${x+0.8}" y="${y+1.08}" font-family="${M}" font-size="0.27" fill="${mu}">${esc(clip(a.ip||TYPE_LABEL[a.type],27,400,M,(g.w-0.9)*100))}</text>`;
    if(!forExport)o+=`<title>${esc(`${a.name} · ${TYPE_LABEL[a.type]}${a.os?' · '+a.os:''}`)}</title>`;
    o+='</g>';});
  // flow being drawn
  if(flatDrag&&flatDrag.kind==='link'){const a=pos(flatDrag.from);o+=`<line x1="${a.x}" y1="${a.y}" x2="${flatDrag.wx}" y2="${flatDrag.wy}" stroke="${ink}" stroke-width="0.09" stroke-dasharray="0.3 0.18" marker-end="url(#mlink)"/>`;}
  const defs=`<pattern id="grid" width="1" height="1" patternUnits="userSpaceOnUse"><path d="M1 0H0V1" fill="none" stroke="${line}" stroke-width="0.025" opacity="0.6"/></pattern><pattern id="grid5" width="5" height="5" patternUnits="userSpaceOnUse"><path d="M5 0H0V5" fill="none" stroke="${line}" stroke-width="0.05"/></pattern>`+
    [...marks].map(c=>`<marker id="m${c.replace(/[^0-9a-z]/gi,'')}" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="userSpaceOnUse" markerWidth="0.55" markerHeight="0.55" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="${c}"/></marker>`).join('')+
    `<marker id="mlink" viewBox="0 0 10 10" refX="9" refY="5" markerUnits="userSpaceOnUse" markerWidth="0.6" markerHeight="0.6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="${ink}"/></marker>`;
  const x0=G.minX-3,y0=-1,w=G.maxX-G.minX+6,h=G.H+2;
  if(forExport)return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${x0} ${y0} ${w} ${h}" width="${Math.round(w*40)}" height="${Math.round(h*40)}" font-family="${F}"><title>${esc(`IS ${SITE.name} · 2D diagram`)}</title><defs>${defs}</defs><rect x="${x0}" y="${y0}" width="${w}" height="${h}" fill="${bg}"/><rect x="${x0}" y="${y0}" width="${w}" height="${h}" fill="url(#grid)"/>${o}</svg>`;
  return `<defs>${defs}</defs><g id="fvp" transform="matrix(${flatView.k},0,0,${flatView.k},${flatView.tx},${flatView.ty})"><rect x="-500" y="-500" width="1000" height="1000" fill="url(#grid)" data-bg="1"/><rect x="-500" y="-500" width="1000" height="1000" fill="url(#grid5)" pointer-events="none"/>${o}</g>`;
}
function shadeHex(hex,k){const n=parseInt(String(hex).replace('#','').slice(0,6),16);if(isNaN(n))return hex;const f=c=>Math.max(0,Math.min(255,Math.round(k<0?c*(1+k):c+(255-c)*k)));return '#'+[n>>16,(n>>8)&255,n&255].map(c=>f(c).toString(16).padStart(2,'0')).join('');}
function renderFlat(){
  if(!state.flat||state.view!=='site')return;
  FL=flatGeometry();
  if(flatFitFor!==SITE.id){flatFitFor=SITE.id;fitFlat(true);}
  flatSvg.innerHTML=flatSvgMarkup(FL,computeVis(),false);
  flatSvg.classList.toggle('tool-flow',state.tool==='flow');flatSvg.classList.toggle('tool-asset',state.tool==='asset');
}
function scheduleFlat(){if(flatRaf)return;flatRaf=requestAnimationFrame(()=>{flatRaf=0;renderFlat();});}
function applyFlatView(){const g=$('#fvp');if(g)g.setAttribute('transform',`matrix(${flatView.k},0,0,${flatView.k},${flatView.tx},${flatView.ty})`);}
function flatViewport(){const r=flatSvg.getBoundingClientRect(),narrow=innerWidth<=760;
  const left=narrow?12:(document.querySelector('#ctl').getBoundingClientRect().right+16),right=narrow?12:(document.body.classList.contains('has-det')?$('#det').getBoundingClientRect().width+32:24);
  const top=narrow?190:(Math.max($('#viewSw').getBoundingClientRect().bottom,$('#cart').getBoundingClientRect().bottom)+14);
  return {x:left,y:top,w:Math.max(200,r.width-left-right),h:Math.max(200,r.height-top-30)};}
function fitFlat(noRender){
  const G=FL||flatGeometry(),vp=flatViewport(),w=G.maxX-G.minX+4,h=G.H+1;
  const k=Math.max(6,Math.min(60,Math.min(vp.w/w,vp.h/h)));
  flatView={k,tx:vp.x+(vp.w-w*k)/2-(G.minX-2)*k,ty:vp.y+(vp.h-h*k)/2};
  if(!noRender)applyFlatView();
}
function zoomFlat(f,cx,cy){const r=flatSvg.getBoundingClientRect();cx=cx==null?r.width/2:cx;cy=cy==null?r.height/2:cy;
  const k=Math.max(4,Math.min(90,flatView.k*f)),s=k/flatView.k;flatView={k,tx:cx-(cx-flatView.tx)*s,ty:cy-(cy-flatView.ty)*s};applyFlatView();}
function centerFlatOn(a){const g=FL&&FL.assets[a.id];if(!g)return;const vp=flatViewport();flatView.tx=vp.x+vp.w/2-g.x*flatView.k;flatView.ty=vp.y+vp.h/2-g.y*flatView.k;applyFlatView();}
const toWorld=e=>{const r=flatSvg.getBoundingClientRect();return [(e.clientX-r.left-flatView.tx)/flatView.k,(e.clientY-r.top-flatView.ty)/flatView.k];};
const plateAt=(x,y,tol=0)=>Object.values(FL.plates).find(P=>!state.hidden.has(P.id)&&x>=P.x-tol&&x<=P.x+P.w+tol&&y>=P.y-tol&&y<=P.y+P.h+tol)||null;
// Current spots of a plate's assets, to save them as hand-placed
const frozen=pid=>{const o={};Object.values(FL.assets).forEach(g=>{if(g.plate===pid)o[g.a.id]=[snap(g.lx),snap(g.lz)];});return o;};
async function saveLayouts(changes,extra){
  const d=clone(SITE.raw);
  d.vlans=(d.vlans||[]).map(x=>{if(!(x.id in changes))return x;const y=Object.assign({},x,extra&&extra[x.id]||{});if(changes[x.id])y.layout=changes[x.id];else delete y.layout;return y;});
  await Store.putSite(SITE.id,d);
}
async function dropAsset(id,X,Y){
  const a=byId[id],P=plateAt(X,Y,0.3);
  if(!P){toast('Drop the asset on a VLAN plate.',true);renderFlat();return;}
  const local=[snap((X-P.cx)/FSX),snap(Y-P.cz)];
  // keep clear of the other assets already on that plate: slide right until free
  const others=Object.values(FL.assets).filter(g=>g.plate===P.id&&g.a.id!==id);
  for(let k=0;k<40;k++){const hit=others.find(g=>Math.abs(g.lx-local[0])<(footW(g.a)+footW(a))/2+0.6&&Math.abs(g.lz-local[1])<1.9);if(!hit)break;local[0]=snap(hit.lx+(footW(hit.a)+footW(a))/2+0.7);}
  try{
    if(P.id===a.vlan){const l=frozen(P.id);l[id]=local;await saveLayouts({[P.id]:l});return;}
    const l=frozen(P.id);l[id]=local;const old=frozen(a.vlan);delete old[id];
    const doc=clone(raw.assets[id]);doc.vlan=P.id;
    await Store.putAsset(id,doc);await saveLayouts({[P.id]:l,[a.vlan]:Object.keys(old).length?old:null});
    toast(`${a.name} moved to VLAN ${P.v.num}.`);
  }catch(e){renderFlat();}
}
async function dropPlate(id,X,Y,drag){
  const P=FL.plates[id],cxNew=P.cx+drag.dx;
  // band under the pointer, or the nearest one
  let bi=FL.bands.findIndex(b=>Y>=b.y&&Y<=b.top+b.D+1.7);if(bi<0)bi=Y<FL.bands[0].y?0:FL.bands.length-1;
  const band=FL.bands[bi],v=vlanById[id];
  let zoneId,ids;
  if(FL.L.zm){
    // free placement on the level under the pointer: left/right and front/back
    const czNew=P.cz+drag.dy,places={},others=[];
    band.ids.filter(x=>x!==id).forEach(x=>{const Q=FL.plates[x];places[x]=[Math.round(Q.x0*2)/2,Math.round(Q.z0*2)/2];others.push({x:Q.x0,z:Q.z0,w:Q.w0,D:Q.h});});
    const z0=Math.max(band.minZ-4,Math.min(band.minZ+band.D+4,czNew-band.top+band.minZ));
    places[id]=clearSpot([cxNew/FSX,z0],P.w0,P.h,others);
    try{await savePlaces(places,band.zoneId!==v.zoneId?{[id]:band.zoneId}:{});toast(band.zoneId!==v.zoneId?`VLAN ${v.num} moved to zone ${(ZONES.find(z=>z.id===band.zoneId)||{}).name}.`:'Plate moved.');}catch(e){renderFlat();}
    return;
  }
  else{const T=band.ids[0];zoneId=vlanById[T].zoneId;const z=ZONES.find(z=>z.id===zoneId);ids=z.vlans.map(x=>x.id).filter(x=>x!==id);
    if(T===id){renderFlat();return;}
    const ti=ids.indexOf(T),upper=Y<band.top+band.D/2;ids.splice(upper?ti+1:ti,0,id);}
  const before=(ZONES.find(z=>z.id===v.zoneId)||{vlans:[]}).vlans.map(x=>x.id);
  if(zoneId===v.zoneId&&ids.join()===before.join()){renderFlat();return;}
  const d=clone(SITE.raw);
  d.vlans=(d.vlans||[]).map(x=>{const k=ids.indexOf(x.id);let y=k<0?x:Object.assign({},x,{pos:k});if(x.id===id)y=Object.assign({},y,{zone:zoneId});return y;});
  try{await Store.putSite(SITE.id,d);toast(zoneId!==v.zoneId?`VLAN ${v.num} moved to zone ${(ZONES.find(z=>z.id===zoneId)||{}).name}.`:'Plates rearranged.');}catch(e){renderFlat();}
}
function flatTip(e){
  if(e.pointerType!=='mouse'){tip.hidden=true;return;}
  const t=e.target,A=t.closest&&t.closest('[data-asset]'),Fl=t.closest&&t.closest('[data-flow]');let html='';
  if(A){const a=byId[A.dataset.asset];html=`<b>${esc(a.name)}</b> · ${esc(a.ip||'')} · <span style="color:var(${SEV[a.sev].css})">${SEV[a.sev].label}</span> · <span style="color:var(${EXP[a.exp].css})">${EXP[a.exp].label}</span>`;}
  else if(Fl){const f=FLOWS.find(x=>x.id===Fl.dataset.flow);if(f)html=`<b>${flowPath(f)}</b> · ${esc(f.port)} · ${f.vol} MB/h · <span style="color:var(${EXP[f.level].css})">${EXP[f.level].label}</span>`;}
  if(html){tip.innerHTML=html;tip.hidden=false;tip.style.left=Math.min(e.clientX+14,innerWidth-tip.offsetWidth-8)+'px';tip.style.top=(e.clientY+14)+'px';}else tip.hidden=true;
}
flatSvg.addEventListener('pointerdown',e=>{
  if(e.button!==0||!FL)return;
  const t=e.target,q=s=>t.closest(s),[wx,wy]=toWorld(e),edit=Store.canWrite&&state.panel!=='form';
  const A=q('[data-asset]'),N=q('[data-internet]'),Fl=q('[data-flow]'),Hd=q('[data-plate-handle]'),Pl=q('[data-plate]'),Au=q('[data-auto]');
  tip.hidden=true;
  const Rz=q('[data-reset-zone]');if(Rz){if(edit)resetPlaces(Rz.dataset.resetZone);return;}
  if(Au){if(edit)saveLayouts({[Au.dataset.auto]:null}).then(()=>toast('Plate arranged automatically.'),()=>{});return;}
  if(state.tool==='flow'&&edit&&(A||N)){flatDrag={kind:'link',from:A?A.dataset.asset:(N.dataset.internet==='1'?'internet':N.dataset.internet),wx,wy,moved:true};flatSvg.setPointerCapture(e.pointerId);scheduleFlat();return;}
  if(state.tool==='asset'&&edit){const P=(Pl||Hd)?FL.plates[(Pl||Hd).dataset.plate||Hd.dataset.plateHandle]:plateAt(wx,wy);
    if(!P){toast('Click on a VLAN plate to place the new asset.',true);return;}
    assetForm(null,P.id,{pos:[snap((wx-P.cx)/FSX),snap(wy-P.cz)]});return;}
  if(N&&N.dataset.svc){flatDrag={kind:'svc',id:N.dataset.svc,sx:e.clientX,sy:e.clientY,moved:false};return;}
  if(A){const g=FL.assets[A.dataset.asset];flatDrag={kind:'asset',id:g.a.id,sx:e.clientX,sy:e.clientY,ox:wx-g.x,oy:wy-g.y,wx:g.x,wy:g.y,moved:false,edit};flatSvg.setPointerCapture(e.pointerId);return;}
  if(Hd&&edit){flatDrag={kind:'plate',id:Hd.dataset.plateHandle,sx:e.clientX,sy:e.clientY,startX:wx,startY:wy,dx:0,dy:0,moved:false};flatSvg.setPointerCapture(e.pointerId);return;}
  if(Fl){flatDrag={kind:'flow',id:Fl.dataset.flow,sx:e.clientX,sy:e.clientY,moved:false};return;}
  flatDrag={kind:'pan',sx:e.clientX,sy:e.clientY,tx:flatView.tx,ty:flatView.ty,moved:false};flatSvg.setPointerCapture(e.pointerId);flatSvg.classList.add('panning');
});
flatSvg.addEventListener('pointermove',e=>{
  const d=flatDrag;if(!d){flatTip(e);return;}
  const far=Math.hypot(e.clientX-(d.sx||0),e.clientY-(d.sy||0))>4,[wx,wy]=toWorld(e);
  if(d.kind==='pan'){if(far)d.moved=true;flatView.tx=d.tx+e.clientX-d.sx;flatView.ty=d.ty+e.clientY-d.sy;applyFlatView();return;}
  if(d.kind==='link'){d.wx=wx;d.wy=wy;scheduleFlat();return;}
  if(d.kind==='asset'){if(!d.edit)return;if(far)d.moved=true;if(d.moved){d.wx=wx-d.ox;d.wy=wy-d.oy;scheduleFlat();}return;}
  if(d.kind==='plate'){if(far)d.moved=true;if(d.moved){d.dx=wx-d.startX;d.dy=wy-d.startY;scheduleFlat();}return;}
  if((d.kind==='flow'||d.kind==='svc')&&far)d.moved=true;
});
flatSvg.addEventListener('pointerup',e=>{
  const d=flatDrag;flatDrag=null;flatSvg.classList.remove('panning');if(!d)return;
  const [wx,wy]=toWorld(e);
  if(d.kind==='pan'){if(!d.moved&&state.panel!=='form'){if(state.selId)select(null);else if(state.panel==='flow')closeDet();}return;}
  if(d.kind==='asset'){if(!d.moved){if(state.panel!=='form')select(byId[d.id],false);return;}dropAsset(d.id,d.wx,d.wy);return;}
  if(d.kind==='plate'){if(!d.moved){renderFlat();return;}dropPlate(d.id,wx,wy,d);return;}
  if(d.kind==='svc'){if(!d.moved&&state.panel!=='form'&&SVC[d.id])showService(SVC[d.id]);return;}
  if(d.kind==='flow'){if(!d.moved&&state.panel!=='form'){const f=FLOWS.find(x=>x.id===d.id);if(f)showFlow(f);}return;}
  if(d.kind==='link'){renderFlat();const el=document.elementFromPoint(e.clientX,e.clientY),T=el&&el.closest&&(el.closest('[data-asset]')||el.closest('[data-internet]'));
    const to=T?(T.dataset.asset||(T.dataset.internet==='1'?'internet':T.dataset.internet)):null;
    if(!to||to===d.from){toast('Release on another asset (or on Internet) to create the flow.',true);return;}
    if(isNet(d.from)&&isNet(to)){toast('One side of a flow must be an asset of this IS.',true);return;}
    flowForm(null,{src:d.from,dst:to});}
});
flatSvg.addEventListener('pointerleave',()=>{if(!flatDrag)tip.hidden=true;});
flatSvg.addEventListener('wheel',e=>{e.preventDefault();const r=flatSvg.getBoundingClientRect();zoomFlat(Math.exp(-e.deltaY*0.001),e.clientX-r.left,e.clientY-r.top);},{passive:false});
function setTool(t){state.tool=t;document.querySelectorAll('#tools2d [data-tool]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.tool===t)));if(state.flat)renderFlat();syncUI();}
function setFlat(on){
  state.flat=!!on;if(state.flat&&state.arrange)setArrange(false);
  document.querySelectorAll('#viewSeg button').forEach(b=>b.setAttribute('aria-pressed',String((b.dataset.v==='2d')===state.flat)));
  showFlatUI();
  if(state.flat&&state.view==='site'){renderFlat();}
  else{tip.hidden=true;controls.update();}
  syncUI();
}
function showFlatUI(){
  const lens=state.view==='site'&&state.lens!=='physical',on=state.flat&&state.view==='site'&&!lens;
  flatEl.hidden=!on;document.body.classList.toggle('flat',on);
  $('#viewSw').hidden=state.view!=='site';$('#tools2d').hidden=!on;$('#viewSeg').hidden=lens;
  lensEl.hidden=!lens;document.body.classList.toggle('lens',lens);
  document.querySelectorAll('#lensSeg button').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.lens===state.lens)));
  if(lens)renderLens();
}
async function exportFlat(){
  if(!FL)return;
  await saveFile(`diagram_${fileStem(SITE.name)}_${today()}.svg`,'image/svg+xml','<?xml version="1.0" encoding="UTF-8"?>\n'+flatSvgMarkup(FL,computeVis(),true));
}
$('#viewSeg').addEventListener('click',e=>{const b=e.target.closest('button');if(b)setFlat(b.dataset.v==='2d');});
$('#tools2d').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;
  if(b.dataset.tool)setTool(b.dataset.tool);
  else if(b.dataset.f==='fit')fitFlat();
  else if(b.dataset.f==='in')zoomFlat(1.25);
  else if(b.dataset.f==='out')zoomFlat(0.8);
  else if(b.dataset.f==='svg')exportFlat();});
document.addEventListener('keydown',e=>{
  if(!state.flat||state.view!=='site'||state.lens!=='physical'||e.target.closest('input,textarea,select')||e.metaKey||e.ctrlKey||e.altKey)return;
  const k=e.key.toLowerCase();
  if(k==='v')setTool('move');else if(k==='f'&&Store.canWrite)setTool('flow');else if(k==='a'&&Store.canWrite)setTool('asset');
  else if(k==='escape'&&flatDrag){flatDrag=null;renderFlat();}
});

/* ================= Views: physical, application, business ================= */
// Physical is the 3D model or the 2D diagram. Application groups the assets by the applications
// they run and draws who calls whom. Business lists the business services and what they rely on.
const lensEl=$('#lens'),lensBody=$('#lensBody');
let APPG=null;
function setLens(l){if(l===state.lens)return;state.lens=l;state.hoverFlow=null;showFlatUI();syncUI();if(l==='physical'){if(state.flat){flatFitFor=null;renderFlat();}refresh();}}
function placeLens(){
  if(!lensEl||lensEl.hidden)return;
  const narrow=innerWidth<=760,sw=$('#viewSw').getBoundingClientRect();
  lensBody.style.paddingLeft=(narrow?12:document.querySelector('#ctl').getBoundingClientRect().right+16)+'px';
  lensBody.style.paddingRight=(narrow||!document.body.classList.contains('has-det')?(narrow?12:24):det.getBoundingClientRect().width+32)+'px';
  lensBody.style.paddingTop=(narrow?sw.bottom+12:Math.max(sw.bottom,$('#cart').getBoundingClientRect().bottom)+16)+'px';
}
addEventListener('resize',placeLens);
function renderLens(){
  if(state.view!=='site'||state.lens==='physical')return;
  if(state.lens==='app')renderAppLens();else renderBizLens();
  placeLens();
}
const worstOf=ids=>ids.reduce((m,id)=>byId[id]&&SEV[byId[id].sev].rank>SEV[m].rank?byId[id].sev:m,'none');
function appNodeLabel(n){
  if(n.kind==='clients'){const v=vlanById[n.vlan];return [n.hosts.length===1?nameOf(n.hosts[0]):`${n.hosts.length} × ${TYPE_LABEL[n.type]||n.type}`,`client${n.hosts.length===1?'':'s'} · VLAN ${v?v.num:'?'}`];}
  if(n.kind==='app')return [n.name,`${n.versions.length?n.versions.join(', ')+' · ':''}on ${n.hosts.map(id=>nameOf(id)).join(', ')}`];
  if(n.kind==='asset')return [n.name,'no application recorded'];
  return [n.name,n.key==='internet'?'any address':(SVC[n.key]?SVC[n.key].hosts.join(', '):'')];
}
function renderAppLens(){
  const G=APPG=SA.appGraph(SITE),W=230,H=50,CG=120,RG=14;
  // external services go to a last column of their own
  const maxR=Math.max(0,...G.nodes.filter(n=>!(n.kind==='net'&&n.key!=='internet')).map(n=>n.rank));
  G.nodes.forEach(n=>{if(n.kind==='net'&&n.key!=='internet')n.rank=maxR+1;});
  const cols={};G.nodes.forEach(n=>(cols[n.rank]=cols[n.rank]||[]).push(n));
  const KO={net:0,clients:1,app:2,asset:3};
  Object.values(cols).forEach(c=>c.sort((a,b)=>KO[a.kind]-KO[b.kind]||a.name.localeCompare(b.name)).forEach((n,i)=>{n.x=n.rank*(W+CG);n.y=i*(H+RG)+40;}));
  const at={};G.nodes.forEach(n=>at[n.key]=n);
  const hW=Math.max(...G.nodes.map(n=>n.x+W),W)+20,hH=Math.max(...G.nodes.map(n=>n.y+H),H)+30;
  const C=n=>css(n),ink=C('--fg'),mu=C('--muted');
  let o='';
  // column titles
  Object.keys(cols).forEach(r=>{o+=`<text x="${r*(W+CG)}" y="18" font-family="${PF.d}" font-weight="700" font-size="11" letter-spacing="1.2" fill="${mu}">${+r===0?'WHERE TRAFFIC STARTS':+r===maxR+1&&cols[r].every(n=>n.kind==='net')?'INTERNET SERVICES':'TIER '+r}</text>`;});
  G.edges.forEach(e=>{const a=at[e.from],b=at[e.to],x1=a.x+W,y1=a.y+H/2,x2=b.x,y2=b.y+H/2,w=Math.min(5,1+Math.log2(e.flows.length));
    const fl=e.flows.map(id=>FLOWS.find(f=>f.id===id)).filter(Boolean),col=C(e.risk?'--crit':'--thread');
    const d=b.rank>a.rank?`M${x1},${y1} C${x1+CG*0.6},${y1} ${x2-CG*0.6},${y2} ${x2},${y2}`:`M${x1},${y1} C${x1+60},${y1} ${x1+60},${Math.max(y1,y2)+H} ${(x1+x2)/2},${Math.max(y1,y2)+H} S${x2-60},${y2} ${x2},${y2}`;
    o+=`<path d="${d}" fill="none" stroke="${col}" stroke-width="${w}" opacity="0.75"${e.risk?' stroke-dasharray="6 4"':''} marker-end="url(#am${e.risk?'r':'n'})"><title>${esc(a.name+' → '+b.name+' · '+[...new Set(fl.map(f=>f.port))].join(', ')+' · '+plural(fl.length,'flow'))}</title></path>`;});
  G.nodes.forEach(n=>{const [t,sub]=appNodeLabel(n),sev=n.kind==='net'?'none':worstOf(n.hosts),dev=n.kind==='asset'&&byId[n.assetId]&&INTERCO.has(byId[n.assetId].type);
    o+=`<g class="an" data-app-node="${esc(n.key)}" role="button" tabindex="0"><rect x="${n.x}" y="${n.y}" width="${W}" height="${H}" rx="4" fill="${C(dev?'--detail':'--panel')}" stroke="${C(n.kind==='net'?'--x-net':'--line')}" stroke-width="${n.kind==='net'?1.6:1}"/>`+
      (sev!=='none'?`<rect x="${n.x}" y="${n.y+H-4}" width="${W}" height="4" fill="${C(SEV[sev].css)}"/>`:'')+
      `<text x="${n.x+10}" y="${n.y+20}" font-family="${PF.d}" font-weight="700" font-size="13" fill="${dev?'#eef0ec':ink}">${esc(clip(t,13,700,PF.d,W-20))}</text>`+
      `<text x="${n.x+10}" y="${n.y+36}" font-family="${PF.m}" font-size="10" fill="${dev?'#aeb6bb':mu}">${esc(clip(sub,10,400,PF.m,W-20))}</text><title>${esc(t+' · '+sub)}</title></g>`;});
  const mk=(id,c)=>`<marker id="${id}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="${c}"/></marker>`;
  lensBody.innerHTML=`<div class="lens-head"><h2>Application view</h2><p>One box per application, with the assets it runs on. Arrows follow the flows: from the application that sends them to the one listening on their port. Red dashes: risky flows. Bar under a box: worst vulnerability of its hosts.</p></div>
  ${G.nodes.length?`<svg class="lens-svg" viewBox="-10 0 ${hW+10} ${hH}" width="${hW+10}" height="${hH}" role="img" aria-label="Applications of IS ${esc(SITE.name)} and the flows between them"><defs>${mk('amn',C('--thread'))}${mk('amr',C('--crit'))}</defs>${o}</svg>`:'<p class="empty">No flow recorded yet: the application view draws the flows between applications.</p>'}`;
}
function showAppNode(key){
  if(state.lens==='business'){const b=SITE.bizById[key];if(b)showBusiness(b);return;}
  const n=APPG&&APPG.nodes.find(x=>x.key===key);if(!n)return;
  if(n.kind==='net'){if(SVC[key])showService(SVC[key]);return;}
  if(n.hosts.length===1){select(byId[n.hosts[0]],false);return;}
  const [t,sub]=appNodeLabel(n),ins=APPG.edges.filter(e=>e.to===key),outs=APPG.edges.filter(e=>e.from===key),nm=k=>appNodeLabel(APPG.nodes.find(x=>x.key===k))[0];
  openDet(`<div class="d-head"><div><span class="cap">${n.kind==='app'?'Application':'Clients'}</span><h2>${esc(t)}</h2><p>${esc(sub)}</p></div><button class="close" data-close aria-label="Close">×</button></div>
  <div class="d-body"><h3 class="cap">Runs on · ${n.hosts.length}</h3><ul class="list">${n.hosts.map(id=>`<li class="reach"><button data-goto="${esc(id)}">${esc(nameOf(id))}<small>${esc(byId[id].ip||'')} · VLAN ${esc(vnum(byId[id]))}</small></button>${tag(byId[id].sev)}</li>`).join('')}</ul>
  <h3 class="cap">Called by · ${ins.length}</h3>${ins.length?`<ul class="list">${ins.map(e=>`<li class="reach"><button data-app-node="${esc(e.from)}">${esc(nm(e.from))}<small>${plural(e.flows.length,'flow')}</small></button></li>`).join('')}</ul>`:'<p class="empty">Nothing calls it.</p>'}
  <h3 class="cap">Calls · ${outs.length}</h3>${outs.length?`<ul class="list">${outs.map(e=>`<li class="reach"><button data-app-node="${esc(e.to)}">${esc(nm(e.to))}<small>${plural(e.flows.length,'flow')}</small></button></li>`).join('')}</ul>`:'<p class="empty">It calls nothing.</p>'}</div>`,'app');
}
function renderBizLens(){
  const B=SITE.business;
  const chips=l=>l.map(x=>x.svc?`<button class="bchip net" data-svc="${esc(x.svc.id)}">${esc(x.svc.name)}</button>`:`<button class="bchip" data-goto="${esc(x.a.id)}" title="${esc(x.direct?x.a.role||'':chain(x.path))}"><i style="background:var(${SEV[x.a.sev].css})"></i>${esc(x.a.name)}</button>`).join('');
  lensBody.innerHTML=`<div class="lens-head"><h2>Business view</h2><p>What the organisation does here, and every asset each business service relies on: the ones it runs on, what they call, the equipment their flows cross and the Internet services they use. Open an asset to see all the services it would hit.</p>
  <div class="btns row2 edit-only" style="max-width:260px"><button class="btn small" data-act="new-biz"><span>+ Business service</span></button></div></div>
  ${B.length?`<div class="bizgrid">${B.map(b=>{const g=bizGroups(b),ids=Object.keys(SITE.impact.byBusiness[b.id].assets),w=worstOf(ids);
    return `<section class="bizcard${state.biz===b.id?' on':''}"><header><button class="bname" data-biz="${esc(b.id)}">${esc(b.name)}</button>${critTag(b.crit)}</header>
    <p class="bmeta">${b.owner?esc(b.owner)+' · ':''}${plural(ids.length,'asset')}${w!=='none'?` · worst: <span style="color:var(${SEV[w].css})">${SEV[w].label}</span>`:''}</p>
    ${g.map(([t,l])=>l.length?`<div class="bgrp"><span class="cap">${t}</span><div class="bchips">${chips(l)}</div></div>`:'').join('')}
    <div class="bfoot"><button class="btn small" data-biz-hl="${esc(b.id)}">Show on the model</button><button class="btn small edit-only" data-edit-biz="${esc(b.id)}">Edit</button></div></section>`;}).join('')}</div>`
  :`<div class="bizempty"><p>No business service recorded for this IS yet. A business service is an activity of the organisation (online sales, payroll, production line 1) and the assets it runs on. Strata works out the rest from the flows.</p></div>`}`;
}
lensEl.addEventListener('click',e=>{
  const t=e.target,q=s=>t.closest(s);
  if(q('[data-app-node]')){showAppNode(q('[data-app-node]').dataset.appNode);return;}
  if(q('[data-biz]')){showBusiness(SITE.bizById[q('[data-biz]').dataset.biz]);return;}
  if(q('[data-biz-hl]')){const id=q('[data-biz-hl]').dataset.bizHl;setBizHighlight(id);showBusiness(SITE.bizById[id]);return;}
  if(q('[data-edit-biz]')){businessForm(SITE.bizById[q('[data-edit-biz]').dataset.editBiz]);return;}
  if(q('[data-goto]')){const a=byId[q('[data-goto]').dataset.goto];if(a){state.selId=a.id;showAsset(a);}return;}
  if(q('[data-svc]')){const x=SVC[q('[data-svc]').dataset.svc];if(x)showService(x);return;}
});
lensEl.addEventListener('keydown',e=>{if((e.key==='Enter'||e.key===' ')&&e.target.closest('[data-app-node]')){e.preventDefault();showAppNode(e.target.closest('[data-app-node]').dataset.appNode);}});
$('#lensSeg').addEventListener('click',e=>{const b=e.target.closest('button');if(b)setLens(b.dataset.lens);});

/* ================= Internet services ================= */
function compileSvcList(list,scope){return (Array.isArray(list)?list:[]).filter(x=>x&&x.id&&x.name).map(x=>({id:'svc:'+x.id,key:x.id,name:String(x.name),category:x.category||'Other',hosts:svcHosts(x.hosts),ports:parsePorts(x.ports),notes:x.notes||'',scope}));}
const globalServices=()=>compileSvcList(raw.services,'global');
const allServices=()=>state.view==='site'&&SITE?SITE.services:globalServices();
function svcFlows(x){
  if(state.view==='site')return FLOWS.filter(f=>f.src===x.id||f.dst===x.id);
  return SITES.flatMap(s=>s.flows.filter(f=>f.src===x.id||f.dst===x.id).map(f=>Object.assign({},f,{siteName:s.name})));
}
function showService(x){
  const fl=svcFlows(x),site=state.view==='site';
  openDet(`<div class="d-head"><div><span class="cap">Internet service · ${esc(x.category)}</span><h2>${esc(x.name)}</h2><p>${esc(x.scope==='site'?`Only for IS ${SITE?SITE.name:''}`:'Shared by every IS')}</p></div><button class="close" data-close aria-label="Close">×</button></div>
  <div class="d-body">
  <div class="actions edit-only"><button class="btn small" data-edit-svc="${esc(x.id)}">Edit</button></div>
  <dl class="kv"><dt>Hosts</dt><dd class="mono">${x.hosts.map(esc).join('<br>')||'—'}</dd><dt>Ports</dt><dd class="mono">${x.ports.map(esc).join(' ')||'—'}</dd>${x.notes?`<dt>Notes</dt><dd>${esc(x.notes)}</dd>`:''}</dl>
  <h3 class="cap">Allowed flows${site?'':' in every IS'} · ${fl.length}</h3>
  ${fl.length?`<ul class="list">${fl.map(f=>{const peer=f.src===x.id?f.dst:f.src,out=f.dst===x.id;return `<li class="flow${f.risk?' risk':''}"><span class="peer"${site?` role="button" data-goto="${esc(peer)}"`:''}>${out?'':'← '}${esc(site?nameOf(peer):(f.siteName+' · '+((raw.assets[peer]||{}).name||peer)))}${out?' →':''}</span><span class="meta">${esc(f.port)}</span><span class="meta">${f.vol} MB/h</span>${site?`<button class="ibtn" data-show-flow="${esc(f.id)}">Path</button>`:'<span></span>'}</li>`;}).join('')}</ul>`:'<p class="empty">No flow uses this service yet. Draw one in the 2D diagram, or add a flow with this service as destination.</p>'}
  </div>`,'service');
}
function serviceForm(x,scopeHint){
  const site=state.view==='site'&&SITE,scope=x?x.scope:(scopeHint==='site'&&site?'site':'global');
  const d=x?{name:x.name,category:x.category,hosts:x.hosts.join(', '),ports:x.ports.join(', '),notes:x.notes}:{name:'',category:'OS updates',hosts:'',ports:'tcp/443',notes:''};
  openForm(x?x.name:'New Internet service',site?`IS ${SITE.name}`:'Shared catalogue',`
    ${fIn('fName','Name *',d.name,'required maxlength="80" placeholder="e.g. ESET update servers"')}
    ${fSel('fCat','Category',SVC_CATS.map(c=>[c,c]),d.category)}
    <div class="f"><label for="fHosts">Hosts (FQDN or IP)</label><textarea id="fHosts" placeholder="update.eset.com, *.eset.com">${esc(d.hosts)}</textarea><span class="hint">Separated by commas or new lines. They become the destination of the firewall rules.</span></div>
    ${fIn('fPorts','Ports',d.ports,'placeholder="tcp/443, tcp/80"')}
    ${site?fSel('fScope','Available to',[['global','Every IS (shared catalogue)'],['site',`IS ${SITE.name} only`]],scope):''}
    <div class="f"><label for="fNotes">Notes</label><textarea id="fNotes" maxlength="1000">${esc(d.notes)}</textarea></div>`,
  async()=>{
    const name=$('#fName').value.trim();if(!name)return formErr('The service needs a name.','fName');
    const ports=parsePorts($('#fPorts').value);
    if(ports.some(p=>!/^(tcp|udp|icmp|any)(\/[\d-]+)?$/.test(p)))return formErr('Write the ports as protocol/number, e.g. tcp/443.','fPorts');
    const newScope=site?$('#fScope').value:'global',key=x?x.key:uid('svc-');
    const doc={id:key,name,category:$('#fCat').value,hosts:svcHosts($('#fHosts').value),ports,notes:$('#fNotes').value.trim()};
    const tasks=[];
    const glob=clone(raw.services||[]).filter(y=>y.id!==key);
    if(newScope==='global')glob.push(doc);
    if(newScope==='global'||(x&&x.scope==='global'))tasks.push(()=>Store.putServices(glob));
    if(site&&(newScope==='site'||(x&&x.scope==='site'))){const sd=clone(SITE.raw);sd.services=(sd.services||[]).filter(y=>y.id!==key);if(newScope==='site')sd.services.push(doc);tasks.push(()=>Store.putSite(SITE.id,sd));}
    for(const t of tasks)await t();
    toast(x?'Service saved.':'Service added.');afterSave(()=>{const nx=allServices().find(y=>y.key===key);if(nx)showService(nx);else restorePanel();});
  },{del:x?{label:'Delete the service and its flows',run:async()=>{
    const id=x.id,tasks=[];
    if(x.scope==='global')tasks.push(()=>Store.putServices((raw.services||[]).filter(y=>y.id!==x.key)));
    Object.entries(raw.si).forEach(([sid,d])=>{const uses=(d.flows||[]).some(f=>f.src===id||f.dst===id),own=x.scope==='site'&&(d.services||[]).some(y=>y.id===x.key);
      if(uses||own){const sd=clone(d);sd.flows=(sd.flows||[]).filter(f=>f.src!==id&&f.dst!==id);if(own)sd.services=(sd.services||[]).filter(y=>y.id!==x.key);tasks.push(()=>Store.putSite(sid,sd));}});
    await Store.many(tasks,'Deleting the service');closeDet();
  }}:null});
}
function renderServiceLists(){
  const row=x=>`<button class="site svc" data-svc="${esc(x.id)}"><b>${esc(x.name)}</b><span class="c mono">${x.ports.length?esc(x.ports[0].replace('tcp/','')):''}</span><small>${esc(x.category)}${x.scope==='site'?' · this IS':''}${x.hosts.length?' · '+esc(x.hosts[0]):''}</small></button>`;
  const g=globalServices();
  $('#svcListOv').innerHTML=g.length?g.map(row).join(''):'<p class="empty">None yet. Declare the Internet services your IS may reach (updates, antivirus, SaaS…).</p>';
  if(state.view==='site'&&SITE){const list=SITE.services.slice().sort((a,b)=>(SITE.usedSvc.has(b.id)-SITE.usedSvc.has(a.id))||a.name.localeCompare(b.name));
    $('#svcList').innerHTML=list.length?list.map(x=>row(x).replace('</small>',`${SITE.usedSvc.has(x.id)?'':' · unused here'}</small>`)).join(''):'<p class="empty">No Internet service declared.</p>';}
}
document.addEventListener('click',e=>{const b=e.target.closest('#svcListOv [data-svc],#svcList [data-svc]');if(b){const x=allServices().find(y=>y.id===b.dataset.svc)||globalServices().find(y=>y.id===b.dataset.svc);if(x)showService(x);}
  const n=e.target.closest('#ctl [data-new-svc]');if(n)serviceForm(null,n.dataset.newSvc);});

/* ================= Proposals, history, accounts (self-hosted server) ================= */
let DIFF=null;
const FIELD_LABEL={name:'name',type:'type',vlan:'VLAN',ip:'IP address',os:'system',role:'role',crit:'criticality',vulns:'vulnerabilities',contacts:'contacts',apps:'applications',notes:'notes',
  src:'source',dst:'destination',port:'port',vol:'volume',risk:'risk',note:'note',via:'path',num:'number',cidr:'range',zone:'zone',pos:'order',layout:'positions on the plate',zones:'zones',kind:'site type',order:'order',category:'category',hosts:'hosts',ports:'ports',ext:'link to the source tool'};
function changedFields(a,b,skip=[]){return [...new Set([...Object.keys(a||{}),...Object.keys(b||{})])].filter(k=>!skip.includes(k)&&k!=='id'&&JSON.stringify((a||{})[k]??null)!==JSON.stringify((b||{})[k]??null)).map(k=>FIELD_LABEL[k]||k);}
function nameRaw(id){
  if(id==='internet')return 'Internet';
  if(isNet(id)){const all=(raw.services||[]).concat(...Object.values(raw.si).map(s=>s.services||[]),...Object.values(liveRaw.si).map(s=>s.services||[]),liveRaw.services||[]);const x=all.find(y=>'svc:'+y.id===id);return x?x.name:id;}
  return (raw.assets[id]||liveRaw.assets[id]||{}).name||id;
}
function diffList(a,b,label,kind,site,marks,items){
  const ma=new Map((a||[]).map(x=>[x.id,x])),mb=new Map((b||[]).map(x=>[x.id,x]));
  mb.forEach((x,id)=>{const o=ma.get(id);if(!o){marks[id]='added';items.push({kind,op:'added',id,site,label:label(x)});}
    else if(JSON.stringify(o)!==JSON.stringify(x)){marks[id]='modified';items.push({kind,op:'modified',id,site,label:label(x),fields:changedFields(o,x)});}});
  ma.forEach((x,id)=>{if(!mb.has(id)){marks[id]='removed';items.push({kind,op:'removed',id,site,label:label(x),before:x});}});
}
// What a draft or a proposal changes, compared with the live map
function computeDiff(){
  if(!(Store.view==='draft'||Store.view==='review')||!Store.prop){DIFF=null;return;}
  const ch=Store.prop.changes||{},A={},F={},V={},items=[];
  Object.entries(ch.assets||{}).forEach(([id,doc])=>{const b=liveRaw.assets[id];
    if(doc==null){if(b){A[id]='removed';items.push({kind:'asset',op:'removed',id,site:b.site,label:b.name,before:b});}}
    else if(!b){A[id]='added';items.push({kind:'asset',op:'added',id,site:doc.site,label:doc.name});}
    else{const f=changedFields(b,doc);if(f.length){A[id]='modified';items.push({kind:'asset',op:'modified',id,site:doc.site,label:doc.name,fields:f});}}});
  Object.entries(ch.si||{}).forEach(([sid,doc])=>{const b=liveRaw.si[sid];
    if(doc==null){items.push({kind:'site',op:'removed',id:sid,site:sid,label:'IS '+(b?b.name:sid)});return;}
    if(!b)items.push({kind:'site',op:'added',id:sid,site:sid,label:'IS '+doc.name});
    const B=b||{};
    diffList(B.vlans,doc.vlans,v=>`VLAN ${v.num} · ${v.name}`,'vlan',sid,V,items);
    // assets moved on their plate in the 2D diagram
    (doc.vlans||[]).forEach(v=>{const o=(B.vlans||[]).find(x=>x.id===v.id)||{},la=o.layout||{},lb=v.layout||{};Object.keys(lb).forEach(id=>{if(!A[id]&&JSON.stringify(la[id])!==JSON.stringify(lb[id])&&(raw.assets[id]||{}).vlan===v.id)A[id]='modified';});});
    diffList(B.flows,doc.flows,f=>`${nameRaw(f.src)} → ${nameRaw(f.dst)} · ${f.port}`,'flow',sid,F,items);
    diffList(B.services,doc.services,x=>x.name,'service',sid,{},items);
    if(b){const f=changedFields(b,doc,['vlans','flows','services']);if(f.length)items.push({kind:'site',op:'modified',id:sid,site:sid,label:'IS '+doc.name,fields:f});}});
  if(ch.services)diffList(liveRaw.services,ch.services,x=>x.name,'service',null,{},items);
  if(ch.wan)items.push({kind:'wan',op:'modified',label:'Inter-IS links'});
  DIFF={A,F,V,items};
}
const DIFF_COL={added:'--low',modified:'--med',removed:'--crit'};
const KIND_LBL={asset:'Asset',flow:'Flow',vlan:'VLAN',site:'IS',service:'Internet service',wan:'WAN'};
function diffHtml(){
  if(!DIFF||!DIFF.items.length)return '<p class="empty">No change yet. Edit the map (2D diagram, sheets, forms): every change goes into this draft.</p>';
  const order={site:0,vlan:1,asset:2,flow:3,service:4,wan:5};
  return `<ul class="list">${DIFF.items.slice().sort((a,b)=>order[a.kind]-order[b.kind]).map(it=>`<li class="chg ${it.op}"><span class="op" style="color:var(${DIFF_COL[it.op]})">${it.op}</span><span class="what"><small>${KIND_LBL[it.kind]}</small>${it.kind==='asset'&&it.op!=='removed'?`<button data-goto="${esc(it.id)}">${esc(it.label)}</button>`:it.kind==='flow'&&it.op!=='removed'?`<button data-show-flow="${esc(it.id)}">${esc(it.label)}</button>`:esc(it.label)}${it.fields&&it.fields.length?`<em>${esc(it.fields.join(', '))}</em>`:''}</span></li>`).join('')}</ul>`;
}
let PROPS=[];
const fmtDate=s=>{if(!s)return '';const d=new Date(s);return d.toLocaleDateString(undefined,{day:'2-digit',month:'short'})+' '+d.toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'});};
const STATUS_LBL={draft:'Draft',submitted:'To review',approved:'Approved',rejected:'Rejected',withdrawn:'Withdrawn'};
async function loadProposals(){try{const j=await Store.api('GET','api/proposals');PROPS=j.proposals||[];}catch(e){PROPS=[];}renderCollabCounts();return PROPS;}
function renderCollabCounts(){const n=PROPS.filter(p=>p.status==='submitted').length;document.querySelectorAll('.propCount').forEach(el=>el.textContent=n?String(n):'');}
function onProposalsChanged(){loadProposals().then(()=>{if(state.panel==='proposals')showProposals();else if(state.panel==='proposal'&&Store.prop&&Store.view==='review')openProposal(Store.prop.id,true);});}
async function showProposals(){
  await loadProposals();
  const me=Store.user,mine=PROPS.filter(p=>p.author===me&&['draft','rejected'].includes(p.status)),todo=PROPS.filter(p=>p.status==='submitted'),done=PROPS.filter(p=>!mine.includes(p)&&!todo.includes(p));
  const row=p=>`<li class="prop"><button data-open-prop="${esc(p.id)}"><b>${esc(p.title)}</b><small>${esc(p.author)} · ${fmtDate(p.updatedAt)} · ${plural(p.changes,'change')}${p.comments?' · '+plural(p.comments,'comment'):''}${p.source==='file'?' · from a file':p.source==='connector'?' · from a connector':''}</small></button><span class="st ${p.status}">${STATUS_LBL[p.status]||p.status}</span></li>`;
  const grp=(t,list,empty)=>`<h3 class="cap">${t} · ${list.length}</h3>${list.length?`<ul class="list">${list.map(row).join('')}</ul>`:`<p class="empty">${empty}</p>`}`;
  openDet(`<div class="d-head"><div><span class="cap">Collaboration</span><h2>Proposals</h2><p>Changes prepared in a draft, reviewed before they reach the map</p></div><button class="close" data-close aria-label="Close">×</button></div>
  <div class="d-body">
  ${Store.me&&Store.me.canPropose?'<div class="actions"><button class="btn small primary" data-new-prop>New proposal</button></div>':''}
  ${grp('To review',todo,'Nothing waiting for review.')}
  ${Store.me&&Store.me.canPropose?grp('My drafts',mine,'No draft. Start one with “New proposal”: you edit the map as usual, then submit it for review.'):''}
  ${grp('History',done.slice(0,30),'No proposal yet.')}
  </div>`,'proposals');
}
function proposalForm(){
  const opts=SITES.map(s=>[s.id,s.name]);
  openForm('New proposal','Collaboration',`
    ${fIn('fTitle','Title *','','required maxlength="140" placeholder="e.g. Allow the Ubuntu repositories for the DMZ servers"')}
    <div class="f"><label for="fDesc">Why, and what to check</label><textarea id="fDesc" maxlength="4000" placeholder="Context for the reviewer"></textarea></div>
    ${opts.length?fSel('fSite','IS concerned',opts,state.siteId||opts[0][0]):''}
    <fieldset><legend>Start from</legend>
      <label class="chk plain"><input type="radio" name="fFrom" value="editor" checked> The current map: I will make the changes in the editor (2D diagram, sheets)</label>
      <label class="chk plain"><input type="radio" name="fFrom" value="file"> A file: a Strata (or IS Map) JSON export (whole map or one IS) edited elsewhere</label>
      <input type="file" id="fFile" accept="application/json,.json" hidden></fieldset>`,
  async()=>{
    const title=$('#fTitle').value.trim();if(!title)return formErr('Give the proposal a title.','fTitle');
    const from=det.querySelector('[name=fFrom]:checked').value;let changes={si:{},assets:{}},siteId=$('#fSite')?$('#fSite').value:null;
    if(from==='file'){
      const f=$('#fFile').files[0];if(!f)return formErr('Choose the file to propose.');
      let o;try{o=JSON.parse(await f.text());}catch(e){return formErr('This file is not valid JSON.');}
      if(!o||typeof o.si!=='object'||typeof o.assets!=='object')return formErr('Unexpected format: a Strata export has the “si” and “assets” keys.');
      changes=changesFromFile(o);const ks=Object.keys(o.si);if(ks.length===1)siteId=ks[0];
      if(!Object.keys(changes.si).length&&!Object.keys(changes.assets).length&&!changes.services)return formErr('This file is identical to the map: nothing to propose.');
    }
    try{const j=await Store.api('POST','api/proposals',{title,description:$('#fDesc').value.trim(),siteId,changes,source:from});
      onSave=null;toast(from==='file'?'Proposal created from the file: check it, then submit it.':'Draft opened: your changes now go into it.');enterProp(j.proposal,'draft');}
    catch(e){formErr(e.message||'Could not create the proposal.');}
  });
  det.querySelectorAll('[name=fFrom]').forEach(r=>r.addEventListener('change',()=>{$('#fFile').hidden=det.querySelector('[name=fFrom]:checked').value!=='file';}));
}
function changesFromFile(o){
  const ch={si:{},assets:{}},sites=Object.keys(o.si||{}),J=JSON.stringify;
  sites.forEach(id=>{if(J(liveRaw.si[id])!==J(o.si[id]))ch.si[id]=o.si[id];});
  Object.entries(o.assets||{}).forEach(([id,a])=>{if(a&&sites.includes(a.site)&&J(liveRaw.assets[id])!==J(a))ch.assets[id]=a;});
  Object.entries(liveRaw.assets).forEach(([id,a])=>{if(sites.includes(a.site)&&!(id in (o.assets||{})))ch.assets[id]=null;});
  if(Array.isArray(o.services)&&J(o.services)!==J(liveRaw.services||[]))ch.services=o.services;
  return ch;
}
async function openProposal(id,keepView){
  let j;try{j=await Store.api('GET','api/proposals/'+encodeURIComponent(id));}catch(e){toast(e.message,true);return;}
  const p=j.proposal;p._conflicts=j.conflicts||[];
  const mine=p.author===Store.user||!Store.features.accounts;
  enterProp(p,mine&&['draft','rejected'].includes(p.status)&&Store.me.canPropose?'draft':'review',keepView);
}
function enterProp(p,view,keep){
  if(state.arrange)setArrange(false);
  Store.view=view;Store.prop=p;Store.preview=null;
  Store.applyView(0);renderModeBar();
  pendingAfterData=()=>{
    if(!keep&&p.siteId&&siteById[p.siteId]&&(state.view!=='site'||state.siteId!==p.siteId))enterSite(siteById[p.siteId]);
    showProposal();
  };
}
function leaveMode(msg){
  Store.view=null;Store.prop=null;Store.preview=null;
  Store.applyView(0);renderModeBar();closeDet();if(msg)toast(msg);
}
function showProposal(){
  const p=Store.prop;if(!p)return;
  const mine=p.author===Store.user||!Store.features.accounts,me=Store.me||{},n=DIFF?DIFF.items.length:0;
  const own=mine||(p.uploadedBy&&p.uploadedBy===Store.user);
  const canDecide=me.canReview&&p.status==='submitted'&&(!own||me.allowSelfApproval||!Store.features.accounts);
  const conf=p._conflicts&&p._conflicts.length?`<p class="warn">Changed on the map since this proposal was prepared: ${p._conflicts.map(c=>esc(c.name||c.kind)).join(', ')}. Approving keeps the proposal's version.</p>`:'';
  openDet(`<div class="d-head"><div><span class="cap">Proposal · <span class="st ${p.status}">${STATUS_LBL[p.status]||p.status}</span></span><h2>${esc(p.title)}</h2><p>${esc(p.author)}${p.uploadedBy?` · file imported by ${esc(p.uploadedBy)}`:''} · ${fmtDate(p.createdAt)}${p.reviewedBy?` · ${p.status==='approved'?'approved':'reviewed'} by ${esc(p.reviewedBy)}`:''}</p></div><button class="close" data-leave-mode aria-label="Close the proposal">×</button></div>
  <div class="d-body">
  ${p.description?`<p class="summary" style="white-space:pre-wrap">${esc(p.description)}</p>`:''}
  ${conf}
  <div class="actions">
    ${Store.view==='draft'?`<button class="btn small primary" data-prop-submit>Submit for review</button><button class="btn small" data-prop-edit>Rename</button><button class="btn small danger" data-prop-delete>Delete the draft</button>`:''}
    ${p.status==='submitted'&&mine?'<button class="btn small" data-prop-withdraw>Withdraw to edit it</button>':''}
    ${canDecide?'<button class="btn small primary" data-prop-approve>Approve and publish</button><button class="btn small danger" data-prop-reject>Reject</button>':''}
    ${p.status==='submitted'&&me.canReview&&own&&!me.allowSelfApproval&&Store.features.accounts?'<p class="fhint">Someone else has to approve your own proposal.</p>':''}
  </div>
  <h3 class="cap">Changes · ${n}</h3>${diffHtml()}
  <p class="fhint">On the map: <b style="color:var(--low)">green</b> added, <b style="color:var(--med)">amber</b> modified${Store.view?'; removed flows are drawn dashed in red in the 2D diagram':''}.</p>
  <h3 class="cap">Discussion · ${(p.comments||[]).length}</h3>
  ${(p.comments||[]).length?`<ul class="list">${p.comments.map(c=>`<li class="cmt ${c.kind||''}"><b>${esc(c.user||'?')}</b><small>${fmtDate(c.at)}${c.kind&&c.kind!=='comment'?' · '+esc(c.kind):''}</small><p>${esc(c.text)}</p></li>`).join('')}</ul>`:'<p class="empty">No comment.</p>'}
  ${me.canPropose?`<div class="f"><label for="fCmt">${canDecide?'Comment (also sent with approve or reject)':'Comment'}</label><textarea id="fCmt" maxlength="4000"></textarea></div><div class="actions"><button class="btn small" data-prop-comment>Post the comment</button></div>`:''}
  </div>`,'proposal');
}
async function propAction(kind){
  const p=Store.prop;if(!p)return;const text=$('#fCmt')?$('#fCmt').value.trim():'';const url='api/proposals/'+encodeURIComponent(p.id);
  try{
    if(kind==='comment'){if(!text)return toast('Write a comment first.',true);const j=await Store.api('POST',url+'/comment',{text});Store.prop=Object.assign(j.proposal,{_conflicts:p._conflicts});showProposal();return;}
    if(kind==='submit'){clearTimeout(Store._dt);await Store.saveDraft();await Store.api('POST',url+'/submit',{text});leaveMode('Proposal submitted: an approver will review it.');loadProposals();return;}
    if(kind==='withdraw'){await Store.api('POST',url+'/withdraw',{});await openProposal(p.id,true);toast('Back to draft: you can edit it again.');return;}
    if(kind==='reject'){await Store.api('POST',url+'/reject',{text:text||'Rejected'});leaveMode('Proposal rejected. The author can rework it.');loadProposals();return;}
    if(kind==='approve'||kind==='force'){const j=await Store.api('POST',url+'/approve',{text,force:kind==='force'});leaveMode(`Proposal approved and published (version ${j.rev}).`);loadProposals();return;}
    if(kind==='delete'){if(!confirmArm('propdel'))return;await Store.api('DELETE',url);leaveMode('Draft deleted.');loadProposals();return;}
  }catch(e){
    if(e.status===409&&e.body&&e.body.conflicts){p._conflicts=e.body.conflicts;showProposal();
      det.querySelector('.actions').insertAdjacentHTML('beforeend','<button class="btn small danger" data-prop-force>Approve anyway (the proposal wins)</button>');toast(e.message,true);return;}
    toast(e.message||'Error',true);
  }
}
function renameProposal(){
  const p=Store.prop;
  openForm('Rename the proposal','Proposal',`${fIn('fTitle','Title *',p.title,'required maxlength="140"')}<div class="f"><label for="fDesc">Why, and what to check</label><textarea id="fDesc" maxlength="4000">${esc(p.description||'')}</textarea></div>`,
  async()=>{const t=$('#fTitle').value.trim();if(!t)return formErr('Give the proposal a title.','fTitle');
    try{const j=await Store.api('PUT','api/proposals/'+encodeURIComponent(p.id),{title:t,description:$('#fDesc').value.trim()});Object.assign(p,{title:j.proposal.title,description:j.proposal.description});onSave=null;renderModeBar();showProposal();}catch(e){formErr(e.message);}
  },{cancel:()=>showProposal()});
}
/* ---- version history ---- */
let HIST={entries:[],oldest:0,rev:0,all:false};
async function showHistory(more){
  try{
    const before=more&&HIST.entries.length?HIST.entries[HIST.entries.length-1].rev:'';
    const j=await Store.api('GET','api/history?limit=200'+(before?'&before='+before:''));
    HIST=Object.assign(HIST,{entries:more?HIST.entries.concat(j.entries):j.entries,oldest:j.oldest,rev:j.rev});
  }catch(e){toast(e.message,true);return;}
  const siteOnly=state.view==='site'&&!HIST.all&&SITE;
  const list=HIST.entries.filter(h=>!siteOnly||h.site===SITE.id);
  const groups=[];list.forEach(h=>{const g=groups[groups.length-1];if(g&&g.batch===h.batch&&g.rev===h.rev||g&&g.batch===h.batch&&h.batch&&!/^r\d+$/.test(h.batch))g.items.push(h);else groups.push({batch:h.batch,rev:h.rev,at:h.at,user:h.user,label:h.label,items:[h]});});
  const KL={si:'IS',assets:'asset',wan:'inter-IS links',services:'Internet services',all:'whole map'};
  const sum=g=>g.label||(g.items.length===1?`${KL[g.items[0].kind]} ${g.items[0].name?'“'+g.items[0].name+'” ':''}${g.items[0].op}`:`${g.items.length} changes: ${[...new Set(g.items.map(h=>h.name).filter(Boolean))].slice(0,4).join(', ')}`);
  const canRestore=Store.liveWrite&&!Store.view;
  openDet(`<div class="d-head"><div><span class="cap">Collaboration</span><h2>History</h2><p>Version ${HIST.rev}${siteOnly?` · IS ${esc(SITE.name)}`:' · whole map'}</p></div><button class="close" data-close aria-label="Close">×</button></div>
  <div class="d-body">
  ${state.view==='site'?`<div class="seg two" id="histScope" style="margin-top:12px"><button data-hs="site" aria-pressed="${!HIST.all}">This IS</button><button data-hs="all" aria-pressed="${HIST.all}">Whole map</button></div>`:''}
  <p class="fhint" style="margin-top:10px">“View” shows the map as it was right after that change, read-only. “Restore” brings the whole map back to that version; the restore is itself recorded and can be undone.</p>
  ${groups.length?`<ul class="list hist">${groups.map((g,i)=>`<li><div class="h1"><b>${esc(sum(g))}</b><span class="mono">v${g.rev}</span></div><small>${esc(g.user||'—')} · ${fmtDate(g.at)}${g.items.length>1&&g.label?' · '+plural(g.items.length,'change'):''}</small>
    <div class="h2">${g.rev===HIST.rev?'<span class="cur">Current version</span>':`<button class="ibtn" data-hist-view="${g.rev}">View</button>${canRestore?`<button class="ibtn" data-hist-restore="${g.rev}">Restore</button>`:''}`}</div></li>`).join('')}</ul>`:'<p class="empty">No recorded change yet.</p>'}
  ${HIST.entries.length&&HIST.entries[HIST.entries.length-1].rev>HIST.oldest+1?'<div class="actions"><button class="btn small" data-hist-more>Older changes</button></div>':''}
  </div>`,'history');
}
async function previewVersion(rev){
  let s;try{s=await Store.api('GET','api/state?at='+rev);}catch(e){toast(e.message,true);return;}
  const g=HIST.entries.find(h=>h.rev===rev)||{};
  Store.view='preview';Store.prop=null;Store.preview={rev,at:g.at,user:g.user,raw:{si:s.si||{},assets:s.assets||{},wan:s.wan||[],services:s.services||[]}};
  Store.applyView(0);renderModeBar();
  pendingAfterData=()=>{if(state.view==='site'&&!siteById[state.siteId])backToOverview();closeDet();};
}
async function restoreVersion(rev,btn){
  if(btn&&!btn.classList.contains('armed')){btn.classList.add('armed');btn.textContent='Confirm restore';setTimeout(()=>{if(btn.isConnected){btn.classList.remove('armed');btn.textContent='Restore';}},5000);return;}
  try{const j=await Store.api('POST','api/rollback',{rev});leaveMode(`Map restored to version ${rev} (new version ${j.rev}).`);await Store.pull();}catch(e){toast(e.message,true);}
}
/* ---- accounts ---- */
async function showAccount(){
  const me=Store.me||{};let users=[];
  if(me.canAdmin&&Store.features.accounts){try{users=(await Store.api('GET','api/users')).users;}catch(e){}}
  const roleOpts=v=>['viewer','contributor','approver','admin'].map(r=>`<option${r===v?' selected':''}>${r}</option>`).join('');
  openDet(`<div class="d-head"><div><span class="cap">Account</span><h2>${esc(me.user||'Open access')}</h2><p>${esc(me.role||'')} · ${{viewer:'reads the map',contributor:'reads, and proposes changes',approver:'edits the map, reviews proposals, restores versions',admin:'everything, and manages the accounts'}[me.role]||''}</p></div><button class="close" data-close aria-label="Close">×</button></div>
  <div class="d-body">
  ${Store.features.accounts?`<h3 class="cap">Change my password</h3>
  <form class="frm" id="pwForm" style="padding:0" novalidate><div class="f"><label for="pwCur">Current password</label><input id="pwCur" type="password" autocomplete="current-password"></div>
  <div class="f2"><div class="f"><label for="pwNew">New password</label><input id="pwNew" type="password" autocomplete="new-password" minlength="10"></div><div class="f"><label for="pwNew2">Again</label><input id="pwNew2" type="password" autocomplete="new-password"></div></div>
  <button class="btn small" type="submit">Change the password</button><p class="fhint">The browser will then ask you to sign in again with the new password.</p></form>`:'<p class="summary">No account is configured on this server: everyone who reaches it can edit. Set EDIT_PASS in .env, or create accounts with scripts/users.mjs.</p>'}
  ${me.canAdmin&&Store.features.accounts?`<h3 class="cap">Accounts · ${users.length}</h3>
  <ul class="list">${users.map(u=>`<li class="usr" data-user="${esc(u.name)}"><b>${esc(u.name)}</b><select data-urole aria-label="Role of ${esc(u.name)}" ${u.name===me.user?'disabled':''}>${roleOpts(u.role)}</select>
    <button class="ibtn" data-utoggle ${u.name===me.user?'disabled':''}>${u.disabled?'Enable':'Disable'}</button><button class="ibtn" data-upass>Password</button><button class="ibtn" data-udel ${u.name===me.user?'disabled':''}>Delete</button>${u.disabled?'<small>disabled</small>':''}</li>`).join('')}</ul>
  <h3 class="cap">New account</h3>
  <form class="frm" id="userForm" style="padding:0" novalidate><div class="f2"><div class="f"><label for="nuName">Name</label><input id="nuName" autocomplete="off" placeholder="e.g. alice.martin"></div><div class="f"><label for="nuRole">Role</label><select id="nuRole">${roleOpts('contributor')}</select></div></div>
  <div class="f"><label for="nuPass">Password (10 characters or more)</label><input id="nuPass" type="password" autocomplete="new-password"></div><button class="btn small" type="submit">Create the account</button></form>`:''}
  </div>`,'account');
  const pf=$('#pwForm');if(pf)pf.addEventListener('submit',async e=>{e.preventDefault();e.stopPropagation();const n=$('#pwNew').value;
    if(n.length<10)return toast('Use at least 10 characters.',true);if(n!==$('#pwNew2').value)return toast('The two new passwords differ.',true);
    try{await Store.api('PUT','api/me/password',{current:$('#pwCur').value,next:n});toast('Password changed. Sign in again with the new one if the browser asks.');pf.reset();}catch(err){toast(err.message,true);}});
  const uf=$('#userForm');if(uf)uf.addEventListener('submit',async e=>{e.preventDefault();e.stopPropagation();const name=$('#nuName').value.trim();
    try{await Store.api('PUT','api/users/'+encodeURIComponent(name),{role:$('#nuRole').value,password:$('#nuPass').value});toast(`Account ${name} created.`);showAccount();}catch(err){toast(err.message,true);}});
}
det.addEventListener('change',async e=>{const s=e.target.closest('[data-urole]');if(!s)return;const name=s.closest('[data-user]').dataset.user;
  try{await Store.api('PUT','api/users/'+encodeURIComponent(name),{role:s.value});toast(`${name} is now ${s.value}.`);}catch(err){toast(err.message,true);showAccount();}});
det.addEventListener('click',async e=>{
  const t=e.target,q=s=>t.closest(s);
  if(q('[data-new-prop]'))return proposalForm();
  if(q('[data-open-prop]'))return openProposal(q('[data-open-prop]').dataset.openProp);
  if(q('[data-leave-mode]'))return leaveMode();
  if(q('[data-prop-submit]'))return propAction('submit');
  if(q('[data-prop-withdraw]'))return propAction('withdraw');
  if(q('[data-prop-approve]'))return propAction('approve');
  if(q('[data-prop-force]'))return propAction('force');
  if(q('[data-prop-reject]'))return propAction('reject');
  if(q('[data-prop-comment]'))return propAction('comment');
  if(q('[data-prop-delete]'))return propAction('delete');
  if(q('[data-prop-edit]'))return renameProposal();
  if(q('[data-hist-view]'))return previewVersion(+q('[data-hist-view]').dataset.histView);
  if(q('[data-hist-restore]'))return restoreVersion(+q('[data-hist-restore]').dataset.histRestore,q('[data-hist-restore]'));
  if(q('[data-hist-more]'))return showHistory(true);
  if(q('[data-hs]')){HIST.all=q('[data-hs]').dataset.hs==='all';return showHistory();}
  const u=q('[data-user]');if(!u)return;const name=u.dataset.user;
  try{
    if(q('[data-utoggle]')){await Store.api('PUT','api/users/'+encodeURIComponent(name),{disabled:q('[data-utoggle]').textContent==='Disable'});showAccount();}
    if(q('[data-udel]')){const b=q('[data-udel]');if(!b.classList.contains('armed')){b.classList.add('armed');b.textContent='Confirm';return;}await Store.api('DELETE','api/users/'+encodeURIComponent(name));showAccount();}
    if(q('[data-upass]')){const p=window.prompt(`New password for ${name} (10 characters or more):`);if(p){await Store.api('PUT','api/users/'+encodeURIComponent(name),{password:p});toast('Password set.');}}
  }catch(err){toast(err.message,true);}
});
/* ---- connectors: built-in modules (Cyberwatch, GLPI, phpIPAM, Palo Alto) and those from the store (self-hosted only) ---- */
let CONN=null,CONN_TAB='installed';
const ORIGIN_LBL={builtin:'Built-in',provided:'Provided by the server',installed:'From the store'};
const permText=p=>[p.map?'reads the map':'',p.network?'connects to your tool over the network':''].filter(Boolean).join(' and ')||'needs neither the map nor the network';
async function loadConnectors(){try{CONN=await Store.api('GET','api/connectors');const b=$('#connBtn .mono');if(b&&CONN.connectors.length)b.textContent=CONN.connectors.map(c=>c.badge).slice(0,5).join(' · ');}catch(e){CONN=null;toast(e.message,true);}return CONN;}
function connStatus(c){
  if(c.running)return `<span class="st running">Running…</span>`;
  if(!c.configured&&c.live!==false&&!(c.file&&!c.fields.some(f=>f.required)))return `<span class="st withdrawn">Not set up</span>`;
  if(c.lastRun&&!c.lastRun.ok)return `<span class="st rejected">Last run failed</span>`;
  if(c.settings.enabled&&+c.settings.everyHours&&c.live)return `<span class="st approved">Every ${+c.settings.everyHours} h</span>`;
  return `<span class="st draft">${c.live?'By hand':c.file?'Files':'By hand'}</span>`;
}
function connRun(r){
  if(!r)return '<p class="fhint">Never run.</p>';
  const props=(r.proposals||[]).map(p=>`<button class="ibtn" data-open-prop="${esc(p.id)}">${esc(p.title)}${p.unchanged?' · unchanged':p.refreshed?' · refreshed':''}</button>`).join('');
  return `<div class="crun ${r.ok?'ok':'ko'}"><small>${fmtDate(r.at)} · ${esc(r.by||'')}${r.file?' · '+esc(r.file):''} · ${(r.ms/1000).toFixed(1)} s</small>
    <p>${esc(r.ok?r.summary:r.error)}</p>${props?`<div class="cprops">${props}</div>`:''}
    ${r.report&&(r.report.unmatchedSample||r.report.noSiteSample||r.report.skipped||[]).length?`<details><summary>Details</summary><ul>${[...(r.report.unmatchedSample||[]).map(x=>'Not on the map: '+x),...(r.report.noSiteSample||[]).map(x=>'No IS for: '+x),...(r.report.skipped||[]),...(r.report.warnings||[])].slice(0,40).map(x=>`<li>${esc(String(x))}</li>`).join('')}</ul></details>`:''}</div>`;
}
const connTabs=C=>C.store?`<div class="seg two ctabs" role="tablist"><button data-ctab="installed" aria-pressed="${CONN_TAB==='installed'}">Installed</button><button data-ctab="store" aria-pressed="${CONN_TAB==='store'}">Module store</button></div>`:'';
const connHead=`<div class="d-head"><div><span class="cap">Collaboration</span><h2>Connectors</h2><p>Data read from your tools arrives as proposals to review, never straight onto the map</p></div><button class="close" data-close aria-label="Close">×</button></div>`;
async function showConnectors(){
  if(!await loadConnectors())return;
  const C=CONN;
  if(CONN_TAB==='store'&&C.store)return showModuleStore();
  const card=c=>{
    const canFile=c.file&&(c.file.role==='contributor'?Store.me.canPropose:C.canRun);
    const meta=[c.origin!=='builtin'?ORIGIN_LBL[c.origin]:'',c.origin!=='builtin'?'v'+c.version:'',c.origin!=='builtin'&&c.author?c.author:''].filter(Boolean).join(' · ');
    return `<li class="conn" data-conn="${esc(c.id)}"><div class="c1"><span class="cico mono">${esc(c.badge)}</span><div><b>${esc(c.name)}</b><small>${esc(c.what)}</small>${meta?`<small class="cmeta">${esc(meta)}${c.origin!=='builtin'?` · ${esc(permText(c.permissions))}`:''}</small>`:''}</div>${C.canRun?connStatus(c):''}</div>
    ${C.canRun?connRun(c.lastRun):''}
    <div class="c2">
      ${C.canRun&&c.live?`<button class="btn small primary" data-conn-run ${c.running?'disabled':''}>${c.running?'Running…':'Sync now'}</button><button class="ibtn" data-conn-test>Test the connection</button>`:''}
      ${canFile?`<button class="btn small${C.canRun&&c.live?'':' primary'}" data-conn-file>${esc(c.file.label)}</button>`:''}
      ${C.canConfigure&&c.fields.length?`<button class="ibtn" data-conn-edit>Settings</button>`:''}
      ${C.canConfigure&&c.origin==='installed'?`<button class="ibtn danger" data-mod-remove>Remove</button>`:''}
    </div><p class="ctest" hidden></p></li>`;};
  openDet(`${connHead}
  <div class="d-body">
  ${connTabs(C)}
  ${C.connectors.length?`<ul class="list conns">${C.connectors.map(card).join('')}</ul>`:'<p class="fhint">No connector you can use here.</p>'}
  ${C.canConfigure&&C.problems&&C.problems.length?`<details class="adv"><summary>${plural(C.problems.length,'module folder')} left out</summary><ul class="fhint">${C.problems.map(p=>`<li>${esc(ORIGIN_LBL[p.origin]||p.origin)} · ${esc(p.folder)}: ${esc(p.error)}</li>`).join('')}</ul></details>`:''}
  ${C.canRun&&C.runs.length?`<h3 class="cap">Recent runs</h3><ul class="list runs">${C.runs.slice(0,12).map(r=>`<li><b>${esc((C.connectors.find(c=>c.id===r.id)||{}).name||r.id)}</b><small>${fmtDate(r.at)} · ${esc(r.by)}</small><span class="${r.ok?'':'bad'}">${esc(r.ok?r.summary:r.error)}</span></li>`).join('')}</ul>`:''}
  ${!C.canConfigure?'<p class="fhint">An administrator sets the connectors up.</p>':''}
  </div>`,'connectors');
}
// The module store: what the registry offers, with what each module may do; installing needs an administrator
async function showModuleStore(fresh){
  const C=CONN;let S;
  openDet(`${connHead}<div class="d-body">${connTabs(C)}<p class="fhint">Reading the module store…</p></div>`,'connectors');
  try{S=await Store.api('GET','api/modules'+(fresh?'?fresh=1':''));}catch(e){S={error:e.message,modules:[]};}
  if(state.panel!=='connectors'||CONN_TAB!=='store')return;
  const card=m=>{
    const btn=!m.compatible?`<span class="fhint">Needs Strata ${esc(m.minStrata)}</span>`
      :m.update?`<button class="btn small primary" data-mod-install>Update to ${esc(m.version)}</button>`
      :m.installed?`<span class="st approved">Installed${m.installed.origin!=='installed'?' ('+esc(ORIGIN_LBL[m.installed.origin].toLowerCase())+')':''}</span>`
      :`<button class="btn small primary" data-mod-install>Install</button>`;
    return `<li class="conn" data-mod="${esc(m.id)}"><div class="c1"><span class="cico mono">${esc(m.badge||m.name.slice(0,3).toUpperCase())}</span><div><b>${esc(m.name)}</b><small>${esc(m.description)}</small>
      <small class="cmeta">v${esc(m.version)}${m.author?' · '+esc(m.author):''}${m.license?' · '+esc(m.license):''}${m.homepage?` · <a href="${esc(m.homepage)}" target="_blank" rel="noopener noreferrer">source</a>`:''}</small>
      <small class="cperm">It ${esc(permText(m.permissions))}.</small></div></div>
      <div class="c2">${btn}</div><p class="ctest" hidden></p></li>`;};
  det.querySelector('.d-body').innerHTML=`${connTabs(C)}
    ${S.error?`<p class="ctest ko">${esc(S.error)}</p>`:''}
    ${S.store&&!S.error?(S.modules.length?`<ul class="list conns">${S.modules.map(card).join('')}</ul>`:'<p class="fhint">The store lists no module yet.</p>'):''}
    ${!S.store?'<p class="fhint">The module store is off on this server (MODULE_REGISTRY).</p>':''}
    <p class="fhint">Modules run on the server, each in its own process that cannot read the data files or the other connectors’ settings. The store only lists modules whose code was reviewed, and checks each package against the checksum it publishes. Installed modules prepare proposals, like the built-in connectors: nothing reaches the map unless an approver accepts it.</p>
    <div class="c2">${S.store?'<button class="ibtn" data-mod-refresh>Check the store again</button>':''}${S.uploads?'<button class="ibtn" data-mod-upload>Install a package file…</button><input type="file" id="modFile" accept=".tgz,.tar.gz,application/gzip" hidden>':''}</div>`;
}
function onConnectorsChanged(){if(state.panel==='connectors'&&CONN_TAB==='installed')showConnectors();}
// One setting field, built from the description the server sends (secrets are never sent back: “unchanged” keeps them)
function connField(f,S){
  const id='cf_'+f.k,v=S[f.k],hint=f.help?`<span class="hint">${esc(f.help)}</span>`:'',siteOpts=SITES.map(s=>[s.id,s.name]);
  if(f.type==='bool')return `<label class="chk plain"><input type="checkbox" id="${esc(id)}" data-ck="${esc(f.k)}"${v?' checked':''}> ${esc(f.label)}</label>${hint}`;
  if(f.type==='select')return fSel(id,esc(f.label),f.options,v||f.default).replace('<select ','<select data-ck="'+esc(f.k)+'" ');
  if(f.type==='site')return fSel(id,esc(f.label)+(f.required?' *':''),[['','Choose…'],...siteOpts],v).replace('<select ','<select data-ck="'+esc(f.k)+'" ');
  if(f.type==='asset')return `<div data-asset-wrap="${esc(f.k)}">${fSel(id,esc(f.label),connAssetOpts(S.site||state.siteId),v).replace('<select ','<select data-ck="'+esc(f.k)+'" ')}${hint}</div>`;
  if(f.type==='multi'||f.type==='sites'){const opts=f.type==='sites'?siteOpts:f.options,cur=Array.isArray(v)?v:[];
    return `<fieldset data-multi="${esc(f.k)}"><legend>${esc(f.label)}</legend>${opts.map(([k,t])=>`<label class="chk plain"><input type="checkbox" value="${esc(k)}"${cur.includes(k)?' checked':''}> ${esc(t)}</label>`).join('')}${hint}</fieldset>`;}
  if(f.type==='rules'||f.type==='text')return `<div class="f"><label for="${esc(id)}">${esc(f.label)}</label><textarea id="${esc(id)}" data-ck="${esc(f.k)}" class="mono" spellcheck="false" placeholder="${esc(f.placeholder||'')}">${esc(v||'')}</textarea>${hint}</div>`;
  if(f.secret)return fIn(id,esc(f.label)+(f.required?' *':''),'',`type="password" autocomplete="new-password" data-ck="${esc(f.k)}" data-secret="${v?1:0}" placeholder="${v?'Saved: leave empty to keep it':esc(f.placeholder||'')}"`,f.help?esc(f.help):'')+(v?`<label class="chk plain small"><input type="checkbox" data-clear="${esc(f.k)}"> Forget the saved value</label>`:'');
  return fIn(id,esc(f.label)+(f.required?' *':''),v==null?'':v,`data-ck="${esc(f.k)}" ${f.type==='number'?'type="number" min="0" step="1"':''} placeholder="${esc(f.placeholder||'')}" autocomplete="off"`,f.help?esc(f.help):'');
}
function connAssetOpts(sid){const s=siteById[sid];if(!s)return [['','—']];const fw=s.assets.filter(a=>INTERCO.has(a.type)),rest=s.assets.filter(a=>!INTERCO.has(a.type));
  return [['','None (direct)'],{group:'Firewalls, routers, gateways',items:fw.map(a=>[a.id,`${a.name} · ${a.ip||''}`])},{group:'Other assets',items:rest.map(a=>[a.id,a.name])}];}
// An "asset" setting follows the "site" one: its list shows that IS, the firewall picked first
function connWireSite(c){
  const siteSel=det.querySelector('[data-ck="site"]');
  if(siteSel)siteSel.addEventListener('change',()=>{const w=det.querySelector('[data-asset-wrap]');if(!w)return;const k=w.dataset.assetWrap,f=c.fields.find(x=>x.k===k);
    const s=siteById[siteSel.value];const fw=s?s.assets.find(a=>a.type==='firewall'):null;
    w.innerHTML=fSel('cf_'+k,esc(f.label),connAssetOpts(siteSel.value),fw?fw.id:'').replace('<select ','<select data-ck="'+esc(k)+'" ');});
}
function connValues(){
  const body={};
  det.querySelectorAll('[data-ck]').forEach(el=>{const k=el.dataset.ck;if(el.type==='checkbox')body[k]=el.checked;else if(el.dataset.secret!==undefined){if(el.value)body[k]=el.value;}else body[k]=el.value;});
  det.querySelectorAll('[data-clear]').forEach(el=>{if(el.checked)body[el.dataset.clear]='';});
  det.querySelectorAll('[data-multi]').forEach(fs=>{body[fs.dataset.multi]=[...fs.querySelectorAll('input:checked')].map(i=>i.value);});
  return body;
}
function connectorForm(c){
  const main=c.fields.filter(f=>!f.advanced),adv=c.fields.filter(f=>f.advanced);
  openForm(`${c.name} settings`,'Connector',`<p class="fhint" style="margin:0">${esc(c.what)}. Each run prepares one proposal per IS; an approver reviews it.</p>
    ${main.map(f=>connField(f,c.settings)).join('')}
    ${adv.length?`<details class="adv"><summary>More settings</summary>${adv.map(f=>connField(f,c.settings)).join('')}</details>`:''}`,
  async()=>{
    const body=connValues();
    const miss=c.fields.find(f=>f.required&&!f.secret&&!String(body[f.k]||'').trim());if(miss)return formErr(`Fill in “${miss.label}”.`,'cf_'+miss.k);
    try{await Store.api('PUT','api/connectors/'+c.id,body);onSave=null;toast(`${c.name} settings saved.`);showConnectors();}catch(e){formErr(e.message);}
  },{cancel:()=>showConnectors()});
  connWireSite(c);
}
// A file imported through a module (a firewall configuration, a CSV inventory…), as a proposal
function fileImportForm(c){
  const S={...c.settings};
  if(!S.site)S.site=state.siteId||(SITES[0]&&SITES[0].id);
  const ff=c.fields.filter(f=>c.file.fields.includes(f.k));
  if(ff.some(f=>f.type==='asset')&&!S.firewall){const s=siteById[S.site],fw=s&&s.assets.find(a=>a.type==='firewall');if(fw)S.firewall=fw.id;}
  openForm(c.file.label,c.name,`
    ${c.file.help?`<p class="fhint" style="margin:0">${esc(c.file.help)}</p>`:''}
    <div class="f"><label for="cfFile">File *</label><input type="file" id="cfFile" accept="${esc(c.file.accept||'')}"></div>
    ${ff.map(f=>connField(f,S)).join('')}
    <p class="fhint">The result is a proposal: nothing changes on the map until it is approved.</p>`,
  async()=>{
    const f=$('#cfFile').files[0];if(!f)return formErr('Choose the file.','cfFile');
    if(f.size>18*1024*1024)return formErr('This file is larger than 18 MB.');
    const overrides=connValues(),miss=ff.find(x=>x.required&&!String(overrides[x.k]||'').trim());if(miss)return formErr(`Fill in “${miss.label}”.`,'cf_'+miss.k);
    const text=await f.text();
    const btn=det.querySelector('.form-foot [type=submit]');btn.disabled=true;btn.textContent='Reading the file…';
    try{const j=await Store.api('POST',`api/connectors/${c.id}/run`,{file:{name:f.name,text},wait:true,overrides});
      onSave=null;const r=j.run;
      if(!r.ok){btn.disabled=false;btn.textContent='Import';return formErr(r.error);}
      toast(r.proposals.length?'Imported: review the proposal.':'Nothing new: the map already matches this file.');
      if(r.proposals.length)openProposal(r.proposals[0].id);else showConnectors();
    }catch(e){btn.disabled=false;btn.textContent='Import';formErr(e.message);}
  },{cancel:()=>showConnectors()});
  det.querySelector('.form-foot [type=submit]').textContent='Import';
  connWireSite(c);
}
det.addEventListener('change',async e=>{
  if(e.target.id!=='modFile'||!e.target.files[0])return;
  const f=e.target.files[0];
  if(f.size>20*1024*1024)return toast('This package is larger than 20 MB.',true);
  const b64=await new Promise((res,rej)=>{const r=new FileReader();r.onload=()=>res(String(r.result).split(',')[1]||'');r.onerror=()=>rej(r.error);r.readAsDataURL(f);});
  try{const j=await Store.api('POST','api/modules/upload',{data:b64});toast(`${j.module.name} ${j.module.version} installed.`);CONN_TAB='installed';showConnectors();}
  catch(err){toast(err.message,true);}
});
det.addEventListener('click',async e=>{
  const tab=e.target.closest('[data-ctab]');if(tab&&CONN){CONN_TAB=tab.dataset.ctab;return showConnectors();}
  if(e.target.closest('[data-mod-refresh]'))return showModuleStore(true);
  if(e.target.closest('[data-mod-upload]')){const i=$('#modFile');if(i){i.value='';i.click();}return;}
  const mcard=e.target.closest('[data-mod]');
  if(mcard&&e.target.closest('[data-mod-install]')){
    const b=e.target.closest('[data-mod-install]'),out=mcard.querySelector('.ctest');
    if(!b.classList.contains('armed')){b.classList.add('armed');b.dataset.label=b.textContent;b.textContent='Confirm: it will run on the server';return;}
    b.disabled=true;b.textContent='Installing…';
    try{const j=await Store.api('POST',`api/modules/${encodeURIComponent(mcard.dataset.mod)}/install`,{});toast(`${j.module.name} ${j.module.version} installed. Set it up under Installed.`);showModuleStore();}
    catch(err){out.hidden=false;out.className='ctest ko';out.textContent=err.message;b.disabled=false;b.classList.remove('armed');b.textContent=b.dataset.label;}
    return;
  }
  const card=e.target.closest('[data-conn]');if(!card||!CONN)return;
  const c=CONN.connectors.find(x=>x.id===card.dataset.conn);if(!c)return;
  const out=card.querySelector('.ctest');
  if(e.target.closest('[data-conn-edit]'))return connectorForm(c);
  if(e.target.closest('[data-conn-file]'))return fileImportForm(c);
  if(e.target.closest('[data-mod-remove]')){const b=e.target.closest('[data-mod-remove]');
    if(!b.classList.contains('armed')){b.classList.add('armed');b.textContent='Confirm: remove it and its settings';return;}
    try{await Store.api('DELETE','api/modules/'+encodeURIComponent(c.id));toast(`${c.name} removed.`);showConnectors();}catch(err){toast(err.message,true);}return;}
  if(e.target.closest('[data-conn-test]')){out.hidden=false;out.className='ctest';out.textContent='Testing…';
    try{const j=await Store.api('POST',`api/connectors/${c.id}/test`,{});out.textContent=j.message;out.classList.add(j.ok?'ok':'ko');}catch(err){out.textContent=err.message;out.classList.add('ko');}return;}
  if(e.target.closest('[data-conn-run]')){const b=e.target.closest('[data-conn-run]');b.disabled=true;b.textContent='Running…';
    try{await Store.api('POST',`api/connectors/${c.id}/run`,{});toast(`${c.name} sync started. Its proposals appear when it is done.`);}catch(err){toast(err.message,true);b.disabled=false;b.textContent='Sync now';}return;}
});
/* ---- mode bar: draft, review or older version ---- */
function renderModeBar(){
  const b=$('#modebar'),v=Store.view;document.body.classList.toggle('has-mode',!!v);document.body.dataset.mode=v||'';
  if(!v){b.hidden=true;b.innerHTML='';syncUI();return;}
  const p=Store.prop,n=DIFF?DIFF.items.length:0;
  if(v==='draft')b.innerHTML=`<span class="mb-k">Draft</span><span class="mb-t"><b>${esc(p.title)}</b><small>${plural(n,'change')} · not on the map until approved</small></span><button class="btn small" data-mb="changes">Changes</button><button class="btn small primary" data-mb="submit">Submit for review</button><button class="btn small" data-mb="leave">Leave</button>`;
  else if(v==='review')b.innerHTML=`<span class="mb-k">${p.status==='submitted'?'Review':'Proposal'}</span><span class="mb-t"><b>${esc(p.title)}</b><small>by ${esc(p.author)} · ${plural(n,'change')} · ${STATUS_LBL[p.status]||p.status}</small></span><button class="btn small" data-mb="changes">Changes</button><button class="btn small" data-mb="leave">Close</button>`;
  else{const pv=Store.preview;b.innerHTML=`<span class="mb-k">Version ${pv.rev}</span><span class="mb-t"><b>Read-only, as it was then</b><small>${esc(pv.user||'')} · ${fmtDate(pv.at)}</small></span>${Store.liveWrite?`<button class="btn small" data-mb="restore">Restore this version</button>`:''}<button class="btn small primary" data-mb="leave">Back to the current map</button>`;}
  b.hidden=false;syncUI();
}
$('#modebar').addEventListener('click',e=>{const k=e.target.closest('[data-mb]');if(!k)return;const m=k.dataset.mb;
  if(m==='leave'){if(Store.view==='draft'){clearTimeout(Store._dt);Store.saveDraft();}leaveMode(Store.view==='draft'?'Draft saved. Reopen it from Proposals.':'');}
  else if(m==='changes')showProposal();
  else if(m==='submit')propAction('submit');
  else if(m==='restore')restoreVersion(Store.preview.rev,k);});
function renderCollab(){
  const on=Store.mode==='api'&&Store.features.proposals;
  document.querySelectorAll('.collab').forEach(el=>el.hidden=!on);
  const ab=$('#accBtn');if(ab)ab.querySelector('.mono').textContent=Store.me?(Store.me.user?`${Store.me.user} · ${Store.me.role}`:'open access'):'';
  const cb=$('#connBtn');if(cb)cb.hidden=!(on&&Store.me&&Store.me.connectors&&Store.me.canPropose);
  const np=$('#newPropBtn');if(np)np.hidden=!(on&&Store.me&&Store.me.canPropose&&!Store.view);
}
$('#ctl').addEventListener('click',e=>{const b=e.target.closest('[data-collab]');if(!b)return;const k=b.dataset.collab;
  if(k==='proposals')showProposals();else if(k==='history'){HIST.all=state.view!=='site';showHistory();}else if(k==='account')showAccount();else if(k==='connectors')showConnectors();else if(k==='new-prop')proposalForm();});
// Export one IS (with its assets and the shared services) to edit it elsewhere and bring it back as a proposal
async function exportSite(s){
  const assets={};Object.entries(raw.assets).forEach(([id,a])=>{if(a.site===s.id)assets[id]=a;});
  const data=JSON.stringify({format:'strata',version:3,scope:'si',exportedAt:new Date().toISOString(),si:{[s.id]:raw.si[s.id]},assets,services:raw.services||[]},null,2);
  await saveFile(`strata_${fileStem(s.name)}_${today()}.json`,'application/json',data);
}

/* ================= Navigation ================= */
let fly=null;
function flyTo(target,dist){const off=camera.position.clone().sub(controls.target);off.setLength(dist||Math.min(off.length(),28));
  fly={t0:performance.now(),dur:reduceMotion?1:800,fromT:controls.target.clone(),fromC:camera.position.clone(),toT:target.clone(),toC:target.clone().add(off)};}
function selectSite(s,focus){
  state.ovSelId=s?s.id:null;
  if(s){showSite(s);if(focus&&OV.sites[s.id]){const o=OV.sites[s.id];flyTo(new THREE.Vector3(o.group.position.x,TABLE_Y+4,o.group.position.z),Math.max(40,OV.ex*1.5));}}
  else closeDet();
  refreshOverview();closeCtlMobile(!!s);
}
function enterSite(s){
  if(!s)return;
  state.view='site';state.siteId=s.id;state.ovSelId=s.id;state.selId=null;state.path=false;state.hidden=new Set();state.biz=null;
  $('#pathBtn').setAttribute('aria-pressed','false');
  setSite(s);closeDet();flatFitFor=null;showFlatUI();renderVlanList();buildScene();layout();refresh();renderCart();syncUI();setViewNow();renderEmpty();
}
function backToOverview(){
  if(!$('#archf').hidden)closeArchFile();
  if(state.arrange)setArrange(false);
  const id=state.siteId;state.view='overview';state.selId=null;state.siteId=null;
  showFlatUI();buildOverview();renderSiteList();renderCart();setViewNow();
  if(siteById[id])selectSite(siteById[id],false);else{closeDet();refreshOverview();}
  renderEmpty();
}
function select(a,focus){
  if(a&&state.path){state.path=false;$('#pathBtn').setAttribute('aria-pressed','false');}
  if(a&&state.hidden.has(a.vlan)){state.hidden.delete(a.vlan);const cb=$('#vl-'+a.vlan);if(cb)cb.checked=true;}
  state.selId=a?a.id:null;
  if(a){showAsset(a);if(focus&&a.group&&!state.flat){const p=new THREE.Vector3();a.group.getWorldPosition(p);p.y+=a.h/2;flyTo(p);}}
  else if(!state.path&&state.panel!=='ports')closeDet();
  refresh();if(a&&focus&&state.flat)centerFlatOn(a);closeCtlMobile(!!a);
}
function setPath(on){state.path=on;$('#pathBtn').setAttribute('aria-pressed',String(on));if(on){state.selId=null;showPath();}else if(!selAsset())closeDet();refresh();}
function closeCtlMobile(cond){if(cond&&innerWidth<=760){document.body.classList.remove('ctl-open');$('#toggleCtl').setAttribute('aria-expanded','false');}}

/* ================= Data arrival ================= */
let dataT=null,pendingAfterData=null,firstView=true,lastCount=0;
function scheduleData(delay){clearTimeout(dataT);dataT=setTimeout(onData,delay==null?(Store.bulk?400:60):delay);}
function onData(){
  compile();renderSiteList();
  if(state.view==='site'){
    const s=siteById[state.siteId];
    if(!s){toast('This IS was deleted.');backToOverview();runPending();return;}
    if(state.biz&&!s.bizById[state.biz])state.biz=null;
    setSite(s);renderVlanList();buildScene();layout();refresh();
    if(state.selId&&!byId[state.selId])state.selId=null;
    if(state.panel!=='form'){
      if(state.panel==='asset'){const a=selAsset();if(a)showAsset(a);else closeDet();}
      else if(state.panel==='path')showPath();else if(state.panel==='ports')showPorts();
      else if(state.panel==='flow'){const f=FLOWS.find(x=>x.id===state.flowId);if(f)showFlow(f);else closeDet();}
      else if(state.panel==='risk')showRisk();
      else if(state.panel==='attack')showAttack();
      else if(state.panel==='business'){const b=SITE.bizById[state.bizPanel];if(b)showBusiness(b);else closeDet();}
    }
  }else{
    buildOverview();
    if(firstView||SITES.length!==lastCount){const was=firstView;firstView=false;was?setViewNow():resetView();}
    if(state.ovSelId&&!siteById[state.ovSelId])state.ovSelId=null;
    if(state.panel==='site'){const s=ovSel();if(s)showSite(s);else closeDet();}
    refreshOverview();
  }
  if(state.panel==='proposal'&&Store.prop)showProposal();
  renderServiceLists();renderCollab();
  lastCount=SITES.length;renderCart();syncUI();renderEmpty();runPending();
}
function runPending(){if(pendingAfterData&&!onSave){const f=pendingAfterData;pendingAfterData=null;f();}}
// After a save: close the form and refresh as soon as the data is read back
function afterSave(fn){onSave=null;onCancel=null;pendingAfterData=fn;scheduleData(0);}

/* ================= Pointer ================= */
const ray=new THREE.Raycaster(),ndc=new THREE.Vector2(),tip=$('#tip');
function isShown(o){while(o){if(!o.visible)return false;o=o.parent;}return true;}
function pick(ev){
  const r=renderer.domElement.getBoundingClientRect();
  ndc.set(((ev.clientX-r.left)/r.width)*2-1,-((ev.clientY-r.top)/r.height)*2+1);ray.setFromCamera(ndc,camera);
  const hit=ray.intersectObjects(pickables,false).find(h=>isShown(h.object)&&(state.view==='overview'||h.object.material.opacity>0.5));
  return hit?hit.object.userData:null;
}
let down=null,drag=null;
const flowPath=f=>f.hops.map(id=>esc(nameOf(id))).join(' → ');
renderer.domElement.addEventListener('pointerdown',e=>{
  // only the left button (or a touch) selects and drags; the others move the view
  down=e.button===0?{x:e.clientX,y:e.clientY}:null;stopRotate();
  if(e.button!==0)return;
  // Arrange mode: grab a plate (or an asset on it) and slide it along its level
  if(state.view!=='site'||!state.arrange||state.mode!=='zones'||!Store.canWrite||state.panel==='form')return;
  const u=pick(e),id=u&&(u.plate||(u.asset&&u.asset.vlan));if(!id||!floors[id])return;
  const fl=floors[id],plane=new THREE.Plane(new THREE.Vector3(0,1,0),-(fl.group.position.y+SLAB/2)),hit=new THREE.Vector3();
  if(!ray.ray.intersectPlane(plane,hit))return;
  drag={id,fl,plane,startX:hit.x,startZ:hit.z,x0:fl.group.position.x,z0:fl.group.position.z,moved:false};
  controls.enabled=false;renderer.domElement.setPointerCapture(e.pointerId);renderer.domElement.style.cursor='grabbing';
});
renderer.domElement.addEventListener('pointerup',e=>{
  if(drag){const d=drag;drag=null;controls.enabled=true;renderer.domElement.style.cursor='';if(d.moved){down=null;finishDrag(d);return;}}
  if(!down)return;const m=Math.hypot(e.clientX-down.x,e.clientY-down.y);down=null;if(m>=6)return;
  if(state.panel==='form')return;
  const u=pick(e);
  if(state.view==='overview'){if(u&&u.site){if(state.ovSelId===u.site.id)enterSite(u.site);else selectSite(u.site,false);}else if(state.ovSelId)selectSite(null);return;}
  if(u&&u.asset)select(u.asset,false);
  else if(u&&u.svc)showService(u.svc);
  else if(u&&u.flow)showFlow(u.flow);
  else if(state.selId)select(null);else if(state.panel==='flow')closeDet();});
renderer.domElement.addEventListener('pointermove',e=>{
  if(drag){
    const r=renderer.domElement.getBoundingClientRect(),hit=new THREE.Vector3();
    ndc.set(((e.clientX-r.left)/r.width)*2-1,-((e.clientY-r.top)/r.height)*2+1);ray.setFromCamera(ndc,camera);
    if(ray.ray.intersectPlane(drag.plane,hit)){drag.fl.group.position.x=drag.x0+(hit.x-drag.startX);drag.fl.group.position.z=drag.z0+(hit.z-drag.startZ);if(!drag.moved){drag.moved=true;FLOWS.forEach(f=>{if(f.tube){f.tube.visible=false;f.parts.forEach(p=>p.visible=false);f.cones.forEach(c=>c.visible=false);}});selRing.visible=false;}}
    return;
  }
  if(e.pointerType!=='mouse'||e.buttons){tip.hidden=true;return;}
  const u=pick(e);let html='',cur='grab';
  if(u&&u.site)html=`<b>IS ${esc(u.site.name)}</b> · ${esc(u.site.kind)} · <span style="color:var(--crit)">${u.site.stats.crit} crit.</span>`;
  else if(u&&u.asset){const a=u.asset;html=`<b>${esc(a.name)}</b> · ${esc(a.ip||'')} · <span style="color:var(${SEV[a.sev].css})">${SEV[a.sev].label}</span> · <span style="color:var(${EXP[a.exp].css})">${EXP[a.exp].label}</span>`;}
  else if(u&&u.svc){const x=u.svc;html=`<b>${esc(x.name)}</b> · ${esc(x.hosts.join(', '))} · ${esc(x.ports.join(' '))}`;}
  else if(u&&u.flow){const f=u.flow;html=`<b>${flowPath(f)}</b> · ${esc(f.port)} · ${f.vol} MB/h · <span style="color:var(${EXP[f.level].css})">${EXP[f.level].label}</span>${f.risk?' · <span style="color:var(--crit)">risky</span>':''}`;}
  else if(u&&u.plate&&state.arrange){const v=vlanById[u.plate];html=`<b>VLAN ${esc(v.num)} · ${esc(v.name)}</b> · drag to move`;}
  if(state.arrange&&u&&(u.plate||u.asset)&&state.mode==='zones')cur='ew-resize';else if(html)cur='pointer';
  renderer.domElement.style.cursor=cur;
  if(html){tip.innerHTML=html;tip.hidden=false;tip.style.left=Math.min(e.clientX+14,innerWidth-tip.offsetWidth-8)+'px';tip.style.top=(e.clientY+14)+'px';}else tip.hidden=true;
});
renderer.domElement.addEventListener('pointerleave',()=>tip.hidden=true);
// Where a plate lands on its level: kept clear of the other plates (pushed along the shorter way out)
function clearSpot(p,w,D,others){
  const gap=1;let [x,z]=p;
  for(let k=0;k<12;k++){
    const o=others.find(o=>Math.abs(x-o.x)<(w+o.w)/2+gap&&Math.abs(z-o.z)<(D+o.D)/2+gap);if(!o)break;
    const px=(w+o.w)/2+gap-Math.abs(x-o.x),pz=(D+o.D)/2+gap-Math.abs(z-o.z);
    if(px<pz)x+=(x>=o.x?1:-1)*px;else z+=(z>=o.z?1:-1)*pz;
  }
  return [Math.round(x*2)/2,Math.round(z*2)/2];
}
// Saves the spot of every plate of a level (plus its zone when it changes), in one change
async function savePlaces(places,zoneOf={}){
  const ids=Object.keys(places).sort((a,b)=>places[a][0]-places[b][0]);
  const d=clone(SITE.raw);d.vlans=(d.vlans||[]).map(x=>{if(!(x.id in places))return x;const y=Object.assign({},x,{place:places[x.id],pos:ids.indexOf(x.id)});if(zoneOf[x.id])y.zone=zoneOf[x.id];return y;});
  await Store.putSite(SITE.id,d);
}
async function resetPlaces(zoneId){
  const d=clone(SITE.raw);d.vlans=(d.vlans||[]).map(x=>{if(x.zone!==zoneId||!x.place)return x;const y=Object.assign({},x);delete y.place;return y;});
  try{await Store.putSite(SITE.id,d);toast('Plates of this level lined up again.');}catch(e){}
}
async function finishDrag(d){
  if(!d.moved){layout();refresh();return;}
  const lvl=Object.entries(floors).filter(([,f])=>f.level===d.fl.level),places={},others=[];
  lvl.forEach(([id,f])=>{if(id!==d.id){places[id]=[Math.round(f.x0*2)/2,Math.round(f.z0*2)/2];others.push({x:f.x0,z:f.z0,w:f.w,D:f.D});}});
  places[d.id]=clearSpot([d.fl.group.position.x,d.fl.group.position.z],d.fl.w,d.fl.D,others);
  try{await savePlaces(places);toast('Plate moved.');}catch(err){layout();refresh();}
}
async function saveVlanOrder(ids){
  const d=clone(SITE.raw);d.vlans=(d.vlans||[]).map(x=>{const k=ids.indexOf(x.id);return k<0?x:Object.assign({},x,{pos:k});});
  await Store.putSite(SITE.id,d);
}
async function moveVlan(id,delta){
  const z=ZONES.find(z=>z.vlans.some(v=>v.id===id));if(!z)return;
  const ids=z.vlans.map(v=>v.id),i=ids.indexOf(id),j=i+delta;if(j<0||j>=ids.length)return;
  if(state.mode==='zones'&&z.vlans.some(v=>v.place)){
    const lv=computeLayout().levels.find(l=>l.zoneId===z.id),places={};
    lv.plates.forEach(pl=>places[pl.id]=[pl.x0,pl.z0]);
    const order=lv.plates.slice().sort((a,b)=>a.x0-b.x0).map(pl=>pl.id),a=order.indexOf(id),b=a+delta;if(b<0||b>=order.length)return;
    [places[order[a]],places[order[b]]]=[places[order[b]],places[order[a]]];
    try{await savePlaces(places);}catch(err){}return;
  }
  [ids[i],ids[j]]=[ids[j],ids[i]];
  try{await saveVlanOrder(ids);}catch(err){}
}
function setArrange(on){
  state.arrange=!!on;
  if(on&&state.mode!=='zones')toast('In “1 VLAN per floor”, reorder the floors with the arrows in the VLAN list.');
  $('#arrangeBtn').setAttribute('aria-pressed',String(state.arrange));
  document.body.classList.toggle('arranging',state.arrange);
  $('#hint').textContent=state.arrange?'Arrange mode · drag a plate anywhere on its level (left, right, front, back) · click “Arrange plates” again to finish':'Drag to orbit · middle or right button to move the view · scroll to zoom · click an asset or a flow';
}
function stopRotate(){if(state.rotate){state.rotate=false;$('#optRotate').checked=false;controls.autoRotate=false;}}

/* ================= Controls ================= */
const rerender=()=>state.view==='site'?refresh():refreshOverview();
const segPress=(sel,b)=>document.querySelectorAll(sel+' button').forEach(x=>x.setAttribute('aria-pressed',String(x===b)));
$('#cart').addEventListener('click',e=>{if(e.target.closest('[data-back]'))backToOverview();});
$('#siteList').addEventListener('click',e=>{const b=e.target.closest('[data-site]');if(b)selectSite(siteById[b.dataset.site],true);});
$('#vlans').addEventListener('change',e=>{const id=e.target.dataset.vlan;if(!id)return;e.target.checked?state.hidden.delete(id):state.hidden.add(id);
  const a=selAsset();if(a&&state.hidden.has(a.vlan))select(null);else refresh();});
$('#vlans').addEventListener('click',e=>{const rz=e.target.closest('[data-reset-zone]');if(rz){resetPlaces(rz.dataset.resetZone);return;}const m=e.target.closest('[data-mv]');if(m){moveVlan(m.dataset.mv,+m.dataset.d);return;}const b=e.target.closest('[data-edit-vlan]');if(b)vlanForm(vlanById[b.dataset.editVlan]);});
$('#spaceSeg').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;const c=b.dataset.space==='compact';if(c===state.compact)return;state.compact=c;segPress('#spaceSeg',b);buildScene();layout();refresh();resetView();});
$('#postSeg').addEventListener('click',e=>{const b=e.target.closest('button');if(!b||b.dataset.posts===state.posts)return;state.posts=b.dataset.posts;segPress('#postSeg',b);
  if(state.view==='site'){layout();refresh();}else{buildOverview();refreshOverview();}});
$('#arrangeBtn').addEventListener('click',()=>setArrange(!state.arrange));
$('#sevSeg').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;state.minSev=+b.dataset.sev;segPress('#sevSeg',b);refresh();});
$('#expSeg').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;state.minExp=+b.dataset.exp;segPress('#expSeg',b);refresh();});
$('#dirSeg').addEventListener('click',e=>{const b=e.target.closest('button');if(!b)return;state.dir=b.dataset.dir;segPress('#dirSeg',b);refresh();
  if(state.panel==='asset'&&selAsset())showAsset(selAsset());});
function setColour(c){if(c===state.color)return;state.color=c;segPress('#colSeg',document.querySelector(`#colSeg [data-col="${c}"]`));buildFlows();refresh();renderLegend();
  // the swatches of the open sheet follow, without rebuilding it (it keeps its scroll)
  det.querySelectorAll('[data-hl-flow]').forEach(li=>{const f=FLOWS.find(x=>x.id===li.dataset.hlFlow),sw=li.querySelector('.fsw');if(f&&sw)sw.style.background=`var(${flowColorVar(f)})`;});}
$('#colSeg').addEventListener('click',e=>{const b=e.target.closest('button');if(b)setColour(b.dataset.col);});
// Hovering a flow in the sheet picks it out on the model and the diagram
function hoverFlow(id){if(state.hoverFlow===id)return;state.hoverFlow=id;if(state.view==='site')refresh();}
det.addEventListener('pointerover',e=>{const li=e.target.closest('[data-hl-flow]');hoverFlow(li?li.dataset.hlFlow:null);
  const p=e.target.closest('[data-hl-path]'),k=p?p.dataset.hlPath:null;if(state.panel==='attack'&&k!==state.attackHl){state.attackHl=k;refresh();}});
det.addEventListener('pointerleave',()=>{hoverFlow(null);if(state.attackHl){state.attackHl=null;refresh();}});
det.addEventListener('change',e=>{const s=e.target.closest('[data-atk-from]');if(s)setAttack(s.value);});
$('#modeSeg').addEventListener('click',e=>{const b=e.target.closest('button');if(!b||b.dataset.mode===state.mode)return;
  state.mode=b.dataset.mode;segPress('#modeSeg',b);buildScene();layout();refresh();resetView();renderVlanList();syncUI();});
$('#optFlows').addEventListener('change',e=>{state.flows=e.target.checked;rerender();});
$('#optRisk').addEventListener('change',e=>{state.riskOnly=e.target.checked;rerender();});
$('#optLabels').addEventListener('change',e=>{state.labels=e.target.checked;refresh();});
$('#optPorts').addEventListener('change',e=>{state.ports=e.target.checked;refresh();});
$('#optRotate').addEventListener('change',e=>{state.rotate=e.target.checked;controls.autoRotate=state.rotate;});
$('#optGap').addEventListener('input',e=>{state.gap=+e.target.value;layout();refresh();});
$('#pathBtn').addEventListener('click',()=>{setPath(!state.path);closeCtlMobile(state.path);});
$('#portsBtn').addEventListener('click',()=>{
  if(state.panel==='ports'){closeDet();return;}
  if(state.path){state.path=false;$('#pathBtn').setAttribute('aria-pressed','false');}
  state.selId=null;if(!state.ports){state.ports=true;$('#optPorts').checked=true;}
  showPorts();refresh();closeCtlMobile(true);
});
$('#archBtn').addEventListener('click',()=>{openArchFile();closeCtlMobile(true);});
$('#archf').addEventListener('click',e=>{const b=e.target.closest('[data-arch]');if(!b)return;
  if(b.dataset.arch==='close')closeArchFile();
  else if(b.dataset.arch==='html'&&ARCHF)saveFile(`architecture-file_${fileStem(SITE.name)}_${ARCHF.date}.html`,'text/html;charset=utf-8',ARCHF.html);});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!$('#archf').hidden)closeArchFile();});
$('#atkBtn').addEventListener('click',()=>{
  if(state.panel==='attack'){closeDet();return;}
  setAttack('internet');closeCtlMobile(true);
});
$('#riskBtn').addEventListener('click',()=>{
  if(state.panel==='risk'){closeDet();return;}
  if(state.path){state.path=false;$('#pathBtn').setAttribute('aria-pressed','false');}
  state.selId=null;showRisk();refresh();closeCtlMobile(true);
});
$('#resetBtn').addEventListener('click',resetView);
$('#search').addEventListener('keydown',e=>{
  if(e.key!=='Enter')return;const q=e.target.value.trim().toLowerCase();if(!q)return;
  const a=ASSETS.find(x=>x.name.toLowerCase()===q||x.ip===q)||ASSETS.find(x=>x.name.toLowerCase().includes(q)||(x.ip||'').includes(q)||(x.role||'').toLowerCase().includes(q));
  if(a){select(a,true);e.target.blur();}else{e.target.setCustomValidity('No asset found');e.target.reportValidity();setTimeout(()=>e.target.setCustomValidity(''),1500);}
});
$('#toggleCtl').addEventListener('click',()=>{const o=document.body.classList.toggle('ctl-open');$('#toggleCtl').setAttribute('aria-expanded',String(o));if(o&&state.panel!=='form')closeDet();});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&state.panel==='form')cancelForm();});

const VIEW_DIR=new THREE.Vector3(34,30,48);
function viewDist(){
  const base=state.view==='overview'?Math.max(80,OV.spanX*1.1,OV.spanZ*1.7):Math.max(78,extent*1.5+6,nLevels*state.gap*1.2);
  return innerWidth<=760?base*1.35:base;
}
function resetView(){const c=center();fly={t0:performance.now(),dur:reduceMotion?1:800,fromT:controls.target.clone(),fromC:camera.position.clone(),toT:c,toC:c.clone().add(VIEW_DIR.clone().setLength(viewDist()))};}
function setViewNow(){fly=null;const c=center();controls.target.copy(c);camera.position.copy(c.clone().add(VIEW_DIR.clone().setLength(viewDist())));}

/* ================= Theme ================= */
// Auto follows the system; Day and Night force it. Remembered in this browser only.
const THEME_KEY='strata-theme';
function setTheme(t,save){
  if(t==='light'||t==='dark')document.documentElement.dataset.theme=t;else delete document.documentElement.dataset.theme;
  document.querySelectorAll('[data-theme-set]').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.themeSet===(t||'auto'))));
  if(save){try{if(t==='light'||t==='dark')localStorage.setItem(THEME_KEY,t);else localStorage.removeItem(THEME_KEY);}catch(e){}}
}
setTheme(document.documentElement.dataset.theme||'auto',false);
$('#themeSeg').addEventListener('click',e=>{const b=e.target.closest('[data-theme-set]');if(b)setTheme(b.dataset.themeSet,true);});
document.addEventListener('keydown',e=>{if((e.key==='n'||e.key==='N')&&!e.ctrlKey&&!e.metaKey&&!e.altKey&&!/INPUT|TEXTAREA|SELECT/.test((e.target||{}).tagName||'')&&!e.target.isContentEditable){
  const dark=document.documentElement.dataset.theme?document.documentElement.dataset.theme==='dark':matchMedia('(prefers-color-scheme: dark)').matches;setTheme(dark?'light':'dark',true);}});
function rebuildTheme(){if(state.view==='overview'){buildOverview();refreshOverview();}else{buildScene();layout();refresh();}}
matchMedia('(prefers-color-scheme: dark)').addEventListener('change',rebuildTheme);
new MutationObserver(rebuildTheme).observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});

/* ================= Loop ================= */
function resize(){const w=innerWidth,h=innerHeight;renderer.setSize(w,h);camera.aspect=w/h;camera.updateProjectionMatrix();}
addEventListener('resize',resize);
const clock=new THREE.Clock();
function tick(){
  const dt=Math.min(clock.getDelta(),0.05);
  if(fly){const k=Math.min(1,(performance.now()-fly.t0)/fly.dur),e=k<.5?2*k*k:1-Math.pow(-2*k+2,2)/2;
    controls.target.lerpVectors(fly.fromT,fly.toT,e);camera.position.lerpVectors(fly.fromC,fly.toC,e);if(k>=1)fly=null;}
  if(!reduceMotion)ANIM.forEach(o=>{if(!o.tube.visible)return;o.parts.forEach(p=>{if(!p.visible)return;p.userData.t=(p.userData.t+dt*o.speed)%1;p.position.copy(o.curve.getPoint(p.userData.t));});});
  if(!(state.flat&&state.view==='site')){controls.update();if(!fly)keepInView();renderer.render(scene,camera);}requestAnimationFrame(tick);
}
function start(){
  resize();buildOverview();renderCart();syncUI();renderEmpty();setViewNow();tick();
  Store.init().then(()=>{renderCollab();if(Store.features.proposals)loadProposals();});
}
const ready=document.fonts&&document.fonts.ready?Promise.race([document.fonts.ready,new Promise(r=>setTimeout(r,1500))]):Promise.resolve();
ready.then(start,start);
})();

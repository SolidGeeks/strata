// SPDX-License-Identifier: AGPL-3.0-or-later
// The logs an asset must send to a SIEM so that its risks can be seen happening: log sources, the events in each
// and the threats of the catalogue in risk.js each event helps detect. For one asset, only the events of the
// threats that apply to it, at the verbosity its risks call for. Pure functions, no DOM: tested in Node.
(function(root){
'use strict';

/* ---- Verbosity ----
   1 minimal: authentication, privileges, changes, alerts; 2 standard: adds activity (processes, sessions,
   connections); 3 detailed: adds access to data and full content. A risk asks for the level of its residual
   risk: low 1, moderate 2, high and critical 3. */
const VERBOSITY=['','Minimal','Standard','Detailed'];
const NEED={low:1,med:2,high:3,crit:3};

const WIN=/windows/i,LINUX=/linux|debian|ubuntu|red ?hat|rhel|centos|suse|alma|rocky|fedora|alpine|amazon linux|oracle linux/i;
const HOST=['server','dc','db','hypervisor','workstation'];
// when: {types, os, notOs, role, ports, outbound, crit} : any condition met (os and notOs narrow types)
const SOURCES=[
  {id:'win-security',name:'Windows Security event log',transport:'Windows Event Forwarding or a SIEM agent',when:{types:['server','dc','db','workstation'],os:'windows'},
    settings:{1:'Advanced audit policy: Logon/Logoff, Account Management, Policy Change, Audit Policy Change, Security State Change (success and failure)',2:'Add Process Creation with the command line (Include command line in process creation events), Other Object Access (scheduled tasks), Security System Extension (services)',3:'Add Detailed File Share and File System auditing (SACL) on sensitive folders'},
    events:[
      {id:'logon',name:'Logons, successful and failed, with type and source',ref:'4624, 4625, 4634',v:1,threats:['brute-force','remote-access','lateral-admin','insider-misuse','default-credentials','third-party-access']},
      {id:'priv',name:'Explicit credentials and special privileges at logon',ref:'4648, 4672',v:2,threats:['lateral-admin','privilege-escalation','directory-takeover']},
      {id:'accounts',name:'Account and group changes (created, enabled, reset, added to a group)',ref:'4720, 4722, 4724, 4726, 4728, 4732, 4756',v:1,threats:['directory-takeover','privilege-escalation','insider-misuse']},
      {id:'process',name:'Process creation with the command line',ref:'4688',v:2,threats:['ransomware','exploit-public','known-exploited','lateral-admin','phishing','detection-blinding','end-of-life']},
      {id:'persist',name:'Services installed and scheduled tasks created',ref:'4697, 7045 (System), 4698',v:2,threats:['lateral-admin','ransomware','privilege-escalation']},
      {id:'tamper',name:'Audit log cleared, audit policy changed',ref:'1102, 4719',v:1,threats:['detection-blinding']},
      {id:'shares',name:'Network share access',ref:'5140, 5145',v:3,threats:['data-theft','ransomware','lateral-admin']},
      {id:'files',name:'Access to sensitive files and folders',ref:'4663',v:3,threats:['data-theft','insider-misuse','data-exposure']},
    ]},
  {id:'win-dc',name:'Domain controller (Active Directory)',transport:'Windows Event Forwarding or a SIEM agent',when:{types:['dc'],role:'domain controller|active directory|\\bad\\b|ldap'},
    settings:{1:'Audit Kerberos Authentication Service, Directory Service Changes, Account Lockout',2:'Add Kerberos Service Ticket Operations and Directory Service Access (with a SACL on the domain root for replication rights)',3:'Add Credential Validation on every DC and LDAP query logging (diagnostics 15 Field Engineering) during investigations'},
    events:[
      {id:'kerberos',name:'Kerberos tickets requested and pre-authentication failures',ref:'4768, 4769, 4771',v:2,threats:['directory-takeover','brute-force','lateral-admin']},
      {id:'dcsync',name:'Directory replication requested by a non-DC (DCSync)',ref:'4662 (replication GUIDs)',v:2,threats:['directory-takeover']},
      {id:'gpo',name:'Directory objects and group policies modified',ref:'5136, 5137, 5141',v:1,threats:['directory-takeover','privilege-escalation','ransomware']},
      {id:'lockout',name:'Account lockouts',ref:'4740',v:1,threats:['brute-force']},
    ]},
  {id:'powershell',name:'PowerShell logging',transport:'Windows Event Forwarding or a SIEM agent',when:{types:['server','dc','db','workstation'],os:'windows'},
    settings:{1:'Module logging for high-risk modules',2:'Script Block Logging on (Microsoft-Windows-PowerShell/Operational)',3:'Add transcription to a protected share'},
    events:[
      {id:'scriptblock',name:'PowerShell script blocks run',ref:'4104',v:2,threats:['phishing','lateral-admin','ransomware','detection-blinding','privilege-escalation']},
    ]},
  {id:'endpoint',name:'Endpoint telemetry (EDR or Sysmon)',transport:'EDR console export or a SIEM agent',when:{types:['server','dc','db','workstation']},
    settings:{1:'EDR alerts and tampering events',2:'Add process starts and network connections (Sysmon 1, 3 with a community configuration)',3:'Add file creation, registry run keys and DNS queries (Sysmon 11, 13, 22)'},
    events:[
      {id:'alerts',name:'EDR or antivirus detections, and protection turned off',ref:'EDR alerts',v:1,threats:['ransomware','phishing','exploit-public','known-exploited','detection-blinding','privilege-escalation']},
      {id:'proc-net',name:'Process starts and their network connections',ref:'Sysmon 1, 3',v:2,threats:['lateral-admin','ransomware','data-theft','exploit-public','known-exploited']},
      {id:'files',name:'Files created and autostart registry keys changed',ref:'Sysmon 11, 13',v:3,threats:['ransomware','privilege-escalation','phishing']},
      {id:'dns',name:'DNS queries per process',ref:'Sysmon 22',v:3,threats:['phishing','data-theft','supply-chain']},
    ]},
  {id:'linux',name:'Linux authentication and audit (auth.log, auditd)',transport:'rsyslog or journald to the SIEM over TLS',when:{types:['server','db','hypervisor','workstation'],os:'linux'},
    settings:{1:'auth and authpriv facilities forwarded: SSH, sudo, su, user and group changes',2:'Add auditd rules for execve by root and for changes to /etc/passwd, /etc/shadow, /etc/sudoers, cron and systemd units',3:'Add auditd file watches on data directories and every execve'},
    events:[
      {id:'ssh',name:'SSH logins accepted and failed, with source',ref:'sshd',v:1,threats:['brute-force','remote-access','lateral-admin','default-credentials','third-party-access']},
      {id:'sudo',name:'sudo and su, user and group changes',ref:'sudo, su, useradd, usermod',v:1,threats:['privilege-escalation','insider-misuse','directory-takeover']},
      {id:'exec',name:'Commands run as root, persistence (cron, systemd) changed',ref:'auditd execve, watches',v:2,threats:['ransomware','exploit-public','known-exploited','lateral-admin','privilege-escalation','end-of-life']},
      {id:'tamper',name:'Logging stopped or audit rules changed',ref:'auditd CONFIG_CHANGE, DAEMON_END',v:1,threats:['detection-blinding']},
      {id:'files',name:'Reads and writes on data directories',ref:'auditd watches',v:3,threats:['data-theft','insider-misuse','data-exposure']},
    ]},
  {id:'firewall',name:'Firewall and router logs',transport:'syslog over TLS, or the vendor\'s log forwarding',when:{types:['firewall','router']},
    settings:{1:'Denied traffic, administrator logins, configuration changes, IPS and threat alerts',2:'Add allowed sessions (start and end) on rules that cross zones or reach the Internet',3:'Add allowed sessions on every rule, with NAT details and bytes sent'},
    events:[
      {id:'deny',name:'Denied connections',ref:'traffic deny',v:1,threats:['exploit-public','lateral-admin','it-ot-pivot','ddos','third-party-access']},
      {id:'admin',name:'Administrator logins and configuration changes',ref:'system, config',v:1,threats:['network-device','default-credentials','detection-blinding','insider-misuse']},
      {id:'ips',name:'IPS, antivirus and threat-prevention alerts, DDoS protection',ref:'threat',v:1,threats:['exploit-public','known-exploited','ddos','web-app']},
      {id:'allow',name:'Allowed sessions between zones and to the Internet',ref:'traffic allow',v:2,threats:['data-theft','lateral-admin','supply-chain','it-ot-pivot','ransomware']},
    ]},
  {id:'vpn',name:'Remote access (VPN) logs',transport:'syslog over TLS, or the vendor\'s log forwarding',when:{types:['gateway'],role:'vpn|remote access|remote-access|citrix|bastion'},
    settings:{1:'Authentication successes and failures with user, source address and MFA result',2:'Add session start and end, assigned address, client posture',3:'Add the resources reached during each session'},
    events:[
      {id:'auth',name:'Authentications, successful and failed, with source address and MFA result',ref:'auth',v:1,threats:['remote-access','brute-force','third-party-access','known-exploited']},
      {id:'session',name:'Sessions: start, end, assigned address, client',ref:'session',v:2,threats:['remote-access','third-party-access','lateral-admin']},
      {id:'admin',name:'Administrator logins and configuration changes',ref:'system, config',v:1,threats:['network-device','known-exploited','detection-blinding']},
    ]},
  {id:'web',name:'Web server, reverse proxy or WAF logs',transport:'file collection by a SIEM agent, or syslog',when:{ports:['tcp/80','tcp/443','tcp/8080','tcp/8443','tcp/8000','tcp/8888'],role:'web|portal|site|api|intranet|extranet|proxy'},
    settings:{1:'Access log with client address, user, method, URL, status and size',2:'Add the error log, the response time and the X-Forwarded-For address',3:'Add WAF events with the matched rule and the request body of blocked requests'},
    events:[
      {id:'access',name:'Requests: client, user, method, URL, status',ref:'access log',v:1,threats:['web-app','exploit-public','defacement','brute-force','known-exploited','ddos']},
      {id:'error',name:'Server errors and application exceptions',ref:'error log',v:2,threats:['web-app','exploit-public']},
      {id:'waf',name:'WAF detections and blocked requests',ref:'WAF',v:3,threats:['web-app','exploit-public','data-exposure']},
    ]},
  {id:'database',name:'Database audit',transport:'native audit to syslog, or a SIEM agent',when:{types:['db'],role:'database|\\bdb\\b|sql|oracle|postgres|mysql|mariadb|mongo'},
    settings:{1:'Logins successful and failed, privileged account use',2:'Add DDL, GRANT and REVOKE, changes to users and audit settings',3:'Add SELECT on sensitive tables, exports and bulk reads'},
    events:[
      {id:'logins',name:'Logins, successful and failed',ref:'audit logon',v:1,threats:['brute-force','default-credentials','insider-misuse','lateral-admin']},
      {id:'ddl',name:'Schema changes, rights granted or revoked, audit changed',ref:'DDL, GRANT, REVOKE',v:2,threats:['privilege-escalation','insider-misuse','detection-blinding','ransomware']},
      {id:'reads',name:'Reads and exports of sensitive tables',ref:'SELECT audit, exports',v:3,threats:['data-theft','data-exposure','insider-misuse']},
    ]},
  {id:'hypervisor',name:'Hypervisor and virtualisation manager (vCenter, ESXi, Hyper-V)',transport:'syslog over TLS from the hosts and the manager',when:{types:['hypervisor'],role:'vcenter|esxi|hyper-v|proxmox|nutanix|virtuali'},
    settings:{1:'Logins, shell or SSH turned on, virtual machines powered off or deleted, datastores deleted',2:'Add every task and event of the manager (vpxd events), host configuration changes',3:'Add the hosts\' shell command history and API calls'},
    events:[
      {id:'logins',name:'Logins to the manager and to the hosts',ref:'auth, vpxd',v:1,threats:['hypervisor-mass','lateral-admin','default-credentials','known-exploited']},
      {id:'destroy',name:'Virtual machines powered off or deleted, snapshots and datastores deleted',ref:'VmPoweredOff, VmRemoved, snapshot, datastore events',v:1,threats:['hypervisor-mass','ransomware','backup-destruction']},
      {id:'shell',name:'Shell or SSH turned on, lockdown mode turned off',ref:'host configuration',v:1,threats:['hypervisor-mass','privilege-escalation']},
      {id:'config',name:'Every task and configuration change',ref:'tasks and events',v:2,threats:['hypervisor-mass','insider-misuse','detection-blinding']},
    ]},
  {id:'backup',name:'Backup software',transport:'syslog, or the vendor\'s SIEM integration',when:{role:'backup|veeam|commvault|rubrik|cohesity|netbackup'},
    settings:{1:'Job failures, restore points deleted, retention and immutability changed, administrator logins',2:'Add every job, restore and configuration change',3:'Add the files restored and by whom'},
    events:[
      {id:'destroy',name:'Restore points deleted, retention or immutability changed',ref:'backup audit',v:1,threats:['backup-destruction','ransomware','insider-misuse']},
      {id:'jobs',name:'Backup jobs failed or skipped',ref:'job status',v:1,threats:['backup-destruction','ransomware']},
      {id:'restores',name:'Restores, and who ran them',ref:'restore audit',v:3,threats:['data-theft','insider-misuse']},
    ]},
  {id:'mail',name:'Mail gateway and mailboxes',transport:'the gateway\'s syslog or API, the mail service\'s audit log',when:{role:'mail|smtp|exchange|messag|relay'},
    settings:{1:'Messages blocked and delivered with sender, recipient and verdict; mailbox logins',2:'Add inbox rules and forwarding created, delegations, attachments and links clicked',3:'Add message tracking for every message'},
    events:[
      {id:'verdict',name:'Messages and their verdict (spam, phishing, malware)',ref:'message tracking',v:1,threats:['phishing','bec']},
      {id:'logins',name:'Mailbox logins, with source address',ref:'mailbox audit',v:1,threats:['bec','brute-force']},
      {id:'rules',name:'Forwarding and inbox rules created, delegations given',ref:'mailbox audit',v:2,threats:['bec','data-theft']},
    ]},
  {id:'network-device',name:'Switch, Wi-Fi and network device logs',transport:'syslog over TLS, SNMP traps',when:{types:['switch','ap','router']},
    settings:{1:'Administrator logins and configuration changes',2:'Add port and link changes, Wi-Fi client authentication failures, rogue access points',3:'Add every Wi-Fi association and 802.1X authentication'},
    events:[
      {id:'admin',name:'Administrator logins and configuration changes',ref:'AAA, config',v:1,threats:['network-device','default-credentials','device-takeover']},
      {id:'ports',name:'Ports up and down, new devices on a port',ref:'link, port-security',v:2,threats:['physical-access','lateral-admin']},
      {id:'wifi',name:'Wi-Fi authentication failures and rogue access points',ref:'WIDS, 802.1X',v:2,threats:['wifi-intrusion','brute-force']},
    ]},
  {id:'ot',name:'Industrial control (PLC, SCADA, historian)',transport:'OT monitoring probe or the engineering station\'s logs',when:{types:['plc'],role:'hmi|scada|supervision|plc|automate|historian'},
    settings:{1:'Program downloads and uploads, mode changes (run, program, stop), engineering logins',2:'Add setpoint and parameter writes, new devices talking on the OT network',3:'Add every control command seen by a passive OT probe'},
    events:[
      {id:'program',name:'Programs downloaded or uploaded, mode changes',ref:'engineering events',v:1,threats:['ot-manipulation','it-ot-pivot']},
      {id:'logins',name:'Engineering and HMI logins',ref:'HMI, engineering station',v:1,threats:['ot-manipulation','default-credentials','it-ot-pivot']},
      {id:'writes',name:'Setpoint and parameter writes, new devices on the OT network',ref:'OT probe',v:2,threats:['ot-manipulation','it-ot-pivot']},
    ]},
  {id:'device',name:'Device logs (cameras, printers, phones, IoT)',transport:'syslog',when:{types:['camera','printer','phone','iot']},
    settings:{1:'Administrator logins, successful and failed; configuration and firmware changes',2:'Add connections to and from the device',3:'Add every request to its web interface'},
    events:[
      {id:'admin',name:'Administrator logins, configuration and firmware changes',ref:'syslog',v:1,threats:['device-takeover','default-credentials']},
      {id:'conn',name:'Connections to and from the device',ref:'syslog, NetFlow',v:2,threats:['device-takeover','lateral-admin']},
    ]},
  {id:'egress',name:'DNS and web proxy logs for this asset',transport:'the DNS resolver and the proxy, to the SIEM',when:{outbound:true},
    settings:{1:'Blocked requests and threat-intelligence matches',2:'Add every DNS query and every proxied request of this asset',3:'Add the bytes sent per request'},
    events:[
      {id:'blocked',name:'Domains and URLs blocked, threat-intelligence matches',ref:'DNS, proxy',v:1,threats:['phishing','ransomware','supply-chain']},
      {id:'queries',name:'DNS queries and web requests',ref:'DNS, proxy',v:2,threats:['phishing','data-theft','supply-chain','ransomware']},
      {id:'volume',name:'Volume sent per destination',ref:'proxy',v:3,threats:['data-theft']},
    ]},
  {id:'availability',name:'Availability monitoring',transport:'the monitoring tool, alerts to the SIEM',when:{crit:3,outbound:true},
    settings:{1:'Service and link down, response time over threshold',2:'Add capacity alerts (bandwidth, sessions)',3:'Add per-minute metrics'},
    events:[
      {id:'down',name:'Service or Internet link down, response time over threshold',ref:'checks',v:1,threats:['ddos','internet-dependency']},
    ]},
  {id:'physical',name:'Physical access control',transport:'the badge system\'s export',when:{types:['server','dc','db','hypervisor','firewall','router','switch'],crit:3},
    settings:{1:'Badge access to the room or rack holding the asset, refused badges',2:'Add door forced or held open',3:'Add camera recordings referenced by time'},
    events:[
      {id:'badge',name:'Badge access and refusals at the room or rack',ref:'access control',v:1,threats:['physical-access']},
    ]},
  {id:'siem-health',name:'Log source health (on the SIEM side)',transport:'a rule in the SIEM',when:{always:true},
    settings:{1:'Alert when this asset sends nothing for longer than its usual gap',2:'Add the expected volume per source',3:'Add an alert on any drop of volume'},
    events:[
      {id:'silence',name:'No log received from the asset',ref:'SIEM rule',v:1,threats:['detection-blinding','ransomware']},
    ]},
];

const re=s=>{try{return new RegExp(s,'i');}catch(e){return null;}};
// Whether a log source exists on an asset
function applies(src,a,ctx){
  const w=src.when||{},os=String(a.os||'');
  if(w.always)return true;
  if(w.os==='windows'&&!(WIN.test(os)||a.type==='dc'))return false;
  if(w.os==='linux'&&!LINUX.test(os))return false;
  const hits=[];
  if(w.types)hits.push(w.types.includes(a.type));
  if(w.role){const r=re(w.role);hits.push(!!r&&r.test(`${a.role||''} ${a.name||''}`));}
  if(w.ports)hits.push((a.ports||[]).some(p=>w.ports.includes(p.port)));
  if(w.outbound)hits.push(!!(ctx&&ctx.outbound));
  if(w.crit)hits.push(Math.max(+a.crit||0,+(ctx&&ctx.bizCrit)||0)>=w.crit);
  // crit narrows the others when both are given
  if(w.crit&&(w.types||w.outbound)){const c=hits.pop();return c&&hits.some(Boolean);}
  return hits.some(Boolean);
}
// The minimum logs of one asset. risks: its rows from StrataRisk.assess (excluded ones are ignored).
// ctx: {outbound, bizCrit}. Returns {sources: [{source, level, settings, events: [{event, risks}]}], uncovered: [risk], retention}
function forAsset(a,risks,ctx){
  const rows=(risks||[]).filter(r=>!r.excluded),need=r=>NEED[r.residual.level]||1,out=[];
  const covered=new Set();
  SOURCES.forEach(src=>{
    if(!applies(src,a,ctx))return;
    const evs=[];
    src.events.forEach(ev=>{
      const hit=rows.filter(r=>ev.threats.includes(r.threat.id)&&need(r)>=ev.v);
      if(hit.length){evs.push({event:ev,risks:hit});hit.forEach(r=>covered.add(r.threat.id));}
    });
    if(evs.length){const level=Math.max(...evs.map(e=>e.event.v));out.push({source:src,level,label:VERBOSITY[level],settings:src.settings[level],events:evs});}
  });
  const worst=rows.reduce((m,r)=>Math.max(m,need(r)),0);
  return {sources:out,uncovered:rows.filter(r=>!covered.has(r.threat.id)),
    // ANSSI recommends keeping logs at least 6 months; a year where a high or critical risk stays
    retention:worst>=3?12:6,events:out.reduce((n,s)=>n+s.events.length,0)};
}

const api={VERBOSITY,SOURCES,applies,forAsset};
root.StrataLogs=api;
})(typeof globalThis!=='undefined'?globalThis:this);

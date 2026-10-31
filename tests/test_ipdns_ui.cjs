const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync('web/ipdns.js','utf8');const ctx=vm.createContext({esc:v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])),console});vm.runInContext(source,ctx);
test('monitor cards show selected VPS only, scoped controls and old IP',()=>{const html=ctx.monitorMarkup({monitors:[{server_id:7,name:'CMHK',enabled:1,current_ip:'1.1.1.1',previous_ip:'8.8.8.8',port:443,status:'ready'}],bindings:[{automatic:1,server_id:7}],servers:[{id:7},{id:8}]});assert.match(html,/CMHK/);assert.match(html,/8\.8\.8\.8/);for(const action of ['check','config','bind','history','remove'])assert.match(html,new RegExp('data-monitor-'+action+'="7"'));assert.doesNotMatch(html,/data-monitor-check="8"/);});
test('empty state invites explicit VPS selection and escapes node names',()=>{assert.match(ctx.monitorMarkup({monitors:[],bindings:[]}),/尚未选择 VPS/);assert.match(ctx.monitorMarkup({monitors:[{server_id:1,name:'<script>',enabled:0,port:443}],bindings:[]}),/&lt;script&gt;/);});
test('DNS line labels distinguish common carriers and retain unknown API line codes',()=>{assert.equal(ctx.dnsLineLabel('telecom'),'电信（telecom）');assert.equal(ctx.dnsLineLabel('mobile'),'移动（mobile）');assert.equal(ctx.dnsLineLabel('custom-line'),'线路（custom-line）');});
test('quick DNS setup renders carrier records as individually selectable checkboxes',()=>{const html=ctx.quickRecordChoicesMarkup([{RecordId:'1',RR:'edge',Line:'telecom',Value:'1.2.3.4'},{RecordId:'2',RR:'edge',Line:'unicom',Value:'1.2.3.4'}],'example.com');assert.equal((html.match(/type="checkbox"/g)||[]).length,2);assert.match(html,/电信（telecom）/);assert.match(html,/联通（unicom）/);assert.match(html,/edge\.example\.com/);});
test('quick DNS choices escape record data before rendering',()=>{const html=ctx.quickRecordChoicesMarkup([{RecordId:'1',RR:'<img>',Line:'custom',Value:'1.2.3.4'}],'example.com');assert.match(html,/&lt;img&gt;/);assert.doesNotMatch(html,/<img>/);});

test('monitor result renders node states, old IP warning and escaped action details',()=>{const html=ctx.monitorDetectionMarkup({source_name:'<probe>',automatic:true,current_ip:'1.1.1.1',source_enabled:true,run:{status:'部分检测点 TCP 不通',updated:1700000000,ip:'8.8.8.8',port:443,details:[{name:'电信',state:'reachable',latency_ms:12},{name:'移动',state:'unreachable'}],action_result:'<script>'}},{current_ip:'1.1.1.1'});assert.match(html,/电信：可达 12 ms/);assert.match(html,/移动：不通/);assert.match(html,/针对旧 IP 或端口/);assert.match(html,/&lt;probe&gt;/);assert.doesNotMatch(html,/<script>/);});
test('pending and unconfigured monitor states do not claim reachability',()=>{assert.match(ctx.monitorDetectionMarkup(null,{}),/尚未配置/);const html=ctx.monitorDetectionMarkup({source_name:'BOCE',source_enabled:true,run:{status:'pending',ip:'8.8.8.8',port:443,details:[]}},{current_ip:'8.8.8.8'});assert.match(html,/检测中，等待节点结果/);assert.doesNotMatch(html,/probe-reachable/);});

test('BOCE card distinguishes reachable, failed and partial carrier results',()=>{const render=states=>ctx.monitorDetectionMarkup({source_kind:'boce',source_name:'BOCE',source_enabled:true,run:{status:'完成',ip:'8.8.8.8',port:443,details:states.map(state=>({state,name:'节点'}))}},{});assert.match(render(['reachable','reachable']),/BOCE 国内探测：国内可达/);assert.match(render(['unreachable','unreachable']),/国内不通（疑似被墙）/);assert.match(render(['reachable','unreachable']),/部分线路不通/);});

test('each configured machine exposes its own action switch',()=>{const render=enabled=>ctx.monitorDetectionMarkup({server_id:7,source_kind:'boce',source_name:'BOCE',response_mode:'change_api',action_enabled:enabled,source_enabled:true},{});assert.match(render(false),/data-action-toggle="7"/);assert.match(render(false),/aria-checked="false"/);assert.match(render(false),/已暂停 · 点击开启/);assert.match(render(true),/已开启 · 点击暂停/);});

test('admin rotation insights expose scoped token generation, copy and revoke',()=>{
 const html=ctx.adminRotationInsightsMarkup([{rotation_id:4,servers:[1,2],ip_lifetimes:{observed_episodes:0,censored:0},dns:{trials:0,trials_without_observations:0,observed_stable:{p95_s:null}},recovery:{completed:{p95_s:null}},recommendation:{ready:false,reasons:['<pending>']}}],[{id:1,name:'<node>'},{id:2,name:'B'}]);
 for(const name of ['data-admin-analysis-generate="4"','data-admin-analysis-copy="4"','data-admin-analysis-revoke="4"','无需切换客户账号'])assert.ok(html.includes(name),name);
 assert.match(html,/&lt;node&gt;/);assert.match(html,/&lt;pending&gt;/);assert.doesNotMatch(html,/<node>/);
 assert.match(ctx.adminRotationInsightsMarkup([],[]),/尚无轮换任务/);
});

test('admin rotation manager renders creation and complete lifecycle controls',()=>{
 const html=ctx.adminRotationsMarkup({rotations:[{id:5,primary_name:'<A>',other_name:'B',owner_role:'admin',enabled:1,active_name:'B',interval_s:3000,lead_s:120,offline_after_s:15,status:'ready'}]});
 for(const text of ['创建双 VPS 轮换','data-rotation-edit="5"','data-rotation-toggle="5"','data-rotation-delete="5"','后台计划'])assert.ok(html.includes(text),text);
 assert.match(html,/&lt;A&gt;/);assert.match(ctx.adminRotationsMarkup({rotations:[]}),/尚无轮换任务/);
});

test('rotation DNS picker lists record identity and carrier lines separately',()=>{
 const html=ctx.adminRotationRecordOptions([{RecordId:'a',RR:'@',Line:'cmcc',Value:'8.8.8.8'},{RecordId:'b',RR:'edge',Line:'telecom',Value:'1.1.1.1'}],'example.com');
 assert.match(html,/example.com · 移动（cmcc） · 8.8.8.8 · #a/);
 assert.match(html,/edge.example.com · 电信（telecom） · 1.1.1.1 · #b/);
 const escaped=ctx.adminRotationRecordOptions([{RecordId:'<id>',RR:'<rr>',Line:'<line>',Value:'<ip>'}],'example.com');
 assert.doesNotMatch(escaped,/<rr>/);assert.match(escaped,/&lt;rr&gt;/);
});

test('admin DNS picker runs connection, domain, record and local-binding flow',async()=>{
 const fields={dns_connection_id:{value:'3'},rotation_domain:{value:''},rotation_record:{value:''},binding_id:{value:''},primary_server_id:{value:'7'}};
 const elements={loadRotationDnsRecords:{},chooseRotationDnsRecord:{},rotationDnsPickerStatus:{},rotationDnsDomains:{}};
 ctx.$=id=>elements[id];const calls=[];ctx.api=async(path,method,body)=>{calls.push({path,method,body});if(path.endsWith('/domains'))return {domains:['example.com']};if(path.endsWith('/records'))return {domain:'example.com',records:[{RecordId:'r1',RR:'edge',Line:'cmcc',Value:'8.8.8.8'}]};return {binding:{id:12,server_id:7,rr:'edge',domain:'example.com',line:'cmcc',expected_ip:'8.8.8.8',credential_owner:null},message:'仅保存面板绑定'};};
 const data={bindings:[]};let refreshed=0;ctx.bindAdminRotationDNSPicker(data,fields,()=>refreshed++);
 await fields.dns_connection_id.onchange();assert.equal(fields.rotation_domain.value,'example.com');assert.match(fields.rotation_record.innerHTML,/cmcc/);
 fields.rotation_record.value='0';fields.rotation_record.onchange();assert.equal(elements.chooseRotationDnsRecord.disabled,false);
 await elements.chooseRotationDnsRecord.onclick();assert.equal(fields.binding_id.value,'12');assert.equal(refreshed,1);assert.equal(data.bindings.length,1);
 assert.equal(calls[2].path,'admin/servers/7/rotation/dns-binding');assert.equal(calls[2].body.record_id,'r1');
});

test('domain-list permission failure permits manually entering an authorized domain',async()=>{
 const fields={dns_connection_id:{value:'3'},rotation_domain:{value:''},rotation_record:{value:''},binding_id:{value:''},primary_server_id:{value:'7'}};
 const elements={loadRotationDnsRecords:{},chooseRotationDnsRecord:{},rotationDnsPickerStatus:{},rotationDnsDomains:{}};
 ctx.$=id=>elements[id];ctx.api=async path=>{if(path.endsWith('/domains'))throw Error('denied');return {domain:'example.com',records:[]};};
 ctx.bindAdminRotationDNSPicker({bindings:[]},fields,()=>{});await fields.dns_connection_id.onchange();assert.match(elements.rotationDnsPickerStatus.textContent,/手动输入/);
 fields.rotation_domain.value='example.com';fields.rotation_domain.oninput();await elements.loadRotationDnsRecords.onclick();assert.match(elements.rotationDnsPickerStatus.textContent,/0 条/);assert.equal(elements.chooseRotationDnsRecord.disabled,true);
});

test('rotation status distinguishes pause recovery overdue and escapes history',()=>{
 const r={enabled:1,phase:'active',next_switch_at:1,active_name:'<A>',status:'<pending>'};
 assert.match(ctx.rotationLiveMarkup(r),/已到计划时间/);assert.match(ctx.rotationLiveMarkup(r),/&lt;pending&gt;/);
 assert.match(ctx.rotationLiveMarkup({...r,enabled:0}),/已暂停/);
 assert.match(ctx.rotationLiveMarkup({...r,phase:'waiting_ip'}),/等待新 IP/);
 assert.match(ctx.rotationHistoryMarkup({events:[{message:'<bad>',created:1,server_id:2}]}),/&lt;bad&gt;/);
 assert.match(ctx.rotationHistoryMarkup({}),/暂无轮换记录/);
});

test('live rotation status shows C failover and freezes timer instead of claiming A serves',()=>{
 const html=ctx.rotationLiveMarkup({phase:'active',mode:'fixed_primary',primary_server_id:1,active_server_id:1,active_name:'C（故障转移）',enabled:1,next_switch_at:2000000000,failover_leases:[{binding_id:3}],status:'A 下线，全部解析接替'});
 assert.match(html,/A 故障转移接替中/);assert.match(html,/故障接替期间暂停定时轮换/);assert.match(html,/C（故障转移）/);
});

test('admin rotation form prechecks and saves the selected telecom record without switching lines',async()=>{
 const appSource=fs.readFileSync('web/app.js','utf8');
 vm.runInContext(appSource.match(/function rotationModeFields\([\s\S]*?\n}/)[0],ctx);
 vm.runInContext(appSource.match(/function rotationModePayload\([^\n]+/)[0],ctx);
 const form={mode:{value:'fixed_primary'},takeover_minutes:{value:'10'},first_switch:{value:''},mobile_only_ack:{checked:true},failover_server_id:{value:''},failover_recovery_s:{value:'60'},primary_server_id:{value:'1'},other_server_id:{value:'2'},binding_id:{value:'12'},interval_minutes:{value:'120'},lead_minutes:{value:'2'},offline_after_s:{value:'15'},connection_threshold:{value:'80'},enabled:{checked:true}};
 const elements={adminRotationForm:form,backAdminRotations:{},checkAdminRotation:{},adminRotationChecks:{},adminRotationError:{}};
 let html='',refreshed=0;const calls=[];
 ctx.$=id=>elements[id];ctx.modal=value=>{html=value;};ctx.bindFailoverChoices=()=>{};ctx.notice=()=>{};ctx.loadAdminRotations=async()=>{refreshed++;};
 ctx.api=async(path,method,body)=>{calls.push({path,method,body});return {checks:[{ok:true,name:'线路',message:'telecom'}],recommended_lead_s:660};};
 ctx.editAdminRotation({servers:[{id:1,name:'A'},{id:2,name:'B'}],bindings:[{id:11,server_id:1,rr:'edge',domain:'example.com',line:'mobile',expected_ip:'8.8.8.8',credential_owner:null},{id:12,server_id:1,rr:'edge',domain:'example.com',line:'telecom',expected_ip:'8.8.8.8',credential_owner:null}]},null);
 assert.match(html,/固定主机＋定时线路轮换/);assert.match(form.binding_id.innerHTML,/电信（telecom）/);
 await elements.checkAdminRotation.onclick();assert.equal(calls[0].path,'admin/servers/1/rotation/readiness');assert.equal(calls[0].body.binding_id,12);
 const submitter={disabled:false};await form.onsubmit({preventDefault(){},submitter});
 assert.equal(calls[1].method,'PUT');assert.equal(calls[1].body.binding_id,12);assert.equal(calls[1].body.mode,'fixed_primary');assert.equal(calls[1].body.interval_s,7200);assert.equal(refreshed,1);assert.equal(submitter.disabled,false);
});

test('admin lifecycle buttons submit pause resume delete and recover after a failed delete',async()=>{
 // Fresh VM avoids replacing the form test's loader.
 const env=vm.createContext({esc:ctx.esc,console});vm.runInContext(source,env);
 const r={id:5,primary_server_id:1,other_server_id:2,binding_id:12,primary_name:'A',other_name:'B',active_name:'B',mode:'fixed_primary',enabled:1,interval_s:7200,lead_s:0,offline_after_s:15,connection_threshold:80,events:[]};
 const buttons=['edit','toggle','delete'].map(name=>({dataset:{['rotation'+name[0].toUpperCase()+name.slice(1)]:String(r.id)},name}));
 const message={};let rejectDelete=true,removed=false;const calls=[];
 env.document={querySelectorAll(selector){return buttons.filter(b=>selector.includes('-'+b.name+']'));}};
 env.$=()=>message;env.modal=()=>{};env.startAdminRotationLive=()=>{};env.confirm=()=>true;
 env.api=async(path,method,body)=>{calls.push({path,method,body});if(path==='admin/rotations')return {rotations:removed?[]:[r]};if(method==='PUT'){r.enabled=body.enabled;return {};}if(method==='DELETE'){if(rejectDelete)throw Error('轮换动作正在提交，请稍后重试删除');removed=true;return {};}};
 await env.loadAdminRotations();await buttons[1].onclick();assert.equal(r.enabled,false);
 await buttons[1].onclick();assert.equal(r.enabled,true);
 await buttons[1].onclick();assert.equal(r.enabled,false);
 await buttons[2].onclick();assert.match(message.textContent,/稍后重试/);assert.equal(buttons[2].disabled,false);
 rejectDelete=false;await buttons[2].onclick();assert.equal(removed,true);
 assert.equal(calls.filter(c=>c.method==='PUT').length,3);assert.equal(calls.filter(c=>c.method==='DELETE').length,2);
});

test('HKT DHCP form generates scoped API without executing DHCP and shows results',async()=>{
 const elements={hktEnableCommand:{},hktDHCPMessage:{},hktDHCPAPI:{},hktDHCPResult:{},hktDHCPStatus:{},hktDHCPForm:{server_id:{value:'7'}}};let html='';const calls=[];
 ctx.$=id=>elements[id];ctx.location={origin:'https://panel.example.com'};ctx.modal=v=>{html=v;};
 ctx.api=async(path,method)=>{calls.push({path,method});return path.endsWith('/status')?{job:{id:1,status:'failed'},result:{state:'unchanged'}}:{path:'/api/hkt-dhcp/7',token:'dummy-scope-token',connection_id:12,message:'仅生成 API'};};
 ctx.hktDHCPForm([{id:7,name:'HKT <node>'}],7);
 assert.match(html,/HKT &lt;node&gt;/);assert.match(elements.hktEnableCommand.textContent,/agent-update.sh/);assert.match(elements.hktEnableCommand.textContent,/ens18/);
 const button={disabled:false};await elements.hktDHCPForm.onsubmit({preventDefault(){},submitter:button});
 assert.equal(calls[0].path,'admin/servers/7/hkt-dhcp/api');assert.equal(button.disabled,false);assert.match(elements.hktDHCPAPI.textContent,/Authorization: Bearer dummy-scope-token/);
 await elements.hktDHCPStatus.onclick();assert.match(elements.hktDHCPResult.textContent,/unchanged/);
 assert.ok(calls.every(x=>x.path.startsWith('admin/')));
});

test('unified change-IP entry routes MoonVM generic and HKT to their respective setup',()=>{
 const env=vm.createContext({esc:ctx.esc,console});vm.runInContext(source,env);
 const form={},calls=[];let html='';env.$=()=>form;env.modal=x=>{html=x;};env.editIPConnection=(...args)=>calls.push(args);env.hktDHCPForm=()=>calls.push(['hkt']);
 env.chooseChangeIPAPI();for(const value of ['moonvm','agent_dhcp','generic'])assert.match(html,new RegExp('value="'+value+'"'));
 for(const provider of ['moonvm','generic','agent_dhcp'])form.onsubmit({preventDefault(){},target:{provider:{value:provider}}});
 assert.deepEqual(calls,[[null,'change_ip','moonvm'],[null,'change_ip','generic'],['hkt']]);
});

test('generic API editor saves GET and parameter-only auth without sending an action',async()=>{
 const env=vm.createContext({esc:ctx.esc,console,FormData:class{constructor(form){return new Map(Object.entries(form.values));}}});vm.runInContext(source,env);
 const fields={ipAPIForm:{},ipAPIError:{},modal:{close(){}}};const calls=[];let html='';env.$=id=>fields[id];env.modal=x=>{html=x;};env.notice=()=>{};env.loadIPDNS=async()=>{};env.api=async(...args)=>{calls.push(args);return {id:1};};
 env.editIPConnection(null,'change_ip','generic');assert.match(html,/name="method"/);assert.match(html,/name="success_path"/);assert.match(html,/name="auth_mode"/);assert.doesNotMatch(html,/MoonVM API 完整链接/);
 const submitter={disabled:false};await fields.ipAPIForm.onsubmit({preventDefault(){},submitter,target:{values:{name:'custom',method:'GET',auth_mode:'none',url:'https://provider.example/change?key={{api_token}}',header:'Authorization',prefix:'Bearer ',secret:'dummy',body_json:'{}',success_path:'code',success_json:'0'}}});
 assert.equal(calls.length,1);assert.equal(calls[0][0],'ip-dns/connections');assert.equal(calls[0][2].config.method,'GET');assert.equal(calls[0][2].config.header,'');assert.equal(calls[0][2].config.success_path,'code');assert.equal(submitter.disabled,false);
});

test('per-server failover editor saves numeric settings and preserves failures for review',async()=>{
 const elements={serverFailoverForm:{elements:{backup_id:{value:'9'},offline_s:{value:'30'},recovery_s:{value:'60'}}},serverFailoverError:{},modal:{close(){this.closed=true;}}};
 let html='',calls=[];ctx.$=id=>elements[id];ctx.modal=value=>{html=value;};ctx.notice=()=>{};
 ctx.api=async(path,method,body)=>{calls.push({path,method,body});if(method==='PUT')return {ok:true};return {config:{backup_id:9,status:'<waiting>'},servers:[{id:9,name:'<backup>'}]};};
 await ctx.editServerFailover(7);assert.match(html,/&lt;backup&gt;/);assert.match(html,/&lt;waiting&gt;/);assert.match(html,/待命时不拨测/);assert.match(html,/多台主机可共享同一备用机/);assert.doesNotMatch(html,/只能分配给一个主机/);
 const submitter={disabled:false};await elements.serverFailoverForm.onsubmit({preventDefault(){},submitter,target:elements.serverFailoverForm});
 assert.equal(calls[1].path,'servers/7/failover');assert.deepEqual(JSON.parse(JSON.stringify(calls[1].body)),{backup_id:9,offline_s:30,recovery_s:60});assert.equal(elements.modal.closed,true);assert.equal(submitter.disabled,false);
 ctx.api=async(path,method)=>{if(method==='PUT')throw Error('解析尚由备用机承载');return {config:null,servers:[]};};elements.modal.closed=false;
 await ctx.editServerFailover(7);await elements.serverFailoverForm.onsubmit({preventDefault(){},submitter,target:elements.serverFailoverForm});assert.match(elements.serverFailoverError.textContent,/尚由备用机承载/);assert.equal(elements.modal.closed,false);assert.equal(submitter.disabled,false);
});

test('existing A standby redirects to rotation configuration without creating another policy',async()=>{
 let html='',calls=0;ctx.modal=value=>{html=value;};ctx.api=async()=>{calls++;return {rotation_failover:{failover_server_id:9,failover_status:'<active>'},servers:[]};};
 await ctx.editServerFailover(7);assert.equal(calls,1);assert.match(html,/轮换设置|配置中管理/);assert.match(html,/&lt;active&gt;/);assert.doesNotMatch(html,/serverFailoverForm/);
});

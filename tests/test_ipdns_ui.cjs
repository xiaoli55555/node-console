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

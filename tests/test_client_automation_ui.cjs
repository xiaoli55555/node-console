const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync('web/app.js','utf8');
const match=source.match(/function customerDnsSection\([\s\S]*?\n}/);
const statusMatch=source.match(/function clientProbeStatusMarkup\([\s\S]*?\n}/);
assert.ok(match,'customer settings renderer exists');
assert.ok(statusMatch,'customer probe status renderer exists');
const ctx=vm.createContext({esc:v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))});
vm.runInContext(source.match(/function rotationModeFields\([\s\S]*?\n}/)[0]+'\n'+statusMatch[0]+'\n'+match[0],ctx);

test('customer VPS settings expose BOCE, AliDNS, Cloudflare, MoonVM, port and recovery controls',()=>{
 const html=ctx.customerDnsSection({sources:[],plan:{response_mode:'change_api',action_enabled:true},monitor:{port:23456,enabled:true}},[],7,[{id:2,name:'My AliDNS',kind:'alidns',access_key_id:'key-id'},{id:3,name:'MoonVM product 9',kind:'change_ip'}]);
 for(const text of ['clientProbeStatus','clientProbeForm','BOCE API Key','业务 TCP 检测端口','clientActionForm','通过面板重启 VPS','MoonVM 换 IP API','AccessKey ID','AccessKey Secret','Cloudflare DNS','Cloudflare API Token','Zone Read、DNS Read、DNS Write','验证凭据并读取 A 记录','保存后开启这条记录自动解析'])assert.ok(html.includes(text),text);
 assert.match(html,/value="23456"/);
 assert.match(html,/option value="personal" selected>客户自有 BOCE（使用自己的 Key）/);
 assert.match(html,/验证并保存 Key/);
 assert.match(html,/客户自有 BOCE 并验证 Key 后加载节点/);
});

test('customers with a saved personal BOCE source can still choose to replace or revalidate their own key',()=>{
 const html=ctx.customerDnsSection({sources:[{id:19,name:'客户自有 BOCE',personal:true}],plan:{source_id:19},monitor:{port:443,enabled:true}},[],7,[]);
 assert.match(html,/option value="personal" >客户自有 BOCE（使用自己的 Key）/);
 assert.match(html,/option value="19" selected>客户自有 BOCE/);
 assert.match(html,/已保存个人 Key；留空不修改/);
});

test('customer Cloudflare connection uses a selectable DNS provider and explains proxied records',()=>{
 const html=ctx.customerDnsSection({sources:[],plan:{},monitor:{port:443,enabled:true}},[{id:8,rr:'edge',domain:'example.com',line:'default',expected_ip:'8.8.8.8',dns_provider:'cloudflare',customer_owned:true}],7,[{id:2,name:'My Cloudflare',kind:'cloudflare',zone_name:'example.com'}]);
 assert.match(html,/value="cloudflare" selected/);
 assert.match(html,/已绑定解析记录/);
 assert.match(html,/Cloudflare DNS/);
});

test('admin-owned active automation renders locked instructions for customers',()=>{
 const html=ctx.customerDnsSection({plan:{actions_locked:true,automatic:true},monitor:{port:443,enabled:true}},[],7,[]);
 assert.match(html,/管理员正在管理这台 VPS 的自动策略/);
 assert.doesNotMatch(html,/<form id="clientActionForm"/);
 assert.match(html,/clientPauseProbe/);
});

test('customer rotation setup exposes paired VPS, DNS record, interval and strict TCP threshold',()=>{
 const html=ctx.customerDnsSection({plan:{},monitor:{port:23456,enabled:true}},[{id:11,rr:'edge',domain:'example.com',line:'default',expected_ip:'8.8.8.8',dns_provider:'cloudflare',customer_owned:true}],7,[],{rotation:null},[{id:8,name:'standby-vps'}]);
 for(const text of ['双 VPS 定时轮换','standby-vps','计划承载周期（分钟）','旧机连接数触发阈值（严格低于）','80','开启定时轮换','BOCE 复检'])assert.ok(html.includes(text),text);
 assert.match(html,/name="interval_minutes"[^>]*value="120"/);
 assert.match(html,/name="binding_id"/);
});

test('rotation analytics provide measurement and scoped integration controls',()=>{
 const html=ctx.customerDnsSection({plan:{},monitor:{port:443}},[],7,[],{rotation:{primary_server_id:7,other_server_id:8,interval_s:3000,lead_s:120,active_name:'A',status:'ready'}},[{id:8,name:'B'}]);
 for(const text of ['查看统计与建议','生成只读分析接口','撤销分析接口令牌','实际 DNS 观察节点','Cloudflare 代理记录'])assert.ok(html.includes(text),text);
});


test('both rotation modes remain available and legacy tasks default to alternating',()=>{
 const fields=ctx.rotationModeFields(null);
 assert.match(fields,/value="alternating" selected/);
 assert.match(fields,/value="fixed_primary"/);
 const fixed=ctx.rotationModeFields({mode:'fixed_primary',takeover_s:1200,mobile_only_ack:1});
 assert.match(fixed,/value="fixed_primary" selected/);
 assert.match(fixed,/B 每次承载时长/);
 assert.match(fixed,/name="mobile_only_ack"[^>]*checked/);
 assert.match(fixed,/现有 TCP 已建立连接总数/);
 assert.doesNotMatch(fixed,/轮换机需升级 agent/);
});

test('primary outage failover exposes a distinct C and all-A scope without a partial selector',()=>{
 const html=ctx.rotationModeFields({mode:'fixed_primary',other_server_id:2,failover_server_id:3,failover_recovery_s:45,failover_status:'<waiting>'},[{id:1,name:'A'},{id:2,name:'B'},{id:3,name:'<C>'}],[],1);
 for(const value of ['name="failover_server_id"','name="failover_recovery_s"','A 的全部绑定解析','A、B 都下线'])assert.ok(html.includes(value),value);
 assert.doesNotMatch(html,/name="failover_binding_ids"/);
 assert.match(html,/备用机闲时不拨测/);
 assert.match(html,/临时继承 A 的探测点/);
 assert.match(html,/value="1" disabled/);assert.match(html,/value="2" disabled/);assert.match(html,/value="3"\s+selected/);
 assert.match(html,/&lt;C&gt;/);assert.match(html,/&lt;waiting&gt;/);
});

test('rotation payload submits optional C without limiting failover to a subset of records',()=>{
 vm.runInContext(source.match(/function rotationModePayload\([^\n]+/)[0],ctx);
 const body=ctx.rotationModePayload({mode:{value:'fixed_primary'},takeover_minutes:{value:'10'},first_switch:{value:''},mobile_only_ack:{checked:true},failover_server_id:{value:'3'},failover_recovery_s:{value:'60'}});
 assert.equal(body.failover_server_id,3);assert.equal(body.failover_recovery_s,60);assert.ok(!('failover_binding_ids' in body));
});

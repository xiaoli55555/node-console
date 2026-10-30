const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync('web/app.js','utf8');
const match=source.match(/function customerDnsSection\([\s\S]*?\n}/);
const statusMatch=source.match(/function clientProbeStatusMarkup\([\s\S]*?\n}/);
assert.ok(match,'customer settings renderer exists');
assert.ok(statusMatch,'customer probe status renderer exists');
const ctx=vm.createContext({esc:v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))});
vm.runInContext(statusMatch[0]+'\n'+match[0],ctx);

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
 for(const text of ['双 VPS 定时轮换','standby-vps','每台 VPS 承载时间（分钟）','旧机连接数触发阈值（严格低于）','80','开启定时轮换','BOCE 复检'])assert.ok(html.includes(text),text);
 assert.match(html,/name="interval_minutes"[^>]*value="120"/);
 assert.match(html,/name="binding_id"/);
});

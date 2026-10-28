const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync('web/app.js','utf8');
const match=source.match(/function customerDnsSection\([\s\S]*?\n}/);
const statusMatch=source.match(/function clientProbeStatusMarkup\([\s\S]*?\n}/);
assert.ok(match,'customer settings renderer exists');
assert.ok(statusMatch,'customer probe status renderer exists');
const ctx=vm.createContext({esc:v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))});
vm.runInContext(statusMatch[0]+'\n'+match[0],ctx);

test('customer VPS settings expose BOCE, AliDNS, MoonVM, port and recovery controls',()=>{
 const html=ctx.customerDnsSection({sources:[],plan:{response_mode:'change_api',action_enabled:true},monitor:{port:23456,enabled:true}},[],7,[{id:2,name:'My AliDNS',kind:'alidns',access_key_id:'key-id'},{id:3,name:'MoonVM product 9',kind:'change_ip'}]);
 for(const text of ['clientProbeStatus','clientProbeForm','BOCE API Key','业务 TCP 检测端口','clientActionForm','通过面板重启 VPS','MoonVM 换 IP API','AccessKey ID','AccessKey Secret','验证阿里云并读取记录','保存后开启该线路自动解析'])assert.ok(html.includes(text),text);
 assert.match(html,/value="23456"/);
});

test('admin-owned active automation renders locked instructions for customers',()=>{
 const html=ctx.customerDnsSection({plan:{actions_locked:true,automatic:true},monitor:{port:443,enabled:true}},[],7,[]);
 assert.match(html,/管理员正在管理这台 VPS 的自动策略/);
 assert.doesNotMatch(html,/<form id="clientActionForm"/);
 assert.match(html,/clientPauseProbe/);
});

const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync('web/ipdns.js','utf8');
function setup(connections=[{id:8,name:'CF zone',kind:'cloudflare',config:{zone_name:'example.com'}},{id:9,name:'Ali',kind:'alidns',config:{}}]){
 const nodes={},calls=[],fields=new Proxy({}, {get:(o,k)=>o[k]??(o[k]=element())});
 function element(){return {value:'',checked:false,disabled:false,dataset:{},innerHTML:'',textContent:'',handlers:{},addEventListener(type,fn){this.handlers[type]=fn;},querySelectorAll(selector){return (this.inputs||[]).filter(x=>!selector.includes(':checked')||x.checked);}};}
 const $=id=>nodes[id]||(nodes[id]=element());$('quickIPForm').elements=fields;$('modal').close=()=>{};
 const records=[{RecordId:'a'.repeat(32),RR:'@',Type:'A',Line:'default',Value:'1.1.1.1',Status:'ENABLE',Proxied:true},{RecordId:'b'.repeat(32),RR:'edge',Type:'A',Line:'default',Value:'1.1.1.1',Status:'ENABLE',Proxied:false}];
 let pending=null;
 const ctx=vm.createContext({$,esc:v=>String(v??'').replaceAll('<','&lt;'),notice:()=>{},loadIPDNS:async()=>{},modal:html=>{ctx.html=html;},api:async(path,method,payload)=>{calls.push({path,method,payload});if(path==='detection')return {sources:[{id:1,kind:'self',name:'probe',enabled:1}]};if(path.endsWith('/check'))return {ip:'1.1.1.1',status:'reachable'};if(path.includes('/connections/'))return pending?pending():{records,total:2,page_size:500};if(path==='ip-dns/bindings')return {id:100+calls.filter(x=>x.path===path).length};return {};}});
 vm.runInContext(source,ctx);ctx.loadIPDNS=async()=>{};vm.runInContext('ipdnsData='+JSON.stringify({connections,servers:[{id:6,name:'VPS'}],monitors:[{server_id:6,port:443}],bindings:[]})+';',ctx);
 Object.assign(fields.server_id,{value:'6'});Object.assign(fields.port,{value:'443'});fields.source_id.value='1';fields.interval_s.value='600';fields.daily_limit.value='1000';fields.failure_threshold.value='3';fields.response_mode.value='none';fields.scheduled.checked=true;fields.verify_new_ip.checked=true;
 return {ctx,$,fields,calls,records,pending:fn=>{pending=fn;}};
}
test('wizard lists Cloudflare, preselects its zone, renders apex/proxy and saves selected records',async()=>{
 const h=setup();await h.ctx.quickIPSetup();assert.match(h.ctx.html,/CF zone · Cloudflare/);assert.match(h.ctx.html,/Ali · 阿里云/);
 h.fields.dns_connection_id.value='8';h.fields.dns_connection_id.onchange();assert.equal(h.fields.domain.value,'example.com');await h.fields.server_id.onchange();await h.$('quickReadRecords').handlers.click();
 const html=h.$('quickRecordChoices').innerHTML;assert.match(html,/>example.com<\/strong>/);assert.doesNotMatch(html,/@\.example/);assert.match(html,/已代理/);assert.match(html,/仅 DNS/);
 h.$('quickRecordChoices').inputs=h.records.map((_,i)=>({checked:true,dataset:{recordIndex:String(i)}}));h.$('quickRecordChoices').onchange();await h.$('quickIPForm').onsubmit({preventDefault(){},submitter:{disabled:false}});
 const bindings=h.calls.filter(x=>x.path==='ip-dns/bindings');assert.equal(bindings.length,2);assert.equal(bindings[0].payload.connection_id,8);assert.equal(bindings[0].payload.domain,'example.com');assert.equal(bindings[0].payload.rr,'@');assert.equal(bindings[0].payload.line,'default');assert.equal(bindings[0].payload.automatic,false);assert.equal(h.$('quickIPError').textContent,'');
});
test('changing DNS connection drops in-flight results and old selections',async()=>{
 const h=setup();await h.ctx.quickIPSetup();h.fields.dns_connection_id.value='8';h.fields.dns_connection_id.onchange();let resolve;h.pending(()=>new Promise(r=>{resolve=r;}));const read=h.$('quickReadRecords').handlers.click();h.fields.dns_connection_id.value='9';h.fields.dns_connection_id.onchange();resolve({records:h.records,total:2});await read;
 assert.equal(h.$('quickRecordChoices').innerHTML,'');assert.equal(h.$('quickSelectAllRecords').disabled,true);assert.match(h.$('quickDNSStatus').textContent,/DNS 连接已修改/);
});
test('Cloudflare-only and missing-DNS setups open without Ali connection',async()=>{
 const cf=setup([{id:8,name:'Only CF',kind:'cloudflare',config:{zone_name:'example.com'}}]);await cf.ctx.quickIPSetup();assert.match(cf.ctx.html,/Only CF · Cloudflare/);assert.doesNotMatch(cf.ctx.html,/尚未配置 DNS API/);
 const empty=setup([]);empty.fields.domain=undefined;empty.fields.dns_connection_id=undefined;await empty.ctx.quickIPSetup();assert.match(empty.ctx.html,/添加 Cloudflare API/);
});
test('Cloudflare auto-sync enables only the selected records after configuration saves',async()=>{
 const h=setup();await h.ctx.quickIPSetup();h.fields.dns_connection_id.value='8';h.fields.dns_connection_id.onchange();await h.fields.server_id.onchange();await h.$('quickReadRecords').handlers.click();h.$('quickRecordChoices').inputs=[{checked:true,dataset:{recordIndex:'1'}}];h.$('quickRecordChoices').onchange();h.fields.auto_dns.checked=true;await h.$('quickIPForm').onsubmit({preventDefault(){},submitter:{disabled:false}});
 const bindings=h.calls.filter(x=>x.path==='ip-dns/bindings');assert.equal(bindings.length,2);assert.equal(bindings[0].payload.automatic,false);assert.equal(bindings[1].payload.automatic,true);assert.equal(bindings[1].payload.record_id,'b'.repeat(32));assert.equal(h.$('quickIPError').textContent,'');
});
test('automatic DNS still rejects a record pointing at another VPS IP',async()=>{
 const h=setup();await h.ctx.quickIPSetup();h.fields.dns_connection_id.value='8';h.fields.dns_connection_id.onchange();await h.fields.server_id.onchange();h.records[0].Value='8.8.8.8';await h.$('quickReadRecords').handlers.click();h.$('quickRecordChoices').inputs=[{checked:true,dataset:{recordIndex:'0'}}];h.$('quickRecordChoices').onchange();h.fields.auto_dns.checked=true;await h.$('quickIPForm').onsubmit({preventDefault(){},submitter:{disabled:false}});
 assert.match(h.$('quickIPError').textContent,/自动同步已阻止/);assert.equal(h.calls.filter(x=>x.path==='ip-dns/bindings').length,0);
});
test('Ali carrier-line selections continue using the same binding flow',async()=>{
 const h=setup();await h.ctx.quickIPSetup();h.fields.dns_connection_id.value='9';h.fields.dns_connection_id.onchange();h.fields.domain.value='example.com';h.records[1].Line='unicom';await h.fields.server_id.onchange();await h.$('quickReadRecords').handlers.click();assert.match(h.$('quickRecordChoices').innerHTML,/联通/);h.$('quickRecordChoices').inputs=[{checked:true,dataset:{recordIndex:'1'}}];h.$('quickRecordChoices').onchange();await h.$('quickIPForm').onsubmit({preventDefault(){},submitter:{disabled:false}});const binding=h.calls.find(x=>x.path==='ip-dns/bindings');assert.equal(binding.payload.connection_id,9);assert.equal(binding.payload.line,'unicom');assert.equal(h.$('quickIPError').textContent,'');
});

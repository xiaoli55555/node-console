const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const ipSource=fs.readFileSync('web/ipdns.js','utf8');
const appSource=fs.readFileSync('web/app.js','utf8');
const escape=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function context(){const ctx=vm.createContext({page:'rotations',esc:escape,console,FormData:class{constructor(f){this.values=f.values;}[Symbol.iterator](){return Object.entries(this.values)[Symbol.iterator]();}}});vm.runInContext(ipSource,ctx);return ctx;}

test('each plan has its own failover entry and saves only that plan backup',async()=>{
 const c=context(),r={id:7,primary_server_id:1,other_server_id:2,primary_name:'<main>',other_name:'C',next_switch_at:2000000000,interval_s:7200,lead_s:0,offline_after_s:15,enabled:1};
 const before=JSON.stringify(r);let html='';const calls=[];
 const form={failover_server_id:{value:'3'},failover_recovery_s:{value:'45'}};
 const elements={rotationFailoverForm:form,backRotationFailover:{},rotationFailoverError:{}};
 c.$=id=>elements[id];c.renderRotationPage=x=>html=x;c.loadAdminRotations=async()=>{};c.notice=()=>{};c.api=async(...args)=>calls.push(args);
 assert.match(c.adminRotationsMarkup({rotations:[r]}),/data-rotation-failover="7"/);
 c.editRotationFailover({servers:[{id:1,name:'A'},{id:2,name:'C'},{id:3,name:'<backup>'}]},r);
 assert.match(html,/value="1" disabled/);assert.match(html,/value="2" disabled/);assert.match(html,/&lt;backup&gt;/);
 assert.match(html,/共用固定主机 A 的计划必须选同一台备用机/);
 const button={disabled:false};await form.onsubmit({preventDefault(){},submitter:button});
 assert.equal(calls[0][0],'admin/rotations/7/failover');assert.equal(calls[0][1],'PATCH');
 assert.deepEqual(JSON.parse(JSON.stringify(calls[0][2])),{failover_server_id:3,failover_recovery_s:45});
 assert.equal(JSON.stringify(r),before);assert.equal(button.disabled,false);
});

test('API rename submits metadata without credentials or action endpoints',async()=>{
 const c=context(),calls=[];let html='';const form={elements:{namedItem:()=>({value:' HKT2 · 换 IP '})}};
 c.$=id=>id==='renameAPIForm'?form:id==='modal'?{close(){}}:{};c.modal=x=>html=x;c.loadIPDNS=async()=>{};c.notice=()=>{};c.api=async(...args)=>calls.push(args);
 c.renameIPConnection({id:19,name:'<old>'});assert.match(html,/&lt;old&gt;/);
 await form.onsubmit({preventDefault(){},submitter:{disabled:false}});
 assert.equal(calls[0][0],'ip-dns/connections/19');assert.equal(calls[0][1],'PATCH');
 assert.deepEqual(JSON.parse(JSON.stringify(calls[0][2])),{name:'HKT2 · 换 IP'});
});

test('MoonVM create form preserves the operator custom name',async()=>{
 const c=context(),form={},calls=[];let html='';
 c.$=id=>id==='ipAPIForm'?form:id==='modal'?{close(){}}:{};c.modal=x=>html=x;c.loadIPDNS=async()=>{};c.notice=()=>{};c.api=async(...args)=>calls.push(args);
 c.editIPConnection(null,'change_ip','moonvm');assert.match(html,/API 自定义名称/);
 await form.onsubmit({preventDefault(){},submitter:{disabled:false},target:{values:{name:'移动备用 · MoonVM',url:'https://store.moonvm.com/ddns.php?product=12345&flag=changeip&iptoken=dummy'}}});
 assert.equal(calls[0][2].name,'移动备用 · MoonVM');
});

test('VPS name save does not send an owner change',async()=>{
 const c=vm.createContext({}),calls=[],elements={saveServerName:{},serverName:{value:' HKT 主承载 '},detailError:{}};
 vm.runInContext(appSource.match(/function bindServerRename\([\s\S]*?\n}/)[0],c);
 c.$=id=>elements[id];c.api=async(...args)=>calls.push(args);c.loadServers=async()=>{};c.detail=async()=>{};c.notice=()=>{};
 c.bindServerRename(8);await elements.saveServerName.onclick();
 assert.equal(calls[0][0],'servers/8');assert.equal(calls[0][1],'PATCH');
 assert.deepEqual(JSON.parse(JSON.stringify(calls[0][2])),{name:'HKT 主承载'});assert.equal(elements.saveServerName.disabled,false);
});

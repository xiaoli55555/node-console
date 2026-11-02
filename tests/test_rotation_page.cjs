const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync('web/ipdns.js','utf8');
const esc=v=>String(v??'').replaceAll('<','&lt;').replaceAll('>','&gt;');
const plan={id:7,primary_name:'<main>',other_name:'Standby',active_name:'<main>',primary_server_id:1,other_server_id:2,binding_id:11,binding_ids:[11,12],enabled:1,interval_s:7200,connection_threshold:80,offline_after_s:15,phase:'waiting_probe',next_switch_at:2000000000,new_ip:'8.8.4.4',old_ip:'1.1.1.1',events:[],status:'等待新 IP 复检'};
function setup(){const timers=[],cleared=[],elements={adminRotationsContent:{innerHTML:''},newAdminRotation:{},adminRotationLiveError:{}};const c=vm.createContext({esc,page:'rotations',console,clearInterval:id=>cleared.push(id),setInterval:fn=>{timers.push(fn);return timers.length;},$:id=>elements[id],document:{querySelectorAll:()=>[]},modal(){throw Error('Unexpected modal');},notice(){}});vm.runInContext(source,c);return {c,timers,cleared,elements};}
test('rotation menu routes to its own page and editors never use a modal',()=>{
 const html=fs.readFileSync('web/index.html','utf8'),app=fs.readFileSync('web/app.js','utf8');
 assert.match(html,/id="adminRotationMenu" data-page="rotations"/);assert.match(html,/id="rotationsPage"/);assert.match(app,/if\(page==='rotations'\)await loadAdminRotations\(\)/);
 for(const [start,end] of [['function editRotationFailover','function editAdminRotation'],['function editAdminRotation','function rotationSelectedValues']]){const section=source.slice(source.indexOf(start),source.indexOf(end,source.indexOf(start)+1));assert.match(section,/renderRotationPage\(/);assert.doesNotMatch(section,/\bmodal\(/);}
});
test('overview and detail load into page; detail shows per-line DNS and candidate separately',async()=>{
 const {c,elements}=setup();c.api=async()=>({rotations:[plan],bindings:[{id:11,rr:'edge',domain:'example.com',line:'telecom',expected_ip:'1.1.1.1'},{id:12,rr:'edge',domain:'example.com',line:'unicom',expected_ip:'9.9.9.9'}]});
 await c.loadAdminRotations();assert.match(elements.adminRotationsContent.innerHTML,/data-rotation-view="7"/);
 await c.loadAdminRotations(7);const html=elements.adminRotationsContent.innerHTML;
 for(const text of ['实时轮换状态','计划设置','DNS 记录与切换状态','新 IP 候选：8.8.4.4','1.1.1.1','9.9.9.9','承载时间记录','最近排空耗时'])assert.ok(html.includes(text),text);
 assert.doesNotMatch(html,/<main>/);assert.match(html,/&lt;main&gt;/);
});
test('late initial response cannot overwrite a different page',async()=>{
 const {c,elements}=setup();let resolve;c.api=()=>new Promise(r=>resolve=r);const pending=c.loadAdminRotations();c.page='servers';resolve({rotations:[plan]});await pending;assert.equal(elements.adminRotationsContent.innerHTML,'');
});
test('live response cannot overwrite an open editor or navigate back after leaving',async()=>{
 const {c,timers,elements}=setup();let resolve;c.api=()=>new Promise(r=>resolve=r);const data={rotations:[{...plan,urgent_probe_floors:'{}'}]};c.startAdminRotationLive(data);
 const pending=timers[0]();c.renderRotationPage('<form>unsaved changes</form>');resolve({rotations:[{...plan,status:'new status'}]});await pending;
 assert.match(elements.adminRotationsContent.innerHTML,/unsaved changes/);assert.equal(data.rotations[0].status,plan.status);
 c.page='servers';await timers[0]();assert.match(elements.adminRotationsContent.innerHTML,/unsaved changes/);
});
test('live refresh updates data used by controls rather than retaining stale enabled state',async()=>{
 const {c,timers,elements}=setup();const data={rotations:[{...plan,urgent_probe_floors:'{}'}],bindings:[]};elements['rotationLive-7']={};elements['rotationSummary-7']={};
 c.api=async()=>({rotations:[{...plan,enabled:0,status:'已暂停'}],bindings:[]});c.startAdminRotationLive(data);await timers[0]();assert.equal(data.rotations[0].enabled,0);assert.match(elements['rotationLive-7'].innerHTML,/已暂停/);assert.equal(elements['rotationSummary-7'].innerHTML,'已暂停');
});

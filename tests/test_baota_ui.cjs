const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
function setup(){
 const elements={},calls=[];let html='';
 const ctx=vm.createContext({setTimeout,clearTimeout,esc:x=>String(x??'').replaceAll('<','&lt;'),$:id=>elements[id],notice(){},FormData:class{constructor(form){return Object.entries(form.elements).filter(([k])=>k!=='enabled').map(([k,v])=>[k,v.value]);}},api:async(path,method,data)=>{calls.push({path,method,data});return {ok:true}},modal:markup=>{html=markup;elements.modal={close(){}};elements.baotaSourceError={};elements.baotaSourceForm={elements:{name:{value:'宝塔'},secret:{value:'tbt_test_key'},enabled:{checked:true}}};}});
 vm.runInContext(fs.readFileSync('web/detectors.js','utf8'),ctx);
 vm.runInContext('loadDetectors=async()=>{};',ctx);
 return {ctx,elements,calls,html:()=>html};
}
test('Baota source saves encrypted-source payload and retains an empty edited key',async()=>{
 const h=setup();await h.ctx.editDetectionSource(null,'baota');
 assert.match(h.html(),/宝塔拨测/);assert.match(h.html(),/https:\/\/t.bt.cn\/api-console/);
 let form=h.elements.baotaSourceForm;await form.onsubmit({preventDefault(){},target:form,submitter:{}});
 assert.equal(h.calls[0].data.kind,'baota');assert.equal(h.calls[0].data.secret,'tbt_test_key');
 await h.ctx.editBaotaSource({id:4,name:'existing',enabled:1});form=h.elements.baotaSourceForm;form.elements.secret.value='';
 await form.onsubmit({preventDefault(){},target:form,submitter:{}});
 assert.equal(h.calls[1].data.id,4);assert.equal(h.calls[1].data.secret,'');
});
test('Baota save failure remains visible and restores submit control',async()=>{
 const h=setup();h.ctx.api=async()=>{throw Error('network unavailable')};await h.ctx.editBaotaSource();
 const form=h.elements.baotaSourceForm,button={};await form.onsubmit({preventDefault(){},target:form,submitter:button});
 assert.equal(h.elements.baotaSourceError.textContent,'network unavailable');assert.equal(button.disabled,false);
});
test('pending refresh does not overlap and stops after completion',async()=>{
 const h=setup();let count=0,resolve;
 h.ctx.loadDetectors=()=>{count++;return new Promise(r=>resolve=r)};
 vm.runInContext("detectorsData={runs:[{status:'pending'}]}",h.ctx);
 const first=h.ctx.refreshDetectionIfPending();await h.ctx.refreshDetectionIfPending();assert.equal(count,1);resolve();await first;
 vm.runInContext("detectorsData={runs:[{status:'宝塔 TCP 可达'}]}",h.ctx);
 await h.ctx.refreshDetectionIfPending();assert.equal(count,1);
});
test('pending refresh can retry after a network error',async()=>{
 const h=setup();vm.runInContext("detectorsData={runs:[{status:'pending'}]}",h.ctx);
 h.ctx.loadDetectors=async()=>{throw Error('network')};await assert.rejects(h.ctx.refreshDetectionIfPending());
 let count=0;h.ctx.loadDetectors=async()=>{count++};await h.ctx.refreshDetectionIfPending();assert.equal(count,1);
});

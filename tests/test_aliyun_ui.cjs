const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
function setup(){
 const elements={},calls=[];let html='';
 const el=()=>({value:'',checked:false,disabled:false,textContent:'',innerHTML:'',setAttribute(){},after(child){if(child.id)elements[child.id]=child;this.next=child;},querySelectorAll(){return []}});
 const control=(value,checked=false)=>Object.assign(el(),{value,checked});
 const ctx=vm.createContext({console,setTimeout,clearTimeout,esc:x=>String(x??'').replaceAll('<','&lt;').replaceAll('"','&quot;'),$:id=>elements[id],dnsOptions:()=>'',notice:()=>{},document:{createElement:el},FormData:class{constructor(form){return Object.entries(form.elements).filter(([k,v])=>!['automatic','enabled'].includes(k)).map(([k,v])=>[k,v.value]);}},api:async(path,method,data)=>{calls.push({path,method,data});if(path==='ip-dns')return {connections:[]};if(path.endsWith('/nodes'))return {nodes:[{id:'546:232',name:'<北京>',isp:'联通'}]};if(path.endsWith('/test'))return {message:'来源可用'};return {ok:true};},modal:markup=>{html=markup;elements.modal={close(){}};if(markup.includes('aliyunProbeForm')){elements.aliyunProbeError=el();elements.aliyunProbeForm={elements:{name:control('阿里云'),key_id:control('test-access-key'),key_secret:control('test-secret-value'),enabled:control('',true)}};}if(markup.includes('detectorPlanForm')){elements.detectorPlanForm={elements:{server_id:control('1'),source_id:control('7'),port:control('50332'),nodes:control('546:232'),interval_s:control('120'),daily_limit:control('2160'),automatic:control('',false),response_mode:control('none'),action_connection_id:control(''),confirm_source_id:control(''),confirm_node:control(''),failure_threshold:control('3')}};for(const id of ['loadConfirmNodes','loadPlanNodes','planNodeChoices','planUsage','detectorPlanError'])elements[id]=el();}}});
 vm.runInContext(fs.readFileSync('web/detectors.js','utf8'),ctx);
 vm.runInContext("loadDetectors=async()=>{};detectorsData={sources:[{id:7,kind:'aliyun',name:'阿里云'}],servers:[{id:1,name:'VPS'}],monitors:[{server_id:1,port:50332}]};",ctx);
 return {ctx,elements,calls,html:()=>html};
}
test('Alibaba form submits credentials only to source endpoint and preserves empty edits',async()=>{
 const h=setup();h.ctx.editAliyunSource();const form=h.elements.aliyunProbeForm,button={disabled:false};
 await form.onsubmit({preventDefault(){},target:form,submitter:button});
 assert.equal(h.calls[0].path,'detection/sources');assert.equal(h.calls[0].data.kind,'aliyun');assert.equal(JSON.parse(h.calls[0].data.secret).access_key_id,'test-access-key');assert.equal(button.disabled,false);
 h.ctx.editAliyunSource({id:7,name:'existing'});const edit=h.elements.aliyunProbeForm;edit.elements.key_id.value='';edit.elements.key_secret.value='';await edit.onsubmit({preventDefault(){},target:edit,submitter:button});assert.equal(h.calls.at(-1).data.secret,'');
});
test('partial credentials show error without making API call',async()=>{
 const h=setup();h.ctx.editAliyunSource();const form=h.elements.aliyunProbeForm;form.elements.key_secret.value='';await form.onsubmit({preventDefault(){},target:form,submitter:{}});assert.equal(h.calls.length,0);assert.match(h.elements.aliyunProbeError.textContent,/同时填写/);
});
test('node listing, source verification and 120 second plan preserve composite node IDs',async()=>{
 const h=setup();await h.ctx.editDetectionPlan();await h.elements.loadPlanNodes.onclick();assert.match(h.elements.planNodeChoices.innerHTML,/546:232/);assert.doesNotMatch(h.elements.planNodeChoices.innerHTML,/<北京>/);
 const button=h.elements.loadPlanNodes.next;const pending=button.onclick();assert.equal(button.disabled,true);assert.match(h.elements.probeSourceStatus.textContent,/正在验证/);await pending;assert.equal(h.elements.probeSourceStatus.textContent,'来源可用');
 const form=h.elements.detectorPlanForm;await form.onsubmit({preventDefault(){},submitter:{}});const payload=h.calls.at(-1).data;assert.equal(payload.nodes[0],'546:232');assert.equal(payload.interval_s,120);assert.equal(payload.port,50332);assert.equal(payload.response_mode,'none');
});
test('changing sources discards delayed validation results',async()=>{
 const h=setup();await h.ctx.editDetectionPlan();let resolve;h.ctx.api=()=>new Promise(r=>resolve=r);const button=h.elements.loadPlanNodes.next,pending=button.onclick();h.elements.detectorPlanForm.elements.source_id.value='8';h.elements.detectorPlanForm.elements.source_id.onchange();resolve({message:'旧来源通过'});await pending;assert.equal(h.elements.probeSourceStatus.textContent,'');assert.equal(button.disabled,false);
});

test('node lookup immediately displays progress and discards results after source change',async()=>{
 const h=setup();await h.ctx.editDetectionPlan();let resolve;h.ctx.api=()=>new Promise(r=>resolve=r);
 const button=h.elements.loadPlanNodes,pending=button.onclick();assert.equal(button.disabled,true);assert.match(button.textContent,/正在获取/);assert.match(h.elements.detectorPlanError.textContent,/正在获取/);
 h.elements.detectorPlanForm.elements.source_id.value='8';h.elements.detectorPlanForm.elements.source_id.onchange();
 resolve({nodes:[{id:'old',name:'旧节点',isp:'test'}]});await pending;
 assert.equal(h.elements.planNodeChoices.innerHTML,'');assert.equal(button.disabled,false);
});
test('node lookup timeout restores button and displays local error',async()=>{
 const h=setup();await h.ctx.editDetectionPlan();let timeout;h.ctx.setTimeout=fn=>{timeout=fn;return 1};h.ctx.clearTimeout=()=>{};h.ctx.api=()=>new Promise(()=>{});
 const pending=h.elements.loadPlanNodes.onclick();timeout();await pending;
 assert.equal(h.elements.loadPlanNodes.disabled,false);assert.match(h.elements.detectorPlanError.textContent,/超时/);
});
test('plan exposes an independent confirmation point and submits it separately',async()=>{
 const h=setup();await h.ctx.editDetectionPlan();assert.match(h.html(),/首轮不通后的独立复测点/);
 const form=h.elements.detectorPlanForm;form.elements.confirm_node.value='304:5';
 await form.onsubmit({preventDefault(){},submitter:{}});
 assert.equal(h.calls.at(-1).data.confirm_node,'304:5');assert.equal(h.calls.at(-1).data.nodes[0],'546:232');
});

test('cross-source confirmation loads distinct source nodes and saves identity',async()=>{
 const h=setup();await h.ctx.editDetectionPlan();const f=h.elements.detectorPlanForm;
 f.elements.confirm_source_id.value='9';f.elements.confirm_source_id.onchange();
 h.ctx.api=async(path,method,data)=>{h.calls.push({path,method,data});return {nodes:[{id:'self',name:'<广州探针>',isp:'自建探针',online:true}]};};
 await h.elements.loadConfirmNodes.onclick();assert.equal(h.calls.at(-1).path,'detection/sources/9/nodes');
 assert.match(f.elements.confirm_node.innerHTML,/self/);assert.doesNotMatch(f.elements.confirm_node.innerHTML,/<广州探针>/);
 f.elements.confirm_node.value='self';await f.onsubmit({preventDefault(){},submitter:{}});
 assert.equal(h.calls.at(-1).data.confirm_source_id,9);assert.equal(h.calls.at(-1).data.confirm_node,'self');
});
test('changing confirmation source discards delayed node results',async()=>{
 const h=setup();await h.ctx.editDetectionPlan();const f=h.elements.detectorPlanForm;
 f.elements.confirm_source_id.value='9';let resolve;h.ctx.api=()=>new Promise(r=>resolve=r);
 const pending=h.elements.loadConfirmNodes.onclick();f.elements.confirm_source_id.value='10';f.elements.confirm_source_id.onchange();
 resolve({nodes:[{id:'self',name:'旧来源',isp:'test'}]});await pending;
 assert.doesNotMatch(f.elements.confirm_node.innerHTML,/旧来源/);assert.equal(h.elements.loadConfirmNodes.disabled,false);
});

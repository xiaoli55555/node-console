const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync('web/app.js','utf8');
function harness(){
 const elements={},calls=[];let response={points:[{id:3,received_at:1700000000,sampled_at:1699999995,addresses:['36.232.68.71'],tcp:4,valid:true,ports:{443:4},context:[{plan_id:1,role:'standby',phase:'draining',threshold:90,below_threshold:true}],address_source:'interface'}],has_more:true,next_before_id:3,recording_started_at:1700000000};
 const ctx=vm.createContext({Date,URLSearchParams,Error,Object,Number,String,esc:v=>String(v??'').replaceAll('<','&lt;'),$:id=>elements[id]||(elements[id]={value:'',open:true,hidden:false}),api:async path=>{calls.push(path);return response;},modal:html=>{ctx.ipHistoryView++;ctx.html=html;elements.modal={open:true};},servers:[{id:6,name:'<HKT2>'}],me:{role:'admin'},ipHistoryView:0,openMetricWindow:()=>{}});
 vm.runInContext(source.slice(source.indexOf('async function openTCPHistory(id)')),ctx);
 return {ctx,elements,calls,setResponse:x=>{response=x;}};
}
test('raw TCP history renders counts, escapes names and filters/pages within one query',async()=>{
 const h=harness();await h.ctx.openTCPHistory(6);assert.match(h.ctx.html,/&lt;HKT2>/);assert.match(h.elements.tcpHistoryRows.innerHTML,/36.232.68.71/);assert.match(h.elements.tcpHistoryRows.innerHTML,/TCP &lt; 90/);
 h.elements.tcpHistoryIP.value='36.232.68.71';h.elements.tcpHistoryFrom.value='2026-11-07T01:00';h.elements.tcpHistoryUntil.value='2026-11-07T02:00';await h.elements.tcpHistoryQuery.onclick();
 assert.match(h.calls.at(-1),/ip=36.232.68.71/);assert.match(h.calls.at(-1),/from=/);await h.elements.tcpHistoryOlder.onclick();assert.match(h.calls.at(-1),/before_id=3/);
});
test('read failure removes stale rows and pagination',async()=>{
 const h=harness();await h.ctx.openTCPHistory(6);h.ctx.api=async()=>{throw Error('接口失败');};await h.elements.tcpHistoryQuery.onclick();assert.equal(h.elements.tcpHistoryRows.textContent,'');assert.equal(h.elements.tcpHistoryOlder.hidden,true);assert.match(h.elements.tcpHistoryStatus.textContent,/读取失败/);
});

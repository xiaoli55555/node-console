const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync('web/ipdns.js','utf8'),ctx=vm.createContext({esc:v=>String(v??'').replaceAll('<','&lt;').replaceAll('>','&gt;')});vm.runInContext(source,ctx);
test('reference status names fixed target, every node, actual latency and task',()=>{
 const html=ctx.referenceProbeMarkup({passed:true,parent_id:19,checked:1793750400,details:[{node_id:'1',name:'广东移动',state:'reachable',latency_ms:12.5},{node_id:'2',name:'<bad>',state:'unknown',latency_ms:null}]});
 for(const value of ['www.baidu.com:80','通过','广东移动','12.5 ms','未知','暂无','目标任务 #19','&lt;bad&gt;'])assert.ok(html.includes(value),value);
});
test('pending or vetoed results never claim station passed or fabricate zero latency',()=>{
 assert.match(ctx.referenceProbeMarkup({stage:'reference',state:'pending',passed:false}),/检测中/);
 const html=ctx.referenceProbeMarkup({stage:'reference',state:'unknown',passed:false,details:[{node_id:'1',state:'unreachable',latency_ms:null}]});assert.match(html,/判定已撤销/);assert.doesNotMatch(html,/0 ms/);
});
test('missing reference belongs to another run and is not carried into new target',()=>{assert.equal(ctx.referenceProbeMarkup(null),'');});
test('monitor status uses unconfirmed tone while control is pending or failure is vetoed',()=>{
 const item={run:{status:'首轮不通',details:[{node_id:'1',state:'unreachable'}],reference:{stage:'reference',state:'pending'}},source_kind:'boce'};
 assert.match(ctx.monitorDetectionMarkup(item),/尚未确认故障/);assert.match(ctx.monitorDetectionMarkup(item),/probe-unknown/);
 item.run.status='参照站未通过，本轮不通判定已撤销';item.run.reference.state='unknown';
 assert.match(ctx.monitorDetectionMarkup(item),/probe-unknown/);assert.doesNotMatch(ctx.monitorDetectionMarkup(item),/国内不通（疑似被墙）/);
});
test('dual stations show separate names, states, delays and pending late result',()=>{
 const html=ctx.referenceProbeMarkup({passed:true,parent_id:88,stage:'target',state:'pending',stations:[{host:'www.qq.com',port:80,state:'completed',checked:1793750400,details:[{node_id:'13',name:'广东移动',state:'reachable',latency_ms:9.8}]},{host:'www.baidu.com',port:80,state:'pending',details:[]}]});
 for(const value of ['www.qq.com:80','www.baidu.com:80','9.8 ms','检测中','参照站校验：通过','同一检测点至少一站可达'])assert.ok(html.includes(value),value);
});
test('dual failed stations show veto and never invent latency',()=>{
 const html=ctx.referenceProbeMarkup({passed:false,parent_id:88,stage:'reference',state:'unknown',stations:[{host:'www.qq.com',state:'completed',details:[{node_id:'13',state:'unreachable',latency_ms:0}]},{host:'www.baidu.com',state:'unknown',message:'接口超时',details:[]}]});
 assert.match(html,/判定已撤销/);assert.match(html,/接口超时/);assert.doesNotMatch(html,/0 ms/);
});

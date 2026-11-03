const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const c=vm.createContext({esc:x=>String(x??'').replaceAll('<','&lt;'),referenceProbeMarkup:()=>''});
vm.runInContext(fs.readFileSync('web/ipdns.js','utf8'),c);
test('rotation probes identify members, latency and obsolete target without action controls',()=>{
 const r={primary_server_id:1,other_server_id:2,failover_server_id:3,active_server_id:1,primary_name:'A',other_name:'B',failover_name:'C'};
 const html=c.rotationProbeMarkup({detections:[{server_id:1,current_ip:'8.8.8.8',current_port:443,source_name:'BOCE',run:{ip:'1.1.1.1',port:443,status:'国内可达',updated:100,details:[{name:'上海移动',state:'reachable',latency_ms:60.85}]}}]},r);
 for(const x of ['A · 当前承载','B · 轮换机','C · 故障备用','60.85 ms','旧 IP／端口','尚未配置探测'])assert.ok(html.includes(x),x);
 assert.ok(!html.includes('<button'));assert.ok(!html.includes('data-action-toggle'));
});

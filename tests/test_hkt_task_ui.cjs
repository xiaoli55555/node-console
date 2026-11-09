const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
test('DHCP history renders read-only timeline and follows event cursor',async()=>{
 const nodes={},calls=[];const node=id=>nodes[id]||(nodes[id]={textContent:'',innerHTML:'',hidden:false,value:'',options:[],addEventListener(){},insertAdjacentHTML(_,html){this.options.push(...[...html.matchAll(/value="(\d+)"/g)].map(m=>({value:m[1]})));if(!this.value&&this.options.length)this.value=this.options[0].value;}});
 node('hktDHCPForm').server_id={value:'4',addEventListener(){}};
 const c=vm.createContext({$:node,modal:html=>{assert.ok(html.includes('下发任务记录'));},esc:s=>String(s??'').replaceAll('<','&lt;'),location:{origin:'https://example.test'},api:async path=>{calls.push(path);if(path.endsWith('/tasks'))return {tasks:[{id:185,status:'failed',created:100}],has_more:false};if(path.endsWith('after=0'))return {history_complete:true,events:[{id:1,created:100,stage:'issued',detail:{state:'unknown'}}],has_more:true,next_after:1};return {events:[{id:2,created:110,stage:'failed',detail:{error_code:'TimeoutExpired'}}],has_more:false};}});
 vm.runInContext(fs.readFileSync('web/ipdns.js','utf8'),c);c.hktDHCPForm([{id:4,name:'hkt'}],4);
 await new Promise(r=>setImmediate(r));
 assert.ok(calls.some(p=>p.endsWith('after=1')));
 assert.ok(node('hktTaskTimeline').innerHTML.includes('已下发'));
 assert.ok(node('hktTaskTimeline').innerHTML.includes('执行超时'));
 assert.ok(calls.every(p=>p.includes('/hkt-dhcp/tasks')));
});

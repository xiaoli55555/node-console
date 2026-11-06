// Exercise chart rendering against missing data, offline nodes and reporting gaps.
const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync('web/app.js','utf8');
const context=vm.createContext({formatRate:n=>n==null?'—':n+' bps',formatBytes:n=>n==null?'—':n+' B',Date,Number,Math});
vm.runInContext(source.slice(source.indexOf('const metricNames=')),context);
function data(){return {now:3600,seconds:3600,bucket:15,online:true,current:{cpu_percent:25,tcp:12},traffic:{},points:[{stamp:100,cpu:20,tcp:10,rx_bps:100,tx_bps:200},{stamp:115,cpu:30,tcp:12,rx_bps:120,tx_bps:220},{stamp:300,cpu:40,tcp:null,rx_bps:140,tx_bps:null}]};}
test('gaps produce separate curve segments, with a shared percentage scale',()=>{const html=context.metricWindowMarkup(data(),'cpu');assert.equal((html.match(/vector-effect=/g)||[]).length,2);assert.match(html,/100.0%/);assert.match(html,/25.0%/);assert.doesNotMatch(html,/NaN|Infinity/);});
test('offline current values remain unavailable while history is preserved',()=>{const d=data();d.online=false;d.current={};const html=context.metricWindowMarkup(d,'tcp');assert.match(html,/<strong>—<\/strong>/);assert.match(html,/服务器离线/);assert.match(html,/12/);});
test('network shows both directions and handles partial series',()=>{const html=context.metricWindowMarkup(data(),'network');assert.match(html,/↓ 下行/);assert.match(html,/↑ 上行/);assert.equal((html.match(/class="monitor-stat"/g)||[]).length,2);assert.doesNotMatch(html,/NaN|Infinity/);});
test('all-null and empty history render empty state without fabricated samples',()=>{for(const points of [[],[{stamp:200,cpu:null}]]){const d=data();d.points=points;const html=context.metricWindowMarkup(d,'cpu');assert.match(html,/暂无历史数据/);assert.doesNotMatch(html,/id="monitorSVG"/);assert.doesNotMatch(html,/NaN|Infinity/);}});

test('resource charts coexist with IP DNS scripts in production load order',()=>{
 const elements={modal:{open:true},modalBody:{querySelectorAll:()=>[]},metricWindowBody:{setAttribute:()=>{}}};
 const ctx=vm.createContext({formatRate:n=>n==null?'—':n+' bps',formatBytes:n=>n==null?'—':n+' B',Date,Number,Math,esc:String,document:{getElementById:id=>elements[id],querySelectorAll:()=>[]},$:id=>elements[id]||(elements[id]={}),setInterval:()=>0,clearInterval:()=>{},me:{role:'admin'}});
 vm.runInContext(source.slice(source.indexOf('const metricNames=')),ctx);
 vm.runInContext(fs.readFileSync('web/ipdns.js','utf8'),ctx);
 for(const key of ['cpu','memory','network','tcp','udp']){
  const html=ctx.metricWindowMarkup(data(),key);assert.match(html,/monitor-stats/);assert.doesNotMatch(html,/NaN|Infinity/);
 }
 assert.match(ctx.monitorMarkup({monitors:[],bindings:[],servers:[]}),/尚未选择 VPS/);
});
test('refresh uses chart renderer after IP monitor script is loaded',async()=>{
 const elements={modal:{open:true},modalBody:{querySelectorAll:()=>[]},metricWindowBody:{setAttribute:()=>{}},metricStatus:{}};
 const ctx=vm.createContext({formatRate:String,formatBytes:String,Date,Number,Math,esc:String,$:id=>elements[id]||(elements[id]={}),setInterval:()=>0,clearInterval:()=>{},api:async()=>data()});
 vm.runInContext("let metricState={id:6,key:'tcp',range:'1h',request:0};",ctx);
 vm.runInContext(source.slice(source.indexOf('const metricNames=')),ctx);
 vm.runInContext(fs.readFileSync('web/ipdns.js','utf8'),ctx);
 await ctx.refreshMetricWindow();assert.match(elements.metricWindowBody.innerHTML,/TCP 连接数/);assert.doesNotMatch(elements.metricStatus.textContent,/读取失败/);
});

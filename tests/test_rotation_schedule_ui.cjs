const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const app=fs.readFileSync('web/app.js','utf8'),ctx=vm.createContext({esc:String});
vm.runInContext(app.slice(app.indexOf('function drainScheduleFields('),app.indexOf('function rotationModeFields(')),ctx);
function form(){const f={drain_schedule_enabled:{checked:true}};['03:00','10:00','20:00'].forEach((v,i)=>f[`drain_boundary_${i}`]={value:v});[80,20,40,80].forEach((v,i)=>f[`drain_threshold_${i}`]={value:String(v)});return f;}
test('four complete periods have explicit switch, boundaries, strict values and default presets',()=>{
 const html=ctx.drainScheduleFields(null);assert.match(html,/北京时间/);assert.match(html,/name="drain_schedule_enabled"/);assert.match(html,/00:00–03:00/);assert.match(html,/20:00–24:00/);assert.match(html,/保存不重置轮换时间/);assert.equal((html.match(/name="drain_threshold_/g)||[]).length,4);
});
test('custom boundaries and limits round trip, off retains editable settings',()=>{
 const f=form();f.drain_boundary_1.value='11:30';f.drain_threshold_2.value='55';const cfg=ctx.drainSchedulePayload(f).drain_schedule;
 assert.equal(cfg.boundaries[1],690);assert.equal(cfg.thresholds[2],55);assert.match(ctx.drainScheduleFields({drain_schedule:cfg}),/value="11:30"/);
 f.drain_schedule_enabled.checked=false;assert.equal(ctx.drainSchedulePayload(f).drain_schedule.enabled,false);
});
test('empty, invalid, overlapping and fractional input blocks submission',()=>{
 for(const [key,value] of [['drain_boundary_0',''],['drain_boundary_0','10:00'],['drain_boundary_2','24:00'],['drain_threshold_2',''],['drain_threshold_2','0'],['drain_threshold_2','20.5']]){const f=form();f[key].value=value;assert.throws(()=>ctx.drainSchedulePayload(f));}
});
test('linked preview immediately displays adjacent boundary changes and validation errors',()=>{
 const f=form(),preview={};f.querySelector=()=>preview;const callbacks={};for(const [key,el] of Object.entries(f))el.addEventListener=(_,fn)=>callbacks[key]=fn;
 ctx.bindDrainSchedule(f);f.drain_boundary_1.value='11:00';callbacks.drain_boundary_1();assert.match(preview.innerHTML,/03:00–11:00/);assert.match(preview.innerHTML,/11:00–20:00/);
 f.drain_boundary_0.value='12:00';callbacks.drain_boundary_0();assert.match(preview.textContent,/分界时间必须递增/);
});

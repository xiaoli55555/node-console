const test=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs');
const source=fs.readFileSync('web/detectors.js','utf8');
const esc=x=>String(x??'').replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
function setup(){const c=vm.createContext({esc,console,page:'incidentHistory'});vm.runInContext(source,c);return c;}
const event={id:1,server_id:4,server_name:'<HKT>',ip:'42.2.1.2',port:443,first_failed:2000,confirmed_at:2010,closed_at:null,duration_s:10,details:[{name:'<probe>',state:'unreachable'}],evidence:{first:{ip_observed_since:1000,ip_age_s:1000,ip_start_censored:true,carrier_state:'serving',bindings:[{rr:'edge',domain:'<domain>',line:'unicom',binding_id:9,rotation_id:1}]},confirmed:{ip_observed_since:1000,ip_age_s:1010,ip_start_censored:true,carrier_state:'standby'}}};
test('serving fault badge preserves first vs confirmed roles and censored lifespan',()=>{
 const c=setup(),html=c.incidentGroupsMarkup([event]);
 for(const text of ['承载中首次不通','incident-serving','原分配起点未知','至少已观察','首次不通时：承载中','确认时：未处于已确认','&lt;HKT&gt;','&lt;probe&gt;','&lt;domain&gt;'])assert.ok(html.includes(text),text);
 assert.doesNotMatch(html,/<HKT>|<probe>|<domain>/);
});
test('legacy unknown is never retroactively classified as serving',()=>{
 const c=setup(),html=c.incidentEvidenceMarkup({...event,evidence:{}});assert.match(html,/历史承载状态未知/);assert.match(html,/存活周期：未知/);assert.doesNotMatch(html,/class="incident-badge incident-serving"/);
});
test('per-VPS filter and older pagination issue only scoped read requests',async()=>{
 const c=setup(),calls=[],elements={modal:{open:false},incidentHistoryContent:{},incidentServerFilter:{value:'4'},incidentCarrierFilter:{checked:true},refreshIncidentHistory:{},incidentLoadMore:{},incidentHistoryRows:{},incidentHistoryError:{}};
 c.$=id=>elements[id];c.navigate=async p=>{c.page=p;};c.notice=()=>{};
 c.api=async path=>{calls.push(path);return {incidents:[event],servers:[{id:4,name:'HKT'}],notice:'notice',has_more:!path.includes('before='),next_cursor:10};};
 await c.showDetectionIncidents(4);await c.loadIncidentHistory();assert.equal(calls[0],'detection/incidents?server_id=4');
 await elements.incidentCarrierFilter.onchange();await new Promise(resolve=>setImmediate(resolve));assert.equal(calls[1],'detection/incidents?server_id=4&carrier_only=1');
 await elements.incidentLoadMore.onclick();assert.equal(calls[2],'detection/incidents?server_id=4&carrier_only=1&before=10');assert.equal(elements.incidentLoadMore.hidden,true);
});
test('late incident response does not overwrite another page',async()=>{
 const c=setup(),host={innerHTML:'unchanged'};c.$=()=>host;let resolve;c.api=()=>new Promise(r=>resolve=r);
 const loading=c.loadIncidentHistory();c.page='servers';resolve({incidents:[event]});await loading;assert.equal(host.innerHTML,'unchanged');
});

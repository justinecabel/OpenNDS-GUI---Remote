// Dependency-free browser logic regressions; run with Node in an isolated container.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const html=fs.readFileSync('templates/index.html','utf8');
const full=html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(full); // Validate the complete production script, including event handlers.
assert.doesNotMatch(html, /api\/domains|client_last_dns|client_dns_play|domain_watch|loadClientDns/);
const merge=full.slice(full.indexOf('function mergeHistory('),full.indexOf('let overviewHistoryCursor='));
const history=full.slice(full.indexOf('let clientDetailGeneration='),full.indexOf('function showClientDetail('));
function fixture(){
  const requests=[],draws=[],dialog={open:true};
  const context={document:{hidden:false},busy:false,clientDetailMac:'client-a',clientHistory:[],clientHistoryResolution:'minutes',
    URLSearchParams,AbortController,encodeURIComponent,$:()=>dialog,
    api:(url,options)=>new Promise(resolve=>requests.push({url,options,resolve})),
    drawClientTraffic:points=>draws.push(points)};
  vm.createContext(context);vm.runInContext(merge+history,context);
  return {context,requests,draws,dialog,run:source=>vm.runInContext(source,context)};
}
const reply=(at,generation='server')=>({ok:true,history:[{at,download:42,upload:0}],reset:true,
  cursor:at,history_start_at:at,recent_start_at:at,generation,recent_resolution:'seconds'});
// Exercise the production canvas renderer, including time filtering and point positions.
const chart=full.slice(full.indexOf('function drawRateChart('),full.indexOf('const CHART_RANGES='));
function renderChart(points,rangeSecs,now=10000){
  const paths=[],labels=[];
  class Path2D {
    constructor(copy){this.points=copy?[...copy.points]:[];}
    moveTo(x,y){this.points.push({x,y});}
    bezierCurveTo(a,b,c,d,x,y){this.points.push({x,y});}
    lineTo(){}closePath(){}
  }
  const ctx={setTransform(){},clearRect(){},beginPath(){},moveTo(){},lineTo(){},stroke(path){if(path)paths.push(path);},
    fill(){},arc(){},fillText(text){labels.push(text);},createLinearGradient(){return {addColorStop(){}};}};
  const canvas={getContext:()=>ctx,getBoundingClientRect:()=>({width:670})};
  const context={Date:{now:()=>now*1000},window:{devicePixelRatio:1},document:{documentElement:{}},
    getComputedStyle:()=>({getPropertyValue:()=>''}),Path2D,fmtRate:String,periodLabel:String,canvas,points,rangeSecs};
  vm.createContext(context);vm.runInContext(chart,context);
  vm.runInContext("drawRateChart(canvas,points,rangeSecs,260,'No samples in this range',180)",context);
  return {paths,labels};
}
(async()=>{
  const cacheCalls=[],cacheContext={busy:false,sqmViewPromise:null,sqmLoaded:true,sqmRuleLoaded:true,
    sqmViewWaiting:false,sqmCachePending:false,initSqmUnit(){},renderSqmLoading(){},
    loadSqmBase:(...args)=>{cacheCalls.push(args);return Promise.resolve();},
    loadSqmRule:()=>Promise.resolve(),loadQosStatus:()=>Promise.resolve()};
  vm.createContext(cacheContext);
  vm.runInContext(full.slice(full.indexOf('function loadSqmView('),full.indexOf('async function loadSqmBase('))+full.slice(full.indexOf('async function loadSqmStatus('),full.indexOf('// Poll only read-only tabs;')),cacheContext);
  await vm.runInContext('loadSqmForNavigation()',cacheContext);
  assert.deepEqual(cacheCalls.pop(),[true,true,false],'navigation must use the cached settings endpoint');
  await vm.runInContext('loadSqm()',cacheContext);
  assert.deepEqual(cacheCalls.pop(),[false,false,true],'explicit Reload must request real router settings');
  await vm.runInContext('loadSqmStatus()',cacheContext);
  assert.equal(cacheCalls.length,0,'ordinary status polling must not touch settings drafts');
  await vm.runInContext('sqmCachePending=true;loadSqmStatus()',cacheContext);
  assert.deepEqual(cacheCalls.pop(),[true,true,false],'pending snapshots retry cheaply while preserving drafts');
  console.log('PASS: SQM navigation uses cache; Reload verifies router; cold snapshots retry without clobbering drafts');
  const badgeSource=full.slice(full.indexOf('function renderQosBadge('),full.indexOf('function renderSqmSingleStatus('));
  const badgeClasses=new Set(),badgeAttributes={},badge={dataset:{},textContent:'Active',
    classList:{toggle:(name,on)=>on?badgeClasses.add(name):badgeClasses.delete(name)},
    setAttribute:(name,value)=>badgeAttributes[name]=value};
  const badgeContext={badge};vm.createContext(badgeContext);vm.runInContext(badgeSource,badgeContext);
  for(const state of ['unknown','pending']){
    vm.runInContext(`renderQosBadge(badge,'${state}')`,badgeContext);
    assert.equal(badge.textContent,'');assert.ok(badgeClasses.has('qos-status-loading'));
    assert.equal(badgeAttributes['aria-busy'],'true');assert.equal(badgeAttributes['aria-label'],'Loading status');
  }
  vm.runInContext("renderQosBadge(badge,'unknown',true)",badgeContext);
  assert.equal(badge.textContent,'Unavailable');assert.ok(!badgeClasses.has('qos-status-loading'));
  for(const [state,label] of [['active','Active'],['ready','Active'],['off','Off'],['error','Error']]){
    vm.runInContext(`renderQosBadge(badge,'${state}')`,badgeContext);assert.equal(badge.textContent,label);
    assert.equal(badgeAttributes['aria-busy'],'false');assert.ok(!badgeClasses.has('qos-status-loading'));
  }
  console.log('PASS: unverified status uses a circular loader; real failures never display Active');
  const oldPoints=[{at:6000,download:100,upload:50},{at:6060,download:200,upload:70}];
  let graph=renderChart(oldPoints,60);
  assert.equal(graph.paths.length,0,'offline activity from an hour ago must not appear in the last minute');
  assert.ok(graph.labels.includes('No samples in this range'));
  graph=renderChart(oldPoints,21600);
  assert.equal(graph.paths.length,2,'older activity must remain available in a wider range');
  const oldX=graph.paths[0].points.at(-1).x;
  assert.ok(Math.abs(oldX-(58+(6060-(10000-21600))/21600*600))<0.001,'old samples must keep their actual position before now');
  graph=renderChart([{at:9990,download:42,upload:0},{at:9995,download:0,upload:0},{at:10001,download:999999,upload:999999}],60);
  assert.equal(graph.paths[0].points.length,2,'future samples must not be moved to now');
  assert.equal(graph.paths[0].points[0].x,558);
  assert.equal(graph.paths[0].points[1].x,608,'the last sample leaves its real gap before now');
  assert.ok(!graph.labels.includes('No samples in this range'),'measured zero is still a sample');
  assert.ok(!renderChart([{at:9995,download:0,upload:0}],60).labels.includes('No samples in this range'));
  assert.ok(renderChart([{at:9995,download:null,upload:null}],60).labels.includes('No samples in this range'));
  assert.ok(renderChart([{at:9990,download:42,upload:0}],60,10060).labels.includes('No samples in this range'),'unchanged history must age out as time advances');
  console.log('PASS: charts anchor to current time, preserve old positions, and show empty ranges without inventing activity');

  const overviewAppend=full.slice(full.indexOf('function appendOverviewSample('),full.indexOf('function mergeHistory('));
  const overviewContext={overviewHistoryLoaded:true,overviewData:{history:[]},drawTraffic(){}};
  vm.createContext(overviewContext);vm.runInContext(overviewAppend,overviewContext);
  vm.runInContext('appendOverviewSample({updated_at:100,live:{download:null,upload:null}})',overviewContext);
  assert.equal(overviewContext.overviewData.history[0].download,null,'a baseline is a gap, not zero traffic');
  vm.runInContext('appendOverviewSample({updated_at:101,live:{download:0,upload:0}})',overviewContext);
  assert.equal(overviewContext.overviewData.history[1].download,0,'confirmed idle clients record actual zero');
  vm.runInContext('appendOverviewSample({updated_at:102,live:{download:42,upload:21}})',overviewContext);
  vm.runInContext('appendOverviewSample({updated_at:102,stale:true,live:{download:null,upload:null}})',overviewContext);
  assert.equal(overviewContext.overviewData.history[2].download,42,'an aging sample must retain its recorded history');
  vm.runInContext('appendOverviewSample({updated_at:103,stale:true,live:{download:null,upload:null}})',overviewContext);
  assert.equal(overviewContext.overviewData.history[3].download,null,'a new failed interval remains a gap');
  console.log('PASS: Overview distinguishes unavailable samples from idle clients and preserves recorded history');

  let f=fixture();
  const first=f.run('loadClientHistory()'),duplicate=f.run('loadClientHistory()');
  assert.equal(f.requests.length,1,'slow requests must not overlap');
  f.requests[0].resolve(reply(100));await Promise.all([first,duplicate]);
  const second=f.run('loadClientHistory()');
  assert.match(f.requests[1].url,/since=100&generation=server/,'subsequent polls must use cursor');
  f.requests[1].resolve({...reply(101),reset:false,history_start_at:100,recent_start_at:100});await second;
  assert.deepEqual(Array.from(f.context.clientHistory,p=>p.at),[100,101]);
  console.log('PASS: requests coalesce and history uses incremental cursors');

  f=fixture();f.context.document.hidden=true;await f.run('loadClientHistory()');
  assert.equal(f.requests.length,0);
  f.context.document.hidden=false;const hidden=f.run('loadClientHistory()');
  f.context.document.hidden=true;f.requests[0].resolve(reply(100));await hidden;
  assert.equal(f.draws.length,0,'hidden response must not draw');
  console.log('PASS: hidden tabs stop requests and discard late responses');

  f=fixture();const old=f.run('loadClientHistory()');
  f.run("clientHistoryController.abort();clientDetailGeneration++;clientHistoryPromise=null;clientHistoryCursor=null;clientDetailMac='client-b';");
  const newer=f.run('loadClientHistory()');
  assert.equal(f.requests[0].options.signal.aborted,true);
  f.requests[0].resolve(reply(100));await old;
  assert.equal(f.draws.length,0,'old client must not replace new client graph');
  assert.equal(f.run('clientHistoryPromise!==null'),true,'old completion must not clear new request');
  f.requests[1].resolve(reply(200));await newer;
  assert.equal(f.context.clientHistory[0].at,200);
  console.log('PASS: switching clients aborts and ignores obsolete requests');

  f=fixture();const same=f.run('loadClientHistory()');
  f.run('clientDetailGeneration++;clientHistoryPromise=null;');
  f.requests[0].resolve(reply(100));await same;
  assert.equal(f.draws.length,0,'reopening same MAC must reject old generation');
  console.log('PASS: reopening the same client ignores previous dialog responses');

  f=fixture();f.context.previous=[{at:120,download:1},{at:180,download:2},{at:181,download:3}];
  f.context.delta={reset:false,history:[{at:180,download:20},{at:182,download:null}],history_start_at:120,recent_start_at:182};
  const merged=f.run('mergeHistory(previous,delta)');
  assert.deepEqual(Array.from(merged,p=>p.at),[120,180,182]);
  assert.equal(merged[1].download,20,'mutable boundary must be replaced');
  assert.equal(merged[2].download,null,'unavailable rates must retain their gap');
  f.context.delta.reset=true;
  assert.deepEqual(Array.from(f.run('mergeHistory(previous,delta)'),p=>p.at),[180,182]);
  console.log('PASS: merge replaces boundary values, prunes old seconds, and honors reset/gaps');


})().catch(error=>{console.error(error);process.exitCode=1;});

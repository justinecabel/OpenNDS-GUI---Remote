// Dependency-free browser logic regressions; run with Node in an isolated container.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const html=fs.readFileSync('templates/index.html','utf8');
const full=html.match(/<script>([\s\S]*?)<\/script>/)[1];
new vm.Script(full); // Validate the complete production script, including event handlers.
const merge=full.slice(full.indexOf('function mergeHistory('),full.indexOf('let overviewHistoryCursor='));
const history=full.slice(full.indexOf('let clientDetailGeneration='),full.indexOf('async function loadClientDns('));
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
(async()=>{
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


  const resetSource=full.slice(full.indexOf('async function resetDomainWatchlist('),full.indexOf('async function addDomainWatch('));
  const requests=[],controls=[],note={textContent:''};let reloads=0;
  const context={busy:false,domainWatchLoaded:true,domainsPromise:null,domainsLoadedAt:123,
    domainWatched:['example.com'],$:()=>note,domainWatchControls:value=>controls.push(value),
    renderDomainWatchlist:()=>{},loadDomainRanking:async()=>{reloads++;},
    api:(url,options)=>new Promise(resolve=>requests.push({url,options,resolve}))};
  vm.createContext(context);vm.runInContext(resetSource,context);
  const reset=vm.runInContext('resetDomainWatchlist()',context);
  const repeated=vm.runInContext('resetDomainWatchlist()',context);
  await Promise.resolve();
  assert.equal(requests.length,1,'reset must serialize against other actions');
  assert.equal(requests[0].url,'/api/domains/reset');assert.equal(requests[0].options.method,'POST');
  requests[0].resolve({ok:true,watched:['example.com']});
  assert.equal(await reset,true);assert.equal(await repeated,false);
  assert.equal(note.textContent,'Counts cleared');assert.equal(reloads,1);
  assert.deepEqual(controls,[true,false]);assert.equal(context.busy,false);
  const failed=vm.runInContext('resetDomainWatchlist()',context);await Promise.resolve();
  requests[1].resolve({ok:false,output:'DNS reset failed: router unavailable'});
  assert.equal(await failed,false);assert.match(note.textContent,/router unavailable/);
  assert.equal(reloads,1,'failed reset must retain the displayed data');assert.equal(context.busy,false);
  console.log('PASS: watchlist reset serializes actions, refreshes counts, and recovers from failures');
})().catch(error=>{console.error(error);process.exitCode=1;});

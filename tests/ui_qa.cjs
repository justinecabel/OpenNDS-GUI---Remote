// Browser QA with synthetic data. Every API call is intercepted; no router writes.
// Optional test tooling only: install Playwright/Chromium outside the workspace.
// Run from the project directory with PLAYWRIGHT_MODULE and CHROMIUM_PATH if needed.
// --layout-only / --behavior-only selects one pass. Artifacts default to /tmp/opennds-ui-qa.
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const fs=require('fs'),assert=require('node:assert/strict');
const project=process.env.UI_PROJECT_ROOT||process.cwd();
const root=process.env.UI_QA_OUTPUT||'/tmp/opennds-ui-qa',tabs=['overview','clients','portal','sqm','mode','limits','punishment','status','logs'];fs.mkdirSync(root,{recursive:true});
const render=s=>s.replaceAll('{% raw %}','').replaceAll('{% endraw %}','').replace(/\{\{ url_for\('static', filename='([^']+)'\) \}\}/g,'/static/$1');
const html=render(fs.readFileSync(project+'/templates/index.html','utf8')),login=render(fs.readFileSync(project+'/templates/login.html','utf8')).replace('{{ next_url }}','/').replace('{{ error }}','');
const now=Math.floor(Date.now()/1000),mac='02:00:00:00:00:99',long='office-'+ 'wireless-device-'.repeat(7)+'99',longDomain='a'.repeat(63)+'.'+'b'.repeat(63)+'.example.com';
const sample={mac,hostname:'Work laptop',ip:'192.168.1.99',online:true,state:'Authenticated',last_active:now,wan_download_rate:1234000,wan_upload_rate:64000,wan_today_download_bytes:234234234,wan_today_upload_bytes:45656756,wan_month_download_bytes:5434534534,wan_month_upload_bytes:556565665};
const history=Array.from({length:361},(_,i)=>({at:now-3600+i*10,download:20000+Math.abs(Math.sin(i/13))*2200000,upload:12000+Math.abs(Math.cos(i/17))*120000}));
let stress=false,networkFail='',fail='',delay=0,writes=[],reads=[];
const state={mode:'portal',config:"config opennds\n\toption enabled '1'\n\toption gatewayname 'Open NDS'\n",limits:{ok:true,default:{up:5000,down:5000,latency_ms:0},devices:{[mac]:{up:250,down:500}},profiles:{Open:{latency_ms:0},Standard:{up:128,down:256},Guest:{up:64,down:128}}},watched:['example.com','youtube.com'],punishment:{ok:true,delay_ms:100,loss_pct:1,download:128,upload:64,tc_active:true},sqm:{enabled:'1',interface:'br-lan',download:12500,upload:25000,qdisc:'cake',script:'piece_of_cake.qos'},rule:{ok:true,enabled:true,threshold_gb:50,download:1024,upload:512,today_bytes:12412312345,today_date:'2026-10-08',wan_interface:'eth0',active:false}};
function fixture(path){
 if(path==='/api/overview')return {ok:true,connected:5,interface:'eth0',updated_at:now,tracking_since:now-20000,live:{download:stress?123456789012:1234000,upload:stress?123456789012:64000},today:{download:21453453434,upload:545454343},month:{download:214534534343,upload:5454543434}};
 if(path.endsWith('/history'))return {ok:true,history,resolution:'seconds',reset:true,cursor:now,generation:'qa',history_start_at:now-86400,recent_start_at:now-3600};
 if(path.endsWith('/dns'))return {ok:true,last_dns:Array.from({length:10},(_,i)=>({domain:stress?longDomain:'cdn'+i+'.example.com',at:now-i*30}))};
 if(path==='/api/clients')return {ok:true,sampled_at:now,data:{clients:{laptop:{...sample,hostname:stress?long:sample.hostname},phone:{...sample,mac:'02:00:00:00:00:98',hostname:'Phone',punished:true,added_ping_ms:100},offline:{...sample,mac:'02:00:00:00:00:97',hostname:'Living room TV',online:false,state:'Offline',last_active:now-86500},trusted:{...sample,mac:'02:00:00:00:00:96',hostname:'Trusted device',trusted:true},blocked:{...sample,mac:'02:00:00:00:00:95',hostname:'Blocked device',blocked:true},throttled:{...sample,mac:'02:00:00:00:00:94',hostname:'Throttled device',throttle:{download:true}}}}};
 if(path==='/api/domains')return {ok:true,watched:stress?[longDomain,...state.watched]:state.watched,domains:(stress?[longDomain,...state.watched]:state.watched).map((domain,i)=>({domain,queries:1234+i,subdomains:[{name:stress?longDomain:'cdn.'+domain,queries:100}],clients:[{name:stress?long:'Work laptop',queries:100}]}))};
 if(path==='/api/status')return {ok:true,output:'openNDS Status\nVersion: 10.3.1\nUptime: 1 day\nGateway: Open NDS\nGateway FQDN: status.client\nManaged interface: br-lan\nFAS: Secure Level 1, URL: http://192.168.1.198:8080/fas\nActive clients: 5\nClient authentications since start: 20\nTotal download: 123456 kByte; average: 35 kbit/s\nTotal upload: 12345 kByte; average: 3 kbit/s\n'+('Detailed status line\n').repeat(80)};
 if(path==='/api/config')return {ok:true,content:state.config};
 if(path==='/api/logs')return {ok:true,output:('Oct 8 10:20:35 openNDS: '+(stress?long:'authenticated 192.168.1.99')+'\n').repeat(40)};
 if(path==='/api/limits'||path==='/api/limits/profile')return state.limits;
 if(path==='/api/mode')return {ok:true,mode:state.mode,auto_trusted:0,auto_authed:2};
 if(path==='/api/punishment')return state.punishment;
 if(path==='/api/sqm')return {ok:true,configured:true,config:state.sqm,interfaces:['br-lan','eth0'],interface_roles:{'br-lan':'LAN','eth0':'WAN'}};
 if(path==='/api/sqm/conditional')return state.rule;
 if(path==='/api/portal/types')return {ok:true,current:'custom',types:[{id:'default',name:'Default'},{id:'custom',name:'Cats'}]};
 if(path==='/api/portal/fas')return {ok:true,url:'http://192.168.1.198:8080',router_ready:true,manager_mode:'portal',old_portal_archived:false};
 return {ok:true,output:'Action completed'};
}
(async()=>{const browser=await chromium.launch({executablePath:process.env.CHROMIUM_PATH||'/usr/bin/chromium',args:['--no-sandbox']});try{
 const context=await browser.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'}),page=await context.newPage(),errors=[],issues=[];page.on('pageerror',e=>errors.push(e.message));
 await context.addInitScript(theme=>localStorage.setItem('opennds-theme',theme),process.env.UI_THEME||'classic');
 await context.route('http://manager.test/**',async route=>{const req=route.request(),path=new URL(req.url()).pathname;
 if(path==='/')return route.fulfill({contentType:'text/html',body:html});if(path==='/login')return route.fulfill({contentType:'text/html',body:login});
 if(path.startsWith('/static/'))return route.fulfill({contentType:path.endsWith('.js')?'application/javascript':'text/css',body:fs.readFileSync(project+path,'utf8')});
 if(networkFail===path&&req.method()!=='GET')return route.abort('failed');
 if(delay&&path==='/api/limits')await new Promise(r=>setTimeout(r,delay));
 if(req.method()==='GET')reads.push(path);else{writes.push({path,method:req.method(),body:req.postDataJSON()});if(path==='/api/mode')state.mode=req.postDataJSON().mode;if(path==='/api/config')state.config=req.postDataJSON().content;if(path==='/api/domains/watch'&&fail!==path)state.watched=[...new Set(req.postDataJSON().domains)].sort();}
 return route.fulfill({contentType:'application/json',body:JSON.stringify(fail===path?{ok:false,output:'QA API failure '+long}:fixture(path))});});
 const load=async tab=>{await page.goto('http://manager.test/?qa='+Date.now()+Math.random()+'#'+tab);await page.evaluate(async tab=>{await ({overview:loadOverview,clients:loadClients,portal:loadHostedPortalStatus,sqm:loadSqm,mode:loadMode,limits:loadLimits,punishment:loadPunishment,status:loadStatusConfig,logs:loadLogs})[tab]();if(tab==='overview'){await loadOverviewHistory();await loadDomainRanking();}await document.fonts.ready;},tab);};
 const geometry=async(name,width)=>{const found=await page.evaluate(()=>{
  const issues=[],visible=el=>el.getClientRects().length&&getComputedStyle(el).visibility!=='hidden',allowed=el=>{for(let p=el;p&&p!==document.body;p=p.parentElement){if(/auto|scroll|hidden/.test(getComputedStyle(p).overflowX)&&p.scrollWidth>p.clientWidth+1)return true;}return false;};
  const sqmHead=document.querySelector('#sqm.active .sqm-heading>div:first-child');if(sqmHead&&sqmHead.getBoundingClientRect().height>180)issues.push('SQM heading excess height');
  if(document.documentElement.scrollWidth>innerWidth+1)issues.push('root overflow '+document.documentElement.scrollWidth);
  for(const el of document.querySelectorAll('section.active button,section.active input,section.active select,section.active summary,dialog[open] button,dialog[open] h4,dialog[open] canvas,dialog[open] ol,dialog[open] .domain-detail-grid')){
   if(!visible(el)||(!el.closest('dialog')&&allowed(el)))continue;const r=el.getBoundingClientRect(),dialog=el.closest('dialog'),bounds=dialog?dialog.getBoundingClientRect():{left:0,right:innerWidth};
   if(r.left<bounds.left-1||r.right>bounds.right+1)issues.push('outside '+(el.id||el.className||el.tagName));
   if(el.tagName==='BUTTON'&&el.scrollWidth>el.clientWidth+2&&getComputedStyle(el).textOverflow!=='ellipsis')issues.push('clipped button '+(el.id||el.textContent));
  }
  for(const el of document.querySelectorAll('dialog[open]'))if(el.scrollWidth>el.clientWidth+1)issues.push('dialog overflow '+el.id+' '+el.scrollWidth+'/'+el.clientWidth);
  return issues;
 });for(const issue of found)issues.push({name,width,issue});};
if(!process.argv.includes('--behavior-only')){
 const widths=[...new Set([...Array.from({length:71},(_,i)=>320+i*32),375,390,412,568,599,600,601,768,899,900,901,1024,1099,1100,1101,1199,1200,1201,1440,1920,2560])].sort((a,b)=>a-b);
 for(stress of [false,true]){for(const tab of tabs){await load(tab);for(const width of widths){await page.setViewportSize({width,height:1000});await geometry((stress?'stress-':'')+tab,width);if([320,768,1100,1920].includes(width))await page.screenshot({path:root+'/'+(stress?'stress-':'')+tab+'-'+width+'.png',fullPage:true});}console.log('Swept '+(stress?'stress ':'')+tab);}}
 const dialogWidths=[320,375,390,568,600,768,900,901,1099,1100,1440,1920];
 for(const width of dialogWidths){await page.setViewportSize({width,height:width===568?320:844});await load('overview');await page.locator('#domain_list button').first().click();await geometry('domain-dialog',width);await page.screenshot({path:root+'/domain-dialog-'+width+'.png'});await page.keyboard.press('Escape');
 await page.locator('#domain_watch_open').click();await geometry('watchlist-dialog',width);await page.screenshot({path:root+'/watchlist-dialog-'+width+'.png'});await page.keyboard.press('Escape');
 await load('clients');await page.locator('#ctable tr').filter({hasText:long}).locator('.btn-link').click();await page.waitForFunction(()=>document.getElementById('client_detail').open);await geometry('client-dialog',width);await page.screenshot({path:root+'/client-dialog-'+width+'.png'});await page.keyboard.press('Escape');
 if(width<=900){await page.locator('#ctable tr').filter({hasText:long}).locator('.client-actions-more').click();await geometry('action-dialog',width);await page.screenshot({path:root+'/action-dialog-'+width+'.png'});await page.keyboard.press('Escape');}
 await page.goto('http://manager.test/login');await geometry('login',width);if([320,768,1920].includes(width))await page.screenshot({path:root+'/login-'+width+'.png'});
 }
 // Contrast audit on actual visible text/background pairs.
 stress=false;const contrast=[];
 for(const tab of tabs){await page.setViewportSize({width:1440,height:1000});await load(tab);contrast.push(...await page.evaluate(tab=>{
  const rgb=s=>s.match(/[\d.]+/g)?.slice(0,3).map(Number),luminance=c=>c.map(v=>{v/=255;return v<=.04045?v/12.92:((v+.055)/1.055)**2.4;}).reduce((sum,v,i)=>sum+v*[.2126,.7152,.0722][i],0);
  const result=[];
  for(const el of document.querySelectorAll('section.active *,#site_header *')){if(!el.getClientRects().length||el.disabled||!Array.from(el.childNodes).some(n=>n.nodeType===3&&n.textContent.trim())||el.closest('canvas,svg,style,script'))continue;
   const s=getComputedStyle(el);let p=el,bg;while(p){const color=getComputedStyle(p).backgroundColor;if(color!=='rgba(0, 0, 0, 0)'&&color!=='transparent'){bg=rgb(color);break;}p=p.parentElement;}bg||=[255,255,255];const fg=rgb(s.color);if(!fg)continue;const a=luminance(fg),b=luminance(bg),ratio=(Math.max(a,b)+.05)/(Math.min(a,b)+.05),large=parseFloat(s.fontSize)>=24||(parseFloat(s.fontSize)>=18.66&&parseInt(s.fontWeight)>=700);
   if(ratio<(large?3:4.5)-.01)result.push({tab,element:el.id||el.className||el.tagName,text:el.textContent.trim().slice(0,50),color:s.color,bg,ratio:Math.round(ratio*100)/100});
  }return result;
 },tab));}
 fs.writeFileSync(root+'/report.json',JSON.stringify({widths,issues,errors,contrast},null,2));
 const grouped={};for(const i of issues){const key=i.name+' '+i.issue;(grouped[key]||=new Set()).add(i.width);}console.log(JSON.stringify({issues:Object.fromEntries(Object.entries(grouped).map(([k,v])=>[k,[...v]])),errors,contrast},null,2));
assert.deepEqual(issues,[]);assert.deepEqual(errors,[]);assert.deepEqual(contrast,[]);
}
if(!process.argv.includes('--layout-only')){stress=false;fail='';delay=0;
 const checks=[];

 const check=async(name,fn)=>{try{await fn();checks.push({name,pass:true});}catch(e){checks.push({name,pass:false,error:e.message});}};
 await check('watchlist modal keyboard, draft and polling focus',async()=>{
 await load('overview');await page.locator('#domain_watch_open').click();await page.locator('#domain_watch_input').fill('draft.example');await page.evaluate(()=>loadDomainRanking());assert.equal(await page.locator('#domain_watch_input').inputValue(),'draft.example');assert.equal(await page.locator('#domain_watch_input').evaluate(el=>el===document.activeElement),true);const remove=page.getByRole('button',{name:'Remove example.com',exact:true});await remove.focus();await page.evaluate(()=>loadDomainRanking());assert.equal(await remove.evaluate(el=>el===document.activeElement),true);await page.keyboard.press('Escape');assert.equal(await page.locator('#domain_watch_open').evaluate(el=>el===document.activeElement),true);await page.locator('#domain_watch_open').click();assert.equal(await page.locator('#domain_watch_input').inputValue(),'draft.example');await page.keyboard.press('Escape');
 });
 await check('watchlist add/remove updates modal, count and ranking',async()=>{
 await load('overview');await page.locator('#domain_watch_open').click();await page.locator('#domain_watch_input').fill('test.example');await page.locator('#domain_watch_input').press('Enter');await page.waitForFunction(()=>document.getElementById('domain_watch_input').value==='');assert.equal(await page.locator('#domain_watch_count').textContent(),'(3)');assert.equal(await page.locator('#domain_list button').count(),3);await page.getByRole('button',{name:'Remove test.example',exact:true}).click();await page.waitForFunction(()=>document.getElementById('domain_watch_count').textContent==='(2)');await page.waitForFunction(()=>!busy);assert.equal(await page.locator('#domain_list button').count(),2);assert.equal(await page.getByRole('button',{name:'Remove youtube.com',exact:true}).evaluate(el=>el===document.activeElement),true);await page.keyboard.press('Escape');
 });
 await check('watchlist failures preserve draft/list inside modal',async()=>{
 await load('overview');await page.locator('#domain_watch_open').click();await page.locator('#domain_watch_input').fill('retry.example');for(const failure of ['api','network']){if(failure==='api')fail='/api/domains/watch';else networkFail='/api/domains/watch';await page.locator('#domain_watch_add').click();await page.waitForFunction(()=>!busy);assert.equal(await page.locator('#domain_watch_input').inputValue(),'retry.example');assert.equal(await page.locator('#domain_watch_list button').count(),2);assert.ok((await page.locator('#domain_watch_out').textContent()).includes('fail'));fail='';networkFail='';}await page.keyboard.press('Escape');
 });
 await check('watchlist serialized saves and empty state',async()=>{
 await load('overview');await page.locator('#domain_watch_open').click();const n=writes.length;await page.evaluate(()=>Promise.all([saveDomainWatchlist([]),saveDomainWatchlist([])]));assert.equal(writes.slice(n).filter(w=>w.path==='/api/domains/watch').length,1);assert.equal(await page.locator('#domain_watch_count').textContent(),'(0)');assert.equal(await page.locator('#domain_watch_list').textContent(),'No domains');await page.evaluate(()=>saveDomainWatchlist(['example.com','youtube.com']));await page.keyboard.press('Escape');
 });
 await check('watchlist long list scrolls; padding keeps open, backdrop closes',async()=>{
 state.watched=Array.from({length:50},(_,i)=>i+'.'+longDomain);for(const width of [320,390,768,1440]){await page.setViewportSize({width,height:844});await load('overview');await page.locator('#domain_watch_open').click();const dialog=page.locator('#domain_watch_dialog');assert.equal(await page.locator('#domain_watch_list').evaluate(el=>el.scrollHeight>el.clientHeight),true);assert.equal(await dialog.evaluate(el=>el.scrollWidth<=el.clientWidth+1&&el.getBoundingClientRect().height<=innerHeight-30),true);const r=await dialog.boundingBox();await page.mouse.click(r.x+2,r.y+2);assert.equal(await dialog.evaluate(el=>el.open),true);await page.mouse.click(2,2);assert.equal(await dialog.evaluate(el=>el.open),false);assert.equal(await page.locator('#domain_watch_open').evaluate(el=>el===document.activeElement),true);}state.watched=['example.com','youtube.com'];await page.setViewportSize({width:1440,height:1000});
 });
 await check('blank Device MAC cannot save Default',async()=>{await load('limits');const n=writes.length;await page.locator('#lim_mac').fill('');await page.getByRole('button',{name:'Save device override'}).click();assert.equal(writes.length,n);assert.equal(await page.locator('#limout').textContent(),'Valid MAC required');});
 await check('client table refresh retains keyboard focus',async()=>{
 await load('clients');const button=page.locator('#ctable tr').filter({hasText:'Work laptop'}).locator('.client-name-edit');await button.focus();await page.evaluate(()=>loadClients());assert.equal(await button.evaluate(el=>el===document.activeElement),true);
 });
 await check('client dialog Escape restores focus after polling',async()=>{
 await load('clients');const button=page.locator('#ctable tr').filter({hasText:'Work laptop'}).locator('.btn-link');await button.click();await page.evaluate(()=>loadClients());await page.keyboard.press('Escape');assert.equal(await button.evaluate(el=>el===document.activeElement),true);
 });
 await check('DNS ranking refresh preserves open detail',async()=>{
 await load('overview');await page.evaluate(()=>loadDomainRanking());await page.locator('#domain_list button').first().click();await page.evaluate(()=>loadDomainRanking());assert.equal(await page.locator('#domain_detail').evaluate(el=>el.open),true);
 });
 await check('client Limits waits for a slow settings response',async()=>{
 await load('clients');delay=700;await page.locator('#ctable tr').filter({hasText:'Work laptop'}).getByRole('button',{name:'limits',exact:true}).click();await page.waitForFunction(()=>document.getElementById('lv_up')?.value==='250');assert.equal(await page.locator('#lim_mac').inputValue(),mac);assert.equal(await page.locator('#lv_up').inputValue(),'250');delay=0;
 });delay=0;
 await check('Limits failed reload preserves edits and reports error',async()=>{
 await load('limits');await page.locator('#ld_up').fill('321');fail='/api/limits';await page.evaluate(()=>loadLimits());assert.equal(await page.locator('#ld_up').inputValue(),'321');assert.ok((await page.locator('#lim_default_out').textContent()).includes('QA API failure'));fail='';
 });fail='';
 await check('SQM failed reload preserves edits and reports error',async()=>{
 await load('sqm');await page.locator('#sqm_down').fill('321');fail='/api/sqm';await page.evaluate(()=>loadSqm());assert.equal(await page.locator('#sqm_down').inputValue(),'321');assert.ok((await page.locator('#sqmout').textContent()).includes('QA API failure'));fail='';
 });fail='';
 await check('chart ranges survive reload, independent for overview/client',async()=>{
 await load('overview');await page.locator('#overview_chart_range').selectOption('900');await page.reload();await page.waitForFunction(()=>document.getElementById('overview_chart_range').value==='900');await load('clients');await page.locator('#ctable .btn-link').first().click();await page.locator('#client_chart_range').selectOption('300');await page.keyboard.press('Escape');await page.reload();await page.locator('#ctable .btn-link').first().click();assert.equal(await page.locator('#client_chart_range').inputValue(),'300');assert.equal(await page.locator('#overview_chart_range').inputValue(),'900');await page.keyboard.press('Escape');
 });
 await check('SQM unit changes preserve canonical rates and survive reload',async()=>{
 await load('sqm');await page.locator('#sqm_unit').selectOption('Mb/s');assert.equal(await page.locator('#sqm_down').inputValue(),'100');await page.getByRole('button',{name:'Apply base queue',exact:true}).click();assert.equal(writes.filter(w=>w.path==='/api/sqm').at(-1).body.download,'12500');await page.reload();await page.waitForFunction(()=>document.getElementById('sqm_down').value==='100');assert.equal(await page.locator('#sqm_unit').inputValue(),'Mb/s');
 });
 await check('profile copies do not submit; save sends complete profile',async()=>{
 await load('limits');await page.locator('#lim_profile_select').selectOption('Guest');const n=writes.length;await page.getByRole('button',{name:'Copy to default'}).click();assert.equal(writes.length,n);assert.equal(await page.locator('#ld_up').inputValue(),'64');await page.getByRole('button',{name:'Save default policy'}).click();await page.waitForFunction(()=>document.getElementById('lim_default_out').textContent.startsWith('Saved'));assert.equal(writes.filter(w=>w.path==='/api/limits').at(-1).body.limits.up,'64');
 });
 await check('punishment validity prevents invalid save',async()=>{
 await load('punishment');await page.locator('#pun_loss').fill('101');const n=writes.length;await page.getByRole('button',{name:'Save punishment policy'}).click();assert.equal(writes.length,n);assert.equal(await page.locator('#pun_loss').evaluate(el=>el.validity.rangeOverflow),true);
 });
 await check('status failed refresh preserves Config draft',async()=>{
 await load('status');const draft='config opennds\n# QA draft';await page.locator('#confout').fill(draft);fail='/api/status';await page.evaluate(()=>loadStatus());assert.equal(await page.locator('#confout').inputValue(),draft);assert.equal(await page.locator('#status_badge').textContent(),'Error');fail='';
 });fail='';

 await check('failed Default save retains edits',async()=>{
 await load('limits');await page.locator('#ld_up').fill('321');fail='/api/limits';await page.getByRole('button',{name:'Save default policy'}).click();await page.waitForFunction(()=>document.getElementById('lim_default_out').textContent.includes('QA API failure'));assert.equal(await page.locator('#ld_up').inputValue(),'321');fail='';
 });fail='';
 await check('settings save network errors release controls and preserve edits',async()=>{
 for(const [tab,path,input,button,out] of [['limits','/api/limits','#ld_up','Save default policy','#lim_default_out'],['sqm','/api/sqm','#sqm_down','Apply base queue','#sqmout']]){
 await load(tab);await page.locator(input).fill('321');networkFail=path;await page.getByRole('button',{name:button}).click();await page.waitForFunction(id=>document.querySelector(id).textContent.startsWith('Failed:'),out);assert.equal(await page.locator(input).inputValue(),'321');await page.waitForFunction(name=>!document.querySelector('button[aria-label="'+name+'"]').disabled,button);networkFail='';}
 });networkFail='';
 await check('concurrent settings saves submit once',async()=>{
 await load('limits');const n=writes.length;await page.evaluate(()=>Promise.all([saveLimits(''),saveLimits('')]));assert.equal(writes.filter((_,i)=>i>=n).filter(w=>w.path==='/api/limits'&&w.method==='PUT').length,1);
 });
 await check('DNS failed reload preserves list and dialog',async()=>{
 await load('overview');await page.locator('#domain_list button').first().click();const title=await page.locator('#domain_detail_title').textContent();fail='/api/domains';await page.evaluate(()=>loadDomainRanking());assert.equal(await page.locator('#domain_detail').evaluate(el=>el.open),true);assert.equal(await page.locator('#domain_detail_title').textContent(),title);assert.ok((await page.locator('#domain_note').textContent()).includes('QA API failure'));fail='';
 });fail='';
 fs.writeFileSync(root+'/behavior.json',JSON.stringify({checks,errors},null,2));console.log(JSON.stringify({checks,errors},null,2));assert.ok(checks.every(c=>c.pass));assert.deepEqual(errors,[]);
}
}finally{await browser.close();}})().catch(e=>{console.error(e);process.exit(1)});

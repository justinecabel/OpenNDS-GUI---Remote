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
const now=Math.floor(Date.now()/1000),mac='02:00:00:00:00:99',long='office-'+ 'wireless-device-'.repeat(7)+'99';
const sample={network:'lan',interface:'br-lan',mac,hostname:'Work laptop',ip:'192.168.1.99',online:true,state:'Authenticated',last_active:now,wan_download_rate:1234000,wan_upload_rate:64000,wan_today_download_bytes:234234234,wan_today_upload_bytes:45656756,wan_month_download_bytes:5434534534,wan_month_upload_bytes:556565665};
const history=Array.from({length:361},(_,i)=>({at:now-3600+i*10,download:20000+Math.abs(Math.sin(i/13))*2200000,upload:12000+Math.abs(Math.cos(i/17))*120000}));
let stress=false,networkFail='',readNetworkFail='',fail='',delay=0,ruleDelay=0,baseDelay=0,clientRows=0,writes=[],reads=[];
const state={mode:'portal',config:"config opennds\n\toption enabled '1'\n\toption gatewayname 'Open NDS'\n",limits:{ok:true,default:{up:5000,down:5000,latency_ms:0},devices:{[mac]:{up:250,down:500}},profiles:{Open:{latency_ms:0},Standard:{up:128,down:256},Guest:{up:64,down:128}}},punishment:{ok:true,delay_ms:100,loss_pct:1,download:128,upload:64,tc_active:true},sqm:{enabled:'1',interface:'br-lan',download:12500,upload:25000,qdisc:'cake',script:'piece_of_cake.qos'},rule:{ok:true,enabled:true,threshold_gb:50,download:1024,upload:512,today_bytes:12412312345,today_date:'2026-10-08',wan_interface:'eth0',active:false}};
function fixture(path){
 if(path==='/api/overview')return {ok:true,connected:5,interface:'eth0',updated_at:now,tracking_since:now-20000,live:{download:stress?123456789012:1234000,upload:stress?123456789012:64000},today:{download:21453453434,upload:545454343},month:{download:214534534343,upload:5454543434}};
 if(path.endsWith('/history'))return {ok:true,history,resolution:'seconds',reset:true,cursor:now,generation:'qa',history_start_at:now-86400,recent_start_at:now-3600};
 if(path==='/api/clients')return {ok:true,sampled_at:now,data:{networks:fixture('/api/networks').networks.filter(n=>n.eligible),clients:{laptop:{...sample,hostname:stress?long:sample.hostname},phone:{...sample,mac:'02:00:00:00:00:98',hostname:'Phone',ip:'172.20.7.98',network:'guests',interface:'br-visitors.37',added_ping_ms:20},offline:{...sample,mac:'02:00:00:00:00:97',hostname:'Living room TV',online:false,state:'Offline',last_active:now-86500},trusted:{...sample,mac:'02:00:00:00:00:96',hostname:'Trusted device',trusted:true},blocked:{...sample,mac:'02:00:00:00:00:95',hostname:'Blocked device',ip:'203.0.113.95',network:'',interface:'',blocked:true},throttled:{...sample,mac:'02:00:00:00:00:94',hostname:'Throttled device',throttle:{download:true}}}}};
 if(path==='/api/status')return {ok:true,output:'openNDS Status\nVersion: 10.3.1\nUptime: 1 day\nGateway: Open NDS\nGateway FQDN: status.client\nManaged interface: br-lan\nFAS: Secure Level 1, URL: http://192.168.1.198:8080/fas\nActive clients: 5\nClient authentications since start: 20\nTotal download: 123456 kByte; average: 35 kbit/s\nTotal upload: 12345 kByte; average: 3 kbit/s\n'+('Detailed status line\n').repeat(80)};
 if(path==='/api/qos/status')return state.qosStatus||{ok:true,stale:false,networks:[
  {network:'lan',interface:'br-lan',placement:'lan',queue_interface:'br-lan',state:'active',clients:3},
  {network:'guests',interface:'br-visitors.37',placement:'wan',queue_interface:'eth0',state:'ready',clients:0}]};
 if(path==='/api/config')return {ok:true,content:state.config};
 if(path==='/api/logs')return {ok:true,output:state.logs??Array.from({length:40},(_,i)=>'Oct 8 10:20:35 daemon.'+['err','warn','notice','info','debug'][i%5]+' openNDS: '+(stress?long:'authenticated 192.168.1.99')).join('\n')};
 if(path==='/api/limits'||path==='/api/limits/profile')return state.limits;
 if(path==='/api/mode')return {ok:true,mode:state.mode,auto_trusted:0,auto_authed:2};
 if(path==='/api/networks')return {ok:true,output:'Applied networks',networks:[
  {name:'lan',device:'br-lan',subnets:['192.168.1.0/24'],up:true,primary:true,eligible:true,mode:state.mode,zone:'lan'},
  {name:'guests',device:'br-visitors.37',subnets:['172.20.7.0/24'],up:true,primary:false,eligible:true,mode:state.guestMode||'portal',zone:'visitors'},
  {name:'wan',device:'eth0',subnets:['192.168.122.0/24'],up:true,primary:false,eligible:false,mode:'unmanaged',role:'WAN',reason:'Upstream / WAN'}]};
 if(path==='/api/punishment')return state.punishment;
 if(path==='/api/sqm')return {ok:true,configured:true,config:state.sqm,baseline_config:state.baselineSqm||state.sqm,baseline_queues:[state.baselineSqm||state.sqm,...(state.extraSqm?[state.extraSqm]:[])],selected_interface:'br-lan',primary_interface:'br-lan',queues:[state.sqm,...(state.extraSqm?[state.extraSqm]:[])],interfaces:['br-lan','eth2','eth0'],interface_roles:{'br-lan':'lan · LAN','eth2':'piso · LAN','eth0':'wan · WAN'}};
 if(path==='/api/sqm/conditional'){const primary={...state.rule,interface:'br-lan',network:'lan',available:true,tracking_since:now-100},extra={ok:true,interface:'eth2',network:'piso',available:true,enabled:false,threshold_gb:5,download:250,upload:500,today_bytes:123456,today_date:'2026-10-08',wan_interface:'eth0',active:false,tracking_since:now-100,...state.extraRule};return {...primary,selected_interface:'br-lan',rules:[primary,extra]};}
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
 if(readNetworkFail===path&&req.method()==='GET')return route.abort('failed');
 if(baseDelay&&path==='/api/sqm'&&req.method()==='GET')await new Promise(r=>setTimeout(r,baseDelay));
 if(ruleDelay&&path==='/api/sqm/conditional'&&req.method()==='GET')await new Promise(r=>setTimeout(r,ruleDelay));
 if(networkFail===path&&req.method()!=='GET')return route.abort('failed');
 if(delay&&path==='/api/limits')await new Promise(r=>setTimeout(r,delay));
 if(req.method()==='GET')reads.push(path);else{writes.push({path,method:req.method(),body:req.postDataJSON()});if(path==='/api/networks'&&fail!==path){state.mode=req.postDataJSON().modes.lan;state.guestMode=req.postDataJSON().modes.guests;}if(path==='/api/sqm'&&fail!==path){const body=req.postDataJSON(),saved={...body,enabled:body.enabled?'1':'0'};if(body.interface==='br-lan'){if(state.baselineSqm){state.baselineSqm=saved;state.sqm=state.rule.active?{...saved,download:state.rule.download,upload:state.rule.upload}:saved;}else state.sqm=saved;}else state.extraSqm=saved;}if(path==='/api/sqm/conditional'&&fail!==path){const body=req.postDataJSON();if(body.interface==='eth2')state.extraRule={...state.extraRule,...body,forced_today:!!body.force_today,active:!!body.force_today};else{state.rule={...state.rule,...body};if(state.baselineSqm){state.rule.active=!!body.enabled&&(!!body.force_today||state.rule.active);state.sqm=state.rule.active?{...state.baselineSqm,download:state.rule.download,upload:state.rule.upload}:{...state.baselineSqm};}}}if(path==='/api/mode')state.mode=req.postDataJSON().mode;if(path==='/api/config')state.config=req.postDataJSON().content;}
 const response=fail===path?{ok:false,output:'QA API failure '+long}:fixture(path);
 if(path==='/api/clients'&&response.ok)for(let i=0;i<clientRows;i++)response.data.clients['scroll-'+i]={...sample,mac:'02:00:00:01:'+Math.floor(i/256).toString(16).padStart(2,'0')+':'+(i%256).toString(16).padStart(2,'0'),hostname:'Scroll device '+String(i).padStart(3,'0')};
 return route.fulfill({contentType:'application/json',body:JSON.stringify(response)});});
 const load=async tab=>{if(tab==='clients')await page.evaluate(()=>{try{localStorage.removeItem('opennds-client-network');localStorage.removeItem('opennds-client-filter');}catch(e){}});await page.goto('http://manager.test/?qa='+Date.now()+Math.random()+'#'+tab);await page.evaluate(async tab=>{await ({overview:loadOverview,clients:loadClients,portal:loadHostedPortalStatus,sqm:loadSqm,mode:loadMode,limits:loadLimits,punishment:loadPunishment,status:loadStatusConfig,logs:loadLogs})[tab]();if(tab==='overview'){await loadOverviewHistory();}if(tab==='sqm')openSqmEditor(sqmSelected);await document.fonts.ready;},tab);};
 const chooseSqm=async iface=>{await page.evaluate(iface=>{if(!sqmListedInterfaces().includes(iface))sqmAdded.add(iface);openSqmEditor(iface);},iface);};
 const geometry=async(name,width)=>{const found=await page.evaluate(()=>{
  const issues=[],visible=el=>el.getClientRects().length&&getComputedStyle(el).visibility!=='hidden',allowed=el=>{for(let p=el;p&&p!==document.body;p=p.parentElement){if(/auto|scroll|hidden/.test(getComputedStyle(p).overflowX)&&p.scrollWidth>p.clientWidth+1)return true;}return false;};
  const sqmHead=document.querySelector('#sqm.active .sqm-heading>div:first-child');if(sqmHead&&sqmHead.getBoundingClientRect().height>180)issues.push('SQM heading excess height');
  if(document.documentElement.scrollWidth>innerWidth+1)issues.push('root overflow '+document.documentElement.scrollWidth);
  for(const el of document.querySelectorAll('section.active button,section.active input,section.active select,section.active summary,dialog[open] button,dialog[open] h4,dialog[open] canvas,dialog[open] ol')){
   if(!visible(el)||(!el.closest('dialog')&&allowed(el)))continue;const r=el.getBoundingClientRect(),dialog=el.closest('dialog'),bounds=dialog?dialog.getBoundingClientRect():{left:0,right:innerWidth};
   if(r.left<bounds.left-1||r.right>bounds.right+1)issues.push('outside '+(el.id||el.className||el.tagName));
   if(el.tagName==='BUTTON'&&el.scrollWidth>el.clientWidth+2&&getComputedStyle(el).textOverflow!=='ellipsis')issues.push('clipped button '+(el.id||el.textContent));
  }
  for(const el of document.querySelectorAll('dialog[open]'))if(el.scrollWidth>el.clientWidth+1)issues.push('dialog overflow '+el.id+' '+el.scrollWidth+'/'+el.clientWidth);
  return issues;
 });for(const issue of found)issues.push({name,width,issue});};
if(!process.argv.includes('--behavior-only')){
 const widths=[...new Set([...Array.from({length:71},(_,i)=>320+i*32),375,390,412,568,599,600,601,768,899,900,901,1024,1099,1100,1101,1199,1200,1201,1299,1300,1301,1440,1920,2560])].sort((a,b)=>a-b);
 for(stress of [false,true]){for(const tab of tabs){await load(tab);for(const width of widths){await page.setViewportSize({width,height:1000});await geometry((stress?'stress-':'')+tab,width);if([320,768,1100,1920].includes(width))await page.screenshot({path:root+'/'+(stress?'stress-':'')+tab+'-'+width+'.png',fullPage:true});}console.log('Swept '+(stress?'stress ':'')+tab);}}
 const dialogWidths=[320,375,390,568,600,768,900,901,1099,1100,1300,1301,1440,1920];
 for(const width of dialogWidths){await page.setViewportSize({width,height:width===568?320:844});
 await load('clients');await page.locator('#ctable tr').filter({hasText:long}).locator('.btn-link').click();await page.waitForFunction(()=>document.getElementById('client_detail').open);await geometry('client-dialog',width);await page.screenshot({path:root+'/client-dialog-'+width+'.png'});await page.keyboard.press('Escape');
 if(width<=1300){await page.locator('#ctable tr').filter({hasText:long}).locator('.client-actions-more').click();await geometry('action-dialog',width);await page.screenshot({path:root+'/action-dialog-'+width+'.png'});await page.keyboard.press('Escape');}
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
 await check('runtime status preserves settings drafts and never claims active after failed or stale reads',async()=>{
  try{
   await load('sqm');await page.locator('#sqm_down').fill('321');
   const before=reads.length;await page.waitForTimeout(1400);
   assert(reads.slice(before).includes('/api/qos/status'));
   assert(!reads.slice(before).includes('/api/sqm'));
   assert.equal(await page.locator('#sqm_down').inputValue(),'321');
   await page.evaluate(async()=>{await show('limits');await loadLimits();});await page.locator('#ld_up').fill('456');
   for(const status of ['active','ready','pending','error','unknown']){
    state.qosStatus={ok:true,stale:false,networks:[{network:'guests',interface:'eth2',queue_interface:'eth0',placement:'wan',state:status,clients:2,message:status==='error'?'ctinfo unavailable':''}]};
    await page.evaluate(()=>loadQosStatus());
    assert.equal(await page.locator('#qos_status_limits .qos-status-state').getAttribute('data-state'),status);
   }
   state.qosStatus.stale=true;state.qosStatus.networks[0].state='active';await page.evaluate(()=>loadQosStatus());
   assert.equal(await page.locator('#qos_status_limits [data-state=active]').count(),0);
   fail='/api/qos/status';await page.evaluate(()=>loadQosStatus());
   assert((await page.locator('#qos_status_limits').textContent()).includes('Status unavailable'));
   assert.equal(await page.locator('#qos_status_limits [data-state=active]').count(),0);
   assert.equal(await page.locator('#ld_up').inputValue(),'456');
  }finally{fail='';delete state.qosStatus;}
 });
 await check('management forms use one column while Clients retains its full-width table',async()=>{
 for(const width of [390,1440]){
 await page.setViewportSize({width,height:1000});
 for(const tab of ['portal','mode','limits','punishment','sqm','status']){
 await load(tab);
 const issues=await page.evaluate(()=>{
  const errors=[],section=document.querySelector('section.active');
  for(const el of section.querySelectorAll('.settings-section,.limit-fields,.admin-fields,.sqm-fields,.profile-name')){
   if(!el.getClientRects().length)continue;
   if(getComputedStyle(el).gridTemplateColumns.split(' ').length!==1)errors.push('multiple columns: '+el.className);
  }
  for(const el of section.querySelectorAll('.settings-section')){
   const heading=el.querySelector('.settings-heading'),body=el.querySelector('.settings-body');
   if(heading&&body&&body.getBoundingClientRect().top<heading.getBoundingClientRect().bottom-1)errors.push('body beside heading');
  }
  if(document.documentElement.scrollWidth>innerWidth+1)errors.push('page overflow');
  return errors;
 });assert.deepEqual(issues,[],tab+' '+width);
 }
 await load('clients');
 const row=page.locator('tr[data-client-network="lan"]').filter({hasText:'Work laptop'});
 assert.equal(await row.evaluate(el=>getComputedStyle(el).display),'table-row');
 assert.equal(await row.locator('td').count(),12);
 assert.equal(await row.locator('td[data-label]').count(),0);
 assert.ok((await row.textContent()).includes(sample.mac));assert.ok((await row.textContent()).includes(sample.ip));
 assert.equal(await row.locator('.client-actions-more').isVisible(),width<=1300);
 const offline=page.locator('tr[data-client-network="lan"]').filter({hasText:'Living room TV'});
 if(width<=1300){await offline.locator('.client-actions-more').click();assert.equal(await page.locator('#client_actions_buttons button').last().textContent(),'delete');await page.keyboard.press('Escape');}
 else{assert.equal(await offline.locator('.client-actions-inline button').last().textContent(),'delete');assert.ok((await page.locator('#clients').boundingBox()).width>800);}
 await load('limits');
 await page.locator('#limtable button').first().click();assert.equal(await page.locator('#lim_mac').inputValue(),mac);
 }
 await page.setViewportSize({width:1440,height:1000});
 });
 await check('vertical content styles leave Overview and navigation unchanged',async()=>{
 for(const width of [390,1440]){
 await page.setViewportSize({width,height:1000});await load('overview');
 const unchanged=await page.evaluate(()=>{
  const sheet=[...document.styleSheets].find(sheet=>sheet.href?.endsWith('/listing.css'));
  const measure=()=>['.site-header','.main-nav','.nav-toggle','#overview','.overview-grid','.metric','#trafficChart'].map(selector=>{
   const el=document.querySelector(selector),r=el.getBoundingClientRect(),style=getComputedStyle(el);
   return [selector,r.x,r.y,r.width,r.height,style.display,style.position,style.fontSize];
  });
  const current=measure();sheet.disabled=true;const previous=measure();sheet.disabled=false;
  return JSON.stringify(current)===JSON.stringify(previous);
 });assert.equal(unchanged,true);
 }await page.setViewportSize({width:1440,height:1000});
 });
 await check('settings drafts survive page changes and browser history without writes',async()=>{
 const cases=[['portal',{portal_type:'default'}],['limits',{ld_up:'321',lim_profile_name:'Draft profile'}],['sqm',{sqm_down:'321',sqm_rule_gb:'77'}],['punishment',{pun_delay:'222'}]];
 for(const [tab,fields] of cases){
 await load(tab);for(const [id,value] of Object.entries(fields)){if(id==='portal_type')await page.locator('#'+id).selectOption(value);else await page.locator('#'+id).fill(value);}
 const n=writes.length;await page.evaluate(async tab=>{await show('clients');await show(tab);},tab);
 for(const [id,value] of Object.entries(fields))assert.equal(await page.locator('#'+id).inputValue(),value);
 assert.equal(writes.length,n);
 await page.goBack();await page.waitForFunction(()=>current==='clients');await page.goForward();await page.waitForFunction(tab=>current===tab,tab);
 for(const [id,value] of Object.entries(fields))assert.equal(await page.locator('#'+id).inputValue(),value);
 assert.equal(writes.length,n);
 }
 });
 await check('punishment distinguishes punished devices from shared traffic control',async()=>{
 await load('punishment');assert.equal(await page.locator('#pun_badge').textContent(),'0 punished');assert.equal(await page.locator('#pun_tc_status').textContent(),'Traffic control active');
 });
 await check('logs preserve reading position and follow new entries only at the bottom',async()=>{
 try{
 state.logs=['Fri Oct  9 10:20:35 2026 daemon.err opennds: failed','Oct 9 10:20:35 kern.crit kernel: critical','Oct 9 10:20:35 daemon.warn odhcpd: No default route','Oct 9 10:20:35 daemon.notice opennds: error count 0','Oct 9 10:20:35 daemon.info opennds: connected','Oct 9 10:20:35 daemon.debug opennds: details','literal <img src=x onerror=alert(1)>'].join('\n');
 await load('logs');await page.evaluate(()=>{busy=true;});
 assert.equal(await page.locator('#logout').textContent(),state.logs);
 assert.deepEqual(await page.locator('#logout .log-line').evaluateAll(rows=>rows.map(row=>row.className)),['log-line log-error','log-line log-error','log-line log-warning','log-line log-notice','log-line log-info','log-line log-debug','log-line log-info']);
 assert.equal(await page.locator('#logout .log-time').count(),6);assert.equal(await page.locator('#logout img, #logout script').count(),0);
 assert.equal(await page.locator('.log-legend .log-key').count(),5);
 state.logs=Array.from({length:100},(_,i)=>'Oct 9 10:20:35 daemon.info opennds: '+i+' '+long.repeat(2)).join('\n');await page.evaluate(()=>loadLogs());
 const atEnd=()=>page.locator('#logout').evaluate(box=>box.scrollHeight-box.clientHeight-box.scrollTop<=3);assert.equal(await atEnd(),true);
 await page.evaluate(()=>{const box=document.getElementById('logout');box.scrollTop=150;box.scrollLeft=120;window.qaLogRow=box.firstChild;});
 const position=()=>page.locator('#logout').evaluate(box=>({top:box.scrollTop,left:box.scrollLeft}));const before=await position();assert.deepEqual(before,{top:150,left:120});
 await page.evaluate(()=>loadLogs());assert.equal(await page.evaluate(()=>document.getElementById('logout').firstChild===window.qaLogRow),true);
 assert.deepEqual(await position(),before);assert.equal(await atEnd(),false);
 await page.locator('#logout').evaluate(box=>{box.scrollTop=150;});
 state.logs+='\nOct 9 10:20:36 daemon.warn opennds: new warning';await page.evaluate(()=>loadLogs());assert.deepEqual(await position(),before);assert.equal(await atEnd(),false);
 await page.locator('#logout').evaluate(box=>{box.scrollTop=box.scrollHeight;});state.logs+='\nOct 9 10:20:37 daemon.err opennds: new error';await page.evaluate(()=>loadLogs());
 assert.equal(await page.locator('#logout').evaluate(box=>box.scrollHeight-box.clientHeight-box.scrollTop<=3),true);
 fail='/api/logs';await page.evaluate(()=>loadLogs());assert.equal(await page.locator('#logout').textContent(),state.logs);assert.match(await page.locator('#logs_error').textContent(),/QA API failure/);fail='';
 }finally{delete state.logs;fail='';await page.evaluate(()=>{busy=false;});}
 });
 await check('networks discover devices, exclude WAN and retain drafts across scans/tabs',async()=>{
 await load('mode');assert.equal(await page.locator('#mode_networks select').count(),2);
 assert.ok((await page.locator('#mode_networks').textContent()).includes('br-visitors.37'));
 assert.equal(await page.getByLabel('wan behavior',{exact:true}).count(),0);
 await page.getByLabel('guests behavior',{exact:true}).selectOption('auto_auth');
 await page.evaluate(async()=>{await show('clients');await show('mode');await loadMode(true);});
 assert.equal(await page.getByLabel('guests behavior',{exact:true}).inputValue(),'auto_auth');
 assert.ok((await page.locator('#modeinfo').textContent()).includes('Drafts retained'));
 });
 await check('network visibility persists and preserves hidden interface drafts and apply payload',async()=>{
 await page.evaluate(()=>localStorage.removeItem('opennds-hidden-networks'));await load('mode');const n=writes.length;
 assert.equal(await page.getByRole('button',{name:'Hide guests in network list',exact:true}).count(),0);await page.locator('#network_edit_list').click();
 await page.getByLabel('guests behavior',{exact:true}).selectOption('auto_auth');await page.getByRole('button',{name:'Hide guests in network list',exact:true}).click();
 assert.equal(await page.getByLabel('guests behavior',{exact:true}).isVisible(),false);assert.equal(writes.length,n);
 await page.evaluate(()=>loadMode(true));assert.equal(await page.getByLabel('guests behavior',{exact:true}).inputValue(),'auto_auth');assert.equal(await page.getByLabel('guests behavior',{exact:true}).isVisible(),false);
 fail='/api/networks';await page.locator('#mode_apply').click();await page.waitForFunction(()=>!networkSettingsBusy);assert.equal(writes.at(-1).body.modes.guests,'auto_auth');fail='';
 await page.reload();await page.waitForFunction(()=>document.querySelector('#mode_networks .network-row[hidden]'));
 assert.equal(await page.getByLabel('guests behavior',{exact:true}).isVisible(),false);assert.equal(await page.locator('#network_hidden_control').isVisible(),false);await page.locator('#network_edit_list').click();await page.locator('#network_show_hidden').check();assert.equal(await page.getByLabel('guests behavior',{exact:true}).isVisible(),true);
 await page.getByRole('button',{name:'Unhide guests in network list',exact:true}).click();assert.equal(await page.locator('#network_hidden_control').isVisible(),false);assert.equal(await page.getByLabel('guests behavior',{exact:true}).isVisible(),true);
 await page.getByRole('button',{name:'Hide lan in network list',exact:true}).click();await page.getByRole('button',{name:'Hide guests in network list',exact:true}).click();await page.getByRole('button',{name:'Hide wan in network list',exact:true}).click();assert.equal(await page.locator('#network_empty').isVisible(),true);await page.locator('#network_show_hidden').check();assert.equal(await page.locator('#network_empty').isVisible(),false);await page.locator('#network_edit_list').click();assert.equal(await page.locator('#network_hidden_control').isVisible(),false);assert.equal(await page.locator('#network_edit_list').getAttribute('aria-pressed'),'false');assert.equal(await page.locator('#network_empty').isVisible(),true);
 await page.evaluate(()=>localStorage.removeItem('opennds-hidden-networks'));await load('mode');
 });
 await check('network saves serialize and failures retain selected behavior',async()=>{
 await load('mode');await page.getByLabel('guests behavior',{exact:true}).selectOption('auto_auth');
 fail='/api/networks';await page.locator('#mode_apply').click();await page.waitForFunction(()=>!networkSettingsBusy);
 assert.equal(await page.getByLabel('guests behavior',{exact:true}).inputValue(),'auto_auth');
 assert.ok((await page.locator('#modeinfo').textContent()).includes('failed'));fail='';
 const n=writes.length;await page.evaluate(()=>Promise.all([saveMode(),saveMode()]));
 assert.equal(writes.slice(n).filter(w=>w.path==='/api/networks').length,1);
 assert.deepEqual(writes.at(-1).body.modes,{lan:state.mode,guests:'auto_auth'});
 assert.equal(await page.locator('#mode_apply').isEnabled(),true);state.guestMode='portal';
 });
 await check('failed initial network scan disables apply and scan can recover',async()=>{
 fail='/api/networks';await load('mode');assert.equal(await page.locator('#mode_apply').isEnabled(),false);
 fail='';await page.locator('#networks_scan').click();await page.waitForFunction(()=>networkSettingsLoaded&&!networkSettingsBusy);
 assert.equal(await page.locator('#mode_apply').isEnabled(),true);
 });
 await check('blank Device MAC cannot save Default',async()=>{await load('limits');const n=writes.length;await page.locator('#lim_mac').fill('');await page.getByRole('button',{name:'Save device override'}).click();assert.equal(writes.length,n);assert.equal(await page.locator('#limout').textContent(),'Valid MAC required');});
 await check('client interface tabs filter rows and preserve selection during polling',async()=>{
 await load('clients');assert.deepEqual(await page.locator('#client_network_tabs [role=tab]').evaluateAll(tabs=>tabs.map(tab=>tab.dataset.network)),['lan','guests','']);
 assert.equal(await page.locator('#client_network_tabs [aria-selected=true]').getAttribute('data-network'),'lan');
 assert.equal(await page.locator('tr[data-client-network="lan"]').count(),4);assert.equal(await page.locator('tr[data-client-network="guests"]').count(),0);
 await page.locator('#client_network_tabs [data-network="guests"]').click();assert.equal(await page.locator('tr[data-client-network="guests"]').count(),1);assert.equal(await page.locator('tr[data-client-network="lan"]').count(),0);
 assert.equal(await page.locator('#ctable .client-network-group').count(),0);assert.equal(await page.locator('#ctable tr[aria-describedby]').count(),0);
 assert.equal(await page.locator('#client_table_wrap').getAttribute('aria-labelledby'),await page.locator('#client_network_tabs [aria-selected=true]').getAttribute('id'));
 assert.ok(!(await page.locator('#ctable').textContent()).includes('Session limits only'));assert.ok((await page.locator('#ctable').textContent()).includes('+20 ms'));
 await page.evaluate(()=>loadClients());assert.equal(await page.locator('#client_network_tabs [aria-selected=true]').getAttribute('data-network'),'guests');assert.equal(await page.locator('#client_network_tabs [data-network="guests"]').evaluate(el=>el===document.activeElement),true);
 await page.reload();await page.waitForFunction(()=>document.querySelector('#client_network_tabs [aria-selected=true]')?.dataset.network==='guests');
 await page.locator('#client_network_tabs [data-network=""]').click();assert.equal(await page.locator('tr[data-client-network=""]').count(),1);
 assert.equal(await page.locator('#client_network_tabs [data-network="wan"]').count(),0);
 });
 await check('device search and status filters retain focus and state across fetches',async()=>{
 await load('clients');await page.locator('#client_network_tabs [data-network="lan"]').click();
 const search=page.locator('#client_search');await search.fill('WORK LAP');
 assert.equal(await page.locator('#ctable tr[data-client-network]').count(),1);
 assert.ok((await page.locator('#client_results').textContent()).includes('1 of 4'));
 await page.evaluate(()=>loadClients());assert.equal(await search.inputValue(),'WORK LAP');assert.equal(await search.evaluate(el=>el===document.activeElement),true);
 await search.fill(sample.ip);assert.equal(await page.locator('#ctable tr[data-client-network]').count(),4);
 await search.fill('02:00:00:00:00:97');assert.equal(await page.locator('#ctable tr[data-client-network]').count(),1);
 await search.fill('');await page.locator('[data-client-filter="offline"]').click();assert.equal(await page.locator('#ctable tr[data-client-network]').count(),1);
 await page.evaluate(()=>loadClients());assert.equal(await page.locator('[data-client-filter="offline"]').getAttribute('aria-pressed'),'true');assert.equal(await page.locator('#ctable tr[data-client-network]').count(),1);
 assert.ok((await page.locator('#client_network_tabs [data-network="lan"]').textContent()).includes('3 online'));
 await search.fill('missing-device');assert.ok((await page.locator('#ctable').textContent()).includes('No matching devices'));
 await search.fill('');await page.locator('[data-client-filter="all"]').click();assert.equal(await page.locator('#ctable tr[data-client-network]').count(),4);
 assert.equal(await page.locator('#ctable .client-state[data-state="online"]').count(),1);assert.equal(await page.locator('#ctable .client-state[data-state="offline"]').count(),1);
 });
 await check('client status filter survives reload and reopening with safe invalid fallback',async()=>{
 await load('clients');await page.locator('#client_network_tabs [data-network="lan"]').click();
 for(const value of ['online','offline','all']){
 await page.locator('[data-client-filter="'+value+'"]').click();
 await page.reload();await page.evaluate(()=>loadClients());
 assert.equal(await page.locator('[data-client-filter="'+value+'"]').getAttribute('aria-pressed'),'true');
 assert.equal(await page.locator('#ctable tr[data-client-network]').count(),value==='all'?4:value==='online'?3:1);
 await page.goto('http://manager.test/#portal');await page.goto('http://manager.test/?reopened='+Date.now()+'#clients');await page.evaluate(()=>loadClients());
 assert.equal(await page.locator('[data-client-filter="'+value+'"]').getAttribute('aria-pressed'),'true');
 }
 await page.evaluate(()=>localStorage.setItem('opennds-client-filter','invalid'));
 await page.reload();await page.evaluate(()=>loadClients());
 assert.equal(await page.locator('[data-client-filter="all"]').getAttribute('aria-pressed'),'true');
 assert.equal(await page.locator('#ctable tr[data-client-network]').count(),4);
 });
 await check('secondary LAN exposes Punish in desktop and mobile actions',async()=>{
 for(const width of [1440,390]){await page.setViewportSize({width,height:1000});await load('clients');await page.locator('#client_network_tabs [data-network="guests"]').click();
 const row=page.locator('tr[data-client-network="guests"]');if(width===390)await row.locator('.client-actions-more').click();
 const trigger=width===390?page.locator('#client_actions_buttons'):row;
 const before=writes.length;await trigger.getByRole('button',{name:'punish',exact:true}).click();await page.waitForFunction(()=>!busy);
 assert.ok(writes.slice(before).some(w=>w.path==='/api/action'&&w.body.action==='punish'&&w.body.mac==='02:00:00:00:00:98'));
 }await page.setViewportSize({width:1440,height:1000});
 });
 await check('client tabs support arrows, Home and End with roving keyboard focus',async()=>{
 await load('clients');await page.locator('#client_network_tabs [aria-selected=true]').focus();
 await page.keyboard.press('ArrowRight');assert.equal(await page.locator('#client_network_tabs [aria-selected=true]').getAttribute('data-network'),'guests');
 await page.keyboard.press('End');assert.equal(await page.locator('#client_network_tabs [aria-selected=true]').getAttribute('data-network'),'');
 await page.keyboard.press('Home');assert.equal(await page.locator('#client_network_tabs [aria-selected=true]').getAttribute('data-network'),'lan');
 assert.equal(await page.locator('#client_network_tabs [tabindex="0"]').count(),1);assert.equal(await page.locator('#client_network_tabs [aria-selected=true]').evaluate(el=>el===document.activeElement),true);
 });
 await check('empty and removed interfaces retain a usable selected tab',async()=>{
 await load('clients');await page.evaluate(()=>{clientsResponse={ok:true,data:{networks:[{name:'empty',device:'eth7',primary:true,subnets:['172.30.0.0/24'],mode:'portal'}],clients:{}}};renderClients();});
 assert.equal(await page.locator('#client_network_tabs [aria-selected=true]').getAttribute('data-network'),'empty');assert.equal((await page.locator('#ctable').textContent()).trim(),'No devices');assert.ok((await page.locator('#client_network_tabs [aria-selected=true]').textContent()).includes('0 online'));
 await page.evaluate(()=>loadClients());assert.equal(await page.locator('#client_network_tabs [aria-selected=true]').getAttribute('data-network'),'lan');
 });
 await check('client table refresh retains keyboard focus',async()=>{
 await load('clients');const button=page.locator('#ctable tr').filter({hasText:'Work laptop'}).locator('.client-name-edit');await button.focus();await page.evaluate(()=>loadClients());assert.equal(await button.evaluate(el=>el===document.activeElement),true);
 });
 await check('client polling preserves vertical and horizontal scroll with focus offscreen',async()=>{
 try{clientRows=50;
 for(const width of [390,1440]){
 await page.setViewportSize({width,height:700});await load('clients');
 await page.evaluate(()=>{busy=true;document.querySelector('#client_network_tabs [aria-selected=true]').focus({preventScroll:true});const wrap=document.getElementById('client_table_wrap');wrap.querySelector('table').style.minWidth='2200px';wrap.scrollLeft=180;window.scrollTo(0,1000);syncClientPanbar(wrap);});
 const position=()=>page.evaluate(()=>({y:scrollY,x:document.getElementById('client_table_wrap').scrollLeft}));
 const before=await position();assert.ok(before.y>500);assert.ok(before.x>100);
 for(let i=0;i<3;i++){await page.evaluate(()=>loadClients());assert.deepEqual(await position(),before);assert.equal(await page.locator('#client_network_tabs [aria-selected=true]').evaluate(el=>el===document.activeElement),true);}
 // Moving focus to a row and panning must also survive fresh row rendering.
 await page.evaluate(()=>{document.querySelector('#ctable .client-name-edit').focus({preventScroll:true});});
 await page.evaluate(()=>loadClients());assert.deepEqual(await position(),before);assert.equal(await page.locator('#ctable .client-name-edit').first().evaluate(el=>el===document.activeElement),true);
 await Promise.all([page.waitForResponse(response=>new URL(response.url()).pathname==='/api/clients'),page.evaluate(()=>{busy=false;})]);
 await page.waitForFunction(()=>!clientsPromise);assert.deepEqual(await position(),before);await page.evaluate(()=>{busy=true;});
 }}finally{clientRows=0;await page.evaluate(()=>{busy=false;});await page.setViewportSize({width:1440,height:1000});}
 });
 await check('client dialog Escape restores focus after polling',async()=>{
 await load('clients');const button=page.locator('#ctable tr').filter({hasText:'Work laptop'}).locator('.btn-link');await button.click();await page.evaluate(()=>loadClients());await page.keyboard.press('Escape');assert.equal(await button.evaluate(el=>el===document.activeElement),true);
 });
 await check('client Limits waits for a slow settings response',async()=>{
 await load('clients');delay=700;await page.locator('#ctable tr').filter({hasText:'Work laptop'}).getByRole('button',{name:'limits',exact:true}).click();await page.waitForFunction(()=>document.getElementById('lv_up')?.value==='250');assert.equal(await page.locator('#lim_mac').inputValue(),mac);assert.equal(await page.locator('#lv_up').inputValue(),'250');delay=0;
 });delay=0;
 await check('Limits failed reload preserves edits and reports error',async()=>{
 await load('limits');await page.locator('#ld_up').fill('321');fail='/api/limits';await page.evaluate(()=>loadLimits());assert.equal(await page.locator('#ld_up').inputValue(),'321');assert.ok((await page.locator('#lim_default_out').textContent()).includes('QA API failure'));fail='';
 });fail='';
 await check('SQM lists configured interfaces and adds only after an explicit choice',async()=>{
 state.extraSqm=null;state.extraRule=null;await load('sqm');await page.locator('#sqm_back').click();
 assert.equal(await page.locator('#sqm_interface').isVisible(),false);assert.equal(await page.locator('#sqm_summary').isVisible(),true);
 assert.deepEqual(await page.locator('[data-sqm-edit]').evaluateAll(buttons=>buttons.map(button=>button.dataset.sqmEdit)),['br-lan']);
 const n=writes.length;await page.locator('#sqm_add').click();assert.equal(await page.locator('#sqm_add_dialog').evaluate(el=>el.open),true);
 assert.equal(await page.locator('#sqm_add_interface option[value="br-lan"]').count(),0);await page.locator('#sqm_add_interface').selectOption('eth2');assert.equal(await page.locator('#sqm_interface').isVisible(),false);assert.equal(writes.length,n);
 await page.locator('#sqm_add_continue').click();assert.equal(await page.locator('#sqm_if').inputValue(),'eth2');assert.equal(await page.locator('#sqm_interface').isVisible(),true);assert.equal(writes.length,n);
 await page.locator('#sqm_down').fill('333');await page.locator('#sqm_rule_gb').fill('9');await page.locator('#sqm_back').click();assert.ok((await page.locator('.sqm-summary-interface[data-interface="eth2"]').textContent()).includes('Draft'));
 await page.getByRole('button',{name:'Edit SQM eth2',exact:true}).click();assert.equal(await page.locator('#sqm_down').inputValue(),'333');assert.equal(await page.locator('#sqm_rule_gb').inputValue(),'9');assert.equal(writes.length,n);
 await page.locator('#sqm_back').click();await page.locator('#sqm_add').click();assert.equal(await page.locator('#sqm_add_interface option[value="eth2"]').count(),0);await page.keyboard.press('Escape');assert.equal(await page.locator('#sqm_add').evaluate(el=>el===document.activeElement),true);
 });
 await check('SQM failed reload preserves edits and reports error',async()=>{
 await load('sqm');await page.locator('#sqm_down').fill('321');fail='/api/sqm';await page.evaluate(()=>loadSqm());assert.equal(await page.locator('#sqm_down').inputValue(),'321');assert.ok((await page.locator('#sqmout').textContent()).includes('QA API failure'));fail='';
 });fail='';
 await check('chart ranges survive reload, independent for overview/client',async()=>{
 await load('overview');await page.locator('#overview_chart_range').selectOption('900');await page.reload();await page.waitForFunction(()=>document.getElementById('overview_chart_range').value==='900');await load('clients');await page.locator('#ctable .btn-link').first().click();await page.locator('#client_chart_range').selectOption('300');await page.keyboard.press('Escape');await page.reload();await page.locator('#ctable .btn-link').first().click();assert.equal(await page.locator('#client_chart_range').inputValue(),'300');assert.equal(await page.locator('#overview_chart_range').inputValue(),'900');await page.keyboard.press('Escape');
 });
 await check('daily WAN loads saved enabled state independently of a failed Base load',async()=>{
 state.rule.enabled=true;fail='/api/sqm';await load('sqm');
 assert.equal(await page.locator('#sqm_rule_en').isChecked(),true);assert.equal(await page.locator('#sqm_rule_gb').inputValue(),'50');
 assert.equal(await page.getByRole('button',{name:'Save daily rule',exact:true}).isEnabled(),true);
 assert.equal(await page.getByRole('button',{name:'Apply baseline',exact:true}).isEnabled(),false);
 assert.ok((await page.locator('#sqm_rule_note').textContent()).includes('Waiting'));fail='';
 });fail='';
 await check('failed initial daily load cannot save unchecked defaults',async()=>{
 for(const failure of ['api','network']){if(failure==='api')fail='/api/sqm/conditional';else readNetworkFail='/api/sqm/conditional';
 await load('sqm');assert.equal(await page.getByRole('button',{name:'Save daily rule',exact:true}).isEnabled(),false);assert.equal(await page.locator('#sqm_rule_en').isEnabled(),false);
 assert.equal(await page.getByRole('button',{name:'Apply baseline',exact:true}).isEnabled(),true);
 assert.ok((await page.locator('#sqm_rule_out').textContent()).includes('load failed'));const n=writes.length;await page.evaluate(()=>saveSqmRule());assert.equal(writes.length,n);fail='';readNetworkFail='';
 await page.evaluate(()=>loadSqmRule());assert.equal(await page.locator('#sqm_rule_en').isChecked(),true);assert.equal(await page.getByRole('button',{name:'Save daily rule',exact:true}).isEnabled(),true);}
 });fail='';readNetworkFail='';
 await check('delayed daily load disables edits until saved values arrive',async()=>{
 ruleDelay=700;await page.goto('http://manager.test/?qa='+Math.random()+'#sqm');
 await page.waitForFunction(()=>!!sqmRulePromise);assert.equal(await page.locator('#sqm_rule_en').isEnabled(),false);assert.equal(await page.getByRole('button',{name:'Save daily rule',exact:true}).isEnabled(),false);
 await page.waitForFunction(()=>sqmRuleLoaded&&!sqmRulePromise);await page.evaluate(()=>openSqmEditor(sqmSelected));assert.equal(await page.locator('#sqm_rule_en').isChecked(),true);ruleDelay=0;
 });ruleDelay=0;
 await check('daily reload failure preserves enabled draft and save targets the rule',async()=>{
 await load('sqm');await page.locator('#sqm_rule_en').uncheck();await page.locator('#sqm_rule_gb').fill('77');
 fail='/api/sqm/conditional';await page.evaluate(()=>loadSqmRule());assert.equal(await page.locator('#sqm_rule_en').isChecked(),false);assert.equal(await page.locator('#sqm_rule_gb').inputValue(),'77');fail='';
 await page.locator('#sqm_rule_en').check();await page.getByRole('button',{name:'Save daily rule',exact:true}).click();await page.waitForFunction(()=>!busy&&!sqmRulePromise);
 const saved=writes.filter(w=>w.path==='/api/sqm/conditional').at(-1).body;assert.equal(saved.enabled,true);assert.equal(saved.threshold_gb,'77');assert.equal(await page.locator('#sqm_rule_en').isChecked(),true);
 state.rule.threshold_gb=50;
 });
 await check('daily interface editors isolate drafts, units, saves and summary',async()=>{
 state.extraRule=null;await load('sqm');await page.locator('#sqm_unit').selectOption('KB/s');
 await page.locator('#sqm_down').fill('888');await page.locator('#sqm_rule_gb').fill('66');
 await chooseSqm('eth2');assert.equal(await page.locator('#sqm_rule_en').isChecked(),false);assert.equal(await page.locator('#sqm_rule_gb').inputValue(),'5');
 await page.locator('#sqm_rule_gb').fill('9');await page.locator('#sqm_rule_down').fill('750');await page.locator('#sqm_rule_en').check();
 await page.locator('#sqm_unit').selectOption('Mb/s');await chooseSqm('br-lan');assert.equal(await page.locator('#sqm_rule_gb').inputValue(),'66');
 await chooseSqm('eth2');assert.equal(await page.locator('#sqm_rule_down').inputValue(),'6');
 const primary={...state.rule};await page.getByRole('button',{name:'Save daily rule',exact:true}).click();await page.waitForFunction(()=>!busy&&!sqmRulePromise);
 const saved=writes.filter(w=>w.path==='/api/sqm/conditional').at(-1).body;assert.equal(saved.interface,'eth2');assert.equal(saved.threshold_gb,'9');assert.equal(saved.download,'750');assert.deepEqual(state.rule,primary);
 assert.equal(await page.locator('#sqm_if').inputValue(),'eth2');await chooseSqm('br-lan');assert.equal(await page.locator('#sqm_down').inputValue(),'7.104');
 await chooseSqm('br-lan');assert.equal(await page.locator('#sqm_rule_gb').inputValue(),'66');
 assert.ok((await page.locator('.sqm-summary-daily-rule[data-interface="eth2"]').textContent()).includes('9 GB'));
 state.extraRule=null;await page.locator('#sqm_unit').selectOption('KB/s');
 });
 await check('Baseline stays separate from active Daily rates through reload, save and disable',async()=>{
 const originalSqm={...state.sqm},originalRule={...state.rule};
 try{
  state.baselineSqm={...state.sqm,download:12500,upload:25000};
  state.sqm={...state.sqm,download:2500,upload:2500};
  Object.assign(state.rule,{enabled:true,active:true,error:'',download:2500,upload:2500});
  await load('sqm');await page.locator('#sqm_unit').selectOption('Mb/s');
  assert.equal(await page.locator('#sqm_base h4').textContent(),'Baseline');
  assert.equal(await page.locator('#sqm_daily h4').textContent(),'Daily');
  assert.equal(await page.locator('#sqm_down').inputValue(),'100');
  assert.equal(await page.locator('#sqm_up').inputValue(),'200');
  assert.equal(await page.locator('#sqm_rule_down').inputValue(),'20');
  const active=page.locator('.sqm-summary-queue[data-interface="br-lan"]');
  const baseline=page.locator('.sqm-summary-baseline[data-interface="br-lan"]');
  assert.ok((await active.textContent()).includes('Daily active'));
  assert.ok((await active.textContent()).includes('20 Mb/s'));
  assert.ok((await baseline.textContent()).includes('200 Mb/s'));
  await page.evaluate(()=>loadSqm());assert.equal(await page.locator('#sqm_down').inputValue(),'100');
  await page.locator('#sqm_down').fill('120');
  await page.getByRole('button',{name:'Apply baseline',exact:true}).click();await page.waitForFunction(()=>!busy);
  assert.equal(writes.filter(w=>w.path==='/api/sqm').at(-1).body.download,'15000');
  assert.equal(await page.locator('#sqm_down').inputValue(),'120');
  assert.ok((await active.textContent()).includes('20 Mb/s'));
  await page.reload();await page.waitForFunction(()=>sqmLoaded&&sqmRuleLoaded&&!sqmPromise&&!sqmRulePromise);
  await page.evaluate(()=>openSqmEditor(sqmSelected));
  assert.equal(await page.locator('#sqm_down').inputValue(),'120');
  await page.locator('#sqm_rule_en').uncheck();
  await page.getByRole('button',{name:'Save daily rule',exact:true}).click();await page.waitForFunction(()=>!busy);
  assert.ok((await active.textContent()).includes('Baseline active'));
  assert.ok((await active.textContent()).includes('120 Mb/s'));
  assert.equal(await page.locator('#sqm_down').inputValue(),'120');
 }finally{state.sqm=originalSqm;state.rule=originalRule;delete state.baselineSqm;}
 });
 await check('summary groups each WAN day rule beneath its own SQM queue',async()=>{
 state.extraSqm={enabled:'1',interface:'eth2',download:1000,upload:500,qdisc:'cake',script:'piece_of_cake.qos'};await load('sqm');
 for(const iface of ['br-lan','eth2']){const group=page.locator('.sqm-summary-interface[data-interface="'+iface+'"]');assert.equal(await group.locator('.sqm-summary-queue[data-interface="'+iface+'"]').count(),1);assert.equal(await group.locator('.sqm-summary-daily-rule[data-interface="'+iface+'"]').count(),1);}
 assert.equal(await page.locator('#sqm_interface #sqm_base').count(),1);assert.equal(await page.locator('#sqm_interface #sqm_daily').count(),1);assert.equal(await page.locator('#sqm_if').count(),1);assert.equal(await page.locator('#sqm_rule_if').count(),0);
 await chooseSqm('eth2');assert.ok((await page.locator('#sqm_rule_scope').textContent()).includes('eth2'));assert.equal(await page.locator('#sqm_rule_gb').inputValue(),'5');state.extraSqm=null;
 });
 await check('failed daily interface save retains draft and selection',async()=>{
 await load('sqm');await chooseSqm('eth2');await page.locator('#sqm_rule_gb').fill('12');fail='/api/sqm/conditional';
 await page.getByRole('button',{name:'Save daily rule',exact:true}).click();await page.waitForFunction(()=>!busy);assert.equal(await page.locator('#sqm_back').isEnabled(),true);assert.equal(await page.locator('#sqm_rule_gb').inputValue(),'12');
 await chooseSqm('br-lan');await chooseSqm('eth2');assert.equal(await page.locator('#sqm_rule_gb').inputValue(),'12');fail='';
 });fail='';
 await check('Apply today activates only selected interface and blocks changes during save',async()=>{
 state.extraRule=null;await load('sqm');await chooseSqm('eth2');
 ruleDelay=500;page.once('dialog',dialog=>dialog.accept());const primary={...state.rule};await page.getByRole('button',{name:'Apply today (WAN rule)',exact:true}).click();
 await page.waitForFunction(()=>sqmRuleSaving);assert.equal(await page.locator('#sqm_back').isEnabled(),false);
 await page.waitForFunction(()=>!busy&&!sqmRuleSaving);assert.deepEqual(state.rule,primary);assert.equal(await page.locator('#sqm_back').isEnabled(),true);
 assert.ok((await page.locator('.sqm-summary-daily-rule[data-interface="eth2"]').textContent()).includes('Forced today'));assert.ok((await page.locator('.sqm-summary-daily-rule[data-interface="br-lan"]').textContent()).includes('Waiting'));
 ruleDelay=0;state.extraRule=null;
 });ruleDelay=0;
 await check('SQM summary and daily fields honor saved units when Base loads later',async()=>{
 await page.evaluate(()=>localStorage.setItem('opennds-sqm-unit','Mb/s'));baseDelay=600;await load('sqm');
 assert.equal(await page.locator('#sqm_unit').inputValue(),'Mb/s');assert.equal(await page.locator('#sqm_rule_down').inputValue(),String(state.rule.download/125));
 assert.ok((await page.locator('#sqm_summary_queues').textContent()).includes('Mb/s'));baseDelay=0;await page.locator('#sqm_unit').selectOption('KB/s');
 });baseDelay=0;
 await check('SQM summary shows saved queues and daily policy without including drafts',async()=>{
 state.extraSqm={enabled:'1',interface:'eth2',download:1000,upload:500,qdisc:'cake',script:'piece_of_cake.qos'};
 await load('sqm');await page.locator('#sqm_unit').selectOption('Mb/s');
 const extra=page.locator('.sqm-summary-queue[data-interface="eth2"]');assert.ok((await extra.textContent()).includes('4 Mb/s'));assert.ok((await extra.textContent()).includes('8 Mb/s'));
 assert.ok((await page.locator('#sqm_summary_queues').textContent()).includes('Waiting'));assert.ok((await page.locator('#sqm_summary_queues').textContent()).includes('br-lan'));assert.ok((await page.locator('#sqm_summary_queues').textContent()).includes('50 GB'));
 const saved=await page.locator('#sqm_summary_queues').textContent();await chooseSqm('eth2');await page.locator('#sqm_down').fill('12');assert.equal(await page.locator('#sqm_summary_queues').textContent(),saved);
 await page.getByRole('button',{name:'Apply baseline',exact:true}).click();await page.waitForFunction(()=>!busy);assert.ok((await extra.textContent()).includes('12 Mb/s'));
 fail='/api/sqm';await page.evaluate(()=>loadSqmBase());assert.ok((await page.locator('#sqm_summary_base_error').textContent()).includes('Last loaded queues'));assert.ok((await extra.textContent()).includes('12 Mb/s'));fail='';
 for(const [policy,expected] of [[{enabled:true,active:true},'Active'],[{enabled:true,active:true,forced_today:true},'Forced today'],[{enabled:false,active:false,forced_today:false},'Off'],[{enabled:true,error:'queue test failed'},'Error']]){Object.assign(state.rule,{error:'',forced_today:false},policy);await page.evaluate(()=>loadSqmRule());assert.ok((await page.locator('#sqm_summary_queues').textContent()).includes(expected));if(expected==='Active'){const primary=page.locator('.sqm-summary-queue[data-interface="br-lan"]');assert.ok((await primary.textContent()).includes('Daily active'));assert.ok((await primary.textContent()).includes('4.096 Mb/s'));}}
 Object.assign(state.rule,{enabled:true,active:false,forced_today:false,error:''});state.extraSqm=null;
 });fail='';
 await check('SQM editors keep independent interface drafts, units and queue settings',async()=>{
 state.extraSqm={enabled:'1',interface:'eth2',download:1000,upload:500,qdisc:'fq_codel',script:'simple.qos'};
 await load('sqm');await page.locator('#sqm_unit').selectOption('KB/s');
 assert.equal(await page.locator('#sqm_if').getAttribute('type'),'hidden');assert.equal(await page.locator('[data-sqm-edit=eth2]').count(),1);
 await page.locator('#sqm_down').fill('777');await page.locator('#sqm_rule_gb').fill('88');await chooseSqm('eth2');assert.equal(await page.locator('#sqm_rule_gb').inputValue(),'5');
 assert.equal(await page.locator('#sqm_down').inputValue(),'1000');assert.equal(await page.locator('#sqm_up').inputValue(),'500');assert.equal(await page.locator('#sqm_qd').inputValue(),'fq_codel');
 await page.locator('#sqm_down').fill('222');await page.locator('#sqm_unit').selectOption('Mb/s');
 await chooseSqm('br-lan');assert.equal(await page.locator('#sqm_down').inputValue(),'6.216');assert.equal(await page.locator('#sqm_rule_gb').inputValue(),'88');
 await chooseSqm('eth2');assert.equal(await page.locator('#sqm_down').inputValue(),'1.776');
 const primary={...state.sqm};await page.getByRole('button',{name:'Apply baseline',exact:true}).click();await page.waitForFunction(()=>!busy);
 const saved=writes.filter(w=>w.path==='/api/sqm').at(-1).body;assert.equal(saved.interface,'eth2');assert.equal(saved.download,'222');assert.deepEqual(state.sqm,primary);
 await page.evaluate(()=>loadSqm());assert.equal(await page.locator('#sqm_if').inputValue(),'eth2');assert.equal(await page.locator('#sqm_down').inputValue(),'1.776');
 assert.ok((await page.locator('#sqm_rule_scope').textContent()).includes('eth2'));assert.equal(await page.locator('#sqm_daily').isVisible(),true);
 await chooseSqm('eth0');assert.equal(await page.locator('#sqm_ingress_label').textContent(),'Download');assert.equal(await page.locator('#sqm_en').isChecked(),false);assert.ok((await page.locator('#sqmout').textContent()).includes('Not applied'));
 state.extraSqm=null;assert.equal(await page.locator('#sqm_daily').isVisible(),false);const n=writes.length;await page.evaluate(()=>saveSqmRule());assert.equal(writes.length,n);await page.locator('#sqm_unit').selectOption('KB/s');
 });
 await check('SQM failed extra-interface save retains selected queue and draft',async()=>{
 await load('sqm');await chooseSqm('eth2');await page.locator('#sqm_down').fill('333');
 fail='/api/sqm';await page.getByRole('button',{name:'Apply baseline',exact:true}).click();await page.waitForFunction(()=>!busy);assert.equal(await page.locator('#sqm_if').inputValue(),'eth2');assert.equal(await page.locator('#sqm_down').inputValue(),'333');assert.equal(await page.locator('#sqm_back').isEnabled(),true);fail='';
 await chooseSqm('br-lan');await chooseSqm('eth2');assert.equal(await page.locator('#sqm_down').inputValue(),'333');
 });
 await check('SQM unit changes preserve canonical rates and survive reload',async()=>{
 await load('sqm');await page.locator('#sqm_unit').selectOption('Mb/s');assert.equal(await page.locator('#sqm_down').inputValue(),'100');await page.getByRole('button',{name:'Apply baseline',exact:true}).click();assert.equal(writes.filter(w=>w.path==='/api/sqm').at(-1).body.download,'12500');await page.reload();await page.waitForFunction(()=>document.getElementById('sqm_down').value==='100');assert.equal(await page.locator('#sqm_unit').inputValue(),'Mb/s');
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
 for(const [tab,path,input,button,out] of [['limits','/api/limits','#ld_up','Save default policy','#lim_default_out'],['sqm','/api/sqm','#sqm_down','Apply baseline','#sqmout']]){
 await load(tab);await page.locator(input).fill('321');networkFail=path;await page.getByRole('button',{name:button}).click();await page.waitForFunction(id=>document.querySelector(id).textContent.startsWith('Failed:'),out);assert.equal(await page.locator(input).inputValue(),'321');await page.waitForFunction(name=>!document.querySelector('button[aria-label="'+name+'"]').disabled,button);networkFail='';}
 });networkFail='';
 await check('concurrent settings saves submit once',async()=>{
 await load('limits');const n=writes.length;await page.evaluate(()=>Promise.all([saveLimits(''),saveLimits('')]));assert.equal(writes.filter((_,i)=>i>=n).filter(w=>w.path==='/api/limits'&&w.method==='PUT').length,1);
 });
 fs.writeFileSync(root+'/behavior.json',JSON.stringify({checks,errors},null,2));console.log(JSON.stringify({checks,errors},null,2));assert.ok(checks.every(c=>c.pass));assert.deepEqual(errors,[]);
}
}finally{await browser.close();}})().catch(e=>{console.error(e);process.exit(1)});

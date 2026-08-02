package publicfiles

const portalHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>ReCasaOS Public Files</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <main>
    <h1>ReCasaOS Public Files</h1>
    <form id="login">
      <label for="token">Access token</label>
      <input id="token" type="password" autocomplete="off" autocapitalize="none" spellcheck="false" minlength="47" maxlength="47" pattern="rc1_[A-Za-z0-9_-]{43}" required>
      <button type="submit">Open files</button>
    </form>
    <section id="browser" hidden>
      <nav><button id="up" type="button">Up</button><code id="path">/</code><button id="logout" type="button">Forget token</button></nav>
      <p id="status" role="status"></p>
      <p class="help">Large files use a fail-closed browser stream when its Service Worker protocol is ready. The unsupported-browser fallback is one download at a time and limited to 32 MiB.</p>
      <ul id="entries"></ul>
    </section>
  </main>
  <script src="app.js" defer></script>
</body>
</html>
`

const portalCSS = `:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{margin:0;padding:2rem;background:#10151d;color:#edf2f7}main{max-width:58rem;margin:auto}[hidden]{display:none!important}form,nav{display:flex;gap:.75rem;align-items:center;flex-wrap:wrap}input,button{font:inherit;padding:.55rem .75rem;border-radius:.4rem;border:1px solid #778;background:#182231;color:inherit}button{cursor:pointer}button:disabled{cursor:not-allowed;opacity:.6}button:focus,input:focus,a:focus{outline:3px solid #69b7ff;outline-offset:2px}ul{list-style:none;padding:0;border-top:1px solid #445}li{display:flex;justify-content:space-between;gap:1rem;padding:.7rem;border-bottom:1px solid #334}a{color:#80c7ff}code{overflow-wrap:anywhere}#status{min-height:1.5rem}.size,.help{color:#aab}.help{font-size:.9rem}`

const downloadFrameHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ReCasaOS secure download transport</title>
</head>
<body>
  <script src="download-frame.js"></script>
</body>
</html>
`

const downloadFrameJavaScript = `'use strict';
const protocolVersion=1;
const workerReplyTimeoutMs=3000;
let binding=false;
let boundDownload=null;
function exactKeys(value,keys){if(!value||typeof value!=='object'||Array.isArray(value))return false;const actual=Object.keys(value).sort();const expected=keys.slice().sort();return actual.length===expected.length&&actual.every((key,index)=>key===expected[index]);}
function deny(port){try{port.postMessage({type:'recasaos-download-denied',version:protocolVersion});}catch(_error){}try{port.close();}catch(_error){}}
function validNonce(value){return typeof value==='string'&&/^[A-Za-z0-9_-]{32}$/.test(value);}
function exactDownloadURL(value,nonce){let url;try{url=new URL(value);}catch(_error){return false;}const keys=Array.from(url.searchParams.keys());return url.origin===location.origin&&url.pathname==='/public-files/api/file'&&keys.length===1&&keys[0]==='path'&&url.searchParams.getAll('path').length===1&&url.searchParams.get('path')!==''&&url.hash==='#'+nonce;}
window.addEventListener('message',event=>{
  const data=event.data;const port=event.ports&&event.ports.length===1?event.ports[0]:null;
  if(event.source!==parent||event.origin!==location.origin)return;
  if(port&&exactKeys(data,['frameProof','nonce','requestURL','type','version'])&&data.type==='recasaos-download-frame-bind'&&data.version===protocolVersion&&validNonce(data.nonce)&&validNonce(data.frameProof)&&exactDownloadURL(data.requestURL,data.nonce)){
    const controller='serviceWorker' in navigator?navigator.serviceWorker.controller:null;
    if(!controller||binding||boundDownload){deny(port);return;}
    binding=true;
    const channel=new MessageChannel();let settled=false;
    const finish=value=>{if(settled)return;settled=true;binding=false;clearTimeout(timer);channel.port1.close();if(value){boundDownload={nonce:data.nonce,requestURL:data.requestURL,frameProof:data.frameProof};try{port.postMessage({type:'recasaos-download-frame-bound',version:protocolVersion,nonce:data.nonce});}catch(_error){}try{port.close();}catch(_error){}}else deny(port);};
    const timer=setTimeout(()=>finish(false),workerReplyTimeoutMs);
    channel.port1.onmessage=status=>finish(exactKeys(status.data,['nonce','type','version'])&&status.data.type==='recasaos-download-frame-bound'&&status.data.version===protocolVersion&&status.data.nonce===data.nonce);
    channel.port1.onmessageerror=()=>finish(false);channel.port1.start();
    try{controller.postMessage({type:'recasaos-download-frame-bind',version:protocolVersion,nonce:data.nonce,frameProof:data.frameProof},[channel.port2]);}catch(_error){finish(false);}
    return;
  }
  if(!port&&exactKeys(data,['nonce','requestURL','type','version'])&&data.type==='recasaos-download-frame-navigate'&&data.version===protocolVersion&&boundDownload&&data.nonce===boundDownload.nonce&&data.requestURL===boundDownload.requestURL&&exactDownloadURL(data.requestURL,data.nonce)){
    const download=boundDownload;boundDownload=null;
    const form=document.createElement('form');form.method='post';form.action=download.requestURL;form.enctype='application/x-www-form-urlencoded';form.hidden=true;
    const proof=document.createElement('input');proof.type='hidden';proof.name='proof';proof.value=download.frameProof;form.append(proof);document.body.append(form);form.submit();
    return;
  }
  if(port)deny(port);
});
`

const portalJavaScript = `'use strict';
const protocolVersion=1;
const fallbackByteLimit=32*1024*1024;
const workerReplyTimeoutMs=3000;
const nativeRequestLifetimeMs=10000;
const bearerPattern=/^rc1_[A-Za-z0-9_-]{43}$/;
const login=document.getElementById('login');
const browser=document.getElementById('browser');
const tokenInput=document.getElementById('token');
const entries=document.getElementById('entries');
const statusNode=document.getElementById('status');
const pathNode=document.getElementById('path');
const upButton=document.getElementById('up');
let accessToken='';
let currentPath='';
let workerReady=false;
let workerController=null;
let pendingNative=null;
let activeNative=null;
let activeFallback=null;
let fallbackObjectURL='';
let nativeFrame=null;
let nativeFrameReady=false;

function token(){return accessToken;}
function apiURL(endpoint,path){const u=new URL(endpoint,window.location.href);u.search='';u.hash='';u.searchParams.set('path',path);return u;}
function nativeURL(path,nonce){const u=apiURL('api/file',path);u.hash=nonce;return u.href;}
function responseIsNoStore(response){return (response.headers.get('Cache-Control')||'').split(',').some(value=>value.trim().toLowerCase()==='no-store');}
function responseHeaderIsOnly(response,name,expected){const values=(response.headers.get(name)||'').split(',').map(value=>value.trim().toLowerCase()).filter(Boolean);return values.length>0&&values.every(value=>value===expected);}
async function api(endpoint,path,signal){
  const response=await fetch(apiURL(endpoint,path),{headers:{Authorization:'Bearer '+token()},credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',signal:signal});
  if(response.status===401){forgetAuthorization('Authorization failed');throw new Error('authorization failed');}
  if(!response.ok)throw new Error('Request failed ('+response.status+')');
  if(!responseIsNoStore(response)||!responseHeaderIsOnly(response,'X-Content-Type-Options','nosniff'))throw new Error('Response security policy is missing');
  return response;
}
function cancelNativeTransport(state){
  if(!state)return;
  if(state.port){try{state.port.close();}catch(_error){}}
  try{state.controller.postMessage({type:'recasaos-download-cancel',version:protocolVersion,nonce:state.nonce,path:state.path,requestURL:state.requestURL});}catch(_error){}
  if(state.frame&&state.frame===nativeFrame){state.frame.remove();nativeFrame=null;nativeFrameReady=false;}
}
function clearNativeState(){
  if(pendingNative){clearTimeout(pendingNative.timer);cancelNativeTransport(pendingNative);pendingNative=null;}
  if(activeNative){clearTimeout(activeNative.timer);cancelNativeTransport(activeNative);activeNative=null;}
}
function nativeDownloadFrame(){
  if(nativeFrame&&nativeFrame.isConnected&&nativeFrameReady)return Promise.resolve(nativeFrame);
  if(nativeFrame){nativeFrame.remove();nativeFrame=null;nativeFrameReady=false;}
  return new Promise(resolve=>{
    const frame=document.createElement('iframe');let settled=false;
    const finish=value=>{if(settled)return;settled=true;clearTimeout(timer);frame.onload=null;frame.onerror=null;if(!value){frame.remove();if(nativeFrame===frame){nativeFrame=null;nativeFrameReady=false;}}resolve(value);};
    const timer=setTimeout(()=>finish(null),workerReplyTimeoutMs);
    frame.hidden=true;frame.title='Secure download transport';frame.referrerPolicy='no-referrer';
    frame.onload=()=>{let valid=false;try{const value=new URL(frame.contentWindow.location.href);valid=value.origin===location.origin&&value.pathname==='/public-files/download-frame'&&value.search===''&&value.hash==='';}catch(_error){}if(valid&&nativeFrame===frame){nativeFrameReady=true;finish(frame);}else finish(null);};
    frame.onerror=()=>finish(null);
    frame.src='download-frame';nativeFrame=frame;document.body.append(frame);
  });
}
function revokeFallbackObjectURL(value){const target=value||fallbackObjectURL;if(!target)return;if(fallbackObjectURL===target)fallbackObjectURL='';URL.revokeObjectURL(target);}
function forgetAuthorization(message){
  accessToken='';
  clearNativeState();
  if(activeFallback){activeFallback.abort();activeFallback=null;}
  revokeFallbackObjectURL();
  showLogin(message);
}
function showLogin(message){login.hidden=false;browser.hidden=true;statusNode.textContent=message||'';tokenInput.value='';tokenInput.focus();}
function humanSize(value){if(value<1024)return value+' B';if(value<1048576)return (value/1024).toFixed(1)+' KiB';if(value<1073741824)return (value/1048576).toFixed(1)+' MiB';return (value/1073741824).toFixed(1)+' GiB';}
function exactKeys(value,keys){if(!value||typeof value!=='object'||Array.isArray(value))return false;const actual=Object.keys(value).sort();const expected=keys.slice().sort();return actual.length===expected.length&&actual.every((key,index)=>key===expected[index]);}
function randomNonce(){const bytes=new Uint8Array(24);crypto.getRandomValues(bytes);let value='';for(const byte of bytes)value+=String.fromCharCode(byte);return btoa(value).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function currentWorker(){return 'serviceWorker' in navigator?navigator.serviceWorker.controller:null;}
function canUseNativeStreaming(){return workerReady&&workerController&&currentWorker()===workerController;}
function waitForController(timeoutMs){
  const existing=currentWorker();if(existing)return Promise.resolve(existing);
  return new Promise(resolve=>{
    let settled=false;
    const finish=value=>{if(settled)return;settled=true;clearTimeout(timer);navigator.serviceWorker.removeEventListener('controllerchange',changed);resolve(value);};
    const changed=()=>finish(currentWorker());
    const timer=setTimeout(()=>finish(null),timeoutMs);
    navigator.serviceWorker.addEventListener('controllerchange',changed);
  });
}
function workerHandshake(controller){
  return new Promise(resolve=>{
    const channel=new MessageChannel();let settled=false;
    const finish=value=>{if(settled)return;settled=true;clearTimeout(timer);channel.port1.close();resolve(value);};
    const timer=setTimeout(()=>finish(false),workerReplyTimeoutMs);
    channel.port1.onmessage=event=>finish(exactKeys(event.data,['type','version'])&&event.data.type==='recasaos-download-protocol'&&event.data.version===protocolVersion);
    channel.port1.onmessageerror=()=>finish(false);
    channel.port1.start();
    try{controller.postMessage({type:'recasaos-download-protocol',version:protocolVersion},[channel.port2]);}catch(_error){finish(false);}
  });
}
async function prepareWorker(){
  if(!('serviceWorker' in navigator))return;
  try{
    await navigator.serviceWorker.register('download-worker.js',{scope:'/public-files/',updateViaCache:'none'});
    await navigator.serviceWorker.ready;
    const controller=await waitForController(workerReplyTimeoutMs);
    if(!controller)return;
    const ready=await workerHandshake(controller);
    if(ready&&currentWorker()===controller){workerController=controller;workerReady=true;}
  }catch(_error){workerController=null;workerReady=false;}
}
async function load(path){
  statusNode.textContent='Loading…';
  const response=await api('api/list',path);
  const body=await response.json();
  currentPath=body.path;
  pathNode.textContent='/'+currentPath;
  upButton.disabled=!currentPath;
  entries.replaceChildren();
  for(const entry of body.entries){
    const item=document.createElement('li');
    const link=document.createElement('a');
    const child=currentPath?currentPath+'/'+entry.name:entry.name;
    link.href='#';
    link.textContent=(entry.type==='directory'?'📁 ':'📄 ')+entry.name;
    if(entry.type==='directory')link.addEventListener('click',event=>{event.preventDefault();load(child).catch(showError);});
    else link.addEventListener('click',event=>{event.preventDefault();download(child,entry).catch(showError);});
    item.append(link);
    if(entry.type==='file'){const size=document.createElement('span');size.className='size';size.textContent=humanSize(entry.size);item.append(size);}
    entries.append(item);
  }
  statusNode.textContent=body.entries.length?body.entries.length+' entries':'This directory is empty';
}
function reserveNativeDownload(controller,state){
  return new Promise(resolve=>{
    const channel=new MessageChannel();let settled=false;
    const finish=value=>{if(settled)return;settled=true;clearTimeout(timer);channel.port1.close();resolve(value);};
    const timer=setTimeout(()=>finish(false),workerReplyTimeoutMs);
    channel.port1.onmessage=event=>finish(exactKeys(event.data,['nonce','type','version'])&&event.data.type==='recasaos-download-prepared'&&event.data.version===protocolVersion&&event.data.nonce===state.nonce);
    channel.port1.onmessageerror=()=>finish(false);
    channel.port1.start();
    try{controller.postMessage({type:'recasaos-download-prepare',version:protocolVersion,nonce:state.nonce,path:state.path,requestURL:state.requestURL,frameProof:state.frameProof},[channel.port2]);}catch(_error){finish(false);}
  });
}
function bindNativeDownloadFrame(controller,state){
  return new Promise(resolve=>{
    const frame=state.frame;const target=frame&&frame.contentWindow;const channel=new MessageChannel();let settled=false;
    const finish=value=>{if(settled)return;settled=true;clearTimeout(timer);channel.port1.close();resolve(value);};
    const timer=setTimeout(()=>finish(false),workerReplyTimeoutMs);
    channel.port1.onmessage=event=>finish(exactKeys(event.data,['nonce','type','version'])&&event.data.type==='recasaos-download-frame-bound'&&event.data.version===protocolVersion&&event.data.nonce===state.nonce);
    channel.port1.onmessageerror=()=>finish(false);
    channel.port1.start();
    if(!target){finish(false);return;}
    try{target.postMessage({type:'recasaos-download-frame-bind',version:protocolVersion,nonce:state.nonce,frameProof:state.frameProof,requestURL:state.requestURL},location.origin,[channel.port2]);}catch(_error){finish(false);}
  });
}
function navigateNativeDownloadFrame(state){const target=state.frame&&state.frame.contentWindow;if(!target)return false;try{target.postMessage({type:'recasaos-download-frame-navigate',version:protocolVersion,nonce:state.nonce,requestURL:state.requestURL},location.origin);return true;}catch(_error){return false;}}
async function startNativeDownload(path,entry){
  if(pendingNative||activeNative||activeFallback)throw new Error('Another download is already being prepared');
  const controller=currentWorker();
  if(!controller||controller!==workerController)throw new Error('Secure browser streaming is not ready');
  const nonce=randomNonce();
  const state={nonce:nonce,frameProof:randomNonce(),path:path,name:entry.name,requestURL:nativeURL(path,nonce),controller:controller,expiresAt:Date.now()+nativeRequestLifetimeMs,timer:null,frame:null};
  pendingNative=state;
  statusNode.textContent='Preparing secure browser stream for '+entry.name+'…';
  state.frame=await nativeDownloadFrame();
  if(pendingNative!==state||!accessToken){cancelNativeTransport(state);return;}
  if(!state.frame||currentWorker()!==controller){cancelNativeTransport(state);pendingNative=null;await boundedDownload(path,entry);return;}
  const prepared=await reserveNativeDownload(controller,state);
  if(pendingNative!==state||!accessToken){cancelNativeTransport(state);return;}
  if(!prepared||currentWorker()!==controller){
    cancelNativeTransport(state);
    pendingNative=null;
    await boundedDownload(path,entry);
    return;
  }
  const bound=await bindNativeDownloadFrame(controller,state);
  if(pendingNative!==state||!accessToken){cancelNativeTransport(state);return;}
  if(!bound||currentWorker()!==controller){cancelNativeTransport(state);pendingNative=null;await boundedDownload(path,entry);return;}
  state.frameProof='';
  state.timer=setTimeout(()=>{
    if(pendingNative!==state)return;
    cancelNativeTransport(state);
    pendingNative=null;
    boundedDownload(path,entry).catch(showError);
  },workerReplyTimeoutMs);
  statusNode.textContent='Handing '+entry.name+' to the browser…';
  if(!navigateNativeDownloadFrame(state)){
    clearTimeout(state.timer);cancelNativeTransport(state);pendingNative=null;
    await boundedDownload(path,entry);
  }
}
async function boundedDownload(path,entry){
  if(pendingNative||activeNative||activeFallback)throw new Error('Another download is already being prepared');
  if(!Number.isSafeInteger(entry.size)||entry.size<0||entry.size>fallbackByteLimit){
    throw new Error('This browser cannot safely download this file in memory; use a reviewed Authorization-header client');
  }
  const controller=new AbortController();activeFallback=controller;
  statusNode.textContent='Preparing bounded download '+entry.name+'…';
  try{
    const response=await api('api/file',path,controller.signal);
    const disposition=response.headers.get('Content-Disposition')||'';
    const contentType=(response.headers.get('Content-Type')||'').split(';',1)[0].trim().toLowerCase();
    if(!/^attachment(?:\s*;|$)/i.test(disposition)||contentType!=='application/octet-stream'||!responseHeaderIsOnly(response,'Accept-Ranges','bytes'))throw new Error('Download response policy is invalid');
    const lengthValue=response.headers.get('Content-Length');
    if(lengthValue===null||!/^(?:0|[1-9][0-9]*)$/.test(lengthValue))throw new Error('Download length is missing or invalid');
    const expectedLength=Number(lengthValue);
    if(!Number.isSafeInteger(expectedLength)||expectedLength>fallbackByteLimit)throw new Error('Download exceeds the '+humanSize(fallbackByteLimit)+' browser-memory limit');
    if(!response.body||typeof response.body.getReader!=='function')throw new Error('This browser cannot enforce the fallback download limit');
    const reader=response.body.getReader();const chunks=[];let received=0;
    try{
      for(;;){
        const result=await reader.read();if(result.done)break;
        if(!(result.value instanceof Uint8Array))throw new Error('Unexpected download data');
        received+=result.value.byteLength;
        if(received>expectedLength||received>fallbackByteLimit)throw new Error('Download exceeded its declared limit');
        chunks.push(result.value);
      }
    }catch(error){try{await reader.cancel();}catch(_cancelError){}throw error;}
    if(received!==expectedLength)throw new Error('Download ended before the declared length');
    revokeFallbackObjectURL();
    const objectURL=URL.createObjectURL(new Blob(chunks,{type:'application/octet-stream'}));fallbackObjectURL=objectURL;
    const link=document.createElement('a');link.href=objectURL;link.download=entry.name;link.referrerPolicy='no-referrer';link.rel='noopener';
    document.body.append(link);link.click();link.remove();
    setTimeout(()=>revokeFallbackObjectURL(objectURL),60000);
    statusNode.textContent='Download handed to the browser: '+entry.name;
  }finally{if(activeFallback===controller)activeFallback=null;}
}
async function download(path,entry){if(canUseNativeStreaming())await startNativeDownload(path,entry);else await boundedDownload(path,entry);}
function denyPort(port){try{port.postMessage({type:'recasaos-download-denied',version:protocolVersion});}catch(_error){}try{port.close();}catch(_error){}}
function handleWorkerChallenge(event){
  const data=event.data;const port=event.ports&&event.ports.length===1?event.ports[0]:null;const pending=pendingNative;
  if(!port)return;
  if(!pending||!exactKeys(data,['nonce','path','requestURL','type','version'])||data.type!=='recasaos-download-auth'||data.version!==protocolVersion||event.source!==pending.controller||currentWorker()!==pending.controller||Date.now()>pending.expiresAt||data.nonce!==pending.nonce||data.path!==pending.path||data.requestURL!==pending.requestURL||!accessToken){denyPort(port);return;}
  clearTimeout(pending.timer);pendingNative=null;
  const state={nonce:pending.nonce,path:pending.path,name:pending.name,requestURL:pending.requestURL,controller:pending.controller,port:port,timer:null,frame:pending.frame};
  state.timer=setTimeout(()=>{if(activeNative===state){cancelNativeTransport(state);activeNative=null;showError(new Error('The browser did not accept the download in time'));}},nativeRequestLifetimeMs);
  activeNative=state;
  port.onmessage=statusEvent=>{
    const status=statusEvent.data;
    if(activeNative!==state||!exactKeys(status,['httpStatus','nonce','path','status','type','version'])||status.type!=='recasaos-download-status'||status.version!==protocolVersion||status.nonce!==state.nonce||status.path!==state.path)return;
    clearTimeout(state.timer);activeNative=null;port.close();
    if(status.status==='handed'&&(status.httpStatus===200||status.httpStatus===206)){statusNode.textContent='Download handed to the browser: '+state.name;return;}
    cancelNativeTransport(state);
    if(status.httpStatus===401){forgetAuthorization('Authorization failed');return;}
    showError(new Error('The browser download was rejected'));
  };
  port.onmessageerror=()=>{if(activeNative===state){clearTimeout(state.timer);cancelNativeTransport(state);activeNative=null;showError(new Error('Secure download authorization failed'));}};
  port.start();
  port.postMessage({type:'recasaos-download-auth-response',version:protocolVersion,nonce:pending.nonce,path:pending.path,token:accessToken});
}
function showError(error){if(!browser.hidden)statusNode.textContent=error&&error.message?error.message:'Request failed';}
login.addEventListener('submit',event=>{event.preventDefault();const candidate=tokenInput.value;tokenInput.value='';if(!bearerPattern.test(candidate)){showLogin('A valid rc1_ access token is required');return;}accessToken=candidate;login.hidden=true;browser.hidden=false;load('').catch(showError);prepareWorker();});
upButton.addEventListener('click',()=>{const parts=currentPath.split('/');parts.pop();load(parts.join('/')).catch(showError);});
document.getElementById('logout').addEventListener('click',()=>forgetAuthorization('Token forgotten for this page'));
if('serviceWorker' in navigator){
  navigator.serviceWorker.addEventListener('message',handleWorkerChallenge);
  navigator.serviceWorker.addEventListener('controllerchange',()=>{clearNativeState();workerReady=false;workerController=null;prepareWorker();});
}
window.addEventListener('pagehide',()=>{accessToken='';clearNativeState();if(nativeFrame){nativeFrame.remove();nativeFrame=null;nativeFrameReady=false;}if(activeFallback)activeFallback.abort();revokeFallbackObjectURL();});
window.addEventListener('pageshow',event=>{if(event.persisted&&!accessToken)showLogin('Token forgotten after page restore');});
showLogin('');
`

const downloadWorkerJavaScript = `'use strict';
const protocolVersion=1;
const challengeTimeoutMs=3000;
const pendingLifetimeMs=10000;
const pendingLimit=8;
const basePath='/public-files';
const filePath=basePath+'/api/file';
const framePath=basePath+'/download-frame';
const portalPath=basePath+'/';
const bearerPattern=/^rc1_[A-Za-z0-9_-]{43}$/;
const pendingDownloads=new Map();
const activeDownloads=new Map();

function exactKeys(value,keys){if(!value||typeof value!=='object'||Array.isArray(value))return false;const actual=Object.keys(value).sort();const expected=keys.slice().sort();return actual.length===expected.length&&actual.every((key,index)=>key===expected[index]);}
function canonicalClient(client){
  if(!client||client.type!=='window'||client.frameType!=='top-level')return false;
  const url=new URL(client.url);
  return url.origin===self.location.origin&&url.pathname===portalPath&&url.search===''&&url.hash==='';
}
function canonicalFrameClient(client){
  if(!client||client.type!=='window'||client.frameType!=='nested')return false;
  const url=new URL(client.url);
  return url.origin===self.location.origin&&url.pathname===framePath&&url.search===''&&url.hash==='';
}
function validRelativePath(value){
  if(!value||value.length>4096||value[0]==='/'||value.indexOf('\\')!==-1||value.indexOf(String.fromCharCode(0))!==-1)return false;
  const parts=value.split('/');
  return parts.every(part=>part&&part!=='.'&&part!=='..'&&part[0]!=='.');
}
function validNonce(value){return typeof value==='string'&&/^[A-Za-z0-9_-]{32}$/.test(value);}
function exactPreparedURL(value,path,nonce){
  let url;try{url=new URL(value);}catch(_error){return false;}
  const keys=Array.from(url.searchParams.keys());
  return url.origin===self.location.origin&&url.pathname===filePath&&keys.length===1&&keys[0]==='path'&&url.searchParams.getAll('path').length===1&&url.searchParams.get('path')===path&&url.hash==='#'+nonce;
}
async function exactNavigationProof(request,prepared){
  const contentType=(request.headers.get('Content-Type')||'').split(';',1)[0].trim().toLowerCase();
  if(contentType!=='application/x-www-form-urlencoded')return false;
  let body='';try{body=await request.text();}catch(_error){return false;}
  return body==='proof='+prepared.frameProof;
}
function purgePending(){const now=Date.now();for(const [nonce,state] of pendingDownloads){if(state.expiresAt<now)pendingDownloads.delete(nonce);}}
function reply(port,value){try{port.postMessage(value);}catch(_error){}try{port.close();}catch(_error){}}
function sameDownloadState(state,data,clientId){return state&&state.clientId===clientId&&state.nonce===data.nonce&&state.path===data.path&&state.requestURL===data.requestURL;}
function cancelDownload(event,data){
  const prepared=pendingDownloads.get(data.nonce);
  if(sameDownloadState(prepared,data,event.source.id))pendingDownloads.delete(data.nonce);
  const active=activeDownloads.get(data.nonce);
  if(sameDownloadState(active,data,event.source.id)){activeDownloads.delete(data.nonce);clearTimeout(active.timer);active.controller.abort();}
}
function bindDownloadFrame(event,data,port){
  if(!port)return;
  if(!canonicalFrameClient(event.source)||!exactKeys(data,['frameProof','nonce','type','version'])||data.type!=='recasaos-download-frame-bind'||data.version!==protocolVersion||!validNonce(data.nonce)||!validNonce(data.frameProof)){reply(port,{type:'recasaos-download-denied',version:protocolVersion});return;}
  purgePending();
  const prepared=pendingDownloads.get(data.nonce);
  if(!prepared||prepared.expiresAt<Date.now()||prepared.frameClientId!==''||prepared.frameProof!==data.frameProof){reply(port,{type:'recasaos-download-denied',version:protocolVersion});return;}
  prepared.frameClientId=event.source.id;
  reply(port,{type:'recasaos-download-frame-bound',version:protocolVersion,nonce:data.nonce});
}
function handleProtocolMessage(event){
  const data=event.data;const port=event.ports&&event.ports.length===1?event.ports[0]:null;
  if(data&&data.type==='recasaos-download-frame-bind'){bindDownloadFrame(event,data,port);return;}
  if(!canonicalClient(event.source))return;
  if(exactKeys(data,['nonce','path','requestURL','type','version'])&&data.type==='recasaos-download-cancel'&&data.version===protocolVersion&&validNonce(data.nonce)&&validRelativePath(data.path)&&exactPreparedURL(data.requestURL,data.path,data.nonce)){cancelDownload(event,data);if(port)reply(port,{type:'recasaos-download-canceled',version:protocolVersion,nonce:data.nonce});return;}
  if(!port)return;
  if(exactKeys(data,['type','version'])&&data.type==='recasaos-download-protocol'&&data.version===protocolVersion){reply(port,{type:'recasaos-download-protocol',version:protocolVersion});return;}
  if(!exactKeys(data,['frameProof','nonce','path','requestURL','type','version'])||data.type!=='recasaos-download-prepare'||data.version!==protocolVersion||!validNonce(data.nonce)||!validNonce(data.frameProof)||!validRelativePath(data.path)||!exactPreparedURL(data.requestURL,data.path,data.nonce)){reply(port,{type:'recasaos-download-denied',version:protocolVersion});return;}
  purgePending();
  if(pendingDownloads.size+activeDownloads.size>=pendingLimit||pendingDownloads.has(data.nonce)||activeDownloads.has(data.nonce)){reply(port,{type:'recasaos-download-denied',version:protocolVersion});return;}
  const state={nonce:data.nonce,path:data.path,requestURL:data.requestURL,clientId:event.source.id,frameClientId:'',frameProof:data.frameProof,expiresAt:Date.now()+pendingLifetimeMs};
  pendingDownloads.set(data.nonce,state);
  setTimeout(()=>{if(pendingDownloads.get(data.nonce)===state)pendingDownloads.delete(data.nonce);},pendingLifetimeMs);
  reply(port,{type:'recasaos-download-prepared',version:protocolVersion,nonce:data.nonce});
}
function parseDownload(request){
  const url=new URL(request.url);
  const supportedNavigation=request.mode==='navigate'&&(request.destination==='document'||request.destination==='iframe');
  if(url.origin!==self.location.origin||url.pathname!==filePath||!supportedNavigation)return null;
  if(request.method!=='POST')return {error:true};
  const keys=Array.from(url.searchParams.keys());const nonce=url.hash.slice(1);
  if(keys.length!==1||keys[0]!=='path'||url.searchParams.getAll('path').length!==1||!validNonce(nonce))return {error:true};
  const path=url.searchParams.get('path');
  if(!validRelativePath(path))return {error:true};
  return {error:false,nonce:nonce,path:path,requestURL:url.href};
}
function requestAuthorization(client,download,signal){
  return new Promise((resolve,reject)=>{
    const channel=new MessageChannel();let settled=false;let timer=0;
    const aborted=()=>finish(new TypeError('download authorization canceled'));
    const finish=(error,value)=>{if(settled)return;settled=true;clearTimeout(timer);signal.removeEventListener('abort',aborted);channel.port1.onmessage=null;channel.port1.onmessageerror=null;if(error){channel.port1.close();reject(error);}else resolve({token:value,port:channel.port1});};
    timer=setTimeout(()=>finish(new TypeError('download authorization timeout')),challengeTimeoutMs);
    if(signal.aborted){finish(new TypeError('download authorization canceled'));return;}
    signal.addEventListener('abort',aborted,{once:true});
    channel.port1.onmessage=event=>{
      const data=event.data;
      if(!exactKeys(data,['nonce','path','token','type','version'])||data.type!=='recasaos-download-auth-response'||data.version!==protocolVersion||data.nonce!==download.nonce||data.path!==download.path||typeof data.token!=='string'||!bearerPattern.test(data.token)){finish(new TypeError('download authorization denied'));return;}
      finish(null,data.token);
    };
    channel.port1.onmessageerror=()=>finish(new TypeError('download authorization message error'));
    channel.port1.start();
    try{client.postMessage({type:'recasaos-download-auth',version:protocolVersion,nonce:download.nonce,path:download.path,requestURL:download.requestURL},[channel.port2]);}catch(_error){finish(new TypeError('download authorization client error'));}
  });
}
function sendStatus(port,download,status,httpStatus){try{port.postMessage({type:'recasaos-download-status',version:protocolVersion,nonce:download.nonce,path:download.path,status:status,httpStatus:httpStatus});}catch(_error){}try{port.close();}catch(_error){}}
function responseHeaderIsOnly(response,name,expected){const values=(response.headers.get(name)||'').split(',').map(value=>value.trim().toLowerCase()).filter(Boolean);return values.length>0&&values.every(value=>value===expected);}
function safeDownloadResponse(response,cleanURL,requestedRange){
  const disposition=response.headers.get('Content-Disposition')||'';
  const contentType=(response.headers.get('Content-Type')||'').split(';',1)[0].trim().toLowerCase();
  const cacheDirectives=(response.headers.get('Cache-Control')||'').split(',').map(value=>value.trim().toLowerCase());
  const contentRange=response.headers.get('Content-Range')||'';
  return !response.redirected&&response.url===cleanURL.href&&(response.status===200||response.status===206)&&/^attachment(?:\s*;|$)/i.test(disposition)&&contentType==='application/octet-stream'&&cacheDirectives.includes('no-store')&&responseHeaderIsOnly(response,'X-Content-Type-Options','nosniff')&&responseHeaderIsOnly(response,'Accept-Ranges','bytes')&&(response.status!==206||(requestedRange&&/^bytes [0-9]+-[0-9]+\/[0-9]+$/.test(contentRange)));
}
async function handleDownload(download,event){
  if(download.error)throw new TypeError('invalid download request');
  purgePending();
  const prepared=pendingDownloads.get(download.nonce);
  if(!prepared||prepared.expiresAt<Date.now()||prepared.path!==download.path||prepared.requestURL!==download.requestURL||prepared.frameClientId==='')throw new TypeError('download was not prepared by this client');
  if(!(await exactNavigationProof(event.request,prepared)))throw new TypeError('download navigation proof changed');
  prepared.frameProof='';
  pendingDownloads.delete(download.nonce);
  const controller=new AbortController();
  const active={nonce:prepared.nonce,path:prepared.path,requestURL:prepared.requestURL,clientId:prepared.clientId,controller:controller,timer:null};
  const abortFromNavigation=()=>controller.abort();
  if(event.request.signal.aborted)controller.abort();else event.request.signal.addEventListener('abort',abortFromNavigation,{once:true});
  active.timer=setTimeout(()=>controller.abort(),pendingLifetimeMs);
  activeDownloads.set(download.nonce,active);
  let authorization=null;let rejectionStatus=0;
  try{
    const client=await self.clients.get(prepared.clientId);
    if(!canonicalClient(client))throw new TypeError('download client is unavailable');
    authorization=await requestAuthorization(client,download,controller.signal);
    const currentClient=await self.clients.get(prepared.clientId);
    if(!canonicalClient(currentClient)||currentClient.id!==client.id||currentClient.url!==client.url)throw new TypeError('download client changed');
    const headers=new Headers();
    for(const name of ['Range','If-Range']){const value=event.request.headers.get(name);if(value!==null)headers.set(name,value);}
    headers.set('Authorization','Bearer '+authorization.token);
    const cleanURL=new URL(filePath,self.location.origin);cleanURL.searchParams.set('path',download.path);
    const request=new Request(cleanURL.href,{method:'GET',headers:headers,credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',mode:'same-origin',signal:controller.signal});
    const response=await fetch(request);
    if(!safeDownloadResponse(response,cleanURL,headers.has('Range'))){rejectionStatus=response.status;throw new TypeError('download response rejected');}
    if(activeDownloads.get(download.nonce)===active)activeDownloads.delete(download.nonce);clearTimeout(active.timer);event.request.signal.removeEventListener('abort',abortFromNavigation);
    sendStatus(authorization.port,download,'handed',response.status);
    return response;
  }catch(error){if(activeDownloads.get(download.nonce)===active)activeDownloads.delete(download.nonce);clearTimeout(active.timer);event.request.signal.removeEventListener('abort',abortFromNavigation);controller.abort();if(authorization)sendStatus(authorization.port,download,'rejected',rejectionStatus);throw error;}
}
function emptyNavigationResponse(){return new Response(null,{status:204,headers:{'Cache-Control':'no-store','Referrer-Policy':'no-referrer','X-Content-Type-Options':'nosniff'}});}
async function respondToDownload(download,event){try{return await handleDownload(download,event);}catch(_error){return emptyNavigationResponse();}}
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('message',handleProtocolMessage);
self.addEventListener('fetch',event=>{const download=parseDownload(event.request);if(download!==null)event.respondWith(respondToDownload(download,event));});
`

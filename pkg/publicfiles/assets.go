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
      <input id="token" name="token" type="password" autocomplete="off" required>
      <button type="submit">Open files</button>
    </form>
    <section id="browser" hidden>
      <nav><button id="up" type="button">Up</button><code id="path">/</code><button id="logout" type="button">Forget token</button></nav>
      <p id="status" role="status"></p>
      <ul id="entries"></ul>
    </section>
  </main>
  <script src="app.js" defer></script>
</body>
</html>
`

const portalCSS = `:root{color-scheme:light dark;font:16px/1.5 system-ui,sans-serif}body{margin:0;padding:2rem;background:#10151d;color:#edf2f7}main{max-width:58rem;margin:auto}form,nav{display:flex;gap:.75rem;align-items:center;flex-wrap:wrap}input,button{font:inherit;padding:.55rem .75rem;border-radius:.4rem;border:1px solid #778;background:#182231;color:inherit}button{cursor:pointer}button:focus,input:focus,a:focus{outline:3px solid #69b7ff;outline-offset:2px}ul{list-style:none;padding:0;border-top:1px solid #445}li{display:flex;justify-content:space-between;gap:1rem;padding:.7rem;border-bottom:1px solid #334}a{color:#80c7ff}code{overflow-wrap:anywhere}#status{min-height:1.5rem}.size{color:#aab}`

const portalJavaScript = `'use strict';
const key='recasaos-public-file-token';
const login=document.getElementById('login');
const browser=document.getElementById('browser');
const tokenInput=document.getElementById('token');
const entries=document.getElementById('entries');
const statusNode=document.getElementById('status');
const pathNode=document.getElementById('path');
const upButton=document.getElementById('up');
let currentPath='';

function token(){return sessionStorage.getItem(key)||'';}
function apiURL(endpoint,path){const u=new URL(endpoint,window.location.href);u.searchParams.set('path',path);return u;}
async function api(endpoint,path){
  const response=await fetch(apiURL(endpoint,path),{headers:{Authorization:'Bearer '+token()},credentials:'omit',cache:'no-store'});
  if(response.status===401){sessionStorage.removeItem(key);showLogin('Authorization failed');throw new Error('authorization failed');}
  if(!response.ok)throw new Error('Request failed ('+response.status+')');
  return response;
}
function showLogin(message){login.hidden=false;browser.hidden=true;statusNode.textContent=message||'';tokenInput.value='';tokenInput.focus();}
function humanSize(value){if(value<1024)return value+' B';if(value<1048576)return (value/1024).toFixed(1)+' KiB';if(value<1073741824)return (value/1048576).toFixed(1)+' MiB';return (value/1073741824).toFixed(1)+' GiB';}
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
    else link.addEventListener('click',event=>{event.preventDefault();download(child,entry.name).catch(showError);});
    item.append(link);
    if(entry.type==='file'){const size=document.createElement('span');size.className='size';size.textContent=humanSize(entry.size);item.append(size);}
    entries.append(item);
  }
  statusNode.textContent=body.entries.length?body.entries.length+' entries':'This directory is empty';
}
async function download(path,name){
  statusNode.textContent='Downloading '+name+'…';
  const response=await api('api/file',path);
  const blob=await response.blob();
  const objectURL=URL.createObjectURL(blob);
  const link=document.createElement('a');link.href=objectURL;link.download=name;document.body.append(link);link.click();link.remove();URL.revokeObjectURL(objectURL);
  statusNode.textContent='Downloaded '+name;
}
function showError(error){statusNode.textContent=error.message||'Request failed';}
login.addEventListener('submit',event=>{event.preventDefault();sessionStorage.setItem(key,tokenInput.value);login.hidden=true;browser.hidden=false;load('').catch(showError);});
upButton.addEventListener('click',()=>{const parts=currentPath.split('/');parts.pop();load(parts.join('/')).catch(showError);});
document.getElementById('logout').addEventListener('click',()=>{sessionStorage.removeItem(key);showLogin('Token forgotten');});
if(token()){login.hidden=true;browser.hidden=false;load('').catch(showError);}else showLogin('');
`

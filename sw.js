importScripts('./vault-config.js');
const config = self.VAULT;
const databaseName = 'time-creation-preview:'+config.base;
let session;
const decrypted = new Map();
const decode = text => Uint8Array.from(atob(text), c=>c.charCodeAt(0));

async function database() {
  return new Promise((resolve,reject) => {
    const request=indexedDB.open(databaseName,1);
    request.onupgradeneeded=()=>request.result.createObjectStore('session');
    request.onsuccess=()=>resolve(request.result);
    request.onerror=()=>reject(request.error);
  });
}
async function readSession() {
  const db=await database();
  try { return await new Promise((resolve,reject)=>{const request=db.transaction('session').objectStore('session').get(config.version);request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);}); }
  finally {db.close();}
}
async function saveSession(value) {
  const db=await database();
  try {await new Promise((resolve,reject)=>{const transaction=db.transaction('session','readwrite');transaction.objectStore('session').clear();transaction.objectStore('session').put(value,config.version);transaction.oncomplete=resolve;transaction.onerror=()=>reject(transaction.error);transaction.onabort=()=>reject(transaction.error);});}
  finally {db.close();}
}
const restored=readSession().then(value=>{if(value?.expires>Date.now())session=value;}).catch(()=>{});
async function decryptFile(path,key) {
  const item=config.files[path];
  const response=await fetch(new URL(config.base+'.sealed/'+item.file,self.location.origin),{cache:'force-cache'});
  if(!response.ok)throw new Error('Could not load the preview. Please try again.');
  return crypto.subtle.decrypt({name:'AES-GCM',iv:decode(item.iv)},key,await response.arrayBuffer());
}
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('message',event=>{
  if(event.data?.type!=='unlock'||!event.ports[0])return;
  event.waitUntil((async()=>{
    try {
      await restored;
      const index=await decryptFile('index.html',event.data.key);
      session={key:event.data.key,expires:Date.now()+12*60*60*1000};
      decrypted.clear();decrypted.set('index.html',Promise.resolve(index));
      await saveSession(session).catch(()=>{});
      event.ports[0].postMessage({ok:true});
    } catch(error) {event.ports[0].postMessage({ok:false,error:error.name==='OperationError'?'That password didn’t match. Please try again.':error.message});}
  })());
});
async function respond(request,path) {
  await restored;
  if(!session||session.expires<=Date.now()) {
    session=undefined;decrypted.clear();
    if(request.mode==='navigate') return fetch(config.base+'gate.html',{cache:'no-store'});
    return new Response('Preview password required',{status:401,headers:{'Cache-Control':'no-store'}});
  }
  if(path===''||path==='index.html'||(request.mode==='navigate'&&!config.files[path]))path='index.html';
  const item=config.files[path];
  if(!item)return new Response('Not found',{status:404});
  try {
    if(!decrypted.has(path))decrypted.set(path,decryptFile(path,session.key).catch(error=>{decrypted.delete(path);throw error;}));
    const buffer=await decrypted.get(path);
    const headers={'Content-Type':item.type,'Content-Length':String(buffer.byteLength),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Accept-Ranges':'bytes'};
    const range=request.headers.get('Range');
    if(range) {
      const match=/^bytes=(\d*)-(\d*)$/.exec(range);
      if(!match||(!match[1]&&!match[2]))return new Response(null,{status:416,headers:{'Content-Range':`bytes */${buffer.byteLength}`}});
      const start=match[1]?Number(match[1]):Math.max(0,buffer.byteLength-Number(match[2]));
      const end=match[1]&&match[2]?Math.min(Number(match[2]),buffer.byteLength-1):buffer.byteLength-1;
      if(start>end||start>=buffer.byteLength)return new Response(null,{status:416,headers:{'Content-Range':`bytes */${buffer.byteLength}`}});
      headers['Content-Range']=`bytes ${start}-${end}/${buffer.byteLength}`;
      headers['Content-Length']=String(end-start+1);
      return new Response(request.method==='HEAD'?null:buffer.slice(start,end+1),{status:206,headers});
    }
    return new Response(request.method==='HEAD'?null:buffer,{headers});
  } catch {return new Response('Unable to load preview asset. Please reload.',{status:503});}
}
self.addEventListener('fetch',event=>{
  const url=new URL(event.request.url);
  if(url.origin!==self.location.origin||!url.pathname.startsWith(config.base))return;
  const path=decodeURIComponent(url.pathname.slice(config.base.length));
  if(['gate.html','gate.js','sw.js','vault-config.js'].includes(path)||path.startsWith('.sealed/'))return;
  if(!['GET','HEAD'].includes(event.request.method))return;
  event.respondWith(respond(event.request,path));
});

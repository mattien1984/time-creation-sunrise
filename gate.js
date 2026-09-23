(() => {
  const form=document.getElementById('entry'),field=document.getElementById('password');
  const button=document.getElementById('enter'),status=document.getElementById('status');
  const decode=text=>Uint8Array.from(atob(text),c=>c.charCodeAt(0));
  const failure=(code,message)=>Object.assign(new Error(message),{code});
  const bounded=(promise,milliseconds,code,message)=>new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(failure(code,message)),milliseconds);
    promise.then(value=>{clearTimeout(timer);resolve(value);},error=>{clearTimeout(timer);reject(error);});
  });
  const progress=text=>{status.textContent=text;};
  let busy=false;

  async function encryptedEntry() {
    const item=VAULT.files['index.html'],controller=new AbortController();
    try {
      return await bounded((async()=>{
        const response=await fetch(VAULT.base+'.sealed/'+item.file,{cache:'force-cache',signal:controller.signal});
        if(!response.ok)throw failure('NET',response.status===404?'This preview was updated. Reload this page and try again.':'The secure preview file could not be downloaded. Please try again.');
        return response.arrayBuffer();
      })(),15000,'NET','The secure preview download timed out. Please try again.');
    } catch(error) {if(!error.code)throw failure('NET','The secure preview could not connect. Please try again.');throw error;}
    finally {controller.abort();}
  }
  async function prepare() {
    if(!navigator.serviceWorker)throw failure('START','Secure preview loading is unavailable in this browser.');
    const script=new URL(VAULT.base+'sw.js?v='+VAULT.version,location.origin).href;
    let registration;
    try {registration=await bounded(navigator.serviceWorker.register(script,{scope:VAULT.base,updateViaCache:'none'}),12000,'START','Safari could not start secure preview loading. Please try again.');}
    catch(error){if(!error.code)throw failure('START','Safari could not start secure preview loading. Please try again.');throw error;}
    await new Promise((resolve,reject)=>{
      const started=Date.now();
      const check=()=>{
        if(registration.active?.scriptURL===script&&registration.active.state==='activated'){clearInterval(timer);resolve();}
        else if(Date.now()-started>=12000){clearInterval(timer);reject(failure('ACT','Safari could not activate secure preview loading. Please try again.'));}
      };
      const timer=setInterval(check,100);check();
    });
    return registration.active;
  }
  function contact(worker,payload,transfer,code) {
    return new Promise((resolve,reject)=>{
      const channel=new MessageChannel();
      const timer=setTimeout(()=>finish(failure(code,'Safari did not respond while opening the secure preview. Please try again.')),10000);
      const finish=(error,value)=>{clearTimeout(timer);channel.port1.close();error?reject(error):resolve(value);};
      channel.port1.onmessage=event=>finish(null,event.data);
      channel.port1.onmessageerror=()=>finish(failure(code,'Safari could not receive the secure preview response. Please try again.'));
      try {worker.postMessage(payload,[channel.port2,...transfer]);}
      catch {finish(failure(code,'Safari could not connect to secure preview loading. Please try again.'));}
    });
  }
  form.addEventListener('submit',async event=>{
    event.preventDefault();if(busy)return;busy=true;button.disabled=true;
    let keyBytes;
    try {
      if(!crypto.subtle)throw failure('CRYPTO','Open this preview in an updated Safari browser.');
      progress('Checking password…');
      // Verify the password in the visible page. No worker or browser storage
      // participates in this step, and no key or password is sent to a server.
      keyBytes=await bounded((async()=>{
        const material=await crypto.subtle.importKey('raw',new TextEncoder().encode(field.value),'PBKDF2',false,['deriveBits']);
        return crypto.subtle.deriveBits({name:'PBKDF2',salt:decode(VAULT.salt),iterations:VAULT.iterations,hash:'SHA-256'},material,256);
      })(),10000,'KEY','Safari could not finish checking the password. Please try again.');
      const key=await bounded(crypto.subtle.importKey('raw',keyBytes,{name:'AES-GCM'},false,['decrypt']),5000,'KEY','Safari could not prepare the secure preview key. Please try again.');
      progress('Loading secure preview…');
      const ciphertext=await encryptedEntry();
      try {await bounded(crypto.subtle.decrypt({name:'AES-GCM',iv:decode(VAULT.files['index.html'].iv)},key,ciphertext),5000,'CRYPTO','Safari could not finish checking the secure preview. Please try again.');}
      catch(error){if(error.name==='OperationError')throw failure('PASSWORD','That password didn’t match. Please try again.');throw error;}
      progress('Preparing secure preview…');
      const worker=await prepare();
      progress('Connecting secure preview…');
      const hello=await contact(worker,{type:'ping',version:VAULT.version},[],'HANDSHAKE');
      if(!hello.ok||hello.version!==VAULT.version)throw failure('VERSION','This preview was updated. Reload this page and try again.');
      progress('Opening the experience…');
      // Transfer bytes instead of structured-cloning a CryptoKey. The worker
      // verifies the supplied ciphertext and imports its own nonextractable key.
      const response=await contact(worker,{type:'unlock',keyBytes,ciphertext,version:VAULT.version},[keyBytes,ciphertext],'OPEN');
      if(!response.ok)throw failure(response.code||'OPEN',response.error||'The secure preview could not open. Please try again.');
      field.value='';
      const directGate=location.pathname===VAULT.base+'gate.html';
      location.replace(directGate?VAULT.base+(location.search||'')+(location.hash||''):location.pathname.startsWith(VAULT.base)?location.href:VAULT.base);
    } catch(error) {
      const code=error.code||'OPEN';
      status.textContent=(error.code?error.message:'The secure preview could not open. Please try again.')+(code==='PASSWORD'?'':` (${code})`);
      button.disabled=false;busy=false;field.focus();field.select();
    } finally {
      // Transferred buffers are detached; failed attempts are wiped locally.
      if(keyBytes?.byteLength)new Uint8Array(keyBytes).fill(0);
    }
  });
})();

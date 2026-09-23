(() => {
  const form = document.getElementById('entry'), field = document.getElementById('password');
  const button = document.getElementById('enter'), status = document.getElementById('status');
  const decode = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
  let registration;
  const timeout = (promise, milliseconds, message) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), milliseconds);
    promise.then(value => { clearTimeout(timer); resolve(value); }, error => { clearTimeout(timer); reject(error); });
  });
  const loadingError = 'Safari could not finish opening the preview. Tap Enter to retry, or reload this page.';
  async function prepare() {
    if (!('serviceWorker' in navigator) || !crypto.subtle) throw new Error('Please open this preview in a current version of Safari, Chrome, Firefox or Edge.');
    const script = new URL(VAULT.base+'sw.js?v='+VAULT.version, location.origin).href;
    registration = await timeout(navigator.serviceWorker.register(script, {scope:VAULT.base, updateViaCache:'none'}), 15000, loadingError);
    // ready can resolve to an older worker, or never settle. Wait for this
    // release's worker to activate, including on a phone's first visit.
    await new Promise((resolve, reject) => {
      const start = Date.now();
      const check = () => {
        if (registration.active?.scriptURL === script && registration.active.state === 'activated') { clearInterval(timer); resolve(); }
        else if (Date.now()-start > 15000) { clearInterval(timer); reject(new Error(loadingError)); }
      };
      const timer = setInterval(check, 100); check();
    });
  }
  let ready;
  function startPreparing() {
    ready = prepare();
    ready.catch(error => { ready = null; status.textContent=error.message; });
  }
  startPreparing();
  form.addEventListener('submit', async event => {
    event.preventDefault(); button.disabled=true; status.textContent='Opening the experience…';
    try {
      if (!ready) startPreparing();
      await ready;
      const material = await crypto.subtle.importKey('raw',new TextEncoder().encode(field.value),'PBKDF2',false,['deriveKey']);
      const key = await crypto.subtle.deriveKey({name:'PBKDF2',salt:decode(VAULT.salt),iterations:VAULT.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
      const response = await new Promise((resolve,reject) => {
        const channel = new MessageChannel();
        const timer = setTimeout(() => { channel.port1.close(); reject(new Error(loadingError)); },20000);
        channel.port1.onmessage = event => {clearTimeout(timer);channel.port1.close();resolve(event.data);};
        registration.active.postMessage({type:'unlock',key,version:VAULT.version},[channel.port2]);
      });
      if (!response.ok) throw new Error(response.error || 'That password didn’t match. Please try again.');
      field.value='';
      // Navigation is controlled by the activated worker. Waiting for a
      // controllerchange on the old password document can strand Safari.
      location.replace(location.pathname.startsWith(VAULT.base) ? location.href : VAULT.base);
    } catch(error) {status.textContent=error.message; button.disabled=false;field.focus();field.select();}
  });
})();

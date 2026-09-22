(() => {
  const form = document.getElementById('entry'), field = document.getElementById('password');
  const button = document.getElementById('enter'), status = document.getElementById('status');
  const decode = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
  let registration;
  async function prepare() {
    if (!('serviceWorker' in navigator) || !crypto.subtle) throw new Error('Please open this preview in a current version of Safari, Chrome, Firefox or Edge.');
    await navigator.serviceWorker.register(VAULT.base+'sw.js', {scope:VAULT.base, updateViaCache:'none'});
    registration = await navigator.serviceWorker.ready;
  }
  const ready = prepare();
  ready.catch(error => { status.textContent=error.message; });
  form.addEventListener('submit', async event => {
    event.preventDefault(); button.disabled=true; status.textContent='Opening the experience…';
    try {
      await ready;
      const material = await crypto.subtle.importKey('raw',new TextEncoder().encode(field.value),'PBKDF2',false,['deriveKey']);
      const key = await crypto.subtle.deriveKey({name:'PBKDF2',salt:decode(VAULT.salt),iterations:VAULT.iterations,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['decrypt']);
      const response = await new Promise((resolve,reject) => {
        const channel = new MessageChannel();
        const timer = setTimeout(() => reject(new Error('The preview took too long to respond. Please try again.')),30000);
        channel.port1.onmessage = event => {clearTimeout(timer);channel.port1.close();resolve(event.data);};
        registration.active.postMessage({type:'unlock',key},[channel.port2]);
      });
      if (!response.ok) throw new Error(response.error || 'That password didn’t match. Please try again.');
      field.value='';
      if (!navigator.serviceWorker.controller) await new Promise(resolve => navigator.serviceWorker.addEventListener('controllerchange',resolve,{once:true}));
      location.replace(location.pathname.startsWith(VAULT.base) ? location.href : VAULT.base);
    } catch(error) {status.textContent=error.message; button.disabled=false;field.focus();field.select();}
  });
})();

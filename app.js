(() => {
  // ---------- helpers ----------
  const $ = (s, el=document) => el.querySelector(s);
  const $$ = (s, el=document) => Array.from(el.querySelectorAll(s));
  const pad = n => String(n).padStart(2,'0');
  const iso = d => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
  const BRL = v => (v||0).toLocaleString('pt-BR',{style:'currency',currency:'BRL'});
  const MESES = ['Janeiro','Fevereiro','Março','Abril','Maio','Junho','Julho','Agosto','Setembro','Outubro','Novembro','Dezembro'];
  const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2,8);
  function hoursBetween(start,end){
    if(!start||!end) return 0;
    const [sh,sm]=start.split(':').map(Number), [eh,em]=end.split(':').map(Number);
    let a=sh*60+sm, b=eh*60+em; if(b<=a) b+=24*60;
    return (b-a)/60;
  }
  function escapeHtml(s){ return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
  function fmtDate(d){
    if(!d) return '—';
    const [y,m,dd]=d.split('-');
    return `${dd}/${m}/${y}`;
  }
  function toast(msg){
    const t=$('#toast'); t.textContent=msg; t.classList.add('show');
    clearTimeout(t._h); t._h=setTimeout(()=>t.classList.remove('show'), 2800);
  }

  // ---------- local storage layer ----------
  const LS = {
    shifts: 'pv_shifts_v1',
    rates: 'pv_rates_v1',
    profile: 'pv_profile_v1',
    apikey: 'pv_apikey_v1',
  };
  function loadShifts(){ try{ return JSON.parse(localStorage.getItem(LS.shifts)||'[]'); }catch(e){ return []; } }
  function saveShifts(arr){ localStorage.setItem(LS.shifts, JSON.stringify(arr)); }
  function loadRates(){ try{ return JSON.parse(localStorage.getItem(LS.rates)||'{}'); }catch(e){ return {}; } }
  function saveRatesArr(obj){ localStorage.setItem(LS.rates, JSON.stringify(obj)); }
  function loadProfile(){ try{ return JSON.parse(localStorage.getItem(LS.profile)||'{}'); }catch(e){ return {}; } }
  function saveProfile(obj){ localStorage.setItem(LS.profile, JSON.stringify(obj)); }
  function loadApiKey(){ return localStorage.getItem(LS.apikey) || ''; }
  function saveApiKey(k){ if(k) localStorage.setItem(LS.apikey, k); else localStorage.removeItem(LS.apikey); }

  // ---------- GitHub sync (stores data.json inside this app's own repo) ----------
  const GH_OWNER = 'lucasebsantos4';
  const GH_REPO = 'plantao-vivo';
  const GH_PATH = 'data/plantoes.json';
  const GH_API = `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/contents/${GH_PATH}`;
  const LS_GHTOKEN = 'pv_ghtoken_v1';
  function loadGhToken(){ return (localStorage.getItem(LS_GHTOKEN) || '').trim(); }
  function friendlyGhError(err){
    const m = String(err.message||'');
    if(err.status===401) return 'Token inválido ou incompleto (401) — gere um novo em github.com/settings/personal-access-tokens/new e cole com cuidado, sem espaços extras.';
    if(err.status===403) return 'Token sem permissão de escrita (403) — edite o token e marque "Contents: Read and write" para o repositório plantao-vivo.';
    if(err.status===404) return 'Repositório não encontrado (404) — confira se o token dá acesso ao repositório plantao-vivo.';
    if(err.status===409) return 'Conflito ao salvar — tente "Sincronizar agora" e depois salve de novo.';
    if(m.includes('Failed to fetch')) return 'Não foi possível conectar ao GitHub agora. Verifique sua internet e tente de novo.';
    return m || 'Erro desconhecido ao sincronizar.';
  }
  function saveGhToken(t){ if(t) localStorage.setItem(LS_GHTOKEN, t); else localStorage.removeItem(LS_GHTOKEN); }
  function b64EncodeUnicode(str){
    const bytes = new TextEncoder().encode(str);
    let bin=''; bytes.forEach(b=>bin+=String.fromCharCode(b));
    return btoa(bin);
  }
  function b64DecodeUnicode(b64){
    const bin = atob(b64.replace(/\n/g,''));
    const bytes = Uint8Array.from(bin, c=>c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  }
  let ghSha = null;
  let remoteSecretsEnc = null; // last-known {salt, iv, ct} blob for the encrypted Anthropic key + GitHub token
  let ghSyncTimer = null;
  let ghSyncing = false;
  function setSyncBadge(text){ const b=$('#syncStatusBadge'); if(b) b.textContent=text; }
  function updateHeaderTag(){
    const tag = $('#syncTag');
    tag.textContent = loadGhToken() ? '☁ sincronizado' : '⚙ configurar';
  }
  async function ghRequest(method, body, {auth=true}={}){
    const opts = {
      method,
      headers:{ 'Accept':'application/vnd.github+json' },
    };
    if(auth){ const token = loadGhToken(); if(token) opts.headers['Authorization'] = `Bearer ${token}`; }
    if(body){ opts.headers['Content-Type']='application/json'; opts.body=JSON.stringify(body); }
    return fetch(GH_API + (method==='GET' ? `?t=${Date.now()}` : ''), opts);
  }
  // ---------- client-side crypto for cross-device key sync ----------
  // The Anthropic key and GitHub token are real secrets and the data.json they
  // travel in is public, so they're never stored there in the clear — only
  // AES-GCM ciphertext (key derived from a passphrase via PBKDF2) ever leaves this browser.
  function bytesToB64(bytes){ let bin=''; bytes.forEach(b=>bin+=String.fromCharCode(b)); return btoa(bin); }
  function b64ToBytes(b64){ return Uint8Array.from(atob(b64), c=>c.charCodeAt(0)); }
  async function deriveAesKey(passphrase, saltB64){
    const salt = saltB64 ? b64ToBytes(saltB64) : crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), {name:'PBKDF2'}, false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      {name:'PBKDF2', salt, iterations:150000, hash:'SHA-256'},
      keyMaterial, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']
    );
    return {key, salt};
  }
  async function encryptSecrets(passphrase, obj){
    const {key, salt} = await deriveAesKey(passphrase, null);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ctBuf = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, new TextEncoder().encode(JSON.stringify(obj)));
    return { salt: bytesToB64(salt), iv: bytesToB64(iv), ct: bytesToB64(new Uint8Array(ctBuf)) };
  }
  async function decryptSecrets(passphrase, blob){
    const {key} = await deriveAesKey(passphrase, blob.salt);
    const ptBuf = await crypto.subtle.decrypt({name:'AES-GCM', iv: b64ToBytes(blob.iv)}, key, b64ToBytes(blob.ct));
    return JSON.parse(new TextDecoder().decode(ptBuf));
  }
  function updateSecretsBadge(){
    const b = $('#secretsBadge'); if(!b) return;
    b.textContent = remoteSecretsEnc ? 'há chaves salvas na nuvem' : 'nenhuma chave salva na nuvem';
  }

  async function pullFromGithub(showToast){
    // The repo is public, so reading doesn't need a token — only writing does.
    setSyncBadge('sincronizando…');
    try{
      const res = await ghRequest('GET', null, {auth:false});
      if(res.status===404){
        ghSha = null;
        setSyncBadge('nenhum dado remoto ainda');
        await pushToGithub();
        return;
      }
      if(!res.ok){ const err=new Error('http_'+res.status); err.status=res.status; throw err; }
      const json = await res.json();
      ghSha = json.sha;
      const remote = JSON.parse(b64DecodeUnicode(json.content));
      shifts = Array.isArray(remote.shifts) ? remote.shifts : [];
      rates = remote.rates || {};
      if(remote.profile) saveProfile(remote.profile);
      if(remote.gcalClientId && !loadGcalClientId()) saveGcalClientId(remote.gcalClientId);
      remoteSecretsEnc = remote.secretsEnc || null;
      updateSecretsBadge();
      saveShifts(shifts); saveRatesArr(rates);
      $('#myName').value = (remote.profile && remote.profile.name) || $('#myName').value;
      renderAll(); renderRates();
      setSyncBadge('sincronizado ' + new Date().toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'}));
      if(showToast) toast('Dados atualizados a partir da nuvem.');
    }catch(e){
      setSyncBadge('erro ao ler dados da nuvem');
      if(showToast) toast(friendlyGhError(e));
    }
  }
  async function pushToGithub(){
    const token = loadGhToken();
    if(!token) return;
    if(ghSyncing) return;
    ghSyncing = true;
    setSyncBadge('sincronizando…');
    try{
      const payload = {
        shifts, rates, profile: loadProfile(),
        gcalClientId: loadGcalClientId() || null,
        secretsEnc: remoteSecretsEnc,
        updatedAt: new Date().toISOString(),
      };
      const content = b64EncodeUnicode(JSON.stringify(payload, null, 2));
      const body = { message:'Atualiza plantões', content, branch:'main' };
      if(ghSha) body.sha = ghSha;
      let res = await ghRequest('PUT', body);
      if(res.status===409){
        const getRes = await ghRequest('GET');
        if(getRes.ok){ const j = await getRes.json(); ghSha = j.sha; body.sha = ghSha; res = await ghRequest('PUT', body); }
      }
      if(!res.ok){
        let msg = 'http_'+res.status;
        try{ const j = await res.json(); if(j.message) msg += ': '+j.message; }catch(e){}
        const err = new Error(msg); err.status = res.status; throw err;
      }
      const j = await res.json();
      ghSha = j.content.sha;
      setSyncBadge('sincronizado ' + new Date().toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'}));
    }catch(e){
      setSyncBadge('erro ao salvar na nuvem');
      toast(friendlyGhError(e));
    }finally{
      ghSyncing = false;
    }
  }
  function queueSync(){
    if(!loadGhToken()) return;
    clearTimeout(ghSyncTimer);
    ghSyncTimer = setTimeout(pushToGithub, 900);
  }

  // ---------- Google Calendar sync ----------
  const GCAL_SCOPE = 'https://www.googleapis.com/auth/calendar.events';
  const LS_GCAL_CLIENTID = 'pv_gcal_clientid_v1';
  const LS_GCAL_CONNECTED = 'pv_gcal_connected_v1';
  function loadGcalClientId(){ return (localStorage.getItem(LS_GCAL_CLIENTID) || '').trim(); }
  function saveGcalClientId(v){ if(v) localStorage.setItem(LS_GCAL_CLIENTID, v); else localStorage.removeItem(LS_GCAL_CLIENTID); }
  function isGcalPreviouslyConnected(){ return localStorage.getItem(LS_GCAL_CONNECTED)==='1'; }
  let gcalTokenClient = null;
  let gcalAccessToken = null;
  let gcalTokenExpiry = 0;
  let gcalPendingTokenResolvers = [];
  function setGcalBadge(text){ const b=$('#gcalStatusBadge'); if(b) b.textContent=text; }
  function ensureGcalTokenClient(){
    const clientId = loadGcalClientId();
    if(!clientId || !window.google || !window.google.accounts) return null;
    if(gcalTokenClient) return gcalTokenClient;
    gcalTokenClient = google.accounts.oauth2.initTokenClient({
      client_id: clientId,
      scope: GCAL_SCOPE,
      callback: (resp)=>{
        if(resp.error){
          setGcalBadge('erro ao conectar');
          toast('Não foi possível conectar ao Google: '+resp.error);
          gcalPendingTokenResolvers.forEach(r=>r(null)); gcalPendingTokenResolvers=[];
          return;
        }
        gcalAccessToken = resp.access_token;
        gcalTokenExpiry = Date.now() + (Number(resp.expires_in||3500) * 1000);
        localStorage.setItem(LS_GCAL_CONNECTED, '1');
        setGcalBadge('conectado');
        gcalPendingTokenResolvers.forEach(r=>r(gcalAccessToken)); gcalPendingTokenResolvers=[];
      },
    });
    return gcalTokenClient;
  }
  function connectGoogleCalendar(){
    const client = ensureGcalTokenClient();
    if(!client){ toast('Cole o ID do cliente OAuth do Google primeiro.'); return; }
    client.requestAccessToken({ prompt: 'consent' });
  }
  // Resolves a usable access token, or null if not connected / user must reconnect.
  function getGcalToken(){
    return new Promise(resolve=>{
      if(!loadGcalClientId() || !isGcalPreviouslyConnected()){ resolve(null); return; }
      if(gcalAccessToken && Date.now() < gcalTokenExpiry - 30000){ resolve(gcalAccessToken); return; }
      const client = ensureGcalTokenClient();
      if(!client){ resolve(null); return; }
      gcalPendingTokenResolvers.push(resolve);
      try{ client.requestAccessToken({ prompt: '' }); }
      catch(e){ resolve(null); }
    });
  }
  function tz(){ try{ return Intl.DateTimeFormat().resolvedOptions().timeZone || 'America/Sao_Paulo'; }catch(e){ return 'America/Sao_Paulo'; } }
  function shiftEndDateIso(shift){
    const [y,m,d] = shift.date.split('-').map(Number);
    const overnight = hoursBetween(shift.startTime, shift.endTime) > 0 && shift.endTime <= shift.startTime;
    const dt = new Date(y, m-1, d + (overnight?1:0));
    return iso(dt);
  }
  function shiftToGcalEvent(shift){
    return {
      summary: `Plantão · ${shift.location||'Sem local'}`,
      description: `Valor: ${BRL(shift.value)} · Status: ${shift.status==='pago'?'Pago':'Pendente'}${shift.notes?(' · '+shift.notes):''}\n\nCriado pelo app Plantões do Lucas.`,
      start: { dateTime: `${shift.date}T${shift.startTime||'00:00'}:00`, timeZone: tz() },
      end: { dateTime: `${shiftEndDateIso(shift)}T${shift.endTime||'00:00'}:00`, timeZone: tz() },
    };
  }
  async function syncShiftToGoogle(shift){
    if(!shift || !shift.date || !shift.startTime || !shift.endTime) return;
    const token = await getGcalToken();
    if(!token) return;
    const eventBody = shiftToGcalEvent(shift);
    try{
      let res;
      if(shift.gcalEventId){
        res = await fetch(`https://www.googleapis.com/calendar/v3/calendars/primary/events/${shift.gcalEventId}`, {
          method:'PATCH', headers:{'Authorization':`Bearer ${token}`,'Content-Type':'application/json'}, body: JSON.stringify(eventBody),
        });
        if(res.status===404 || res.status===410){ shift.gcalEventId=null; return syncShiftToGoogle(shift); }
      } else {
        res = await fetch('https://www.googleapis.com/calendar/v3/calendars/primary/events', {
          method:'POST', headers:{'Authorization':`Bearer ${token}`,'Content-Type':'application/json'}, body: JSON.stringify(eventBody),
        });
      }
      if(!res.ok) throw new Error('http_'+res.status);
      const j = await res.json();
      if(j.id && j.id !== shift.gcalEventId){
        const i = shifts.findIndex(s=>s.id===shift.id);
        if(i>=0){ shifts[i].gcalEventId = j.id; saveShifts(shifts); queueSync(); }
      }
    }catch(e){ /* silent: calendar sync is a best-effort extra layer */ }
  }
  async function deleteShiftFromGoogle(shift){
    if(!shift || !shift.gcalEventId) return;
    const token = await getGcalToken();
    if(!token) return;
    try{
      await fetch(`https://www.googleapis.com/calendar/v3/calendars/primary/events/${shift.gcalEventId}`, {
        method:'DELETE', headers:{'Authorization':`Bearer ${token}`},
      });
    }catch(e){}
  }
  async function pushAllShiftsToGoogle(){
    const token = await getGcalToken();
    if(!token){ toast('Conecte-se ao Google primeiro.'); return; }
    toast(`Enviando ${shifts.length} plantão(ões) ao Google Calendário…`);
    for(const s of shifts){ await syncShiftToGoogle(s); }
    toast('Envio concluído.');
  }

  let shifts = loadShifts();
  let rates = loadRates();
  let calMonth = new Date(); calMonth.setDate(1);
  let fatMonth = new Date(); fatMonth.setDate(1);
  let selectedDay = null;
  let editingId = null;
  let pendingImport = [];

  $('#refYear').value = new Date().getFullYear();
  $('#myName').value = (loadProfile().name || '');
  $('#myName').addEventListener('change', ()=>{ saveProfile({name: $('#myName').value.trim()}); queueSync(); });

  // ---------- tabs ----------
  $$('#tabs button').forEach(b=>b.addEventListener('click', ()=>{
    $$('#tabs button').forEach(x=>x.classList.remove('active'));
    b.classList.add('active');
    $$('.view').forEach(v=>v.classList.remove('active'));
    $('#view-'+b.dataset.view).classList.add('active');
  }));

  // ---------- shift CRUD ----------
  function addShift(data){
    const s = {id: uid(), createdAt: new Date().toISOString(), ...data};
    shifts.push(s);
    saveShifts(shifts); renderAll(); queueSync();
    syncShiftToGoogle(s);
  }
  function addShiftsBulk(dataArr){
    const now = new Date().toISOString();
    const added = dataArr.map(data=>{ const s={id: uid(), createdAt: now, ...data}; shifts.push(s); return s; });
    saveShifts(shifts); renderAll(); queueSync();
    added.forEach(s=>syncShiftToGoogle(s));
  }
  function updateShift(id, data){
    const i = shifts.findIndex(s=>s.id===id);
    if(i>=0){ shifts[i] = {...shifts[i], ...data}; saveShifts(shifts); renderAll(); queueSync(); syncShiftToGoogle(shifts[i]); }
  }
  function deleteShift(id){
    const removed = shifts.find(s=>s.id===id);
    shifts = shifts.filter(s=>s.id!==id);
    saveShifts(shifts); renderAll(); queueSync();
    if(removed) deleteShiftFromGoogle(removed);
  }
  function saveRates(){ saveRatesArr(rates); renderRates(); queueSync(); }

  // ---------- shift modal ----------
  const seg = $('#fStatusSeg');
  let fStatus = 'pendente';
  seg.addEventListener('click', e=>{
    const b = e.target.closest('button'); if(!b) return;
    fStatus = b.dataset.v;
    $$('#fStatusSeg button').forEach(x=>x.classList.toggle('on', x===b));
  });
  function openShiftModal(existing, prefDate){
    editingId = existing ? existing.id : null;
    $('#shiftModalTitle').textContent = existing ? 'Editar plantão' : 'Novo plantão';
    $('#fDate').value = existing ? existing.date : (prefDate || iso(new Date()));
    $('#fLocation').value = existing ? existing.location : '';
    $('#fStart').value = existing ? existing.startTime : '19:00';
    $('#fEnd').value = existing ? existing.endTime : '07:00';
    $('#fValue').value = existing ? existing.value : '';
    $('#fNotes').value = existing ? (existing.notes||'') : '';
    fStatus = existing ? existing.status : 'pendente';
    $$('#fStatusSeg button').forEach(x=>x.classList.toggle('on', x.dataset.v===fStatus));
    $('#fDelete').style.display = existing ? 'inline-block' : 'none';
    $('#locOptions').innerHTML = [...new Set(shifts.map(s=>s.location).filter(Boolean))].map(l=>`<option value="${escapeHtml(l)}">`).join('');
    $('#fRecurringWrap').style.display = existing ? 'none' : 'flex';
    $('#fRecurring').checked = false;
    $('#recurringFields').style.display = 'none';
    $('#fRecurWeeks').value = 4;
    $('#fRecurCount').value = 4;
    $('#shiftModalBg').classList.add('open');
  }
  $('#fRecurring').addEventListener('change', ()=>{
    $('#recurringFields').style.display = $('#fRecurring').checked ? 'grid' : 'none';
  });
  function closeShiftModal(){ $('#shiftModalBg').classList.remove('open'); editingId=null; }
  $('#fCancel').addEventListener('click', closeShiftModal);
  $('#shiftModalClose').addEventListener('click', closeShiftModal);
  $('#addShiftBtn').addEventListener('click', ()=>openShiftModal(null));
  $('#dayAddBtn').addEventListener('click', ()=>openShiftModal(null, selectedDay));
  $('#fSave').addEventListener('click', ()=>{
    const data = {
      date: $('#fDate').value,
      location: $('#fLocation').value.trim() || 'Sem local',
      startTime: $('#fStart').value,
      endTime: $('#fEnd').value,
      value: parseFloat($('#fValue').value)||0,
      status: fStatus,
      notes: $('#fNotes').value.trim(),
    };
    if(!data.date){ toast('Informe a data.'); return; }
    if(editingId){
      updateShift(editingId, data);
      toast('Plantão salvo.');
    } else if($('#fRecurring').checked){
      const weeks = Math.max(1, parseInt($('#fRecurWeeks').value)||4);
      const count = Math.max(2, parseInt($('#fRecurCount').value)||4);
      const rows = [];
      const [y,m,d] = data.date.split('-').map(Number);
      for(let i=0;i<count;i++){
        const dt = new Date(y, m-1, d + i*weeks*7);
        rows.push({...data, date: iso(dt)});
      }
      addShiftsBulk(rows);
      toast(`${count} plantões recorrentes criados (a cada ${weeks} semana(s)).`);
    } else {
      addShift(data);
      toast('Plantão salvo.');
    }
    closeShiftModal();
  });
  $('#fDelete').addEventListener('click', ()=>{
    if(editingId){ deleteShift(editingId); toast('Plantão excluído.'); closeShiftModal(); }
  });

  // ---------- Settings modal (API key + GitHub sync) ----------
  $('#ghRepoLabel').textContent = `${GH_OWNER}/${GH_REPO}`;
  $('#syncTag').addEventListener('click', ()=>{
    $('#apiKeyInput').value = loadApiKey();
    $('#ghTokenInput').value = loadGhToken();
    setSyncBadge(loadGhToken() ? 'configurado' : 'não configurado');
    $('#gcalClientIdInput').value = loadGcalClientId();
    setGcalBadge(isGcalPreviouslyConnected() ? 'conectado' : 'não conectado');
    $('#syncPassInput').value = '';
    updateSecretsBadge();
    $('#apiModalBg').classList.add('open');
  });
  $('#apiModalClose').addEventListener('click', ()=>$('#apiModalBg').classList.remove('open'));
  $('#apiModalCancel').addEventListener('click', ()=>$('#apiModalBg').classList.remove('open'));
  $('#apiKeySave').addEventListener('click', ()=>{
    saveApiKey($('#apiKeyInput').value.trim());
    toast('Chave salva neste navegador.');
  });
  $('#apiKeyClear').addEventListener('click', ()=>{
    saveApiKey(''); $('#apiKeyInput').value='';
    toast('Chave removida.');
  });
  $('#ghTokenSave').addEventListener('click', async ()=>{
    const t = $('#ghTokenInput').value.trim();
    if(!t){ toast('Cole o token antes de salvar.'); return; }
    saveGhToken(t);
    updateHeaderTag();
    toast('Token salvo. Sincronizando…');
    await pullFromGithub(true);
  });
  $('#ghTokenClear').addEventListener('click', ()=>{
    saveGhToken(''); $('#ghTokenInput').value=''; ghSha=null;
    updateHeaderTag();
    setSyncBadge('não configurado');
    toast('Token removido — sincronização desativada neste navegador.');
  });
  $('#ghSyncNow').addEventListener('click', ()=>{
    if(!loadGhToken()){ toast('Configure o token do GitHub primeiro.'); return; }
    pullFromGithub(true);
  });

  $('#gcalConnect').addEventListener('click', ()=>{
    const cid = $('#gcalClientIdInput').value.trim();
    if(!cid){ toast('Cole o ID do cliente OAuth do Google primeiro.'); return; }
    saveGcalClientId(cid);
    gcalTokenClient = null; // rebuild with the (possibly new) client id
    connectGoogleCalendar();
  });
  $('#gcalDisconnect').addEventListener('click', ()=>{
    localStorage.removeItem(LS_GCAL_CONNECTED);
    gcalAccessToken = null; gcalTokenExpiry = 0;
    setGcalBadge('não conectado');
    toast('Desconectado. Os eventos já criados continuam na sua agenda.');
  });
  $('#gcalPushAll').addEventListener('click', ()=>{ pushAllShiftsToGoogle(); });

  $('#secretsEncryptSave').addEventListener('click', async ()=>{
    const pass = $('#syncPassInput').value;
    if(!pass){ toast('Digite uma frase secreta.'); return; }
    const apiKey = loadApiKey(), ghToken = loadGhToken();
    if(!apiKey && !ghToken){ toast('Não há chave da Anthropic nem token do GitHub configurados neste aparelho ainda.'); return; }
    try{
      remoteSecretsEnc = await encryptSecrets(pass, {apiKey, ghToken});
      updateSecretsBadge();
      if(ghToken){ await pushToGithub(); toast('Chaves cifradas e sincronizadas.'); }
      else { toast('Chaves cifradas — configure o token do GitHub para poder enviá-las à nuvem.'); }
    }catch(e){ toast('Erro ao cifrar as chaves: '+e.message); }
  });
  $('#secretsUnlock').addEventListener('click', async ()=>{
    const pass = $('#syncPassInput').value;
    if(!pass){ toast('Digite a frase secreta.'); return; }
    if(!remoteSecretsEnc){ toast('Nenhuma chave salva na nuvem ainda.'); return; }
    try{
      const obj = await decryptSecrets(pass, remoteSecretsEnc);
      if(obj.apiKey){ saveApiKey(obj.apiKey); $('#apiKeyInput').value = obj.apiKey; }
      if(obj.ghToken){ saveGhToken(obj.ghToken); $('#ghTokenInput').value = obj.ghToken; setSyncBadge('configurado'); updateHeaderTag(); }
      toast('Chaves carregadas neste aparelho.');
    }catch(e){ toast('Frase incorreta, ou nada para decifrar.'); }
  });

  // ---------- render: plantões table ----------
  function renderShiftsTable(){
    const tbody = $('#shiftsTbody');
    const sorted = [...shifts].sort((a,b)=> (b.date||'').localeCompare(a.date||''));
    tbody.innerHTML = sorted.map(s=>`
      <tr data-id="${s.id}">
        <td class="mono">${fmtDate(s.date)}</td>
        <td>${escapeHtml(s.location||'')}</td>
        <td class="mono">${s.startTime||''}–${s.endTime||''}</td>
        <td class="mono">${BRL(s.value)}</td>
        <td><span class="chip ${s.status}">${s.status==='pago'?'Pago':'Pendente'}</span></td>
        <td><button class="icon-btn edit-shift">✎</button></td>
      </tr>`).join('');
    $('#shiftsEmpty').style.display = sorted.length ? 'none':'block';
    $$('.edit-shift', tbody).forEach(btn=>btn.addEventListener('click', e=>{
      const id = e.target.closest('tr').dataset.id;
      openShiftModal(shifts.find(s=>s.id===id));
    }));
  }

  // ---------- calendar ----------
  function renderCalendar(){
    $('#calLabel').textContent = `${MESES[calMonth.getMonth()]} ${calMonth.getFullYear()}`;
    const grid = $('#calGrid'); grid.innerHTML='';
    const first = new Date(calMonth.getFullYear(), calMonth.getMonth(), 1);
    const startOffset = first.getDay();
    const daysInMonth = new Date(calMonth.getFullYear(), calMonth.getMonth()+1, 0).getDate();
    const todayIso = iso(new Date());
    const cells = [];
    for(let i=0;i<startOffset;i++) cells.push(null);
    for(let d=1; d<=daysInMonth; d++) cells.push(d);
    while(cells.length % 7 !== 0) cells.push(null);
    cells.forEach(d=>{
      const cell = document.createElement('div');
      if(d===null){ cell.className='day out'; grid.appendChild(cell); return; }
      const dIso = `${calMonth.getFullYear()}-${pad(calMonth.getMonth()+1)}-${pad(d)}`;
      const dayShifts = shifts.filter(s=>s.date===dIso);
      cell.className = 'day' + (dIso===todayIso ? ' today':'');
      const total = dayShifts.reduce((a,s)=>a+(s.value||0),0);
      const locLabel = [...new Set(dayShifts.map(s=>s.location).filter(Boolean))].join(', ');
      cell.innerHTML = `<div class="d">${d}</div>
        <div class="marks">${dayShifts.map(s=>`<span class="dot" style="color:${s.status==='pago'?'var(--paid)':'var(--pending)'}"></span>`).join('')}</div>
        ${locLabel?`<div class="loc" title="${escapeHtml(locLabel)}">${escapeHtml(locLabel)}</div>`:''}
        ${total?`<div class="amt">${BRL(total)}</div>`:''}`;
      cell.addEventListener('click', ()=>{ selectedDay = dIso; showDayPanel(dIso); });
      grid.appendChild(cell);
    });
  }
  function showDayPanel(dIso){
    const panel = $('#dayPanel'); panel.style.display='block';
    $('#dayPanelTitle').textContent = fmtDate(dIso);
    const list = shifts.filter(s=>s.date===dIso);
    $('#dayPanelList').innerHTML = list.length ? list.map(s=>`
      <div class="row between" style="padding:8px 0;border-bottom:1px solid var(--line);" data-id="${s.id}">
        <div>
          <div style="font-weight:600;">${escapeHtml(s.location||'')}</div>
          <div class="mono" style="font-size:12.5px;color:var(--ink-soft);">${s.startTime}–${s.endTime} · ${BRL(s.value)}</div>
        </div>
        <span class="chip ${s.status}">${s.status==='pago'?'Pago':'Pendente'}</span>
        <button class="icon-btn edit-day">✎</button>
      </div>`).join('') : '<div class="empty">Nenhum plantão nesta data.</div>';
    $$('.edit-day', $('#dayPanelList')).forEach(btn=>btn.addEventListener('click', e=>{
      const id = e.target.closest('[data-id]').dataset.id;
      openShiftModal(shifts.find(s=>s.id===id));
    }));
  }
  $('#calPrev').addEventListener('click', ()=>{ calMonth.setMonth(calMonth.getMonth()-1); renderCalendar(); });
  $('#calNext').addEventListener('click', ()=>{ calMonth.setMonth(calMonth.getMonth()+1); renderCalendar(); });

  // ---------- resumo ----------
  function renderResumo(){
    const now = new Date();
    const ym = `${now.getFullYear()}-${pad(now.getMonth()+1)}`;
    $('#resumoMesLabel').textContent = `· ${MESES[now.getMonth()]} ${now.getFullYear()}`;
    const monthShifts = shifts.filter(s=>s.date && s.date.startsWith(ym));
    const total = monthShifts.reduce((a,s)=>a+(s.value||0),0);
    const pago = monthShifts.filter(s=>s.status==='pago').reduce((a,s)=>a+(s.value||0),0);
    const pendente = total - pago;
    const horas = monthShifts.reduce((a,s)=>a+hoursBetween(s.startTime,s.endTime),0);
    $('#stPlantoes').textContent = monthShifts.length;
    $('#stHoras').textContent = Math.round(horas);
    $('#stTotal').textContent = BRL(total);
    $('#stPendente').textContent = BRL(pendente);
    $('#stPago').textContent = BRL(pago);

    const upcoming = shifts.filter(s=>s.date >= iso(now)).sort((a,b)=>a.date.localeCompare(b.date)).slice(0,5);
    $('#proximosList').innerHTML = upcoming.length ? upcoming.map(s=>`
      <div class="row between" style="padding:8px 0;border-bottom:1px solid var(--line);">
        <div><div style="font-weight:600;">${escapeHtml(s.location||'')}</div>
        <div class="mono" style="font-size:12.5px;color:var(--ink-soft);">${fmtDate(s.date)} · ${s.startTime}–${s.endTime}</div></div>
        <span class="chip ${s.status}">${s.status==='pago'?'Pago':'Pendente'}</span>
      </div>`).join('') : '<div class="empty">Nenhum plantão futuro cadastrado.</div>';

    const byLoc = {};
    monthShifts.forEach(s=>{ byLoc[s.location]= (byLoc[s.location]||0) + (s.value||0); });
    const maxV = Math.max(1, ...Object.values(byLoc));
    $('#porLocalList').innerHTML = Object.keys(byLoc).length ? Object.entries(byLoc).sort((a,b)=>b[1]-a[1]).map(([loc,v])=>`
      <div style="margin-bottom:10px;">
        <div class="row between" style="margin-bottom:4px;"><span style="font-size:13px;font-weight:600;">${escapeHtml(loc)}</span><span class="mono" style="font-size:12.5px;color:var(--money);">${BRL(v)}</span></div>
        <div style="height:6px;border-radius:4px;background:var(--paper);overflow:hidden;"><div style="height:100%;width:${(v/maxV*100).toFixed(0)}%;background:var(--accent);"></div></div>
      </div>`).join('') : '<div class="empty">Sem plantões este mês.</div>';
  }

  // ---------- faturamento ----------
  function renderFaturamento(){
    $('#fatLabel').textContent = `${MESES[fatMonth.getMonth()]} ${fatMonth.getFullYear()}`;
    const ym = `${fatMonth.getFullYear()}-${pad(fatMonth.getMonth()+1)}`;
    const monthShifts = shifts.filter(s=>s.date && s.date.startsWith(ym));
    const total = monthShifts.reduce((a,s)=>a+(s.value||0),0);
    const pago = monthShifts.filter(s=>s.status==='pago').reduce((a,s)=>a+(s.value||0),0);
    $('#fatTotal').textContent = BRL(total);
    $('#fatPago').textContent = BRL(pago);
    $('#fatPendente').textContent = BRL(total-pago);

    const byLoc = {};
    monthShifts.forEach(s=>{
      byLoc[s.location] = byLoc[s.location] || {items:[], total:0, pago:0};
      byLoc[s.location].items.push(s);
      byLoc[s.location].total += (s.value||0);
      if(s.status==='pago') byLoc[s.location].pago += (s.value||0);
    });
    const wrap = $('#fatByLocation');
    wrap.innerHTML = Object.keys(byLoc).length ? Object.entries(byLoc).map(([loc,info])=>`
      <div class="card" style="background:var(--paper);box-shadow:none;padding:14px;margin-bottom:10px;">
        <div class="row between">
          <div><strong>${escapeHtml(loc)}</strong> <span class="sub" style="color:var(--ink-faint);font-size:12.5px;">${info.items.length} plantão(ões)</span></div>
          <div class="mono">${BRL(info.total)}</div>
        </div>
        <div class="row between" style="margin-top:6px;">
          <span style="font-size:12.5px;color:var(--ink-soft);">Recebido ${BRL(info.pago)} · Pendente ${BRL(info.total-info.pago)}</span>
          <button class="btn small mark-paid" data-loc="${escapeHtml(loc)}">Marcar tudo como pago</button>
        </div>
      </div>`).join('') : '<div class="empty">Sem lançamentos neste mês.</div>';
    $$('.mark-paid', wrap).forEach(btn=>btn.addEventListener('click', ()=>{
      const loc = btn.dataset.loc;
      const changed = [];
      byLoc[loc].items.forEach(s=>{ const i=shifts.findIndex(x=>x.id===s.id); if(i>=0){ shifts[i].status='pago'; changed.push(shifts[i]); } });
      saveShifts(shifts); renderAll(); queueSync();
      changed.forEach(s=>syncShiftToGoogle(s));
      toast('Marcado como pago.');
    }));
  }
  $('#fatPrev').addEventListener('click', ()=>{ fatMonth.setMonth(fatMonth.getMonth()-1); renderFaturamento(); });
  $('#fatNext').addEventListener('click', ()=>{ fatMonth.setMonth(fatMonth.getMonth()+1); renderFaturamento(); });

  $('#genReceiptBtn').addEventListener('click', ()=>{
    const ym = `${fatMonth.getFullYear()}-${pad(fatMonth.getMonth()+1)}`;
    const monthShifts = shifts.filter(s=>s.date && s.date.startsWith(ym)).sort((a,b)=>a.date.localeCompare(b.date));
    if(!monthShifts.length){ toast('Nenhum plantão neste mês.'); return; }
    if(!window.jspdf){ toast('Biblioteca de PDF não carregou.'); return; }
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    doc.setFont('helvetica','bold'); doc.setFontSize(16);
    doc.text('Relatório de Plantões', 14, 18);
    doc.setFontSize(11); doc.setFont('helvetica','normal');
    doc.text(`${MESES[fatMonth.getMonth()]} de ${fatMonth.getFullYear()}`, 14, 26);
    let y = 38;
    doc.setFont('helvetica','bold');
    doc.text('Data', 14, y); doc.text('Local', 38, y); doc.text('Horário', 118, y); doc.text('Valor', 150, y); doc.text('Status', 172, y);
    doc.setFont('helvetica','normal'); y+=6;
    doc.setLineWidth(0.2); doc.line(14,y-4,196,y-4);
    let total=0, pago=0;
    monthShifts.forEach(s=>{
      if(y>270){ doc.addPage(); y=20; }
      doc.text(fmtDate(s.date), 14, y);
      doc.text(String(s.location||'').slice(0,38), 38, y);
      doc.text(`${s.startTime||''}-${s.endTime||''}`, 118, y);
      doc.text(BRL(s.value), 150, y);
      doc.text(s.status==='pago'?'Pago':'Pendente', 172, y);
      total += (s.value||0); if(s.status==='pago') pago += (s.value||0);
      y+=7;
    });
    y+=4; doc.line(14,y-4,196,y-4);
    doc.setFont('helvetica','bold');
    doc.text(`Total: ${BRL(total)}`, 14, y+4);
    doc.text(`Recebido: ${BRL(pago)}   Pendente: ${BRL(total-pago)}`, 14, y+11);
    doc.save(`plantoes-${ym}.pdf`);
    toast('Recibo salvo.');
  });

  // ---------- rates config ----------
  function renderRates(){
    const wrap = $('#ratesList');
    const entries = Object.entries(rates);
    wrap.innerHTML = entries.length ? entries.map(([loc,cfg])=>`
      <div class="locrow" data-loc="${escapeHtml(loc)}">
        <input type="text" class="rate-loc" value="${escapeHtml(loc)}">
        <select class="rate-mode"><option value="fixed" ${cfg.mode==='fixed'?'selected':''}>Fixo</option><option value="hourly" ${cfg.mode==='hourly'?'selected':''}>Por hora</option></select>
        <input type="number" class="rate-value mono" value="${cfg.value||0}" step="0.01">
        <button class="icon-btn rate-del">✕</button>
      </div>`).join('') : '<div class="empty">Nenhum valor padrão configurado.</div>';
    $$('.locrow', wrap).forEach(row=>{
      const origLoc = row.dataset.loc;
      row.querySelector('.rate-del').addEventListener('click', ()=>{ delete rates[origLoc]; saveRates(); });
      const commit = ()=>{
        const newLoc = row.querySelector('.rate-loc').value.trim();
        const mode = row.querySelector('.rate-mode').value;
        const value = parseFloat(row.querySelector('.rate-value').value)||0;
        if(!newLoc) return;
        if(newLoc !== origLoc) delete rates[origLoc];
        rates[newLoc] = {mode, value};
        saveRates();
      };
      row.querySelectorAll('input,select').forEach(el=>el.addEventListener('change', commit));
    });
  }
  $('#addRateBtn').addEventListener('click', ()=>{
    let n=1, name='Novo local';
    while(rates[name]) { name = `Novo local ${++n}`; }
    rates[name] = {mode:'fixed', value:0};
    saveRates();
  });

  // ---------- export / import backup ----------
  $('#exportBtn').addEventListener('click', ()=>{
    const data = { shifts, rates, profile: loadProfile(), exportedAt: new Date().toISOString() };
    const blob = new Blob([JSON.stringify(data,null,2)], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `plantao-vivo-backup-${iso(new Date())}.json`;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(url), 2000);
    toast('Backup exportado.');
  });
  $('#importBtn').addEventListener('click', ()=>$('#importFile').click());
  $('#importFile').addEventListener('change', e=>{
    const f = e.target.files[0]; if(!f) return;
    const reader = new FileReader();
    reader.onload = ev=>{
      try{
        const data = JSON.parse(ev.target.result);
        if(!Array.isArray(data.shifts)) throw new Error('formato inválido');
        shifts = data.shifts; saveShifts(shifts);
        rates = data.rates || {}; saveRatesArr(rates);
        if(data.profile) saveProfile(data.profile);
        $('#myName').value = (data.profile && data.profile.name) || '';
        renderAll(); renderRates(); queueSync();
        toast(`Backup importado: ${shifts.length} plantão(ões).`);
      }catch(err){ toast('Arquivo de backup inválido.'); }
    };
    reader.readAsText(f);
    e.target.value='';
  });

  // ---------- image resize (keeps API cost/time down) ----------
  function resizeImage(file, maxDim=1568, quality=0.85){
    return new Promise((resolve,reject)=>{
      const img = new Image();
      const url = URL.createObjectURL(file);
      img.onload = ()=>{
        let {width:w, height:h} = img;
        if(w>maxDim || h>maxDim){
          const scale = maxDim / Math.max(w,h);
          w = Math.round(w*scale); h = Math.round(h*scale);
        }
        const canvas = document.createElement('canvas');
        canvas.width=w; canvas.height=h;
        canvas.getContext('2d').drawImage(img,0,0,w,h);
        canvas.toBlob(blob=>{ URL.revokeObjectURL(url); resolve(blob); }, 'image/jpeg', quality);
      };
      img.onerror = ()=>{ URL.revokeObjectURL(url); reject(new Error('Não foi possível abrir a imagem.')); };
      img.src = url;
    });
  }
  function blobToBase64(blob){
    return new Promise((resolve,reject)=>{
      const reader = new FileReader();
      reader.onload = ()=>resolve(reader.result.split(',')[1]);
      reader.onerror = reject;
      reader.readAsDataURL(blob);
    });
  }

  // ---------- Claude API call ----------
  async function callClaude({prompt, imageBlob}){
    const apiKey = loadApiKey();
    if(!apiKey) { const e = new Error('Configure sua chave de API primeiro (⚙ no topo).'); e.code='no_key'; throw e; }
    const content = [];
    if(imageBlob){
      const b64 = await blobToBase64(imageBlob);
      content.push({ type:'image', source:{ type:'base64', media_type:'image/jpeg', data:b64 } });
    }
    content.push({ type:'text', text: prompt });
    const res = await fetch('https://api.anthropic.com/v1/messages', {
      method:'POST',
      headers:{
        'content-type':'application/json',
        'x-api-key': apiKey,
        'anthropic-version':'2023-06-01',
        'anthropic-dangerous-direct-browser-access':'true',
      },
      body: JSON.stringify({
        model:'claude-sonnet-5',
        max_tokens: 3000,
        messages:[{ role:'user', content }],
      }),
    });
    if(!res.ok){
      let msg = `Erro ${res.status}`;
      try{ const j = await res.json(); msg = (j.error && j.error.message) || msg; }catch(e){}
      const e = new Error(msg); e.code = res.status===401?'auth':(res.status===429?'rate_limited':'http_error');
      throw e;
    }
    const data = await res.json();
    const text = (data.content||[]).filter(b=>b.type==='text').map(b=>b.text).join('\n');
    return text;
  }
  function extractJson(text){
    let s = text.trim();
    const fence = s.match(/```(?:json)?\s*([\s\S]*?)```/i);
    if(fence) s = fence[1].trim();
    try{ return JSON.parse(s); }catch(e){}
    const start = Math.min(...['[','{'].map(c=>{ const i=s.indexOf(c); return i<0?Infinity:i; }));
    const endBrace = s.lastIndexOf('}');
    const endBracket = s.lastIndexOf(']');
    const end = Math.max(endBrace, endBracket);
    if(isFinite(start) && end>start){
      try{ return JSON.parse(s.slice(start, end+1)); }catch(e){}
    }
    throw new Error('invalid_json');
  }

  // ---------- importar escala ----------
  let selectedImageBlob = null;
  $('#uploadBox').addEventListener('click', ()=>$('#fileInput').click());
  $('#fileInput').addEventListener('change', async e=>{
    const f = e.target.files[0]; if(!f) return;
    $('#uploadBoxContent').textContent = 'Preparando imagem…';
    try{
      selectedImageBlob = await resizeImage(f);
      const url = URL.createObjectURL(selectedImageBlob);
      $('#uploadBoxContent').innerHTML = `<img src="${url}"><div>${escapeHtml(f.name)}</div>`;
    }catch(err){
      $('#uploadBoxContent').textContent = '📷 Toque para escolher uma imagem da escala';
      toast('Não foi possível ler essa imagem.');
    }
  });

  $('#readScaleBtn').addEventListener('click', async ()=>{
    const refYear = parseInt($('#refYear').value) || new Date().getFullYear();
    const pastedText = $('#pasteText').value.trim();
    const myName = $('#myName').value.trim();
    if(!selectedImageBlob && !pastedText){ toast('Envie uma imagem ou cole o texto da escala.'); return; }
    if(!myName){ toast('Informe seu nome como aparece na escala.'); return; }

    const prompt = `Você extrai os plantões de UMA pessoa específica dentro de uma escala médica.
A escala pode ser: (a) pessoal, com um plantão por linha; ou (b) uma grade de equipe/serviço, com VÁRIOS nomes de médicos por dia, organizada em colunas de dias/datas e blocos ou seções por turno (ex.: um cabeçalho único da tabela como "Noturno 19:00 as 07:00", ou seções separadas como "DIURNO 07X19h" e "NOTURNO 19X07h"). Categorias dentro do dia como "COM"/"SUS" ou nomes de setor não mudam o horário do turno — o horário vem do cabeçalho/seção da tabela, não de cada linha.

Pessoa a localizar (comparação sem diferenciar maiúsculas/acentos, aceitando nome parcial): "${myName}"

Tarefa: encontre TODAS as datas em que essa pessoa aparece em QUALQUER lista/coluna de nomes da escala. Para cada ocorrência, extraia:
- date (AAAA-MM-DD) — a data daquela coluna/dia. Datas podem vir parciais (ex.: "31/ago", "7 -", "05/set (Sáb)"): complete o mês faltante deduzindo pela sequência do calendário e o ano usando o mês/ano indicado no título da escala (ex.: "SETEMBRO / 2026"); se o título não indicar ano, use ${refYear}.
- start / end (HH:MM, 24h) — o horário do turno daquele bloco/seção/cabeçalho (ex.: "19:00"/"07:00" para "Noturno 19:00 as 07:00", ou "07:00"/"19:00" para "DIURNO 07X19h").
- location — nome do serviço/unidade que aparece no título da escala (ex.: "Unidade Clínica de Emergência", "Emergência/Incor").
- notes — deixe em branco, a menos que haja uma marcação específica ao lado do nome (ex.: "**") que valha a pena registrar.

Se o nome não aparecer em nenhuma data, responda com um array vazio [].
Responda APENAS com um array JSON válido, sem nenhum texto antes ou depois, no formato exato:
[{"date":"2026-09-12","start":"19:00","end":"07:00","location":"Emergência","notes":""}]
${pastedText ? ('\nTexto da escala:\n' + pastedText.slice(0,4000)) : '\nA escala está na imagem enviada.'}`;

    const statusEl = $('#importStatus');
    statusEl.innerHTML = '<span class="spin"></span> Lendo escala…';
    $('#readScaleBtn').disabled = true;
    try{
      const text = await callClaude({ prompt, imageBlob: selectedImageBlob });
      const data = extractJson(text);
      const arr = Array.isArray(data) ? data : (Array.isArray(data.plantoes) ? data.plantoes : []);
      if(!arr.length){ statusEl.textContent = `Não encontrei "${myName}" nesta escala. Confira a grafia do nome ou tente uma imagem mais nítida.`; return; }
      pendingImport = arr.map(x=>({
        date: x.date||'', start: x.start||x.startTime||'19:00', end: x.end||x.endTime||'07:00',
        location: x.location||'', notes: x.notes||'', include:true
      }));
      applyDefaultRates();
      renderReview();
      statusEl.textContent = `${pendingImport.length} plantão(ões) encontrado(s). Revise abaixo antes de importar.`;
    }catch(e){
      if(e.code==='no_key') statusEl.textContent = 'Configure sua chave de API da Anthropic (⚙ no topo) para ler escalas.';
      else if(e.code==='auth') statusEl.textContent = 'Chave de API inválida ou sem permissão. Confira em ⚙ no topo.';
      else if(e.code==='rate_limited') statusEl.textContent = 'Muitas tentativas seguidas — aguarde um pouco e tente novamente.';
      else if(e.message==='invalid_json') statusEl.textContent = 'Não consegui interpretar a resposta. Tente novamente ou uma imagem mais nítida.';
      else statusEl.textContent = 'Erro ao ler escala: ' + e.message;
    }finally{
      $('#readScaleBtn').disabled = false;
    }
  });

  function applyDefaultRates(){
    pendingImport.forEach(row=>{
      const cfg = rates[row.location];
      if(cfg){
        row.value = cfg.mode==='fixed' ? cfg.value : Math.round(cfg.value * hoursBetween(row.start,row.end) * 100)/100;
      } else row.value = 0;
    });
  }

  function renderReview(){
    $('#reviewCard').style.display = 'block';
    const wrap = $('#reviewList');
    wrap.innerHTML = `<div class="import-row header"><div>Data</div><div>Início</div><div>Fim</div><div>Local</div><div>Valor</div><div></div></div>` +
      pendingImport.map((row,i)=>`
      <div class="import-row" data-i="${i}">
        <input type="date" class="ri-date" value="${row.date}">
        <input type="time" class="ri-start" value="${row.start}">
        <input type="time" class="ri-end" value="${row.end}">
        <input type="text" class="ri-loc" value="${escapeHtml(row.location)}">
        <input type="number" class="ri-value mono" value="${row.value||0}" step="0.01">
        <button class="icon-btn ri-del" title="Remover">✕</button>
      </div>`).join('');
    $$('.import-row[data-i]', wrap).forEach(rowEl=>{
      const i = parseInt(rowEl.dataset.i);
      rowEl.querySelector('.ri-date').addEventListener('change', e=>pendingImport[i].date=e.target.value);
      rowEl.querySelector('.ri-start').addEventListener('change', e=>{pendingImport[i].start=e.target.value; recalcRow(i);});
      rowEl.querySelector('.ri-end').addEventListener('change', e=>{pendingImport[i].end=e.target.value; recalcRow(i);});
      rowEl.querySelector('.ri-loc').addEventListener('change', e=>{pendingImport[i].location=e.target.value; recalcRow(i);});
      rowEl.querySelector('.ri-value').addEventListener('change', e=>pendingImport[i].value=parseFloat(e.target.value)||0);
      rowEl.querySelector('.ri-del').addEventListener('click', ()=>{ pendingImport.splice(i,1); renderReview(); });
    });
  }
  function recalcRow(i){
    const row = pendingImport[i];
    const cfg = rates[row.location];
    if(cfg) row.value = cfg.mode==='fixed' ? cfg.value : Math.round(cfg.value*hoursBetween(row.start,row.end)*100)/100;
  }

  $('#bulkLocApply').addEventListener('click', ()=>{
    const v = $('#bulkLoc').value.trim();
    if(!v){ toast('Digite o local para aplicar.'); return; }
    pendingImport.forEach(row=>{ row.location = v; });
    renderReview();
    toast(`Local aplicado a ${pendingImport.length} plantão(ões).`);
  });
  $('#bulkValueApply').addEventListener('click', ()=>{
    const v = parseFloat($('#bulkValue').value);
    if(isNaN(v)){ toast('Digite o valor para aplicar.'); return; }
    pendingImport.forEach(row=>{ row.value = v; });
    renderReview();
    toast(`Valor aplicado a ${pendingImport.length} plantão(ões).`);
  });

  $('#reviewCancel').addEventListener('click', ()=>{
    pendingImport=[]; $('#reviewCard').style.display='none';
    $('#bulkLoc').value=''; $('#bulkValue').value='';
  });
  $('#reviewConfirm').addEventListener('click', ()=>{
    const rows = pendingImport.filter(r=>r.date);
    if(!rows.length){ toast('Nenhum plantão com data válida.'); return; }
    const added = rows.map(r=>{
      const s = {
        id: uid(), date:r.date, startTime:r.start, endTime:r.end, location:r.location||'Sem local',
        value:r.value||0, status:'pendente', notes:r.notes||'', source:'import', createdAt:new Date().toISOString()
      };
      shifts.push(s); return s;
    });
    saveShifts(shifts);
    added.forEach(s=>syncShiftToGoogle(s));
    toast(`${rows.length} plantão(ões) importado(s).`);
    pendingImport = []; $('#reviewCard').style.display='none';
    $('#importStatus').textContent=''; selectedImageBlob=null;
    $('#uploadBoxContent').textContent='📷 Toque para escolher uma imagem da escala';
    $('#fileInput').value=''; $('#pasteText').value='';
    $('#bulkLoc').value=''; $('#bulkValue').value='';
    $$('#tabs button').forEach(x=>x.classList.remove('active'));
    $('#tabs button[data-view="plantoes"]').classList.add('active');
    $$('.view').forEach(v=>v.classList.remove('active'));
    $('#view-plantoes').classList.add('active');
    renderAll(); queueSync();
  });

  // ---------- global render ----------
  function renderAll(){
    renderShiftsTable();
    renderCalendar();
    if(selectedDay) showDayPanel(selectedDay);
    renderResumo();
    renderFaturamento();
  }
  renderAll(); renderRates();
  updateHeaderTag();
  // Reading data.json is public (no token needed), so always try — this is what lets a
  // brand-new device pick up shifts, the Google Client ID, and encrypted keys automatically.
  pullFromGithub(false);
  document.addEventListener('visibilitychange', ()=>{
    if(document.visibilityState==='visible' && loadGhToken() && !ghSyncing
       && !$('#shiftModalBg').classList.contains('open') && $('#reviewCard').style.display!=='block'){
      pullFromGithub(false);
    }
  });
})();

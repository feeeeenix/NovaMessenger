const API = '';
let token = localStorage.getItem('nm_token') || '';
let me = JSON.parse(localStorage.getItem('nm_user') || 'null');
let activeDialogId = null;
let recorder = null;
let chunks = [];
const socket = window.io ? io() : null;

const $ = s => document.querySelector(s);
const views = [...document.querySelectorAll('.view')];
const navBtns = [...document.querySelectorAll('.nav-btn')];
const dialogsEl = $('#dialogs');
const messagesEl = $('#messages');

function showView(name){
  views.forEach(v => v.classList.toggle('active', v.id === `${name}View`));
  navBtns.forEach(b => b.classList.toggle('active', b.dataset.view === name));
  if(name === 'chat') loadDialogs();
  if(name === 'admin') loadAdmin();
}

navBtns.forEach(btn => btn.addEventListener('click', () => showView(btn.dataset.view)));

async function api(path, options={}){
  const headers = options.headers || {};
  if(token) headers.Authorization = `Bearer ${token}`;
  if(!(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
  const res = await fetch(API + path, {...options, headers});
  const data = await res.json().catch(()=> ({}));
  if(!res.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function toast(msg){
  const host = document.getElementById('toastHost');
  if(!host) return alert(msg);
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateY(10px)'; }, 2200);
  setTimeout(() => el.remove(), 2600);
}

function escapeHtml(s){
  return String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;');
}

$('#registerForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  try {
    await api('/api/register', { method:'POST', body: JSON.stringify({
      name: $('#regName').value,
      email: $('#regEmail').value,
      password: $('#regPassword').value,
    })});
    toast('Код отправлен на почту');
    showView('verify');
  } catch(err){ toast(err.message); }
});

$('#verifyForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  try {
    await api('/api/verify-email', { method:'POST', body: JSON.stringify({
      email: $('#verifyEmail').value,
      code: $('#verifyCode').value,
    })});
    toast('Почта подтверждена');
    showView('login');
  } catch(err){ toast(err.message); }
});

$('#loginForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  try {
    const data = await api('/api/login', { method:'POST', body: JSON.stringify({
      email: $('#loginEmail').value,
      password: $('#loginPassword').value,
    })});
    token = data.token; me = data.user;
    localStorage.setItem('nm_token', token);
    localStorage.setItem('nm_user', JSON.stringify(me));
    if(socket) socket.emit('auth', token);
    toast('Вход выполнен');
    showView('chat');
  } catch(err){ toast(err.message); }
});

async function loadDialogs(){
  try {
    const data = await api('/api/dialogs');
    dialogsEl.innerHTML = data.dialogs.map(d => `
      <div class="message" style="cursor:pointer" data-id="${d.id}">
        <b>${escapeHtml(d.a_name || d.b_name)}</b>
        <div class="muted">Dialog #${d.id}</div>
      </div>`).join('') || '<div class="muted">Нет диалогов</div>';
    dialogsEl.querySelectorAll('[data-id]').forEach(el => {
      el.onclick = () => { activeDialogId = el.dataset.id; loadMessages(); };
    });
  } catch(err){ dialogsEl.innerHTML = `<div class="muted">${err.message}</div>`; }
}

async function loadMessages(){
  if(!activeDialogId) return;
  const data = await api(`/api/dialogs/${activeDialogId}/messages`);
  messagesEl.innerHTML = data.messages.map(m => {
    if(m.type === 'text') return `<div class="message"><b>${m.sender_id === me.id ? 'Вы' : 'Пользователь'}</b><div>${escapeHtml(m.text || '')}</div></div>`;
    if(m.type === 'voice') return `<div class="message"><b>Войс</b><audio controls src="${m.file_url}"></audio></div>`;
    return `<div class="message"><b>Файл</b><a href="${m.file_url}" target="_blank">${escapeHtml(m.file_name || 'download')}</a></div>`;
  }).join('');
}

$('#messageForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  if(!activeDialogId) return toast('Выбери диалог');
  const text = $('#messageText').value.trim();
  if(!text) return;
  socket?.emit('send_message', { dialogId: activeDialogId, text });
  $('#messageText').value = '';
});

$('#fileInput')?.addEventListener('change', async e => {
  if(!activeDialogId) return toast('Выбери диалог');
  const file = e.target.files[0]; if(!file) return;
  const fd = new FormData(); fd.append('file', file);
  try {
    await api(`/api/dialogs/${activeDialogId}/messages/file`, { method:'POST', body: fd });
    e.target.value = '';
    loadMessages();
  } catch(err){ toast(err.message); }
});

$('#voiceBtn')?.addEventListener('click', async () => {
  if(!activeDialogId) return toast('Выбери диалог');
  if(!navigator.mediaDevices || !window.MediaRecorder) return toast('Войс не поддерживается');
  const stream = await navigator.mediaDevices.getUserMedia({ audio:true });
  recorder = new MediaRecorder(stream); chunks = [];
  recorder.ondataavailable = ev => ev.data.size && chunks.push(ev.data);
  recorder.onstop = async () => {
    const blob = new Blob(chunks, { type:'audio/webm' });
    const fd = new FormData(); fd.append('file', blob, 'voice.webm');
    await api(`/api/dialogs/${activeDialogId}/messages/file`, { method:'POST', body: fd });
    loadMessages();
    stream.getTracks().forEach(t => t.stop());
  };
  recorder.start();
  setTimeout(() => recorder?.stop(), 5000);
});

async function loadAdmin(){
  const box = $('#adminBox');
  const notifyBox = $('#notifyBox');
  const presence = $('#presence');
  try {
    const users = await api('/api/users');
    const logs = await api('/api/admin/logs');
    box.innerHTML = `<h3>Пользователи</h3><pre>${escapeHtml(JSON.stringify(users.users, null, 2))}</pre>`;
    notifyBox.innerHTML = `<h3>Уведомления</h3><pre>${escapeHtml(JSON.stringify(logs.logs.slice(0,10), null, 2))}</pre>`;
  } catch(err){ box.innerHTML = `<div class="muted">${err.message}</div>`; }

  if (presence) {
    presence.innerHTML = `<h3>Онлайн</h3><pre>${escapeHtml(JSON.stringify([], null, 2))}</pre>`;
  }
}

if(socket){
  socket.on('ready', () => { if(token) socket.emit('auth', token); });
  socket.on('new_message', msg => {
    if (String(msg.dialog_id) === String(activeDialogId)) loadMessages();
  });
  socket.on('presence:update', list => {
    const presence = $('#presence');
    if (!presence) return;
    presence.innerHTML = `<h3>Онлайн</h3><pre>${escapeHtml(JSON.stringify(list, null, 2))}</pre>`;
  });
}

$('#resetForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  try {
    const email = $('#resetEmail').value.trim();
    await api('/api/auth/reset-request', { method:'POST', body: JSON.stringify({ email }) });
    toast('Код для сброса отправлен на почту');
  } catch(err){ toast(err.message); }
});

$('#newPassForm')?.addEventListener('submit', async e => {
  e.preventDefault();
  try {
    await api('/api/auth/reset-confirm', {
      method:'POST',
      body: JSON.stringify({
        email: $('#newPassEmail').value.trim(),
        code: $('#newPassCode').value.trim(),
        password: $('#newPassPassword').value.trim(),
      })
    });
    toast('Пароль обновлён');
  } catch(err){ toast(err.message); }
});

if(token && me){
  if(socket) socket.emit('auth', token);
  showView('chat');
} else {
  showView('register');
}

const API = {
  issueDeviceToken: (id) => postForm(`/api/devices/${id}/issue-token`, {}, true), 
  login: (email, password) => postForm('/api/auth/login', {email, password}),
  register: (email, password) => postForm('/api/auth/register', {email, password}),
  dashboard: () => authGet('/api/dashboard'),
  devices: () => authGet('/api/devices'),
  addDevice: (name, capacity_gb) => postForm('/api/devices', {name, capacity_gb}, true),
  updateDevice: (id, payload) => patchForm(`/api/devices/${id}`, payload, true),
  deleteDevice: (id) => authFetch(`/api/devices/${id}`, {method:'DELETE'}),
  files: () => authGet('/api/files'),
  uploadFile: (file, deviceIds) => upload('/api/files', file, deviceIds),
  assignFile: (fileId, deviceId) => postForm(`/api/files/${fileId}/assign`, {device_id: deviceId}, true),
  unassignFile: (fileId, deviceId) => authFetch(`/api/files/${fileId}/assign/${deviceId}`, {method:'DELETE'}),
};

// ---- Helpers ----

function isOnline(lastSeenIso, thresholdSec = 90){
  if (!lastSeenIso) return false;
  const last = new Date(lastSeenIso).getTime();
  return (Date.now() - last) / 1000 < thresholdSec;
}
function fmtBytes(n){
  if (n == null) return "0 B";
  const u = ["B","KB","MB","GB","TB"]; let i=0;
  while (n >= 1024 && i < u.length-1){ n/=1024; i++; }
  return `${n.toFixed(1)} ${u[i]}`;
}

async function copyText(txt){
  try { await navigator.clipboard.writeText(txt); alert('Copied'); }
  catch {
    const ta = document.createElement('textarea');
    ta.value = txt; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); document.body.removeChild(ta);
    alert('Copied');
  }
}

function token(){ return localStorage.getItem('token'); }
function setToken(t){ localStorage.setItem('token', t); }
function authHeaders(){ return token() ? {'Authorization': 'Bearer ' + token()} : {}; }

async function authFetch(url, opts={}){
  const res = await fetch(url, { ...opts, headers: { ...(opts.headers||{}), ...authHeaders()}});
  if(!res.ok){ throw new Error((await res.json()).detail || 'Request failed'); }
  return res.json();
}
async function authGet(url){ return authFetch(url); }

async function postForm(url, obj, withAuth){
  const fd = new FormData();
  Object.entries(obj).forEach(([k,v])=>fd.append(k, v));
  const res = await fetch(url, { method: 'POST', body: fd, headers: withAuth ? authHeaders() : undefined });
  if(!res.ok){ throw new Error((await res.json()).detail || 'Request failed'); }
  return res.json();
}
async function patchForm(url, obj, withAuth){
  const fd = new FormData();
  Object.entries(obj).forEach(([k,v])=>fd.append(k, v));
  const res = await fetch(url, { method: 'PATCH', body: fd, headers: withAuth ? authHeaders() : undefined });
  if(!res.ok){ throw new Error((await res.json()).detail || 'Request failed'); }
  return res.json();
}
async function upload(url, file, deviceIds){
  const fd = new FormData();
  fd.append('thefile', file);
  if(deviceIds && deviceIds.length){ fd.append('device_ids', JSON.stringify(deviceIds.map(Number))); }
  const res = await fetch(url, { method:'POST', body: fd, headers: authHeaders() });
  if(!res.ok){ throw new Error((await res.json()).detail || 'Upload failed'); }
  return res.json();
}

function timeAgo(iso){
  if(!iso) return '—';
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  const m = Math.floor(s/60), h = Math.floor(m/60);
  if (h >= 1) return `${h}h ${m%60}m ago`;
  if (m >= 1) return `${m}m ago`;
  return `${s}s ago`;
}


// ---- UI State ----
const authScreen = document.getElementById('auth-screen');
const appShell = document.getElementById('app-shell');
const userEmailEl = document.getElementById('user-email');
const logoutBtn = document.getElementById('logout');

const views = [...document.querySelectorAll('.view')];
const navButtons = [...document.querySelectorAll('.nav-btn')];

function showView(id){
  views.forEach(v => v.classList.toggle('hidden', v.id !== `view-${id}`));
  navButtons.forEach(b => b.classList.toggle('bg-slate-100', b.dataset.view === id));
  if(id === 'dashboard') loadDashboard();
  if(id === 'devices') loadDevices();
  if(id === 'files') loadFiles();
}

navButtons.forEach(b => b.addEventListener('click', ()=>showView(b.dataset.view)));

document.getElementById('btn-login').onclick = async () => {
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  try{
    const data = await API.login(email, password);
    setToken(data.token);
    enterApp(email);
  }catch(e){ alert(e.message); }
};
document.getElementById('btn-register').onclick = async () => {
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  try{
    const data = await API.register(email, password);
    setToken(data.token);
    enterApp(email);
  }catch(e){ alert(e.message); }
};

logoutBtn.onclick = ()=>{ localStorage.removeItem('token'); location.reload(); };

function enterApp(email){
  authScreen.classList.add('hidden');
  appShell.classList.remove('hidden');
  userEmailEl.textContent = email;
  showView('dashboard');
}

// Auto-enter if token exists (email unknown here)
if(token()){
  authScreen.classList.add('hidden');
  appShell.classList.remove('hidden');
  userEmailEl.textContent = 'Signed in';
  showView('dashboard');
}

// ---- Dashboard ----
let storageChart;

async function loadDashboard() {
  try {
    const d = await API.dashboard();
    document.getElementById('stat-devices').textContent = d.total_devices;
    document.getElementById('stat-total-storage').textContent = d.total_storage_gb.toFixed(0);
    document.getElementById('stat-used-storage').textContent = d.used_storage_gb.toFixed(1);
    document.getElementById('stat-files').textContent = d.total_files;

  // Connected devices list
    const devices = await API.devices();
    const container = document.getElementById('connected-devices');
    container.innerHTML = '';
    devices.forEach(dev => {
    const el = document.createElement('div');
    el.className = 'border rounded-lg p-3 flex items-center justify-between';
    const usedGB = dev.used_bytes / Math.pow(1024,3);
    const lastSync = dev.last_sync ? new Date(dev.last_sync).toLocaleString() : '—';
    const freeGB = (dev.free_bytes ? (dev.free_bytes / Math.pow(1024,3)) : null);
    el.innerHTML =
      '<div>' +
        '<div class="font-medium">' + dev.name + (dev.is_online ? ' <span class="ml-2 text-xs text-green-600">● online</span>' : ' <span class="ml-2 text-xs text-slate-500">● offline</span>') + '</div>' +
       '<div class="text-xs text-slate-500">' +
          dev.capacity_gb + ' GB • ' + usedGB.toFixed(1) + ' GB used' +
          (freeGB !== null ? ' • ' + freeGB.toFixed(1) + ' GB free' : '') +
          ' • last heartbeat: ' + lastSync +
        '</div>' +
      '</div>';
    container.appendChild(el);
  });


    // Chart
    const ctx = document.getElementById('chart-overview');
    const labels = d.per_device.map(x => x.device_name);
    const capacities = d.per_device.map(x => x.capacity_gb);
    const used = d.per_device.map(x => x.used_bytes / Math.pow(1024, 3));
    if (storageChart) storageChart.destroy();
    storageChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [
          { label: 'Capacity (GB)', data: capacities },
          { label: 'Used (GB)', data: used }
        ]
      },
      options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
    });
  } catch (e) {
    console.error(e);
    alert('Failed to load dashboard: ' + (e.message || e));
  }
}

// ---- Devices ----
document.getElementById('btn-add-device').onclick = async () => {
  const name = prompt('Device name?');
  if (!name) return;
  const cap = Number(prompt('Storage capacity (GB)?', '500'));
  if (!cap) return;
  try {
    await API.addDevice(name, cap);
    loadDevices();
    loadDashboard();
  } catch (e) { alert(e.message); }
};

async function loadDevices(){
  const list = document.getElementById('devices-list') 
            || document.getElementById('device-grid');  // fallback
  if (!list) { console.log('No devices container found'); return; }
  list.innerHTML = '';

  let devices = [];
  try {
    devices = (typeof API !== 'undefined' && API.devices)
      ? await API.devices()
      : await authFetch('/api/devices');
  } catch (e) {
    alert('Failed to load devices: ' + (e.message || e));
    return;
  }

  console.log('Rendering devices:', devices.length);

  devices.forEach(dev => {
    const usedBytes = Number(dev.used_bytes || 0);
    const capBytes  = Number(dev.capacity_gb || 0) * 1024 ** 3;
    const pct       = capBytes ? Math.min(100, (usedBytes / capBytes) * 100) : 0;

    const online = isOnline(dev.last_seen);
    const statusPill = `<span class="px-2 py-0.5 rounded-full text-xs ${online ? 'bg-green-100 text-green-700' : 'bg-slate-200 text-slate-600'}">
      ${online ? 'Online' : 'Offline'}
    </span>`;

    const lastSeenStr = dev.last_seen ? ` • seen ${timeAgo(dev.last_seen)}` : '';

    const card = document.createElement('div');
    card.className = 'border rounded-lg p-4 shadow-sm bg-white mb-4';
    card.innerHTML = `
      <div class="flex items-center justify-between">
        <div class="text-xl font-semibold">${dev.name}</div>
        ${statusPill}
      </div>

      <div class="mt-2 text-sm text-slate-600">
        Storage • ${dev.capacity_gb ?? 0} GB
      </div>

      <div class="w-full h-2 bg-slate-100 rounded mt-2 overflow-hidden">
        <div class="h-2 bg-emerald-500" style="width:${pct.toFixed(1)}%"></div>
      </div>

      <div class="mt-1 text-xs text-slate-500">
        ${fmtBytes(usedBytes)} used
        ${dev.free_bytes ? ` • ${fmtBytes(dev.free_bytes)} free` : ''}
        ${lastSeenStr}
      </div>

      <div class="mt-3 flex gap-2">
        <button class="px-3 py-1.5 rounded border" data-act="token">Issue Token</button>
        <button class="px-3 py-1.5 rounded border border-red-400 text-red-600" data-act="delete">Unbind</button>
      </div>
    `;

    const btnToken = card.querySelector('[data-act="token"]');
    if (btnToken) btnToken.onclick = async () => {
      try {
        const r = await postForm(`/api/devices/${dev.id}/issue-token`, {}, true);
        const t = r.device_token;
        alert(`Device token issued:\n\n${t}`);
        try { await navigator.clipboard.writeText(t); } catch {}
      } catch (e) {
        alert(e.message || 'Failed to issue token');
      }
    };

    const btnDelete = card.querySelector('[data-act="delete"]');
    if (btnDelete) btnDelete.onclick = async () => {
      if (!confirm(`Unbind ${dev.name}?`)) return;
      await authFetch(`/api/devices/${dev.id}`, { method: 'DELETE' });
      loadDevices();
    };

    list.appendChild(card);
  });
}



// ---- Files ----
document.getElementById('upload-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const fileEl = document.getElementById('file-input');
  if (!fileEl.files.length) return alert('Choose a file');
  const selected = [...document.getElementById('assign-select').selectedOptions].map(o => o.value);
  try {
    await API.uploadFile(fileEl.files[0], selected);
    fileEl.value = '';
    loadFiles();
    loadDashboard();
  } catch (err) { alert(err.message); }
});

async function loadFiles() {
  const list = await API.files();
  const tbody = document.getElementById('files-tbody');
  tbody.innerHTML = '';
  list.forEach(f => {
    const tr = document.createElement('tr');
    tr.className = 'border-t';
    const sizeGB = (f.size_bytes / Math.pow(1024, 3));
    const sizeText = sizeGB < 1
      ? (f.size_bytes / Math.pow(1024, 2)).toFixed(1) + ' MB'
      : sizeGB.toFixed(2) + ' GB';
    tr.innerHTML =
      '<td class="p-3">' + f.name + '</td>' +
      '<td class="p-3">' + sizeText + '</td>' +
      '<td class="p-3">' + (f.assignments.map(a => a.device_name + ' (' + a.status + ')').join(', ') || '-') + '</td>' +
      '<td class="p-3 text-right">' +
        '<button class="text-red-600 underline mr-3" data-act="delete">Delete</button>' +
      '</td>';
    tr.querySelector('[data-act="delete"]').onclick = async () => {
      if (confirm('Delete file?')) {
        await authFetch('/api/files/' + f.id, { method: 'DELETE' });
        loadFiles();
        loadDashboard();
      }
    };
    tbody.appendChild(tr);
  });
}


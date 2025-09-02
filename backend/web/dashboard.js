// dashboard.js — Full

import { API, fmt, safeFetch, requireAuth, getUser, clearUser } from './shared.js';

/* -------------------- Auth & Hello -------------------- */
const user = requireAuth();
document.getElementById('hello').textContent = user.username || '-';
function currentUserName(){
  try { return (JSON.parse(sessionStorage.getItem('user')||'{}').username) || 'dashboard'; }
  catch { return 'dashboard'; }
}

/* -------------------- Elements -------------------- */
// Topbar / quick
const doorStatusEl    = document.getElementById('doorStatus');
const doorStatusLarge = document.getElementById('doorStatusLarge');
const statusChip      = document.querySelector('.status-chip');
const chipDot         = statusChip ? statusChip.querySelector('.dot')    : null;
const chipLabel       = statusChip ? statusChip.querySelector('strong') : null;
const toggleDoor      = document.getElementById('toggleDoor');
const btnRefreshLock  = document.getElementById('btnRefreshLock');
const btnDoor         = document.getElementById('btnDoor');

// OTP
const otpMinutes   = document.getElementById('otpMinutes');
const otpUses      = document.getElementById('otpUses');
const otpComment   = document.getElementById('otpComment');
const otpList      = document.getElementById('otpList');
const otpHistoryBox= document.getElementById('otpHistory');
const btnGenOtp    = document.getElementById('btnGenOtp');
const btnClearOtpHistory = document.getElementById('btnClearOtpHistory');

// Camera
const camFeed      = document.getElementById('camFeed');
const btnStartCam  = document.getElementById('btnStartCam');
const btnStopCam   = document.getElementById('btnStopCam');
const btnSnapshot  = document.getElementById('btnSnapshot');
const snapshotLink = document.getElementById('snapshotLink');

// Logs
const logTableBody = document.querySelector('#logTable tbody');

// Biometrics
const fpUser   = document.getElementById('fpUser');
const fpFinger = document.getElementById('fpFinger');
const fpList   = document.getElementById('fpList');
const faceUser = document.getElementById('faceUser');
const faceFile = document.getElementById('faceFile');
const faceList = document.getElementById('faceList');

// Toast host
const toastHost = document.getElementById('toastHost');

/* -------------------- Utils -------------------- */
function addLog(entry){
  const tr = document.createElement('tr');
  tr.innerHTML = `<td>${fmt(entry.ts)}</td><td>${entry.who||'-'}</td><td><span class="tag">${entry.action}</span></td><td class="small">${entry.info||''}</td>`;
  logTableBody.prepend(tr);
}
function toast(msg){
  const el = document.createElement('div');
  el.className = 'toast';
  el.textContent = msg;
  toastHost.appendChild(el);
  setTimeout(()=>el.remove(), 3000);
}

/* -------------------- Safe Mode + Confirm Modal -------------------- */
const safeModeToggle = document.getElementById('safeMode');
const SAFE_MODE_KEY  = 'sm_safe_mode';

function isSafeMode(){ return !!(safeModeToggle && safeModeToggle.checked); }
function loadSafeMode(){
  const v = localStorage.getItem(SAFE_MODE_KEY);
  if (safeModeToggle) safeModeToggle.checked = (v === '1');
}
function saveSafeMode(){
  if (!safeModeToggle) return;
  localStorage.setItem(SAFE_MODE_KEY, safeModeToggle.checked ? '1' : '0');
}
safeModeToggle?.addEventListener('change', ()=>{
  saveSafeMode();
  toast(safeModeToggle.checked ? '🔒 เปิดโหมดความปลอดภัย' : '⚡ ปิดโหมดความปลอดภัย');
});

// Confirm Modal (Promise)
const modalEl   = document.getElementById('confirmModal');
const msgEl     = document.getElementById('confirmMessage');
const titleEl   = document.getElementById('confirmTitle');
const okBtn     = document.getElementById('confirmOk');
const cancelBtn = document.getElementById('confirmCancel');
let _resolver = null;
let _lastFocused = null;

function openConfirm({ title='ยืนยันการสั่งงาน', message='คุณต้องการดำเนินการหรือไม่', okText='ยืนยัน', cancelText='ยกเลิก' } = {}){
  return new Promise((resolve)=>{
    _resolver = resolve;
    _lastFocused = document.activeElement;

    if (titleEl)   titleEl.textContent = title;
    if (msgEl)     msgEl.textContent   = message;
    if (okBtn)     okBtn.textContent   = okText;
    if (cancelBtn) cancelBtn.textContent = cancelText;

    modalEl?.classList.remove('hidden');
    modalEl?.setAttribute('aria-hidden','false');
    setTimeout(()=> okBtn?.focus(), 10);
  });
}
function closeConfirm(result){
  modalEl?.classList.add('hidden');
  modalEl?.setAttribute('aria-hidden','true');
  if (_resolver){ _resolver(result); _resolver = null; }
  _lastFocused?.focus?.();
}
okBtn?.addEventListener('click',   ()=> closeConfirm(true));
cancelBtn?.addEventListener('click',()=> closeConfirm(false));
modalEl?.addEventListener('click', (e)=>{
  if (e.target === modalEl || e.target.classList.contains('modal__backdrop')){
    closeConfirm(false);
  }
});
window.addEventListener('keydown', (e)=>{
  if (!modalEl || modalEl.classList.contains('hidden')) return;
  if (e.key === 'Escape') closeConfirm(false);
  if (e.key === 'Enter')  closeConfirm(true);
});

async function confirmIfSafe(action){
  if (!isSafeMode()) return true;
  const verb = action === 'unlock' ? 'ปลดล็อก' : 'ล็อก';
  const message = `ยืนยันการ${verb}ประตู?\nผู้ใช้: ${currentUserName()} • เวลา: ${new Date().toLocaleString()}`;
  return await openConfirm({
    title: 'โหมดความปลอดภัย',
    message,
    okText: 'ยืนยัน',
    cancelText: 'ยกเลิก',
  });
}

/* -------------------- Door UI -------------------- */
function setChipPending(){
  chipLabel && (chipLabel.textContent = '-');
  chipDot   && chipDot.classList.remove('dot--ok','dot--bad');
  doorStatusEl    && (doorStatusEl.textContent = '-');
  doorStatusLarge && (doorStatusLarge.textContent = '-');
}
function applyDoorUI(locked){
  // hero button (ถ้ามี)
  if (btnDoor){
    btnDoor.classList.toggle('is-locked',   locked);
    btnDoor.classList.toggle('is-unlocked', !locked);
    const icon  = btnDoor.querySelector('.door-hero__icon .lock');
    const state = btnDoor.querySelector('.door-hero .state');
    const hint  = btnDoor.querySelector('.door-hero .hint');
    if (icon && state && hint){
      if (locked){
        icon.textContent  = '🔒';
        state.textContent = 'ล็อกอยู่';
        hint.textContent  = 'แตะเพื่อปลดล็อก';
      }else{
        icon.textContent  = '🔓';
        state.textContent = 'ปลดล็อกอยู่';
        hint.textContent  = 'แตะเพื่อล็อก';
      }
    }
  }
  doorStatusEl    && (doorStatusEl.textContent    = locked ? 'ล็อก' : 'ปลดล็อก');
  doorStatusLarge && (doorStatusLarge.textContent = locked ? 'ล็อก' : 'ปลดล็อก');
  chipLabel && (chipLabel.textContent = locked ? 'ล็อก' : 'ปลดล็อก');
  if (chipDot){
    chipDot.classList.toggle('dot--ok',  !locked);
    chipDot.classList.toggle('dot--bad',  locked);
  }
  toggleDoor && (toggleDoor.checked = !locked);
}
function setDoorUI(locked){ applyDoorUI(locked); } // compatibility

/* -------------------- Boot -------------------- */
bootDashboard();
async function bootDashboard(){
  loadSafeMode();
  await refreshLockStatus();
  await loadOtps();
  await loadOtpHistory();
  await loadLogs();
  await loadFingerprints();
  await loadFaces();
  startCam();
  setInterval(refreshLockStatus, 10000);
}

/* -------------------- Logout -------------------- */
document.getElementById('btnLogout').addEventListener('click', ()=>{
  clearUser();
  location.href = 'login.html';
});

/* -------------------- Door Control -------------------- */
async function refreshLockStatus(){
  setChipPending();
  const r = await safeFetch(`${API}/lock/status`);
  const locked = r.__error ? true : !!r.locked;
  applyDoorUI(locked);
}
btnRefreshLock?.addEventListener('click', refreshLockStatus);

btnDoor?.addEventListener('click', async ()=>{
  const isLockedNow = chipDot?.classList.contains('dot--bad');
  const action = isLockedNow ? 'unlock' : 'lock';
  if (!await confirmIfSafe(action)) return;
  doorCommand(action);
});
window.addEventListener('keydown', async (e)=>{
  if (e.key.toLowerCase() !== 'l') return;
  const isLockedNow = chipDot?.classList.contains('dot--bad');
  const action = isLockedNow ? 'unlock' : 'lock';
  if (!await confirmIfSafe(action)) return;
  doorCommand(action);
});
if (toggleDoor){
  toggleDoor.addEventListener('change', async ()=>{
    const action = toggleDoor.checked ? 'unlock' : 'lock';
    if (!await confirmIfSafe(action)){
      toggleDoor.checked = !toggleDoor.checked;
      return;
    }
    doorCommand(action);
  });
}
async function doorCommand(action){
  const wasLocked = (doorStatusEl?.textContent === 'ล็อก');
  applyDoorUI(action !== 'unlock'); // optimistic
  const r = await safeFetch(`${API}/lock`, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ action, who: currentUserName() })
  });
  if(r.__error){
    applyDoorUI(wasLocked);
    alert('สั่งงานไม่สำเร็จ');
    return;
  }
  addLog({ts:Date.now(), who:currentUserName(), action: action.toUpperCase(), info:'สั่งจาก Dashboard'});
  toast(action==='unlock'? '✅ ปลดล็อกประตูแล้ว' : '🔒 ล็อกประตูแล้ว');
  refreshLockStatus();
}

/* -------------------- OTP (Active) -------------------- */
async function loadOtps(){
  otpList.innerHTML = '';
  const r = await safeFetch(`${API}/otp/active`);
  const items = r.__error ? [] : (r.items||[]);
  if(items.length===0){
    otpList.innerHTML = '<div class="otp-empty">ยังไม่มี OTP ที่ใช้งาน</div>';
    return;
  }
  items.forEach(renderOtp);
}
function renderOtp(o){
  const el = document.createElement('div');
  el.className='otp-item';
  el.innerHTML = `
    <div class="info">
      <div>รหัส: <strong>${o.code}</strong></div>
      <div class='small muted'>
        สร้าง: ${fmt(o.created_at||Date.now())} • 
        หมดอายุ: ${fmt(o.expires_at)} • 
        ใช้ได้อีก: ${o.remaining ?? o.uses}/${o.uses ?? '∞'}
      </div>
      ${o.comment ? `<div class="otp-comment">💬 ${o.comment}</div>` : ''}
    </div>
    <button class="btn-otp-cancel">ยกเลิก</button>
  `;
  el.querySelector('.btn-otp-cancel').addEventListener('click', async ()=>{
    const r = await safeFetch(`${API}/otp/${o.code}`, {method:'DELETE'});
    if(!r.__error){
      el.remove();
      addLog({ts:Date.now(), who:currentUserName(), action:'OTP_REVOKE', info:`ยกเลิก ${o.code}`});
      toast('🗑️ ยกเลิก OTP แล้ว');
      loadOtpHistory();
      if (!otpList.querySelector('.otp-item')) {
        otpList.innerHTML = '<div class="otp-empty">ยังไม่มี OTP ที่ใช้งาน</div>';
      }
    }else{
      toast('ไม่สามารถยกเลิก OTP ได้');
    }
  });
  otpList.appendChild(el);
}

btnGenOtp?.addEventListener('click', async ()=>{
  const minutes = Math.max(1, parseInt(otpMinutes.value||'10',10));
  const uses    = Math.max(1, parseInt(otpUses.value||'1',10));
  const comment = (otpComment?.value || '').trim();

  const r = await safeFetch(`${API}/otp`, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ minutes, uses, who: currentUserName(), comment })
  });
  if(r.__error){ alert('สร้าง OTP ไม่สำเร็จ'); return; }

  otpList.querySelector('.otp-empty')?.remove();
  renderOtp(r);
  addLog({ts:Date.now(), who:currentUserName(), action:'OTP_CREATE', info:`${r.code} (${uses} ครั้ง / ${minutes} นาที)${comment? ' • '+comment : ''}`});
  if(otpComment) otpComment.value='';
  toast('✨ สร้าง OTP ใหม่แล้ว');
  loadOtpHistory();
});

/* -------------------- OTP History -------------------- */
async function loadOtpHistory(){
  if(!otpHistoryBox) return;
  otpHistoryBox.innerHTML = '';
  const r = await safeFetch(`${API}/otp/history?limit=200`);
  const rows = r.__error ? [] : (r.items||[]);
  if(rows.length===0){ 
    otpHistoryBox.innerHTML = '<div class="otp-empty">ยังไม่มี OTP ที่หมดอายุ</div>'; 
    return; 
  }
  rows.forEach(it=>{
    const el = document.createElement('div');
    el.className = 'otp-item';
    el.innerHTML = `
      <div class="info">
        <div>รหัส: <strong>${it.code}</strong> <span class="tag">${it.status}</span></div>
        <div class="small muted">
          สร้าง: ${fmt(it.created_at)} • หมดอายุ: ${fmt(it.expires_at)} • ใช้ได้: ${it.remaining}/${it.uses}
        </div>
        ${it.comment ? `<div class="otp-comment">💬 ${it.comment}</div>` : ''}
      </div>`;
    otpHistoryBox.appendChild(el);
  });
}

// เคลียร์ประวัติ OTP (ถามยืนยันด้วย modal)
document.getElementById("btnClearOtpHistory")?.addEventListener("click", async () => {
  const ok = await openConfirm({
    title: "ล้างประวัติ OTP",
    message: "คุณต้องการล้างประวัติ OTP ที่หมดอายุทั้งหมดหรือไม่?\nการกระทำนี้ย้อนกลับไม่ได้",
    okText: "ล้างประวัติ",
    cancelText: "ยกเลิก",
  });
  if (!ok) return;

  const res = await safeFetch(`${API}/otp/history/clear`, { method: "DELETE" });
  if (res.__error) {
    toast("ไม่สามารถเคลียร์ประวัติ OTP ได้");
    return;
  }

  toast(`ลบประวัติ OTP แล้ว ${res.cleared ?? 0} รายการ`);
  await loadOtpHistory();
});


/* -------------------- Camera -------------------- */
const PLACEHOLDER = "./assets/cam_off.png";
const _preload = new Image(); _preload.src = PLACEHOLDER;

camFeed?.addEventListener('error', ()=>{
  camFeed.classList.add('is-placeholder');
  camFeed.src = PLACEHOLDER;
  btnStopCam?.setAttribute('disabled','disabled');
  btnStartCam?.removeAttribute('disabled');
});

function startCam(){
  camFeed.classList.remove('is-placeholder');
  camFeed.src = `${API}/camera/mjpeg?ts=${Date.now()}`;
  btnStartCam?.setAttribute('disabled','disabled');
  btnStopCam?.removeAttribute('disabled');
}
function stopCam(){
  camFeed.classList.add('is-placeholder');
  camFeed.src = PLACEHOLDER;
  btnStopCam?.setAttribute('disabled','disabled');
  btnStartCam?.removeAttribute('disabled');
}
btnStartCam?.addEventListener('click', startCam);
btnStopCam?.addEventListener('click',  stopCam);

btnSnapshot?.addEventListener('click', async ()=>{
  try{
    // demo snapshot
    const cvs = document.createElement('canvas');
    cvs.width = 640; cvs.height = 360;
    const ctx = cvs.getContext('2d');
    ctx.fillStyle = '#000'; ctx.fillRect(0,0,640,360);
    ctx.fillStyle = '#fff'; ctx.font = '16px Poppins, Arial';
    ctx.fillText('Snapshot demo', 20, 40);
    cvs.toBlob(b=>{
      const url = URL.createObjectURL(b);
      snapshotLink.href = url;
      snapshotLink.textContent = 'ดาวน์โหลดภาพล่าสุด';
      snapshotLink.download = `snapshot_${Date.now()}.jpg`;
      toast('📸 บันทึกภาพเดโม่แล้ว');
    });
  }catch{
    alert('ไม่สามารถแคปภาพได้');
  }
});

/* -------------------- Logs -------------------- */
async function loadLogs(){
  const r = await safeFetch(`${API}/logs`);
  const logs = r.__error ? [] : (r.items||[]);
  logs.forEach(addLog);
}

/* -------------------- Fingerprints -------------------- */
async function loadFingerprints(){
  if(!fpList) return;
  fpList.innerHTML='';
  const r = await safeFetch(`${API}/fingerprints`);
  const items = r.__error ? [] : (r.items||[]);
  if(items.length===0){ fpList.innerHTML = '<div class="muted small">ยังไม่มีข้อมูลลายนิ้วมือ</div>'; return; }
  items.forEach(fp=>{
    const el=document.createElement('div'); el.className='otp-item';
    el.innerHTML=`<div class="info"><div><strong>${fp.user}</strong></div><div class='small muted'>${fp.finger}</div></div><button class='btn-otp-cancel'>ลบ</button>`;
    el.querySelector('button').addEventListener('click', async()=>{
      const r=await safeFetch(`${API}/fingerprints/${fp.id}`, {method:'DELETE'});
      if(!r.__error){ el.remove(); addLog({ts:Date.now(), who:currentUserName(), action:'FP_DELETE', info:`${fp.user} - ${fp.finger}`}); toast('🗑️ ลบลายนิ้วมือแล้ว'); }
    });
    fpList.appendChild(el);
  });
}
document.getElementById('btnEnrollFp')?.addEventListener('click', async()=>{
  const u = (fpUser.value||'').trim(); const finger = fpFinger.value;
  if(!u) return alert('ใส่ชื่อผู้ใช้');
  const r = await safeFetch(`${API}/fingerprints/enroll`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ user: u, finger })});
  if(r.__error){ alert('ลงทะเบียนลายนิ้วมือไม่สำเร็จ'); return; }
  addLog({ts:Date.now(), who:currentUserName(), action:'FP_ENROLL', info:`${u} - ${finger}`});
  toast('✅ ลงทะเบียนลายนิ้วมือแล้ว');
  loadFingerprints(); fpUser.value='';
});

/* -------------------- Faces -------------------- */
async function loadFaces(){
  if(!faceList) return;
  faceList.innerHTML='';
  const r = await safeFetch(`${API}/faces`);
  const items = r.__error ? [] : (r.items||[]);
  if(items.length===0){ faceList.innerHTML = '<div class="muted small">ยังไม่มีข้อมูลใบหน้า</div>'; return; }
  items.forEach(fc=>{
    const el=document.createElement('div'); el.className='otp-item';
    el.innerHTML=`<div class="info"><div><strong>${fc.user}</strong></div><div class='small muted'>Face ID: ${fc.id}</div></div><button class='btn-otp-cancel'>ลบ</button>`;
    el.querySelector('button').addEventListener('click', async()=>{
      const r=await safeFetch(`${API}/faces/${fc.id}`, {method:'DELETE'});
      if(!r.__error){ el.remove(); addLog({ts:Date.now(), who:currentUserName(), action:'FACE_DELETE', info:`${fc.user}`}); toast('🗑️ ลบข้อมูลใบหน้าแล้ว'); }
    });
    faceList.appendChild(el);
  });
}
document.getElementById('btnEnrollFace')?.addEventListener('click', async()=>{
  const u = (faceUser.value||'').trim();
  if(!u) return alert('ใส่ชื่อผู้ใช้');
  const file = faceFile.files[0];
  const fd = new FormData(); fd.append('user', u); if(file) fd.append('file', file);
  const r = await safeFetch(`${API}/faces/enroll`, {method:'POST', body: fd});
  if(r.__error){ alert('ลงทะเบียนใบหน้าไม่สำเร็จ'); return; }
  addLog({ts:Date.now(), who:currentUserName(), action:'FACE_ENROLL', info:`${u}`});
  toast('✅ ลงทะเบียนใบหน้าแล้ว');
  loadFaces(); faceUser.value=''; faceFile.value='';
});

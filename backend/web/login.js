import { API, safeFetch, setUser } from './shared.js';


const form = document.getElementById('loginForm');
form.addEventListener('submit', async (e)=>{
e.preventDefault();
const username = document.getElementById('username').value.trim();
const password = document.getElementById('password').value;
const res = await safeFetch(`${API}/login`, {
method:'POST', headers:{'Content-Type':'application/json'},
body: JSON.stringify({username,password})
});
if(!res.__error && res.success){
const user = res.user || { username };
setUser(user);
const params = new URLSearchParams(location.search);
const next = params.get('next') || 'dashboard.html';
location.href = next;
}else{
alert(res.message || 'ล็อกอินไม่สำเร็จ');
}
});
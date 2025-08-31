// Base config & helpers shared by both pages
export const API = 'http://localhost:8000';


export function fmt(ts){ return new Date(ts).toLocaleString(); }


export async function safeFetch(url, opts){
try{ const r = await fetch(url, opts); if(!r.ok) throw new Error('HTTP '+r.status); return await r.json(); }
catch(e){ return { __error: true, message: e.message }; }
}


export function setUser(user){ sessionStorage.setItem('user', JSON.stringify(user)); }
export function getUser(){ try{return JSON.parse(sessionStorage.getItem('user')||'{}')}catch{return{}} }
export function clearUser(){ sessionStorage.removeItem('user'); }


export function requireAuth(){
const u = getUser();
if(!u || !u.username){
// redirect to login.html preserving original path
const back = encodeURIComponent(location.pathname + location.search + location.hash);
location.href = `login.html?next=${back}`;
}
return u;
}
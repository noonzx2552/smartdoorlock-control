// Base config & helpers shared by both pages
export const API = ''; 



export function fmt(ts){ return new Date(ts).toLocaleString(); }


export async function safeFetch(url, opts = {}) {
  try {
    const r = await fetch(url, {
      headers: { Accept: "application/json", ...(opts.headers || {}) },
      ...opts,
    });
    const ct = r.headers.get("content-type") || "";
    const data = ct.includes("application/json") ? await r.json() : await r.text();
    if (!r.ok) {
      return { __error: true, status: r.status, message: (data?.message || data || `HTTP ${r.status}`) };
    }
    return data;
  } catch (e) {
    return { __error: true, message: String(e) };
  }
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
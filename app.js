
const pages=document.querySelectorAll(".page");
const title=document.getElementById("pageTitle");
document.querySelectorAll(".nav").forEach(b=>b.onclick=()=>showPage(b.dataset.page));
function showPage(id){
 pages.forEach(p=>p.classList.add("hidden"));
 document.getElementById(id).classList.remove("hidden");
 document.querySelectorAll(".nav").forEach(x=>x.classList.toggle("active",x.dataset.page===id));
 const names={dashboard:"Security Dashboard",scan:"New Security Scan",history:"Scan History",reports:"Reports"};
 title.textContent=names[id]||"Scan Results";
 if(id==="history"||id==="reports"||id==="dashboard") loadHistory();
}
async function loadHistory(){
 const r=await fetch("/api/history"); const data=await r.json();
 document.getElementById("total").textContent=data.length;
 let counts={Critical:0,High:0,Medium:0,Low:0};
 data.forEach(x=>Object.keys(counts).forEach(k=>counts[k]+=x.counts[k]||0));
 Object.keys(counts).forEach(k=>document.getElementById(k.toLowerCase()).textContent=counts[k]);
 if(data[0]){
   document.getElementById("score").textContent=data[0].score;
   document.getElementById("latest").innerHTML=`<b>${escapeHtml(data[0].target)}</b><p class="muted">${new Date(data[0].created_at).toLocaleString()}</p><button class="primary" onclick="openScan(${data[0].id})">View results</button>`;
 }
 const rows=data.map(x=>`<tr><td>${x.id}</td><td>${escapeHtml(x.target)}</td><td>${new Date(x.created_at).toLocaleString()}</td><td>${x.score}</td><td>${x.counts.Critical+x.counts.High+x.counts.Medium+x.counts.Low}</td><td><button onclick="openScan(${x.id})">View</button></td></tr>`).join("");
 document.getElementById("historyTable").innerHTML=`<table class="table"><tr><th>ID</th><th>Target</th><th>Date</th><th>Score</th><th>Findings</th><th></th></tr>${rows||"<tr><td colspan=6>No scans yet.</td></tr>"}</table>`;
 document.getElementById("reportList").innerHTML=data.map(x=>`<div class="finding"><b>#${x.id} — ${escapeHtml(x.target)}</b><p class="muted">Score: ${x.score}</p><div class="links"><a href="/api/report/${x.id}.json">JSON</a><a href="/api/report/${x.id}.pdf">PDF</a></div></div>`).join("")||"<p class='muted'>No reports yet.</p>";
}
async function openScan(id){
 const r=await fetch(`/api/scan/${id}`); const d=await r.json();
 showPage("results"); renderResults(d);
}
function renderResults(d){
 document.getElementById("resultTitle").textContent="Scan Results";
 document.getElementById("resultMeta").textContent=`${d.target} → ${d.final_url} • HTTP ${d.status}`;
 document.getElementById("resultScore").textContent=d.score+"/100";
 const el=document.getElementById("findings");
 el.innerHTML=d.findings.length?d.findings.map(f=>`<article class="finding">
 <div class="finding-top"><h3>${escapeHtml(f.name)}</h3><span class="badge ${f.severity}">${f.severity}</span></div>
 <p><b>Description:</b> ${escapeHtml(f.description)}</p><p><b>Why it matters:</b> ${escapeHtml(f.why)}</p>
 <p><b>Remediation:</b> ${escapeHtml(f.remediation)}</p><p class="muted"><b>Component:</b> ${escapeHtml(f.component)} · <b>OWASP:</b> ${escapeHtml(f.owasp||"N/A")}</p>
 </article>`).join(""):"<div class='finding'><h3>No findings detected</h3><p>None of the implemented passive checks reported a finding.</p></div>";
}
document.getElementById("start").onclick=async()=>{
 const url=document.getElementById("url").value.trim(), auth=document.getElementById("authorized").checked;
 const err=document.getElementById("error"), prog=document.getElementById("progress"), bar=prog.querySelector("div"), stage=document.getElementById("stage");
 err.classList.add("hidden");
 if(!url||!auth){err.textContent="Enter a URL and confirm authorization.";err.classList.remove("hidden");return}
 prog.classList.remove("hidden");bar.style.width="25%";stage.textContent="Validating target…";
 setTimeout(()=>{bar.style.width="55%";stage.textContent="Running passive security checks…"},500);
 try{
   const r=await fetch("/api/scan",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url,authorized:auth})});
   const d=await r.json(); if(!r.ok) throw new Error(d.error||"Scan failed");
   bar.style.width="100%";stage.textContent="Scan complete.";
   setTimeout(()=>{prog.classList.add("hidden");showPage("results");renderResults(d)},400);
 }catch(e){prog.classList.add("hidden");err.textContent=e.message;err.classList.remove("hidden")}
};
document.getElementById("theme").onclick=()=>document.body.classList.toggle("light");
function escapeHtml(s){return String(s??"").replace(/[&<>"']/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[m]))}
loadHistory();

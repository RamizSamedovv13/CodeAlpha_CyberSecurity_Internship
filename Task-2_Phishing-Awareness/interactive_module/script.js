'use strict';
const SECTIONS = [['dashboard','Dashboard'],['fundamentals','Fundamentals'],['types','Attack types'],['social','Social engineering'],['email','Email analysis'],['website','Fake websites'],['prevention','Prevention'],['quiz','Quiz']];
const TYPES = [
 ['Email phishing','Mass emails posing as a trusted brand to steal credentials or spread malware.'],
 ['Spear phishing','Targeted messages using personal or company details to look credible.'],
 ['Whaling','Spear phishing aimed at executives or senior staff, often requesting payments or data.'],
 ['Smishing','Phishing via SMS, often with delivery or account-alert themes.'],
 ['Vishing','Voice calls pretending to be a bank, support desk or authority.'],
 ['Clone phishing','A real, previously delivered email is copied and resent with a malicious link or attachment.']];
const SOCIAL = [
 ['Urgency and fear','Deadlines and threats push you to act before thinking.'],
 ['Authority and impersonation','Posing as a boss, bank, police or IT to make you comply.'],
 ['Trust and familiarity','Using names, logos or a hijacked colleague account to seem known.'],
 ['Curiosity and rewards','Prizes, refunds or "see this document" lures that tempt a click.']];
const EMAILS = [
 {legit:false,from:'Northbridge Security <alerts@northbridge-secure-login.example>',subject:'URGENT: Account suspended in 24 hours',body:'Dear Customer,\nWe detected unusual activity. Verify your identity within 24 hours or your account will be closed.\n[Verify Now] http://northbridge-secure-login.example/verify',flags:[['Lookalike domain','The domain is not the bank\'s real domain (northbridge.example).'],['Urgency and threat','A 24-hour deadline pressures you to act.'],['Generic greeting','"Dear Customer" instead of your name.'],['Credential request via link','Real banks do not ask you to log in through an emailed link.']]},
 {legit:false,from:'Parcelo Express <delivery@parcelo-track.example>',subject:'Package held – customs fee required',body:'Your parcel #PX-88120 is on hold. Pay a small fee to release it.\nDownload the invoice: customs_invoice.pdf.exe',flags:[['Unexpected parcel','You were not expecting a delivery.'],['Double extension','.pdf.exe is an executable disguised as a PDF.'],['Payment request','Small fees are used to capture card details.']]},
 {legit:false,from:'Alex Rivera (CEO) <alex.rivera.ceo@mail-box.example>',subject:'Quick favour – confidential',body:'Are you at your desk? I need gift cards for a client today. Keep this between us and reply here, I am in meetings.',flags:[['Executive impersonation','A personal-looking address is used instead of the company domain.'],['Secrecy and rush','Classic business email compromise pressure.'],['Unusual request','Gift card purchases are not normal procurement.']]},
 {legit:true,from:'Cloudly Accounts <no-reply@cloudly.example>',subject:'Your monthly statement is ready',body:'Hello Sam,\nYour statement is available. Sign in to the Cloudly app or type cloudly.example into your browser to view it.\nNo action is required.',flags:[['Correct domain','Sender domain matches the official cloudly.example.'],['Personalised, no pressure','Uses your name and sets no deadline.'],['No login link','Directs you to open the app/site yourself.']]}];
const SITES = [
 {bad:true,url:'https://northbridge-secure-login.example/verify?next=http://203.0.113.9/collect',title:'Northbridge Bank – Sign in',markers:['Domain is not northbridge.example (misleading words like "secure-login").','The URL contains a redirect parameter sending you to an unknown address.','The page asks for your PIN and card number, which real sites do not.','Padlock/HTTPS is not proof the site is genuine.']},
 {bad:true,url:'https://cloud1y.example/login',title:'Cloudly – Sign in',markers:['Typosquatting: "cloud1y" uses the digit 1 instead of the letter l.','Unexpected redirect: it sends you here from an email, not from the official site.','No visible company or contact details, an indicator of a hastily built clone.','The form requests your password and a one-time MFA code together.']},
 {bad:false,url:'https://www.cloudly.example/login',title:'Cloudly – Sign in (legitimate comparison)',markers:['Exact official domain.','Only asks for credentials on the official domain, then MFA as a separate step.']}];
const $ = (s, r=document) => r.querySelector(s);
const el = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h !== undefined) e.textContent = h; return e; };
const visited = new Set(['dashboard']);

function show(id){
 document.querySelectorAll('.panel').forEach(p => p.classList.toggle('active', p.id === id));
 document.querySelectorAll('#nav button').forEach(b => b.classList.toggle('on', b.dataset.t === id));
 visited.add(id); updateProgress(); window.scrollTo({top:0,behavior:'smooth'});
}
function updateProgress(){
 const pct = Math.round((visited.size - 1) / (SECTIONS.length - 1) * 100);
 $('#bar').style.width = pct + '%'; $('#pct').textContent = pct + '% of sections visited';
}
function cards(list, target){
 list.forEach(([t, d]) => {
  const b = el('button','card'); b.type='button'; b.setAttribute('aria-expanded','false');
  b.append(el('strong','',t), el('div','more',d));
  b.onclick = () => { const o = b.classList.toggle('open'); b.setAttribute('aria-expanded', o); };
  target.append(b);
 });
}
function buildNav(){
 SECTIONS.forEach(([id, label]) => {
  const b = el('button','',label); b.dataset.t = id; b.type='button'; b.onclick = () => show(id); $('#nav').append(b);
  if (id !== 'dashboard'){ const c = el('button','card'); c.type='button'; c.append(el('strong','',label)); c.onclick = () => show(id); $('#cards').append(c); }
 });
}
function buildEmails(){
 EMAILS.forEach(m => {
  const box = el('article','mail' + (m.legit ? ' legit' : ''));
  const dl = el('dl'); [['From',m.from],['Subject',m.subject]].forEach(([k,v]) => { dl.append(el('dt','',k), el('dd','',v)); });
  const fl = el('ul','flags'); m.flags.forEach(([a,b]) => { const li = el('li'); li.append(el('b','',a + ': '), document.createTextNode(b)); fl.append(li); });
  const btn = el('button','btn','Reveal indicators'); btn.type='button';
  btn.onclick = () => { const s = fl.classList.toggle('show'); btn.textContent = s ? 'Hide indicators' : 'Reveal indicators'; };
  box.append(el('strong','', m.legit ? 'Legitimate example (for comparison)' : 'Suspicious example'), dl, el('div','body',m.body), btn, fl);
  $('#emails').append(box);
 });
}
function buildSites(){
 SITES.forEach(s => {
  const box = el('div','site'); box.append(el('div','urlbar ' + (s.bad ? 'bad' : 'good'), s.url));
  const lg = el('div','login'); lg.append(el('strong','',s.title));
  const u = el('input'); u.placeholder='Username'; u.disabled = true; const p = el('input'); p.placeholder = s.bad ? 'Password / PIN / card number' : 'Password'; p.disabled = true;
  const sb = el('button','fake','Sign in (disabled demo)'); sb.disabled = true; lg.append(u,p,sb);
  const notes = el('div','notes','Click a marker to read the explanation.');
  const mk = el('div'); s.markers.forEach((t,i) => { const b = el('button','mk',String(i+1)); b.type='button'; b.setAttribute('aria-label','Indicator '+(i+1)); b.onclick = () => { notes.textContent = (i+1)+': '+t; }; mk.append(b); });
  box.append(lg, mk, notes); $('#sites').append(box);
 });
}
/* Quiz */
let questions = [], qi = 0, score = 0, answered = false;
async function loadQuiz(){
 const box = $('#quizBox');
 try { const r = await fetch('../quiz/questions.json'); if (!r.ok) throw new Error(r.status); questions = await r.json(); startQuiz(); }
 catch (e) { box.textContent = 'Could not load ../quiz/questions.json. Run a local server (see README), e.g. "python3 -m http.server" in the project root.'; }
}
function startQuiz(){ qi = 0; score = 0; renderQ(); }
function renderQ(){
 const box = $('#quizBox'); box.replaceChildren(); answered = false;
 if (qi >= questions.length) return renderResult();
 const q = questions[qi];
 box.append(el('p','muted',`Question ${qi+1} of ${questions.length} · ${q.topic}`), el('h3','',q.question));
 const fb = el('div','fb'); fb.hidden = true; const next = el('button','btn', qi === questions.length-1 ? 'See results' : 'Next question'); next.hidden = true; next.onclick = () => { qi++; renderQ(); };
 const opts = q.options.map((o,i) => { const b = el('button','opt',o); b.type='button'; b.onclick = () => pick(i, opts, fb, next); box.append(b); return b; });
 box.append(fb, next);
}
function pick(i, opts, fb, next){
 if (answered) return; answered = true; const q = questions[qi]; const ok = i === q.answer; if (ok) score++;
 opts.forEach((b,j) => { b.disabled = true; if (j === q.answer) b.classList.add('right'); else if (j === i) b.classList.add('wrong'); });
 fb.textContent = (ok ? '✅ Correct. ' : '❌ Incorrect. ') + (ok ? '' : q.incorrect + ' ') + q.explanation; fb.hidden = false; next.hidden = false;
}
function renderResult(){
 const box = $('#quizBox'), pct = Math.round(score / questions.length * 100);
 const msg = pct >= 80 ? 'Excellent awareness.' : pct >= 60 ? 'Good start; review the missed topics.' : 'Revisit the modules and try again.';
 const r = el('button','btn','Retake quiz'); r.onclick = startQuiz;
 box.append(el('h3','',`Score: ${score} / ${questions.length} (${pct}%)`), el('p','',msg), r);
}
buildNav(); cards(TYPES, $('#typeList')); cards(SOCIAL, $('#socialList')); buildEmails(); buildSites(); loadQuiz(); show('dashboard');

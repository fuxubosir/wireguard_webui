function toast(msg,type='info',ms=2600){
  const box=document.getElementById('toastBox');
  if(!box)return;
  const el=document.createElement('div');
  el.className='toast '+type;
  el.innerText=String(msg||'');
  box.appendChild(el);
  setTimeout(()=>{el.style.opacity='0';el.style.transform='translateY(-6px)';setTimeout(()=>el.remove(),220)},ms);
}
function forceLogin(msg='expired'){
  location.href='/login?force=1&msg='+encodeURIComponent(msg);
}
async function api(url,opt={}){
  const r=await fetch(url,opt);
  if(!r.ok){
    let t=await r.text();let msg=t||'请求失败';
    try{const j=JSON.parse(t);msg=j.detail||j.message||msg}catch(e){}
    if(r.status===401){toast('登录已过期，请重新登录','warn',1600);setTimeout(()=>forceLogin('expired'),600);throw new Error('登录已过期')}
    toast(msg,'err',5200);throw new Error(msg)
  }
  return r.headers.get('content-type')?.includes('json')?r.json():r.text()
}
async function logout(){await api('/api/logout',{method:'POST'});location.href='/'}
const LIST_LIMIT=10;
const listExpanded={user:false,site:false,permission:false};
const viewMode={user:'list',site:'list',permission:'list'};
let userGrouped=true;
function toggleListMore(type){listExpanded[type]=!listExpanded[type];renderPeers()}
function toggleUserGrouping(){userGrouped=!userGrouped;renderPeers()}
function setViewMode(type,mode){
  if(!viewMode.hasOwnProperty(type))return;
  viewMode[type]=mode==='card'?'card':'list';
  renderPeers();
}
function toggleViewMode(type){
  if(!viewMode.hasOwnProperty(type))return;
  viewMode[type]=viewMode[type]==='card'?'list':'card';
  renderPeers();
}
function updateViewButtons(type){
  const mode=viewMode[type]||'list';
  document.querySelectorAll(`[data-view-toggle="${type}"]`).forEach(btn=>{
    const isSingle=!btn.dataset.viewMode;
    const active=isSingle?mode==='card':btn.dataset.viewMode===mode;
    btn.classList.toggle('active',active);
    btn.setAttribute('aria-pressed',active?'true':'false');
    if(isSingle)btn.innerText=mode==='card'?'列表显示':'卡片显示';
  });
}
function esc(s){return String(s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function attrEsc(s){return esc(s).replace(/"/g,'&quot;')}
function jsArg(s){return String(s||'').replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/\r?\n/g,' ')}
function enc(s){return encodeURIComponent(s)}
function typeCn(t){return t==='user'?'用户':t==='site'?'站点':t}
function handshakeText(p){if(p.latest_handshake_age===null||p.latest_handshake_age===undefined)return '从未握手';const s=Number(p.latest_handshake_age||0);if(s<60)return `${s} 秒前`;const m=Math.floor(s/60);if(m<60)return `${m} 分钟前`;const h=Math.floor(m/60);if(h<24)return `${h} 小时前`;const d=Math.floor(h/24);return `${d} 天前`}
function statusHtml(p){const tip=handshakeText(p);const inner=p.online?`<span class="status online" title="最后握手 ${esc(tip)}"><span class="dot on"></span>在线</span>`:`<span class="status offline" title="${esc(tip)}"><span class="dot off"></span>离线</span>`;return `<div class="status-cell">${inner}</div>`}
function handshakeHtml(p){const t=handshakeText(p);const abs=p.latest_handshake_time||'';return `<span class="handshake">${esc(t)}</span>${abs?`<span class="detail-small">${esc(abs)}</span>`:''}`}
function traffic(p){return `<span class="traffic">${esc(p.rx_human)} 接收<span class="detail-small">${esc(p.tx_human)} 发送</span></span>`}
function humanBytes(n){const units=['B','KiB','MiB','GiB','TiB'];let f=Number(n||0),i=0;while(f>=1024&&i<units.length-1){f/=1024;i++}return i===0?`${Math.round(f)} B`:`${f.toFixed(1)} ${units[i]}`}
function safeId(p){return `menu-${p.type}-${String(p.name).replace(/[^a-zA-Z0-9_-]/g,'_')}`}
function actionHtml(p,ctx='row'){const id=`${ctx}-${safeId(p)}`;const name=jsArg(p.name);const primary=p.type==='site'?`<button class="btn-main" onclick="downloadSitePackage('${name}')">下载部署包</button>`:`<button class="btn-main" onclick="showConf('user','${name}')">查看配置</button>`;const userMenu=p.type==='user'?`<button onclick="showQr('user','${name}');closeMenus()">二维码</button><button onclick="downloadConf('user','${name}');closeMenus()">下载配置</button>`:'';const siteMenu=p.type==='site'?`<button onclick="editSiteRemark('${name}');closeMenus()">编辑备注</button><button onclick="editSiteNetworks('${name}');closeMenus()">编辑内网网段</button><button onclick="showConf('site','${name}');closeMenus()">查看配置</button><button onclick="downloadSitePackage('${name}');closeMenus()">下载部署包</button>`:'';return `<div class="actions" id="wrap-${id}">${primary}<button class="btn-caret" aria-label="展开操作菜单" onclick="toggleMenu('${id}',event)"><span class="chev"></span></button><div class="menu" id="${id}">${userMenu}${siteMenu}<button class="danger" onclick="delPeer('${p.type}','${name}');closeMenus()">删除${p.type==='user'?'用户':'节点'}</button></div></div>`}
function networkHtml(p){const secondary=p.type==='site'?(p.lan_ips||p.allowed_ips||'-'):(p.allowed_ips||'-');return `<div class="net-stack" title="${esc(p.allowed_ips||'')}"><span class="net-primary">${esc(p.vpn_ip||'-')}</span><span class="net-secondary">${esc(secondary)}</span></div>`}
function endpointHtml(p){const ep=p.endpoint||'';return ep?`<span class="endpoint" title="${esc(ep)}">${esc(ep)}</span>`:`<span class="endpoint empty">未连接</span>`}
function accessSummary(p){if(p.type!=='user')return '';const detail=String(p.access_detail||'').trim();if(detail)return detail;const labels=Array.isArray(p.access_site_labels)?p.access_site_labels.filter(Boolean):[];if((p.access_mode||'all')==='all')return '全部站点';if(labels.length)return labels.join('、');return Number(p.access_site_count||0)>0?`${Number(p.access_site_count||0)} 个站点`:'未授权站点'}
function rowHtml(p){const cls=p.online?'':' class="offline-row"';const remark=p.type==='site'&&p.remark?`<span class="site-remark" title="${attrEsc(p.remark)}">${esc(p.remark)}</span>`:'';return `<tr${cls}><td class="name" title="${attrEsc(p.name)}${p.remark?' - '+attrEsc(p.remark):''}"><span class="node-name">${esc(p.name)}</span>${remark}</td><td>${statusHtml(p)}</td><td>${networkHtml(p)}</td><td>${handshakeHtml(p)}</td><td>${traffic(p)}</td><td>${endpointHtml(p)}</td><td class="actions-cell">${actionHtml(p,'row')}</td></tr>`}
function cardActionPrimary(p){
  const rawName=String(p.raw_name||p.name||'').trim();
  const name=jsArg(rawName);
  if(p.type==='site')return `<button class="btn-main" onclick="downloadSitePackage('${name}')">下载部署包</button>`;
  return `<button class="btn-main" onclick="showConf('user','${name}')">查看配置</button>`;
}
function compactLans(p){
  const raw=String(p.lan_ips||p.allowed_ips||'').split(',').map(x=>x.trim()).filter(Boolean).filter(x=>!x.startsWith('10.9.'));
  return raw.length?raw.join('，'):'未配置运行网段';
}
function peerRawName(p){return String(p.name||p.username||p.client_name||p.peer_name||'').trim()}
function displayPeerName(p){
  const n=peerRawName(p);
  if(n)return n;
  const pk=String(p.public_key||'').trim();
  if(pk)return `节点-${pk.slice(0,6)}`;
  return p.type==='site'?'未命名站点':'未命名用户';
}
function displayPeerRemark(p){
  if(p.type==='site')return String(p.remark||p.owner||'').trim()||'未设置备注';
  return String(p.owner||p.remark||'').trim()||'未设置备注';
}
function peerCardHtml(p){
  const cls=p.online?'online':'offline';
  const remark=displayPeerRemark(p);
  const name=displayPeerName(p);
  const rawName=peerRawName(p)||name;
  const mid=p.type==='site'?compactLans(p):(p.vpn_ip||p.ip||'-');
  const title=`${remark}\n${name}\n${mid}`;
  const action=actionHtml({...p,name:rawName},'card');
  const statusText=p.online?'在线':'离线';
  const dotColor=p.online?'#16a34a':'#94a3b8';
  const statusBg=p.online?'#dcfce7':'#f1f5f9';
  const statusColor=p.online?'#166534':'#475569';
  return `<div class="wgx-peer-card ${cls}" title="${attrEsc(title)}" style="height:136px;display:grid;grid-template-rows:44px 1fr 34px;border:1px solid ${p.online?'#bfdbfe':'#e5e7eb'};background:${p.online?'linear-gradient(180deg,#ffffff,#f8fbff)':'#f8fafc'};border-radius:14px;padding:12px 13px;box-shadow:0 5px 14px rgba(15,23,42,.045);min-width:0;overflow:visible;box-sizing:border-box;">
    <div class="wgx-peer-head" style="display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:start;width:100%;min-width:0;overflow:hidden;">
      <div class="wgx-peer-title" style="min-width:0;display:block;overflow:hidden;text-align:left;">
        <div class="wgx-peer-remark" style="display:block!important;color:#111827!important;font-size:15px!important;font-weight:950!important;line-height:18px!important;height:18px!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;text-align:left!important;visibility:visible!important;opacity:1!important;">${esc(remark)}</div>
        <div class="wgx-peer-name" style="display:block!important;color:#64748b!important;font-size:12px!important;font-weight:850!important;line-height:15px!important;height:15px!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;text-align:left!important;visibility:visible!important;opacity:1!important;margin-top:3px!important;">${esc(name)}</div>
      </div>
      <span class="wgx-peer-status" style="display:inline-flex;align-items:center;gap:6px;height:28px;border-radius:999px;padding:0 10px;background:${statusBg};color:${statusColor};font-size:14px;font-weight:950;white-space:nowrap;"><i style="display:inline-block;width:8px;height:8px;border-radius:999px;background:${dotColor};"></i>${statusText}</span>
    </div>
    <div class="wgx-peer-mid" title="${attrEsc(mid)}" style="align-self:center;display:block;color:#0f172a;font-size:13px;font-weight:950;line-height:18px;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;max-width:100%;">${esc(mid)}</div>
    <div class="wgx-peer-actions" style="display:flex;justify-content:flex-end;align-items:end;overflow:visible;">${action}</div>
  </div>`;
}
function ownerName(p){return String(p.owner||'').trim()||'未分类'}
function groupHeaderHtml(owner,items){const online=items.filter(p=>p.online).length;return `<tr class="group-row"><td colspan="7"><span class="owner-group-line"><span class="owner-label">归属人：</span><span class="owner-name">${esc(owner)}</span><span class="owner-online">在线 ${online}/${items.length}</span><span class="owner-count">${items.length} 个节点</span></span></td></tr>`}
function hasConnected(p){return Number(p.latest_handshake||0)>0||p.latest_handshake_age!==null&&p.latest_handshake_age!==undefined||!!p.latest_handshake_time}
function groupRank(owner,items){
  if(owner==='未分类')return 3;
  if(items.some(p=>p.online))return 0;
  if(items.some(hasConnected))return 1;
  return 2;
}
function groupLastSeen(items){
  return Math.max(...items.map(p=>Number(p.latest_handshake||0)||0),0);
}
function groupedUserRowsHtml(users){
  const groups=new Map();
  users.forEach(p=>{const owner=ownerName(p);if(!groups.has(owner))groups.set(owner,[]);groups.get(owner).push(p)});
  return Array.from(groups.entries()).sort((a,b)=>{
    const ra=groupRank(a[0],a[1]),rb=groupRank(b[0],b[1]);
    if(ra!==rb)return ra-rb;
    const la=groupLastSeen(a[1]),lb=groupLastSeen(b[1]);
    if(la!==lb)return lb-la;
    return a[0].localeCompare(b[0],'zh-Hans-CN');
  }).map(([owner,items])=>groupHeaderHtml(owner,items)+items.sort(peerSort).map(rowHtml).join('')).join('');
}
function resetMenuFloat(menu){
  if(!menu)return;
  menu.classList.remove('mobile-float');
  menu.style.left='';menu.style.top='';menu.style.right='';menu.style.bottom='';menu.style.visibility='';menu.style.display='';
  const parentId=menu.dataset.parentWrap;
  const parent=parentId?document.getElementById(parentId):null;
  if(parent && menu.parentElement!==parent)parent.appendChild(menu);
}
function positionMobileMenu(menu,trigger){
  if(!menu||!trigger||!window.matchMedia('(max-width:760px)').matches){resetMenuFloat(menu);return}
  const parent=menu.closest('.actions');
  if(parent)menu.dataset.parentWrap=parent.id;
  document.body.appendChild(menu);
  menu.classList.add('mobile-float');
  menu.style.visibility='hidden';
  menu.style.display='flex';
  const rect=trigger.getBoundingClientRect();
  const vv=window.visualViewport;
  const viewLeft=vv?vv.offsetLeft:0;
  const viewTop=vv?vv.offsetTop:0;
  const viewWidth=vv?vv.width:window.innerWidth;
  const viewHeight=vv?vv.height:window.innerHeight;
  const gap=6;
  const mw=Math.min(menu.offsetWidth||150,viewWidth-20);
  const mh=Math.min(menu.offsetHeight||190,Math.max(160,viewHeight*0.56));
  menu.style.maxHeight=`${Math.floor(mh)}px`;
  let left=viewLeft+Math.min(Math.max(10,rect.right-mw),viewWidth-mw-10);
  let top=viewTop+rect.bottom+gap;
  if(top+mh>viewTop+viewHeight-10)top=viewTop+Math.max(10,rect.top-mh-gap);
  if(top<viewTop+10)top=viewTop+Math.max(10,viewHeight-mh-10);
  menu.style.left=`${Math.round(left)}px`;
  menu.style.top=`${Math.round(top)}px`;
  menu.style.right='auto';
  menu.style.bottom='auto';
  menu.style.visibility='';
  menu.style.display='flex';
}
function positionMenu(menu,trigger,wrap){
  if(!menu||!trigger||!wrap)return;
  wrap.classList.remove('drop-up');
  if(window.matchMedia('(max-width:760px)').matches){positionMobileMenu(menu,trigger);return}
  resetMenuFloat(menu);
  menu.style.visibility='hidden';
  menu.style.display='flex';
  const rect=menu.getBoundingClientRect();
  const triggerRect=trigger.getBoundingClientRect();
  const viewHeight=window.innerHeight||document.documentElement.clientHeight;
  if(rect.bottom>viewHeight-10 && triggerRect.top>rect.height+10)wrap.classList.add('drop-up');
  menu.style.visibility='';
  menu.style.display='';
}
function closeMenus(){
  document.querySelectorAll('.menu.open').forEach(m=>{m.classList.remove('open');resetMenuFloat(m)});
  document.querySelectorAll('.actions.menu-active').forEach(a=>a.classList.remove('menu-active'));
  document.querySelectorAll('.actions.drop-up').forEach(a=>a.classList.remove('drop-up'));
}
function toggleMenu(id,e){
  e.stopPropagation();
  document.querySelectorAll('.menu.open').forEach(m=>{if(m.id!==id){m.classList.remove('open');resetMenuFloat(m)}});
  document.querySelectorAll('.actions.menu-active').forEach(a=>{if(a.id!==`wrap-${id}`){a.classList.remove('menu-active');a.classList.remove('drop-up')}});
  const menu=document.getElementById(id);
  const wrap=document.getElementById(`wrap-${id}`);
  if(!menu||!wrap)return;
  const open=!menu.classList.contains('open');
  if(open){menu.classList.add('open');wrap.classList.add('menu-active');positionMenu(menu,e.currentTarget,wrap)}
  else{menu.classList.remove('open');wrap.classList.remove('menu-active');wrap.classList.remove('drop-up');resetMenuFloat(menu)}
}
document.addEventListener('click',closeMenus)
window.addEventListener('resize',closeMenus)
window.addEventListener('scroll',closeMenus,{passive:true})

const pageMeta={
  dashboard:{title:'仪表盘',subtitle:'服务状态、在线状态、最近握手、待应用配置和系统信息'},
  users:{title:'用户管理',subtitle:'用户列表、新增用户、客户端配置和用户状态'},
  sites:{title:'站点管理',subtitle:'站点列表、新增站点、站点网段和站点状态'},
  permissions:{title:'权限管理',subtitle:'用户权限、批量授权、站点授权和 ACL 生效状态'},
  system:{title:'系统管理',subtitle:'WebUI 升级、本地网段、部署包和日志清理'},
  logs:{title:'运行日志',subtitle:'连接快照和服务日志'}
};
function setActiveNav(id){
  document.querySelectorAll('.nav a').forEach(a=>a.classList.toggle('active',a.dataset.nav===id));
}
function switchPage(id, updateHash=true){
  if(['upgrade','systemInfo','create'].includes(id))id='system';
  if(!pageMeta[id])id='dashboard';
  closeMenus();
  document.body.dataset.page=id;
  document.querySelectorAll('.page-section').forEach(el=>el.classList.toggle('active',el.id===id));
  setActiveNav(id);
  const meta=pageMeta[id]||pageMeta.dashboard;
  const title=document.getElementById('pageTitle');
  const sub=document.getElementById('pageSubtitle');
  if(title)title.innerText=meta.title;
  if(sub)sub.innerText=meta.subtitle;
  if(updateHash && location.hash!=='#'+id)history.replaceState(null,'','#'+id);
  window.scrollTo({top:0,behavior:'instant'});
}
document.querySelectorAll('.nav a[data-nav]').forEach(a=>{
  a.addEventListener('click',(e)=>{e.preventDefault();switchPage(a.dataset.nav);});
});
window.addEventListener('hashchange',()=>switchPage((location.hash||'#dashboard').slice(1),false));
function setServiceButtons(running){
  if(typeof btnSvcStart==='undefined'||typeof btnSvcStop==='undefined'||typeof btnSvcRestart==='undefined')return;
  btnSvcStart.disabled=!!running;
  btnSvcStop.disabled=!running;
  btnSvcRestart.disabled=!running;
  btnSvcStart.title=running?'WireGuard 已运行，无需重复启动':'启动 WireGuard';
  btnSvcStop.title=running?'关闭 WireGuard':'WireGuard 已停止，无需关闭';
  btnSvcRestart.title=running?'重启 WireGuard':'WireGuard 已停止，不能重启，请先启动';
}
function setApplyButton(status){
  const main=document.getElementById('btnApplyConfig');
  const pending=!!(status&&status.pending);
  const reasons=(status&&status.reasons||[]).filter(Boolean).join('；');
  const urgent=pending&&/新增站点|必须点击应用配置|不会加载该站点/.test(reasons);
  const pendingText=urgent?'立即应用配置':'应用配置';
  if(main){main.disabled=!pending;main.classList.toggle('apply-pending',pending);main.classList.toggle('apply-idle',!pending);main.classList.toggle('apply-urgent',urgent);main.innerText=pending?pendingText:'无需应用';}
  const applyTitle=pending?(reasons||'有配置变更需要应用并刷新路由'):'当前没有需要应用的配置';
  if(main)main.title=applyTitle;
  const quick=document.getElementById('btnApplyConfigQuick');
  if(quick){quick.disabled=!pending;quick.className=pending?'btn-green':'btn-gray';quick.innerText=pending?pendingText:'无需应用';quick.title=applyTitle;}
  const top=document.getElementById('btnApplyConfigTop');
  if(top){top.disabled=!pending;top.className='top-apply-btn '+(pending?'pending':'')+(urgent?' urgent':'');top.innerText=pending?pendingText:'配置已生效';top.title=applyTitle;}
}
async function loadApplyStatus(){
  try{const st=await api('/api/config/apply-status');setApplyButton(st);return st}catch(e){setApplyButton({pending:false,reasons:['状态读取失败']});return null}
}
async function loadService(){try{const s=await api('/api/service');svcName.innerText=s.service||'wg-quick@wg0';svcEnabled.innerText=`开机自启：${s.enabled||'unknown'}`;const running=!!s.running;const cls=running?'on':'off';const text=running?'运行中':'已停止';svcState.title=running?'WireGuard 正在运行':'WireGuard 已停止';svcState.innerHTML=`<span class="dot ${cls}"></span>${esc(text)}`;if(typeof envServiceSub!=='undefined')envServiceSub.innerText=`${s.service||'wg-quick@wg0'} · 自启 ${s.enabled||'unknown'}`;if(typeof envWgStatus!=='undefined'){envWgStatus.innerText=text;envWgStatus.className='status-badge '+(running?'':'off')}setServiceButtons(running);await loadApplyStatus()}catch(e){svcState.innerHTML='<span class="dot off"></span>状态读取失败';if(typeof envServiceSub!=='undefined')envServiceSub.innerText='服务状态读取失败';setServiceButtons(false);setApplyButton({pending:false})}}
async function formatUptime(sec){return ''}
function fmtBytes(n){return humanBytes(n||0)}
function uptimeText(sec){sec=Number(sec||0);if(!sec)return '运行时间未知';const d=Math.floor(sec/86400),h=Math.floor((sec%86400)/3600),m=Math.floor((sec%3600)/60);return `已运行 ${d?d+' 天 ':''}${h} 小时 ${m} 分钟`}
async function loadSystem(){try{const r=await api('/api/system');const current=r.current_instance||'wg0';const rt=r.runtime||{};const mem=rt.memory||{};const disk=rt.disk||{};const ins=r.instances||[];const cur=ins.find(i=>i.name===current)||{};envOS.innerText=r.app_version||'未知版本';if(typeof envTime!=='undefined')envTime.innerText=`服务器时间 ${r.server_time||'-'}`;envInstance.innerText=current;if(typeof envInstanceSub!=='undefined')envInstanceSub.innerText=`配置 ${ins.length||0} 个 · ${cur.config||r.current_config||'-'}`;if(typeof envWgStatus!=='undefined'){envWgStatus.innerText=cur.running?'运行中':'已停止';envWgStatus.className='status-badge '+(cur.running?'':'off')}if(typeof envServiceSub!=='undefined')envServiceSub.innerText=`内核 ${((r.os||{}).kernel)||'-'} · ${((r.os||{}).machine)||'-'}`;envTools.innerText=`内存 ${mem.percent??'-'}% · 磁盘 ${disk.percent??'-'}%`;if(typeof envRuntimeSub!=='undefined')envRuntimeSub.innerText=`${uptimeText(rt.uptime_seconds)} · 负载 ${((rt.loadavg||{})['1m']??'-')}`;await loadIpPools()}catch(e){envOS.innerText='读取失败';envTools.innerText='读取失败';if(typeof envWgStatus!=='undefined'){envWgStatus.innerText='读取失败';envWgStatus.className='status-badge bad'}}}
async function loadIpPools(){try{const r=await api('/api/ip-pools');const s=r.site||{},u=r.user||{};if(typeof envSitePool!=='undefined')envSitePool.innerText=`${s.used||0} / ${s.total||0}`;if(typeof envSitePoolSub!=='undefined')envSitePoolSub.innerText=`剩余 ${s.free||0} · 范围 ${s.start||'-'}-${s.end||'-'}`;if(typeof envUserPool!=='undefined')envUserPool.innerText=`${u.used||0} / ${u.total||0}`;if(typeof envUserPoolSub!=='undefined')envUserPoolSub.innerText=`剩余 ${u.free||0} · 范围 ${u.start||'-'}-${u.end||'-'}`}catch(e){if(typeof envSitePool!=='undefined')envSitePool.innerText='读取失败';if(typeof envUserPool!=='undefined')envUserPool.innerText='读取失败'}}
async function serviceAction(action){const map={start:'启动',stop:'关闭',restart:'重启'};if(!confirm(`确认${map[action]} WireGuard 服务？`))return;await api(`/api/service/${action}`,{method:'POST'});await loadService();await loadPeers();toast(`${map[action]}成功`,'ok')}
async function applyConfig(){
  const st=await loadApplyStatus();
  if(!st||!st.pending){toast('当前没有需要应用的配置','info');return}
  if(!confirm('确认应用 WireGuard 配置、刷新站点路由并同步服务端访问控制？\n\n该操作使用热更新方式，不重启 WireGuard 服务，尽量避免影响在线用户。'))return;
  try{
    const r=await api('/api/config/apply',{method:'POST'});
    await loadService();
    await loadPeers();
    toast(r.message||'配置已应用，路由与访问控制已刷新','ok',5200);
  }catch(e){
    await loadApplyStatus();
    toast('应用配置失败：'+(e.message||e),'err',7200);
  }
}
function peerSort(a,b){
  if(!!a.online!==!!b.online)return a.online?-1:1;
  return String(a.name||'').localeCompare(String(b.name||''),'zh-Hans-CN');
}
let allPeers=[];
function peerMatches(p,q){
  if(!q)return true;
  const text=[p.name,p.owner,p.remark,p.allowed_ips,p.public_key,p.type,p.endpoint,p.vpn_ip,p.lan_ips].join(' ').toLowerCase();
  return text.includes(q.toLowerCase());
}

function siteLanList(p){
  const raw=String(p.lan_ips||p.allowed_ips||'');
  const vpn=String(p.vpn_ip||'').trim();
  return raw.split(',').map(x=>x.trim()).filter(x=>x && x!==vpn && !x.startsWith('10.9.'));
}
function siteNetworkCardHtml(p){
  const lans=siteLanList(p);
  const label=String(p.remark||'').trim()||p.name||'未命名站点';
  const sub=String(p.remark||'').trim()?p.name:'站点节点';
  const status=p.online?'在线':'离线';
  const statusCls=p.online?'on':'off';
  const chips=lans.length?lans.map(n=>`<span class="site-net-chip" title="${attrEsc(n)}">${esc(n)}</span>`).join(''):'<span class="site-net-empty">未配置内网网段</span>';
  return `<div class="site-net-card ${lans.length?'':'empty-net'}" title="${attrEsc(label+'\n'+sub+'\n'+lans.join('，'))}"><div class="site-net-top"><div class="site-net-title"><span class="site-net-name">${esc(label)}</span><span class="site-net-sub">${esc(sub||'站点')}</span></div><span class="site-net-status ${statusCls}"><span class="dot ${statusCls==='on'?'on':'off'}"></span>${status}</span></div><div class="site-net-meta"><span>${esc(p.vpn_ip||'-')}</span><span>${lans.length} 个网段</span></div><div class="site-net-chips">${chips}</div><div class="site-net-actions"><button class="btn-gray" onclick="editSiteNetworks('${jsArg(p.name)}')">编辑网段</button><button onclick="downloadSitePackage('${jsArg(p.name)}')">部署包</button></div></div>`;
}
function renderSiteNetworkBoard(sites,allSites,q){
  const board=document.getElementById('siteNetworkBoard');
  if(!board)return;
  const total=allSites.length;
  const configured=allSites.filter(p=>siteLanList(p).length>0).length;
  const netCount=allSites.reduce((sum,p)=>sum+siteLanList(p).length,0);
  const setText=(id,val)=>{const el=document.getElementById(id);if(el)el.innerText=String(val)};
  setText('siteNetTotal',total);setText('siteNetConfigured',configured);setText('siteNetCount',netCount);
  const countEl=document.getElementById('siteNetworkCount');if(countEl)countEl.innerText=q?`(${sites.length}/${total})`:`(${total})`;
  const hint=document.getElementById('siteNetworkHint');if(hint)hint.innerText=q?`当前匹配 ${sites.length} 个站点`:'按站点集中展示内网网段';
  if(!sites.length){board.innerHTML=`<div class="empty">${q?'没有匹配的站点网段':'暂无站点网段'}</div>`;return}
  board.innerHTML=sites.map(siteNetworkCardHtml).join('');
}

function dashboardPeerLabel(p){return p.type==='site'?String(p.remark||'').trim():String(p.owner||'').trim()}
function dashboardPeerTitle(p){const label=dashboardPeerLabel(p);const bits=[];if(label)bits.push(label);bits.push(p.name||'');bits.push(p.type==='site'?'站点':'用户');if(p.vpn_ip)bits.push(p.vpn_ip);return bits.filter(Boolean).join(' / ')}
function miniPeerHtml(p){const label=dashboardPeerLabel(p);const name=p.name||'';return `<div class="mini-item" title="${attrEsc(dashboardPeerTitle(p))}"><span class="mini-main">${label?`<span class="mini-label">${esc(label)}</span>`:''}<span class="mini-name">${esc(name)}</span></span><span class="mini-meta">${esc(p.vpn_ip||'-')} · ${esc(handshakeText(p))}</span></div>`}
function renderDashboardLists(users,sites){
  const onlineUsers=(users||[]).filter(p=>p.online).slice(0,8);
  const onlineSites=(sites||[]).filter(p=>p.online).slice(0,8);
  const recent=[...(users||[]),...(sites||[])].filter(hasConnected).sort((a,b)=>Number(b.latest_handshake||0)-Number(a.latest_handshake||0)).slice(0,10);
  const uBox=document.getElementById('dashboardOnlineUsers');
  const sBox=document.getElementById('dashboardOnlineSites');
  const rBox=document.getElementById('dashboardRecentHandshake');
  if(uBox)uBox.innerHTML=onlineUsers.length?onlineUsers.map(miniPeerHtml).join(''):'<div class="mini-empty">暂无在线用户</div>';
  if(sBox)sBox.innerHTML=onlineSites.length?onlineSites.map(miniPeerHtml).join(''):'<div class="mini-empty">暂无在线站点</div>';
  if(rBox)rBox.innerHTML=recent.length?recent.map(p=>{const label=dashboardPeerLabel(p);return `<div class="mini-item" title="${attrEsc(dashboardPeerTitle(p))}"><span class="mini-main">${label?`<span class="mini-label">${esc(label)}</span>`:''}<span class="mini-name">${esc(p.name)} <span class="mini-type">${p.type==='site'?'站点':'用户'}</span></span></span><span class="mini-meta">${esc(handshakeText(p))}</span></div>`}).join(''):'<div class="mini-empty">暂无握手记录</div>';
  const ut=document.getElementById('dashboardUserOnlineText'); if(ut)ut.innerText=`${onlineUsers.length}/${(users||[]).length}`;
  const st=document.getElementById('dashboardSiteOnlineText'); if(st)st.innerText=`${onlineSites.length}/${(sites||[]).length}`;
}
function renderPeers(){
  const peers=allPeers||[];
  const allUsers=peers.filter(p=>p.type==='user').sort(peerSort);
  const allSites=peers.filter(p=>p.type==='site').sort(peerSort);
  const uq=(document.getElementById('userSearch')?.value||'').trim();
  const sq=(document.getElementById('siteSearch')?.value||'').trim();
  if(typeof userSearchMobile!=='undefined' && userSearchMobile.value!==uq)userSearchMobile.value=uq;
  if(typeof siteSearchMobile!=='undefined' && siteSearchMobile.value!==sq)siteSearchMobile.value=sq;
  const users=allUsers.filter(p=>peerMatches(p,uq));
  const sites=allSites.filter(p=>peerMatches(p,sq));
  const userOnline=allUsers.filter(p=>p.online).length;
  const siteOnline=allSites.filter(p=>p.online).length;
  renderDashboardLists(allUsers,allSites);
  const rx=peers.reduce((s,p)=>s+Number(p.rx||0),0);
  const tx=peers.reduce((s,p)=>s+Number(p.tx||0),0);
  statTotal.innerText=peers.length;
  statTotalHint.innerText=`用户 ${allUsers.length} / 站点 ${allSites.length}`;
  statUserOnline.innerText=`${userOnline} / ${allUsers.length}`;
  statUserRate.innerText=`在线率 ${allUsers.length?Math.round(userOnline*100/allUsers.length):0}%`;
  statSiteOnline.innerText=`${siteOnline} / ${allSites.length}`;
  statSiteRate.innerText=`在线率 ${allSites.length?Math.round(siteOnline*100/allSites.length):0}%`;
  statTraffic.innerText=humanBytes(rx+tx);
  statTrafficHint.innerText=`接收 ${humanBytes(rx)} / 发送 ${humanBytes(tx)}`;
  if(typeof barUserOnline!=='undefined')barUserOnline.style.width=`${allUsers.length?Math.round(userOnline*100/allUsers.length):0}%`;
  if(typeof barSiteOnline!=='undefined')barSiteOnline.style.width=`${allSites.length?Math.round(siteOnline*100/allSites.length):0}%`;
  if(typeof barTotal!=='undefined')barTotal.style.width=`${Math.min(100,peers.length*5)}%`;
  if(typeof barTraffic!=='undefined')barTraffic.style.width=`${Math.min(100,Math.round(Math.log10((rx+tx)||1)*12))}%`;
  userCount.innerText=uq?`(${users.length}/${allUsers.length})`:`(${allUsers.length})`;
  siteCount.innerText=sq?`(${sites.length}/${allSites.length})`:`(${allSites.length})`;
  if(typeof userSearchHint!=='undefined')userSearchHint.innerText=uq?`匹配 ${users.length} 个用户`:'';
  if(typeof siteSearchHint!=='undefined')siteSearchHint.innerText=sq?`匹配 ${sites.length} 个站点`:'';
  if(typeof btnToggleUserGroup!=='undefined')btnToggleUserGroup.innerText=userGrouped?'全部节点':'按归属人';
  const userNeedMore=!uq && users.length>LIST_LIMIT;
  const siteNeedMore=!sq && sites.length>LIST_LIMIT;
  const visibleUsers=userNeedMore&&!listExpanded.user?users.slice(0,LIST_LIMIT):users;
  const visibleSites=siteNeedMore&&!listExpanded.site?sites.slice(0,LIST_LIMIT):sites;
  updateViewButtons('user');updateViewButtons('site');
  const userTable=document.getElementById('userTableWrap'),siteTable=document.getElementById('siteTableWrap'),userCards=document.getElementById('userCardBoard'),siteCards=document.getElementById('siteCardBoard');
  const userIsCard=viewMode.user==='card',siteIsCard=viewMode.site==='card';
  if(userTable)userTable.style.display=userIsCard?'none':''; if(userCards)userCards.style.display=userIsCard?'grid':'none';
  if(siteTable)siteTable.style.display=siteIsCard?'none':''; if(siteCards)siteCards.style.display=siteIsCard?'grid':'none';
  userBody.innerHTML=visibleUsers.length?(userGrouped?groupedUserRowsHtml(visibleUsers):visibleUsers.map(rowHtml).join('')):`<tr><td colspan="7" class="empty">${uq?'没有匹配的用户节点':'暂无用户节点'}</td></tr>`;
  siteBody.innerHTML=visibleSites.length?visibleSites.map(rowHtml).join(''):`<tr><td colspan="7" class="empty">${sq?'没有匹配的站点节点':'暂无站点节点'}</td></tr>`;
  if(userCards)userCards.innerHTML=visibleUsers.length?visibleUsers.map(peerCardHtml).join(''):`<div class="empty">${uq?'没有匹配的用户节点':'暂无用户节点'}</div>`;
  if(siteCards)siteCards.innerHTML=visibleSites.length?visibleSites.map(peerCardHtml).join(''):`<div class="empty">${sq?'没有匹配的站点节点':'暂无站点节点'}</div>`;
  if(typeof userMoreBox!=='undefined'){userMoreBox.style.display=userNeedMore?'flex':'none';userMoreBtn.innerText=listExpanded.user?`收起，仅显示前 ${LIST_LIMIT} 个`:`展开更多（还有 ${users.length-LIST_LIMIT} 个）`;}
  if(typeof siteMoreBox!=='undefined'){siteMoreBox.style.display=siteNeedMore?'flex':'none';siteMoreBtn.innerText=listExpanded.site?`收起，仅显示前 ${LIST_LIMIT} 个`:`展开更多（还有 ${sites.length-LIST_LIMIT} 个）`;}
  renderPermissions(allUsers);
}
function permissionActionHtml(p,ctx='row'){const name=jsArg(p.name);const id=`${ctx}-perm-${safeId(p)}`;return `<div class="actions" id="wrap-${id}"><button class="btn-main" onclick="editUserAccess('${name}')">访问权限</button><button class="btn-caret" aria-label="展开权限操作" onclick="toggleMenu('${id}',event)"><span class="chev"></span></button><div class="menu" id="${id}"><button onclick="editUserOwner('${name}');closeMenus()">设置归属人</button><button onclick="editUserAccess('${name}');closeMenus()">访问权限</button></div></div>`}
function permissionCardHtml(p){
  const access=accessSummary(p);
  const accessTitle=String(p.access_detail_title||access);
  const owner=ownerName(p);
  const name=displayPeerName(p);
  const rawName=peerRawName(p)||name;
  const action=permissionActionHtml({...p,name:rawName},'card');
  const ip=String(p.vpn_ip||p.ip||'-');
  const title=`${owner}\n${name}\n${ip}\n${accessTitle}`;
  return `<div class="wgx-peer-card permission-mini-card" title="${attrEsc(title)}" style="height:136px;display:grid;grid-template-rows:44px 1fr 34px;border:1px solid #e5e7eb;background:#ffffff;border-radius:14px;padding:12px 13px;box-shadow:0 5px 14px rgba(15,23,42,.045);min-width:0;overflow:visible;box-sizing:border-box;">
    <div class="wgx-peer-head" style="display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:start;width:100%;min-width:0;overflow:hidden;">
      <div class="wgx-peer-title" style="min-width:0;display:block;overflow:hidden;text-align:left;">
        <div class="wgx-peer-remark" style="display:block!important;color:#111827!important;font-size:15px!important;font-weight:950!important;line-height:18px!important;height:18px!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;text-align:left!important;visibility:visible!important;opacity:1!important;">${esc(owner)}</div>
        <div class="wgx-peer-name" style="display:block!important;color:#64748b!important;font-size:12px!important;font-weight:850!important;line-height:15px!important;height:15px!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;text-align:left!important;visibility:visible!important;opacity:1!important;margin-top:3px!important;">${esc(name)}</div>
      </div>
      <span class="badge-soft" style="max-width:92px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(ip)}</span>
    </div>
    <div class="wgx-peer-mid" title="${attrEsc(accessTitle)}" style="align-self:center;display:block;color:#0f172a;font-size:13px;font-weight:950;line-height:18px;text-align:left;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;max-width:100%;">${esc(access)}</div>
    <div class="wgx-peer-actions" style="display:flex;justify-content:flex-end;align-items:end;overflow:visible;">${action}</div>
  </div>`;
}
function permissionMatches(p,q){
  if(!q)return true;
  const access=accessSummary(p);
  const title=String(p.access_detail_title||access||'');
  const text=[p.name,p.owner,p.vpn_ip,p.allowed_ips,access,title].join(' ').toLowerCase();
  return text.includes(q.toLowerCase());
}
function renderPermissions(users){
  if(typeof permissionBody==='undefined')return;
  const pq=(document.getElementById('permissionSearch')?.value||'').trim();
  const all=(users||[]).slice().sort((a,b)=>String(a.owner||'').localeCompare(String(b.owner||''),'zh-Hans-CN')||String(a.name||'').localeCompare(String(b.name||''),'zh-Hans-CN'));
  const list=all.filter(p=>permissionMatches(p,pq));
  const needMore=!pq && list.length>LIST_LIMIT;
  const visible=needMore&&!listExpanded.permission?list.slice(0,LIST_LIMIT):list;
  if(typeof permissionCount!=='undefined')permissionCount.innerText=pq?`(${list.length}/${all.length})`:`(${all.length})`;
  if(typeof permissionSearchHint!=='undefined')permissionSearchHint.innerText=pq?`匹配 ${list.length} 个用户`:'';
  updateViewButtons('permission');
  const permTable=document.getElementById('permissionTableWrap'),permCards=document.getElementById('permissionCardBoard');
  const permIsCard=viewMode.permission==='card';
  if(permTable)permTable.style.display=permIsCard?'none':''; if(permCards)permCards.style.display=permIsCard?'grid':'none';
  permissionBody.innerHTML=visible.length?visible.map(p=>{const access=accessSummary(p);const accessTitle=String(p.access_detail_title||access);const owner=ownerName(p);return `<tr data-user="${attrEsc(p.name)}"><td class="name"><span class="node-name" title="${esc(p.name)}">${esc(p.name)}</span><span class="detail-small">${esc(p.vpn_ip||'-')}</span></td><td><span class="owner-text" title="${esc(owner)}">${esc(owner)}</span></td><td><span class="access-text" title="${attrEsc(accessTitle)}">${esc(access)}</span></td><td class="actions-cell">${permissionActionHtml(p,'row')}</td></tr>`}).join(''):`<tr><td colspan="4" class="empty">${pq?'没有匹配的权限记录':'暂无用户节点'}</td></tr>`;
  if(permCards)permCards.innerHTML=visible.length?visible.map(permissionCardHtml).join(''):`<div class="empty">${pq?'没有匹配的权限记录':'暂无用户节点'}</div>`;
  if(typeof permissionMoreBox!=='undefined'){
    permissionMoreBox.style.display=needMore?'flex':'none';
    permissionMoreBtn.innerText=listExpanded.permission?`收起，仅显示前 ${LIST_LIMIT} 个`:`展开更多（还有 ${list.length-LIST_LIMIT} 个）`;
  }
}
function menuIsOpen(){return !!document.querySelector('.menu.open')}
function modalIsOpen(){return document.getElementById('modal')?.style.display==='flex'}
function nowTimeText(){const d=new Date();return d.toLocaleTimeString('zh-CN',{hour12:false})}
async function loadPeers(silent=false){
  if(!silent && typeof peerRefreshText!=='undefined')peerRefreshText.innerText='正在刷新状态...';
  const data=await api('/api/peers');
  allPeers=data.peers||[];
  renderPeers();
  if(typeof peerRefreshText!=='undefined')peerRefreshText.innerText=`更新 ${nowTimeText()}`;
}
async function manualRefreshPeers(){
  try{await loadPeers(false);toast('节点状态已刷新','ok')}catch(e){toast('节点状态刷新失败','err')}
}
async function addUser(){let name=userName.value.trim();let owner=(typeof userOwner!=='undefined'?(userOwner.value||'').trim():'');if(!name){toast('请输入用户名','warn');return}await api('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,owner})});userName.value='';if(typeof userOwner!=='undefined')userOwner.value='';await loadPeers();toast('用户已创建','ok')}
async function addSite(){let name=siteName.value.trim(),lan_cidr=siteLan.value.trim(),lan_if=siteIf.value.trim(),remark=(typeof siteRemark!=='undefined'?(siteRemark.value||'').trim():'');if(!name){toast('请输入站点名称','warn');return}if(/[，;；\n\r\t]/.test(lan_cidr)){toast('请使用英文逗号分隔网段','warn');return}const r=await api('/api/sites',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,lan_cidr,lan_if,remark})});siteName.value=siteLan.value=siteIf.value='';if(typeof siteRemark!=='undefined')siteRemark.value='';await loadPeers();await loadApplyStatus();toast('站点已创建，请应用配置','warn');if(confirm('站点已创建，是否应用配置？')){await applyConfig();}}
async function delPeer(type,name){if(!confirm(`确认删除${typeCn(type)}：${name}？`))return;await api(`/api/peers/${type}/${enc(name)}`,{method:'DELETE'});await loadPeers();await loadApplyStatus();toast(type==='site'?'站点已删除，请应用配置':'节点已删除',type==='site'?'warn':'ok')}
async function showConf(type,name){let conf=await api(`/api/conf/${type}/${enc(name)}`);modalTitle.innerText=`${typeCn(type)}节点 ${name} 配置`;modalBody.innerHTML=`<div class="log-actions"><button onclick="downloadConf('${type}','${name}')">下载配置</button></div><pre id="confPre">${esc(conf)}</pre>`;modal.style.display='flex'}
function copyModalPre(){const el=document.getElementById('confPre');if(!el)return;navigator.clipboard.writeText(el.innerText||'').then(()=>toast('已复制配置','ok')).catch(()=>toast('复制失败，请手动选择复制','err'))}
function downloadConf(type,name){window.open(`/api/conf/${type}/${enc(name)}/download`,'_blank')}
function downloadSitePackage(name){window.open(`/api/site-package/${enc(name)}/download`,'_blank')}

function editUserOwner(name){
  const peer=(allPeers||[]).find(p=>p.type==='user'&&p.name===name)||{};
  const owner=peer.owner||'';
  modalTitle.innerText=`设置归属人：${name}`;
  modalBody.innerHTML=`<div class="tips">用于分组和搜索。</div><input id="ownerInput" style="width:100%;margin-top:12px" value="${attrEsc(owner)}" placeholder="归属人"><div class="log-actions"><button onclick="saveUserOwner('${jsArg(name)}')">保存</button><button class="btn-gray" onclick="closeModal()">取消</button></div>`;
  modal.style.display='flex';
  setTimeout(()=>document.getElementById('ownerInput')?.focus(),30);
}

async function saveUserOwner(name){
  const owner=(document.getElementById('ownerInput')?.value||'').trim();
  await api(`/api/users/${enc(name)}/owner`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({owner})});
  closeModal();
  await loadPeers(true);
  toast(owner?`已设置归属人：${owner}`:'已清空归属人','ok');
}


function togglePermissionSelectAll(checked){document.querySelectorAll('.perm-user-check').forEach(cb=>cb.checked=!!checked)}
function selectedPermissionUsers(){return [...document.querySelectorAll('.perm-user-check')].filter(cb=>cb.checked).map(cb=>cb.value)}
function userCheckboxListHtml(selected=new Set()){
  const users=(allPeers||[]).filter(p=>p.type==='user').sort(peerSort);
  return users.length?users.map(u=>{const title=u.name||'';const sub=`${u.owner||'未设置归属人'} · ${u.vpn_ip||u.ip||'-'}`;const checked=selected.has(u.name)?'checked':'';return `<label class="perm-card" title="${attrEsc(title+'\n'+sub)}"><input type="checkbox" class="bulk-user" value="${attrEsc(u.name)}" ${checked}><span class="perm-card-main"><span class="perm-card-title">${esc(title)}</span><span class="perm-card-sub">${esc(sub)}</span></span></label>`}).join(''):'<div class="empty">暂无用户</div>';
}
function siteCheckboxListHtml(selected=new Set(), disabled=false){
  const sites=(allPeers||[]).filter(p=>p.type==='site').sort(peerSort);
  return sites.length?sites.map(s=>{const lans=(s.lan_ips||s.allowed_ips||'').split(',').map(x=>x.trim()).filter(x=>x&&!x.startsWith('10.9.')).join(', ')||'-';const label=(s.remark||'').trim()||s.name;const sub=(s.remark||'').trim()?s.name:'站点';const checked=selected.has(s.name)?'checked':'';return `<label class="perm-card" title="${attrEsc((label||'')+'\n'+(s.name||'')+'\n'+lans)}"><input type="checkbox" class="bulk-site" value="${attrEsc(s.name)}" ${checked} ${disabled?'disabled':''}><span class="perm-card-main"><span class="perm-card-title">${esc(label)}</span><span class="perm-card-sub">${esc(sub)}</span></span></label>`}).join(''):'<div class="empty">暂无站点</div>';
}
function filterPermGrid(inputId,gridId){const q=(document.getElementById(inputId)?.value||'').trim().toLowerCase();document.querySelectorAll(`#${gridId} .perm-card`).forEach(el=>{el.style.display=(!q||(el.innerText||'').toLowerCase().includes(q))?'flex':'none'})}
function openBulkAccess(){
  modalTitle.innerText='批量授权';
  const selected=new Set(selectedPermissionUsers());
  modalBody.innerHTML=`<div class="tips">选择用户和站点。</div>
    <div class="perm-step"><div class="perm-head-row"><div class="perm-step-title">1. 选择用户</div><div class="perm-step-meta"><span id="bulkUserSelectedText">已选择 0 个用户</span><label class="perm-select-all"><input type="checkbox" onchange="document.querySelectorAll('.bulk-user').forEach(cb=>cb.checked=this.checked);updateBulkSelectedText()"> 全选/全不选</label></div></div><div id="bulkUserGrid" class="perm-grid" onchange="updateBulkSelectedText()">${userCheckboxListHtml(selected)}</div></div>
    <div class="perm-step"><div class="perm-head-row"><div class="perm-step-title">2. 选择操作</div></div><div class="perm-action-list"><label><input type="radio" name="bulkAction" value="add" checked onchange="toggleBulkMode()"><span class="perm-action-text">添加站点权限</span></label><label><input type="radio" name="bulkAction" value="remove" onchange="toggleBulkMode()"><span class="perm-action-text">移除站点权限</span></label><label><input type="radio" name="bulkAction" value="set_custom" onchange="toggleBulkMode()"><span class="perm-action-text">覆盖为指定站点</span></label><label><input type="radio" name="bulkAction" value="set_all" onchange="toggleBulkMode()"><span class="perm-action-text">覆盖为全部站点</span></label></div></div>
    <div class="perm-step" id="bulkSiteStep"><div class="perm-head-row"><div class="perm-step-title">3. 选择站点</div><div class="perm-step-meta"><span id="bulkSiteSelectedText">已选择 0 个站点</span><label class="perm-select-all"><input type="checkbox" onchange="document.querySelectorAll('.bulk-site:not(:disabled)').forEach(cb=>cb.checked=this.checked);updateBulkSelectedText()"> 全选/全不选</label></div></div><div id="bulkSiteGrid" class="perm-grid compact" onchange="updateBulkSelectedText()">${siteCheckboxListHtml()}</div><div class="tips" id="bulkZeroTip"></div></div>
    <div class="tips">保存后请应用配置。</div>
    <div class="log-actions"><button class="btn-theme" onclick="saveBulkAccess()">保存批量授权</button><button class="btn-gray" onclick="closeModal()">取消</button></div>`;
  modal.style.display='flex';
  toggleBulkMode();
  updateBulkSelectedText();
}
function updateBulkSelectedText(){const u=document.querySelectorAll('.bulk-user:checked').length;const s=document.querySelectorAll('.bulk-site:checked:not(:disabled)').length;const ut=document.getElementById('bulkUserSelectedText');const st=document.getElementById('bulkSiteSelectedText');if(ut)ut.innerText=`已选择 ${u} 个用户`;if(st)st.innerText=`已选择 ${s} 个站点`;}
function toggleBulkMode(){const action=document.querySelector('input[name="bulkAction"]:checked')?.value||'add';const disabled=action==='set_all';document.querySelectorAll('.bulk-site').forEach(cb=>{cb.disabled=disabled});const tip=document.getElementById('bulkZeroTip');if(tip)tip.innerText=action==='set_custom'?'可不选择任何站点，表示覆盖为 0 个站点权限。':(action==='set_all'?'全部站点模式不需要选择站点。':'请选择要添加或移除的站点。');updateBulkSelectedText()}
async function saveBulkAccess(){
  const users=[...document.querySelectorAll('.bulk-user')].filter(cb=>cb.checked).map(cb=>cb.value);
  if(!users.length){toast('请先选择需要修改权限的用户','warn');return}
  const action=document.querySelector('input[name="bulkAction"]:checked')?.value||'add';
  const sites=[...document.querySelectorAll('.bulk-site')].filter(cb=>cb.checked&&!cb.disabled).map(cb=>cb.value);
  if((action==='add'||action==='remove')&&!sites.length){toast('请选择要添加或移除的站点','warn');return}
  const r=await api('/api/permissions/bulk',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({users,action,sites})});
  closeModal();
  await loadPeers(true);await loadAllowedIPsStatus();await loadApplyStatus();
  toast(`批量授权已保存：${r.changed||0}/${r.total||0}`, 'ok');
}
function openSiteAuthorization(){
  const sites=(allPeers||[]).filter(p=>p.type==='site').sort(peerSort);
  if(!sites.length){toast('暂无站点','warn');return}
  modalTitle.innerText='站点授权';
  modalBody.innerHTML=`<div class="tips">选择可访问该站点的用户。</div><select id="authSiteSelect" style="width:100%;height:38px;margin-top:10px" onchange="loadSiteAuthorizationUsers()">${sites.map(s=>`<option value="${attrEsc(s.name)}">${esc(s.name)}</option>`).join('')}</select><div class="perm-step"><div class="perm-head-row"><div class="perm-step-title">选择用户</div><div class="perm-step-meta"><span id="authUserSelectedText">已选择 0 个用户</span><label class="perm-select-all"><input type="checkbox" onchange="document.querySelectorAll('.auth-user').forEach(cb=>cb.checked=this.checked);updateAuthSelectedText()"> 全选/全不选</label></div></div><div id="authUserBox" class="perm-grid" onchange="updateAuthSelectedText()"><span class="small-muted">读取中...</span></div></div><div class="tips">保存后请应用配置。</div><div class="log-actions"><button class="btn-theme" onclick="saveSiteAuthorization()">保存站点授权</button><button class="btn-gray" onclick="closeModal()">取消</button></div>`;
  modal.style.display='flex';
  loadSiteAuthorizationUsers();
}
async function loadSiteAuthorizationUsers(){
  const site=document.getElementById('authSiteSelect')?.value||'';if(!site)return;
  const box=document.getElementById('authUserBox');box.innerHTML='<span class="small-muted">读取中...</span>';
  const r=await api(`/api/sites/${enc(site)}/authorized-users`);
  const users=r.users||[];
  box.innerHTML=users.length?users.map(u=>{const sub=`${u.owner||'未设置归属人'} · ${u.vpn_ip||'-'}`;return `<label class="perm-card" title="${attrEsc((u.name||'')+'\n'+sub)}"><input type="checkbox" class="auth-user" value="${attrEsc(u.name)}" ${u.authorized?'checked':''}><span class="perm-card-main"><span class="perm-card-title">${esc(u.name)}</span><span class="perm-card-sub">${esc(sub)}</span></span></label>`}).join(''):'<div class="empty">暂无用户</div>';
  updateAuthSelectedText();
}
function updateAuthSelectedText(){const n=document.querySelectorAll('.auth-user:checked').length;const t=document.getElementById('authUserSelectedText');if(t)t.innerText=`已选择 ${n} 个用户`;}
async function saveSiteAuthorization(){
  const site=document.getElementById('authSiteSelect')?.value||'';
  const users=[...document.querySelectorAll('.auth-user')].filter(cb=>cb.checked).map(cb=>cb.value);
  const r=await api(`/api/sites/${enc(site)}/authorized-users`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({users})});
  closeModal();
  await loadPeers(true);await loadAllowedIPsStatus();await loadApplyStatus();
  toast(`站点授权已保存：${users.length} 个用户`, 'ok');
}

async function editUserAccess(name){
  try{
    const r=await api(`/api/users/${enc(name)}/site-permissions`);
    const selected=new Set(r.selected_sites||[]);
    const allChecked=(r.mode||'all')==='all';
    const siteRows=(r.sites||[]).length?(r.sites||[]).map(s=>{
      const checked=allChecked||selected.has(s.name)?'checked':'';
      const disabled=allChecked?'disabled':'';
      const lans=(s.lan_cidrs||[]).join(', ')||'-';
      const label=(s.remark||'').trim()||s.name;
      const sub=(s.remark||'').trim()?s.name:'站点';
      return `<label class="perm-card" title="${attrEsc((label||'')+'\n'+(s.name||'')+'\n'+lans)}"><input type="checkbox" class="access-site" value="${attrEsc(s.name)}" ${checked} ${disabled}><span class="perm-card-main"><span class="perm-card-title">${esc(label)}</span><span class="perm-card-sub">${esc(sub)}</span></span></label>`;
    }).join(''):'<div class="empty">暂无站点</div>';
    modalTitle.innerText=`用户 ${name} 访问权限`;
    modalBody.innerHTML=`<div class="tips">保存后请同步网段并应用配置。</div>
      <label style="display:block;margin:12px 0"><input type="radio" name="accessMode" value="all" ${allChecked?'checked':''} onchange="toggleAccessMode()"> 允许访问全部站点</label>
      <label style="display:block;margin:12px 0"><input type="radio" name="accessMode" value="custom" ${!allChecked?'checked':''} onchange="toggleAccessMode()"> 只允许访问指定站点</label>
      <div id="accessSiteBox" class="perm-grid compact" style="margin-top:8px">${siteRows}</div>
      <div class="tips">保存后请应用配置。</div>
      <div class="log-actions"><button onclick="saveUserAccess('${jsArg(name)}')">保存权限</button><button class="btn-gray" onclick="closeModal()">取消</button></div>`;
    modal.style.display='flex';
    toggleAccessMode();
  }catch(e){toast('读取访问权限失败：'+(e.message||e),'err',5200)}
}
function toggleAccessMode(){
  const mode=document.querySelector('input[name="accessMode"]:checked')?.value||'all';
  document.querySelectorAll('.access-site').forEach(cb=>{cb.disabled=mode==='all';if(mode==='all')cb.checked=true});
}
async function saveUserAccess(name){
  const mode=document.querySelector('input[name="accessMode"]:checked')?.value||'all';
  const sites=[...document.querySelectorAll('.access-site')].filter(cb=>cb.checked&&!cb.disabled).map(cb=>cb.value);
  const r=await api(`/api/users/${enc(name)}/site-permissions`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mode,sites})});
  closeModal();
  await loadPeers(true);
  await loadAllowedIPsStatus();
  toast('访问权限已保存，请应用配置', 'ok');
}

async function editSiteRemark(name){
  const peer=(allPeers||[]).find(p=>p.type==='site'&&p.name===name)||{};
  modalTitle.innerText=`站点 ${name} 备注`;
  modalBody.innerHTML=`<div class="tips">用于显示和搜索。</div><textarea id="siteRemarkInput" style="width:100%;min-height:120px;margin-top:12px" maxlength="200" placeholder="备注">${esc(peer.remark||'')}</textarea><div class="log-actions"><button onclick="saveSiteRemark('${jsArg(name)}')">保存备注</button><button class="btn-gray" onclick="closeModal()">取消</button></div>`;
  modal.style.display='flex';
  setTimeout(()=>document.getElementById('siteRemarkInput')?.focus(),80);
}

async function saveSiteRemark(name){
  const el=document.getElementById('siteRemarkInput');
  if(!el)return;
  const remark=(el.value||'').trim();
  try{
    await api(`/api/sites/${enc(name)}/remark`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({remark})});
    closeModal();
    await loadPeers(true);
    toast(remark?'站点备注已保存':'站点备注已清空','ok');
  }catch(e){
    toast('保存站点备注失败：'+(e.message||e),'err',5200);
  }
}

async function editSiteNetworks(name){
  try{
    const r=await api(`/api/sites/${enc(name)}/networks`);
    modalTitle.innerText=`站点 ${name} 内网网段`;
    modalBody.innerHTML=`<div class="tips">可空；每行一个网段。</div><textarea id="siteNetworksInput" style="width:100%;min-height:150px;margin-top:12px" placeholder="内网网段，可空">${esc((r.lan_cidrs||[]).join('\n'))}</textarea><div class="log-actions"><button onclick="saveSiteNetworks('${esc(name)}')">保存网段</button><button class="btn-gray" onclick="closeModal()">取消</button></div><div class="tips">VPN IP：${esc(r.vpn_ip||'-')}</div>`;
    modal.style.display='flex';
  }catch(e){
    toast('读取站点网段失败：'+(e.message||e),'err',4200);
  }
}

async function saveSiteNetworks(name){
  const el=document.getElementById('siteNetworksInput');
  if(!el)return;
  const lan_cidr=(el.value||'').split(/\n+/).map(x=>x.trim()).filter(Boolean).join(',');
  if(/[，;；\t]/.test(lan_cidr)){toast('多个网段只支持英文逗号或换行分隔','warn');return}
  try{
    const r=await api(`/api/sites/${enc(name)}/networks`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({lan_cidr})});
    closeModal();
    await loadPeers();
    await loadAllowedIPsStatus();
    await loadApplyStatus();
    toast(r.changed?'站点网段已保存，请应用配置':'站点网段无变化',r.changed?'warn':'ok');
    if(r.sync&&Number(r.sync.need_update||0)>0){
      toast(`有 ${r.sync.need_update} 个用户配置还未包含最新站点网段；需要时请使用“一键同步 AllowedIPs”`, 'warn', 5200);
    }
  }catch(e){
    toast('保存站点网段失败：'+(e.message||e),'err',6200);
  }
}


function renderCleanup(data){
  const count=Number(data.count||0);
  const bytes=Number(data.bytes||0);
  const mb=(bytes/1024/1024).toFixed(2);
  const cc=document.getElementById('cleanupCount'); if(cc)cc.innerText=`${count} 项`;
  const cb=document.getElementById('cleanupBytes'); if(cb)cb.innerText=`${mb} MB`;
  const cs=document.getElementById('cleanupSummary'); if(cs)cs.innerText=data.deleted?'已清理':`${count} 项 / ${mb} MB`;
  const cp=document.getElementById('cleanupPolicy');
  if(cp&&data.policy){cp.innerText=`备份保留 ${data.policy.backup_keep} 个 · 日志保留 ${data.policy.log_keep_days} 天`;}
  const hint=document.getElementById('cleanupHint');
  if(hint){
    if(data.deleted){const ok=(data.deleted||[]).filter(x=>x.ok).length;hint.innerText=`清理完成：成功 ${ok} 项，失败 ${(data.deleted||[]).length-ok} 项。`;}
    else hint.innerText=`扫描完成：可清理 ${count} 项，约 ${mb} MB。点击“一键安全清理”执行。`;
  }
}
async function previewCleanup(){try{const data=await api('/api/cleanup/preview');renderCleanup(data);toast('清理预览已生成','ok')}catch(e){toast('清理预览失败：'+e.message,'err')}}
async function applyCleanup(){if(!confirm('确认执行安全清理？\n会按保留策略删除旧备份、旧日志、旧发布包，不会删除当前配置和当前 WireGuard 配置。'))return;try{const data=await api('/api/cleanup/apply',{method:'POST'});renderCleanup(data);toast('安全清理完成','ok')}catch(e){toast('安全清理失败：'+e.message,'err')}}

function downloadReleasePackage(kind){
  const allowed=['full','uninstaller'];
  if(!allowed.includes(kind)){toast('下载类型错误','err');return}
  window.open(`/api/packages/download/${encodeURIComponent(kind)}`,'_blank');
}

function showQr(type,name){modalTitle.innerText=`${typeCn(type)}节点 ${name} 二维码`;modalBody.innerHTML=`<img class="qr-img" src="/api/qr/${type}/${enc(name)}?t=${Date.now()}" onerror="this.outerHTML='<div class=&quot;empty&quot;>配置文件不存在，无法生成二维码</div>'">`;modal.style.display='flex'}
function closeModal(){modal.style.display='none'}

let uploadedPackage='';
function renderPrecheck(pre){if(!pre){precheckLog.innerText='暂无预检结果';return}const lines=[];lines.push(pre.ok?'✅ 升级包预检通过':'❌ 升级包预检未通过');lines.push(`文件：${pre.filename||pre.package||''}`);for(const c of (pre.checks||[])){lines.push(`${c.ok?'✅':'❌'} ${c.name}：${c.message}`)}precheckLog.innerText=lines.join('\n');}
async function loadUpgradeInfo(){
  try{
    const info=await api('/api/upgrade/info');
    renderBackupInfo(info);
    versionText.innerText=info.version||'未知版本'; if(typeof footerVersion!=='undefined')footerVersion.innerText=info.version||'未知版本';
    const st=await api('/api/upgrade/status');
    if(typeof upgradeStatusText!=='undefined'){const statusText={running:'升级中',success:'已完成',failed:'失败'}[st.status]||st.status;upgradeStatusText.innerText=st.status&&st.status!=='idle'?` · ${statusText}${st.status==='running'&&st.step?'：'+st.step:''}`:''}
    if(info.upgrade_running){
      btnStartUpgrade.disabled=true;
      upgradePkgText.innerText=st.message||'升级任务正在后台运行，页面可能会短暂断开，稍后刷新即可。';
      if(typeof runtimeLog!=='undefined')loadLog('upgrade');
    }else if(st.status==='success'){
      upgradePkgText.innerText=st.message||'最近一次升级已完成';
    }else if(st.status==='failed'){
      upgradePkgText.innerText=st.message||'最近一次升级失败，已尝试自动回滚，请查看升级日志';
    }
  }catch(e){}
}

function renderBackupInfo(info){
  const sum=document.getElementById('backupSummary');
  const list=document.getElementById('backupList');
  const backups=(info&&info.backups)||[];
  if(sum)sum.innerText=info&&info.backup_summary?info.backup_summary:`当前 ${backups.length} 个`;
  if(!list)return;
  if(!backups.length){list.innerHTML='<div class="mini-empty">暂无 WebUI 备份</div>';return}
  list.innerHTML=backups.slice(0,12).map(b=>`<div class="backup-item"><div><div class="backup-name">${esc(b.name)}</div><div class="backup-meta">${esc(b.path||'')} · ${esc(b.size_human||'')}</div></div><div class="system-actions"><button class="btn-gray" onclick="downloadBackup('${esc(b.name)}')">下载</button><button onclick="restoreBackup('${esc(b.name)}')">恢复</button><button class="btn-red" onclick="deleteBackup('${esc(b.name)}')">删除</button></div></div>`).join('');
}
async function createBackup(){
  if(!confirm('确认立即创建 WebUI 备份？'))return;
  const r=await api('/api/backups/create',{method:'POST'});
  toast('备份已创建：'+(r.name||''),'ok');
  await loadUpgradeInfo();
}
function downloadBackup(name){location.href='/api/backups/download/'+encodeURIComponent(name)}
async function deleteBackup(name){
  if(!confirm('确认删除备份 '+name+'？'))return;
  await api('/api/backups/'+encodeURIComponent(name),{method:'DELETE'});
  toast('备份已删除','ok');
  await loadUpgradeInfo();
}
async function restoreBackup(name){
  const confirmText=prompt('恢复会覆盖 WebUI 程序目录，不会主动重启 wg-quick@wg0。\n请输入 RESTORE-WEBUI 确认恢复：');
  if(confirmText!=='RESTORE-WEBUI'){toast('已取消恢复','info');return}
  const r=await api('/api/backups/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,confirm:'RESTORE-WEBUI'})});
  toast(r.message||'恢复完成，请刷新页面或重启 wg-webui','ok',6000);
}
async function uploadUpgrade(){
  const f=upgradeFile.files[0];
  if(!f){toast('请选择升级包','warn');return}
  if(!confirm('确认上传升级包？上传不会影响 WireGuard，只有点击开始升级后才会升级 WebUI。'))return;
  const fd=new FormData();fd.append('file',f);
  const r=await api('/api/upgrade/upload',{method:'POST',body:fd});
  uploadedPackage=r.package;
  renderPrecheck(r.precheck);
  btnStartUpgrade.disabled=!r.ok;
  upgradePkgText.innerText=r.ok?`已上传并预检通过：${r.filename}`:`已上传但预检未通过：${r.filename}`;
  await loadUpgradeInfo();
  toast(r.ok?'升级包上传成功':'升级包预检未通过', r.ok?'ok':'err');
}
async function startUpgrade(){
  if(!uploadedPackage){toast('请先上传升级包','warn');return}
  const pre=await api('/api/upgrade/precheck',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package:uploadedPackage})});
  renderPrecheck(pre);
  if(!pre.ok){btnStartUpgrade.disabled=true;toast('升级包预检未通过，不能开始升级','err');return}
  if(!confirm('预检已通过。确认开始升级 WebUI？升级过程不会停止 WireGuard 隧道，页面可能会短暂断开。'))return;
  await api('/api/upgrade/start',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({package:uploadedPackage})});
  btnStartUpgrade.disabled=true;
  upgradePkgText.innerText='升级任务已启动。升级完成后会返回登录界面。';
  toast('升级任务已启动，完成后请重新登录','ok',5200);
  setTimeout(loadUpgradeInfo,2000);
  setTimeout(()=>loadLog('upgrade'),2500);
  setTimeout(()=>forceLogin('upgraded'),9000);
}

let reservedNetworks=[];
function renderReservedNetworks(data){
  reservedNetworks=(data&&data.reserved_client_allowed_ips)||[];
  if(typeof reservedSummary!=='undefined')reservedSummary.innerText=reservedNetworks.length?`${reservedNetworks.length} 个：${reservedNetworks.join(', ')}`:'未配置';
  if(typeof reservedList!=='undefined')reservedList.innerHTML=reservedNetworks.length?reservedNetworks.map((n,i)=>`<span class="reserved-chip">${esc(n)} <button onclick="removeReservedNetwork(${i})">删除</button></span>`).join(''):'<span class="small-muted">暂无本地/保留网段。首次安装或新增本地网段时在这里添加。</span>';
  if(typeof reservedMeta!=='undefined')reservedMeta.innerText=`配置文件：${(data&&data.config_file)||'/etc/wg-webui/config.json'} · 最终 AllowedIPs：${(data&&data.final_allowed_ips)||'-'}`;
  const conflicts=(data&&data.conflicts)||[];
  if(typeof reservedWarn!=='undefined'){
    if(conflicts.length){reservedWarn.style.display='block';reservedWarn.innerText='提示：以下保留网段和站点网段重叠：'+conflicts.map(c=>`${c.reserved} ↔ ${c.site_lan}`).join('； ')}
    else{reservedWarn.style.display='none';reservedWarn.innerText=''}
  }
}
async function loadReservedNetworks(){try{const r=await api('/api/settings/reserved-networks');renderReservedNetworks(r)}catch(e){if(typeof reservedSummary!=='undefined')reservedSummary.innerText='读取失败'}}
function addReservedNetwork(){const raw=(reservedInput.value||'').trim();if(!raw){toast('请输入网段','warn');return}for(const n of raw.split(',')){const v=n.trim();if(v && !reservedNetworks.includes(v))reservedNetworks.push(v)}reservedInput.value='';renderReservedNetworks({reserved_client_allowed_ips:reservedNetworks,config_file:'/etc/wg-webui/config.json'});}
function removeReservedNetwork(i){reservedNetworks.splice(i,1);renderReservedNetworks({reserved_client_allowed_ips:reservedNetworks,config_file:'/etc/wg-webui/config.json'});}
async function saveReservedNetworks(){
  try{
    const r=await api('/api/settings/reserved-networks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({reserved_client_allowed_ips:reservedNetworks,sync:false})});
    renderReservedNetworks(r);
    await loadAllowedIPsStatus();
    await loadApplyStatus();
    toast('已保存本地/保留网段；如需同步用户配置和刷新服务端，请点击顶部“应用配置”','ok',5200);
  }catch(e){toast('保存失败：'+(e.message||e),'err',5200)}
}

const SETTINGS_CRITICAL_FIELDS=['server_endpoint','wg_if','wg_cidr','site_ip_start','site_ip_end','user_ip_start','user_ip_end'];
const SETTINGS_TEXT_FIELDS=['server_endpoint','client_dns','wg_if','wg_cidr'];
const SETTINGS_LIST_FIELDS=['reserved_client_allowed_ips'];
const SETTINGS_INT_FIELDS=['online_threshold_seconds','site_ip_start','site_ip_end','user_ip_start','user_ip_end','login_max_attempts','login_window_seconds','login_lockout_seconds','backup_keep','webui_backup_keep','config_backup_keep','log_keep_days','package_keep'];
let systemSettingsCache={};
let accountSecurityCache={username:"", env_locked:false};
let advancedSettingsUnlocked=false;
function settingEl(name){return document.getElementById('set_'+name)}
function setSettingValue(name,value){const el=settingEl(name);if(!el)return;if(el.type==='checkbox')el.checked=!!value;else if(Array.isArray(value))el.value=value.join('\n');else el.value=value??''}
function splitSettingList(value){return String(value||'').split(/[\n,]+/).map(x=>x.trim()).filter(Boolean)}
function setText(id,value){const el=document.getElementById(id);if(el)el.innerText=value??'-'}
function setSessionMinutesFromSeconds(seconds){const el=document.getElementById('set_session_ttl_minutes');if(el)el.value=Math.max(5,Math.round(Number(seconds||1800)/60));}
function getSessionTtlSeconds(){const el=document.getElementById('set_session_ttl_minutes');return Math.max(300,Math.round(Number(el?.value||30))*60)}
function setAdvancedLocked(locked){
  advancedSettingsUnlocked=!locked;
  SETTINGS_CRITICAL_FIELDS.forEach(k=>{const el=settingEl(k);if(el)el.disabled=locked});
  const panel=document.getElementById('advancedSettingsPanel');
  if(panel)panel.classList.toggle('advanced-unlocked',!locked);
  const actions=document.getElementById('advancedActions');
  if(actions)actions.style.display=locked?'none':'flex';
  const btn=document.getElementById('btnUnlockAdvanced');
  if(btn)btn.style.display=locked?'inline-flex':'none';
  }
function renderCriticalViews(cfg){
  if(advancedSettingsUnlocked)return;
  SETTINGS_CRITICAL_FIELDS.forEach(k=>setSettingValue(k,cfg[k]));
  setAdvancedLocked(true);
}
async function loadSystemSettings(){
  try{
    const r=await api('/api/settings/config');
    const cfg=(r&&r.config)||{};
    systemSettingsCache=cfg;
    [...SETTINGS_TEXT_FIELDS,...SETTINGS_INT_FIELDS].forEach(k=>{if(!advancedSettingsUnlocked||!SETTINGS_CRITICAL_FIELDS.includes(k))setSettingValue(k,cfg[k])});
    setSessionMinutesFromSeconds(cfg.session_ttl_seconds||1800);
    const fixedRoutes=[...(cfg.client_allowed_ips||[]),...(cfg.reserved_client_allowed_ips||[])].filter((v,i,a)=>v&&a.indexOf(v)===i);
    setSettingValue('reserved_client_allowed_ips',fixedRoutes);
    renderCriticalViews(cfg);
    if(typeof settingsStatus!=='undefined')settingsStatus.innerText=`已读取 · ${cfg.config_file||''}`;
    if(typeof settingsHint!=='undefined'){
      const eff=cfg.effective||{};
      settingsHint.innerText=`当前生效：${eff.wg_if||cfg.wg_if||'wg0'} · ${eff.wg_conf||''}。日常配置保存后立即生效；固定下发网段变化后点击顶部“应用配置”同步客户端配置。`;
    }
  }catch(e){
    if(typeof settingsStatus!=='undefined')settingsStatus.innerText='读取失败';
  }
}
async function saveSystemSettings(){
  const data={};
  SETTINGS_TEXT_FIELDS.forEach(k=>{const el=settingEl(k);if(el&&!SETTINGS_CRITICAL_FIELDS.includes(k))data[k]=el.value.trim()});
  SETTINGS_LIST_FIELDS.forEach(k=>{const el=settingEl(k);if(el)data[k]=splitSettingList(el.value)});
  if('reserved_client_allowed_ips' in data)data.client_allowed_ips=[];
  SETTINGS_INT_FIELDS.forEach(k=>{const el=settingEl(k);if(el&&el.value!==''&&!SETTINGS_CRITICAL_FIELDS.includes(k))data[k]=Number(el.value)});
  if(document.getElementById('set_session_ttl_minutes'))data.session_ttl_seconds=getSessionTtlSeconds();
  const accountNeedSave=accountSecurityChanged();
  if(accountNeedSave&&!validateAccountSecurityInput())return;
  try{
    const r=await api('/api/settings/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    await loadSystemSettings();
    await loadApplyStatus();
    await loadAllowedIPsStatus();
    const changed=(r.changed||[]).length;
    let msg=changed?`已保存 ${changed} 项配置`:'配置无变化';
    if(r.apply_required)msg+='\n需要点击顶部“应用配置”刷新 WireGuard/客户端配置';
    if((r.runtime_updated||[]).length)msg+='\n安全配置已即时生效';
    if(accountNeedSave){
      toast(msg+'\n正在保存账号配置...','warn',3200);
      await saveAccountSecurity(true);
      return;
    }
    toast(msg,r.apply_required?'warn':'ok',7200);
  }catch(e){
    toast('保存系统配置失败：'+(e.message||e),'err',6200);
  }
}

async function saveCriticalPatch(patch){
  const r=await api('/api/settings/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...patch,confirm_critical:true})});
  closeModal();
  await loadSystemSettings();
  await loadApplyStatus();
  let msg='关键配置已保存';
  if(r.apply_required)msg+='\n请点击顶部“应用配置”刷新相关配置';
  toast(msg,'warn',6200);
}
function unlockAdvancedSettings(){
  if(!confirm('高级设置会影响 WireGuard 运行、客户端连接和地址分配。\n\n确认要解锁修改吗？'))return;
  setAdvancedLocked(false);
  toast('高级设置已解锁，修改后请点击“保存高级设置”','warn',4200);
}
function cancelAdvancedSettings(){
  renderCriticalViews(systemSettingsCache||{});
  setAdvancedLocked(true);
  toast('已取消高级设置修改','info');
}
async function saveAdvancedSettings(){
  const patch={};
  SETTINGS_CRITICAL_FIELDS.forEach(k=>{
    const el=settingEl(k);
    if(!el)return;
    patch[k]=SETTINGS_INT_FIELDS.includes(k)?Number(el.value):el.value.trim();
  });
  if(!confirm('确认保存高级设置？\n\n保存后可能需要点击“应用配置”或重启相关服务。'))return;
  const r=await api('/api/settings/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...patch,confirm_critical:true,skip_apply_pending:true})});
  await loadSystemSettings();
  let msg=(r.changed||[]).length?`高级设置已保存 ${r.changed.length} 项`:'高级设置无变化';
  msg+='\n配置仍保持解锁，可继续修改或点击旁边“重启 WebUI”生效';
  toast(msg,'ok',6200);
}

async function loadAccountSecurity(){
  try{
    const r=await api('/api/security/account');
    accountSecurityCache={username:r.username||'', env_locked:!!r.env_locked};
    if(typeof acct_username!=='undefined')acct_username.value=r.username||'';
    if(typeof accountStatus!=='undefined')accountStatus.innerText='已配置';
    if(typeof accountHint!=='undefined'){
      accountHint.innerText=r.env_locked?'账号由服务环境变量管理，不能在 WebUI 修改。':'账号修改后点击上方“保存配置”，保存成功后需要重新登录。';
      accountHint.className='tips';
    }
  }catch(e){
    if(typeof accountStatus!=='undefined')accountStatus.innerText='读取失败';
  }
}
function accountSecurityChanged(){
  const username=(acct_username?.value||'').trim();
  return username!==String(accountSecurityCache.username||'')||!!(acct_current_password?.value||acct_new_password?.value||acct_confirm_password?.value);
}
function validateAccountSecurityInput(){
  if(accountSecurityCache.env_locked){toast('账号由服务环境变量管理，不能在 WebUI 修改','warn');return false}
  const data={
    username:(acct_username?.value||'').trim(),
    current_password:acct_current_password?.value||'',
    new_password:acct_new_password?.value||'',
    confirm_password:acct_confirm_password?.value||''
  };
  if(!data.current_password||!data.new_password){toast('修改账号或密码时，需要填写当前密码和新密码','warn');return false}
  if(data.new_password.length<8){toast('新密码至少 8 位','warn');return false}
  if(data.new_password!==data.confirm_password){toast('两次输入的新密码不一致','warn');return false}
  return true;
}
async function saveAccountSecurity(fromUnified=false){
  if(!validateAccountSecurityInput())return false;
  const data={
    username:(acct_username?.value||'').trim(),
    current_password:acct_current_password?.value||'',
    new_password:acct_new_password?.value||'',
    confirm_password:acct_confirm_password?.value||''
  };
  try{
    const r=await api('/api/security/account',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});
    toast(r.message||'账号已更新，请重新登录','ok',5200);
    await api('/api/logout',{method:'POST'});
    setTimeout(()=>forceLogin('expired'),800);
    return true;
  }catch(e){
    toast('账号保存失败：'+(e.message||e),'err',6200);
    return false;
  }
}


async function loadAllowedIPsStatus(){
  try{
    const r=await api('/api/users/allowedips-status');
    const n=Number(r.need_update||0);
    if(typeof btnRefreshAllowedIPs!=='undefined'){
      btnRefreshAllowedIPs.disabled=n===0;
      btnRefreshAllowedIPs.innerText=n===0?'已同步':`按权限同步 ${n} 个用户`;
      btnRefreshAllowedIPs.title=n===0?'所有用户配置已符合当前访问权限':'发现用户配置与访问权限不一致，点击按权限同步';
    }
    if(typeof allowedSyncText!=='undefined'){
      allowedSyncText.innerText=n===0?'用户网段已按权限同步':`发现 ${n} 个用户需要按权限同步`;
    }
  }catch(e){
    if(typeof allowedSyncText!=='undefined')allowedSyncText.innerText='同步状态读取失败';
  }
}

async function syncUserAllowedIPs(name){
  if(!confirm(`确认同步用户 ${name} 的 AllowedIPs？\n\n会按该用户访问权限重新生成客户端网段，不会重启 WireGuard。`))return;
  try{
    const r=await api(`/api/users/${enc(name)}/refresh-allowedips`,{method:'POST'});
    const action=r.changed?'已同步':'无需更新';
    let msg=`${action}：${name}\n${r.message||''}`;
    if(r.allowed_ips)msg+=`\n当前网段：${r.allowed_ips}`;
    toast(msg,r.changed?'ok':'info',5200);
    await loadAllowedIPsStatus();
  }catch(e){
    toast(`同步失败：${name}`,'err',4200);
  }
}

async function refreshAllowedIPs(skipConfirm=false){
  if(!skipConfirm&&!confirm('确认按当前访问权限批量更新所有用户 AllowedIPs？会自动备份 /etc/wireguard/clients，不会影响正在运行的 WireGuard。'))return;
  const r=await api('/api/users/refresh-allowedips',{method:'POST'});
  let msg=`已按权限更新 ${r.updated} 个用户配置，服务端访问控制待应用`;
  if(r.backup)msg+=`\n备份目录：${r.backup}`;
  if((r.failed||[]).length)msg+=`\n失败：${r.failed.join('; ')}`;
  toast(msg,'ok',5200);
  await loadAllowedIPsStatus();
  await loadApplyStatus();
}

function setOpsActive(kind){
  document.querySelectorAll('[data-ops-tool]').forEach(btn=>{
    btn.classList.toggle('active', btn.dataset.opsTool===kind);
  });
}
function getRuntimeLogEl(){return document.getElementById('runtimeLog');}
function scrollRuntimeLog(){const el=getRuntimeLogEl();if(el&&document.getElementById('logAutoScroll')?.checked)el.scrollTop=el.scrollHeight;}

async function runDoctorPanel(){
  setOpsActive('doctor');
  const el=getRuntimeLogEl();
  if(el)el.innerText='正在执行一键诊断，请稍等...';
  try{
    const r=await api('/api/doctor/run',{method:'POST'});
    const title=r.ok?'一键诊断完成：未发现阻断性问题':'一键诊断完成：发现需要处理的问题';
    if(el){
      el.innerText=`${title}\n返回码：${r.returncode}\n\n${r.output||'无输出'}`;
      scrollRuntimeLog();
    }
    toast(r.ok?'诊断完成':'诊断发现异常，请查看结果',r.ok?'ok':'warn',4200);
  }catch(e){
    if(el)el.innerText='一键诊断执行失败：'+e.message;
  }
}
async function loadOps(kind){
  setOpsActive(kind);
  const name={service:'服务状态',network:'路由 / 转发检查',commands:'快捷指令'}[kind]||'运维信息';
  const el=getRuntimeLogEl();
  if(el)el.innerText=`正在读取 ${name}...`;
  try{
    const text=await api(`/api/ops/${kind}`);
    if(el){
      el.innerText=text||'无输出';
      scrollRuntimeLog();
    }
  }catch(e){
    if(el)el.innerText=`读取 ${name} 失败：${e.message}`;
  }
}


function showPingTool(){
  setOpsActive('ping');
  const el=getRuntimeLogEl();
  if(!el)return;
  el.innerHTML=`<div class="ops-net-tool">
    <div class="ops-net-form ops-ping-port-form">
      <label>目标 IP / 域名<input id="opsPingTarget" placeholder="例如 10.8.0.2、192.168.1.1、example.com" onkeydown="if(event.key==='Enter')runOpsNetworkTest()"></label>
      <label>TCP 端口<input id="opsPortList" placeholder="例如 22,80,443 或 8000-8010" onkeydown="if(event.key==='Enter')runOpsNetworkTest()"></label>
      <label>Ping 模式<select id="opsPingCount"><option value="1">快速：1 包</option><option value="2">普通：2 包</option><option value="4">完整：4 包</option></select></label>
      <div class="ops-net-checks">
        <label><input type="checkbox" id="opsDoPing" checked> Ping</label>
        <label><input type="checkbox" id="opsDoPorts" checked> 端口</label>
      </div>
      <button class="btn-primary" onclick="runOpsNetworkTest()">开始检测</button>
    </div>
    <div class="ops-ping-tip">这里只做单个 IP / 域名检测。Ping 默认 1 包快速返回；端口检测使用 TCP 连接测试，适合查 SSH、Web、设备服务是否开放。</div>
    <div class="ops-net-presets">
      <button class="btn-gray" onclick="fillOpsNetwork('', '22,80,443,8080')">常见管理端口</button>
      <button class="btn-gray" onclick="fillOpsNetwork('', '53,80,443,8000,8080,8443')">常见 Web/服务端口</button>
      <button class="btn-gray" onclick="fillOpsNetwork('10.8.0.1', '')">检测 VPN 网关</button>
    </div>
    <div id="opsPingOutput">请输入单个 IP 或域名后开始检测。网段不要填这里，去“网段快速扫描”。</div>
  </div>`;
  setTimeout(()=>document.getElementById('opsPingTarget')?.focus(),50);
}
function showNetworkScanTool(){
  setOpsActive('scan');
  const el=getRuntimeLogEl();
  if(!el)return;
  el.innerHTML=`<div class="ops-net-tool">
    <div class="ops-net-form ops-scan-form">
      <label>扫描网段<input id="opsScanTarget" placeholder="例如 192.168.1.0/24、10.8.0.0/24" onkeydown="if(event.key==='Enter')runOpsNetworkScan()"></label>
      <label>并发数<select id="opsScanWorkers"><option value="32">32</option><option value="64" selected>64</option><option value="96">96</option></select></label>
      <div class="ops-net-checks"><label><input type="checkbox" id="opsScanShowDead"> 显示无响应地址</label></div>
      <button class="btn-primary" onclick="runOpsNetworkScan()">快速扫描</button>
    </div>
    <div class="ops-ping-tip">网段扫描是独立逻辑：并发扫描，每个地址只发 1 个 ICMP 包，1 秒超时。网页端限制最多 /24，避免误扫大网段拖垮服务。</div>
    <div class="ops-net-presets">
      <button class="btn-gray" onclick="fillOpsScan('10.8.0.0/24')">VPN 网段</button>
      <button class="btn-gray" onclick="fillOpsScan('192.168.1.0/24')">常见现场网段</button>
      <button class="btn-gray" onclick="fillOpsScan('192.168.0.0/24')">常见办公网段</button>
    </div>
    <div id="opsScanOutput">请输入 CIDR 网段后开始快速扫描。</div>
  </div>`;
  setTimeout(()=>document.getElementById('opsScanTarget')?.focus(),50);
}
function fillOpsNetwork(target, ports){
  const t=document.getElementById('opsPingTarget');
  const p=document.getElementById('opsPortList');
  if(t && target)t.value=target;
  if(p && ports)p.value=ports;
  (t||p)?.focus();
}
function fillOpsScan(target){
  const t=document.getElementById('opsScanTarget');
  if(t)t.value=target;
  t?.focus();
}
async function runOpsNetworkTest(){
  setOpsActive('ping');
  const target=(document.getElementById('opsPingTarget')?.value||'').trim();
  const ports=(document.getElementById('opsPortList')?.value||'').trim();
  const doPing=!!document.getElementById('opsDoPing')?.checked;
  const doPorts=!!document.getElementById('opsDoPorts')?.checked;
  const pingCount=parseInt(document.getElementById('opsPingCount')?.value||'1',10)||1;
  const out=document.getElementById('opsPingOutput');
  if(!target){toast('请输入要检测的单个 IP 或域名','warn');return;}
  if(target.includes('/')){toast('网段请使用“网段快速扫描”模块','warn');return;}
  if(out)out.innerText=`正在检测 ${target} ...`;
  try{
    const text=await api('/api/ops/network-test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,ports,ping:doPing,ports_enabled:doPorts,ping_count:pingCount})});
    if(out)out.innerText=text||'无输出';
  }catch(e){
    if(out)out.innerText=`网络检测失败：${e.message}`;
  }
}
async function runOpsNetworkScan(){
  setOpsActive('scan');
  const target=(document.getElementById('opsScanTarget')?.value||'').trim();
  const workers=parseInt(document.getElementById('opsScanWorkers')?.value||'64',10)||64;
  const showDead=!!document.getElementById('opsScanShowDead')?.checked;
  const out=document.getElementById('opsScanOutput');
  if(!target){toast('请输入 CIDR 网段，例如 192.168.1.0/24','warn');return;}
  if(!target.includes('/')){toast('网段快速扫描需要 CIDR 格式，例如 192.168.1.0/24','warn');return;}
  if(out)out.innerText=`正在快速扫描 ${target}，并发 ${workers} ...`;
  try{
    const text=await api('/api/ops/network-scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,workers,show_dead:showDead})});
    if(out)out.innerText=text||'无输出';
  }catch(e){
    if(out)out.innerText=`网段扫描失败：${e.message}`;
  }
}
// Backward-compatible alias for old button handlers.
async function runOpsPing(){return runOpsNetworkTest();}

async function loadLog(kind){
  setOpsActive('');
  const el=getRuntimeLogEl();
  const name={webui:'WebUI 服务日志',wireguard:'WireGuard 服务日志',handshake:'连接快照',upgrade:'升级日志'}[kind]||'日志';
  if(el)el.innerText=`正在读取 ${name}...`;
  try{if(el){el.innerText=await api(`/api/logs/${kind}?lines=500`);scrollRuntimeLog();}}catch(e){if(el)el.innerText='读取日志失败'}
}

const PEER_COL_KEY='wg-webui-peer-column-widths-v1';
const DEFAULT_PEER_COL_WIDTHS=[18,8,14,17,17,15,11];
function getPeerColWidths(){
  try{
    const saved=JSON.parse(localStorage.getItem(PEER_COL_KEY)||'[]');
    if(Array.isArray(saved)&&saved.length===DEFAULT_PEER_COL_WIDTHS.length&&saved.every(n=>Number(n)>0))return saved;
  }catch(e){}
  return DEFAULT_PEER_COL_WIDTHS.slice();
}
function applyPeerColWidths(widths){
  document.querySelectorAll('.peer-table colgroup').forEach(group=>{
    Array.from(group.children).forEach((col,i)=>{
      if(widths[i])col.style.setProperty('width',`${widths[i]}%`,'important');
    });
  });
}
function savePeerColWidths(widths){
  localStorage.setItem(PEER_COL_KEY,JSON.stringify(widths.map(n=>Math.round(n*100)/100)));
}
function initPeerColumnResize(){
  const tables=Array.from(document.querySelectorAll('.peer-table'));
  if(!tables.length)return;
  applyPeerColWidths(getPeerColWidths());
  tables.forEach(table=>{
    table.classList.add('resizable');
    Array.from(table.tHead?.rows?.[0]?.cells||[]).forEach((th,idx)=>{
      if(idx>=DEFAULT_PEER_COL_WIDTHS.length-1||th.querySelector('.col-resizer'))return;
      const handle=document.createElement('span');
      handle.className='col-resizer';
      handle.title='拖动调整列宽，双击恢复默认';
      handle.addEventListener('dblclick',e=>{
        e.preventDefault();e.stopPropagation();
        const reset=DEFAULT_PEER_COL_WIDTHS.slice();
        savePeerColWidths(reset);applyPeerColWidths(reset);
      });
      handle.addEventListener('pointerdown',e=>{
        e.preventDefault();e.stopPropagation();
        const startX=e.clientX;
        const start=getPeerColWidths();
        const tableWidth=table.getBoundingClientRect().width||1;
        const next=idx+1;
        const mins=[8,6,10,10,10,10,9];
        handle.classList.add('dragging');
        document.body.classList.add('col-resize-active');
        const move=ev=>{
          const delta=(ev.clientX-startX)/tableWidth*100;
          const pair=start[idx]+start[next];
          let left=Math.max(mins[idx],Math.min(pair-mins[next],start[idx]+delta));
          let right=pair-left;
          const now=start.slice();
          now[idx]=left;now[next]=right;
          savePeerColWidths(now);applyPeerColWidths(now);
        };
        const up=()=>{
          handle.classList.remove('dragging');
          document.body.classList.remove('col-resize-active');
          window.removeEventListener('pointermove',move);
          window.removeEventListener('pointerup',up);
        };
        window.addEventListener('pointermove',move);
        window.addEventListener('pointerup',up);
      });
      th.appendChild(handle);
    });
  });
}

initPeerColumnResize();loadService();loadSystem();loadSystemSettings();loadAccountSecurity();loadPeers(true);loadUpgradeInfo();loadAllowedIPsStatus();setInterval(()=>{loadService();if(!menuIsOpen()&&!modalIsOpen())loadPeers(true);loadUpgradeInfo();loadAllowedIPsStatus()},15000);setInterval(()=>{loadSystem();loadSystemSettings();loadAccountSecurity()},60000)

// v1.11.50 页面切换初始化
switchPage((location.hash||'#dashboard').slice(1), false);


// v1.12.52: 高级设置保存后保持解锁，不再触发顶部配置应用提示
function toggleSettingsMore(){
  const wrap=document.getElementById('settingsMoreUnified');
  const btn=document.getElementById('btnSettingsMore');
  if(!wrap||!btn)return;
  const open=!wrap.classList.contains('open');
  wrap.classList.toggle('open',open);
  btn.innerText=open?'收起更多':'展示更多';
}
async function restartWebUI(){
  if(!confirm('确认重启 WebUI 管理服务？\n\n只会重启网页管理后台，不会重启 WireGuard，也不会断开现有 VPN 隧道。'))return;
  try{
    await api('/api/webui/restart',{method:'POST'});
    toast('WebUI 正在重启，稍后会返回登录页','ok',2600);
    setTimeout(()=>forceLogin('restarted'),1800);
  }catch(e){
    toast('重启 WebUI 失败：'+(e.message||e),'err',6200);
  }
}

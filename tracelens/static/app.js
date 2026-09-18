const $ = (selector, root = document) => root.querySelector(selector);
const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state = {token:'', config:{}, page:1, keyword:'', severity:'', hours:24, case:null, tab:'overview', snapshot:0, routeVersion:0};
const statuses = {investigating:'调查中', monitoring:'持续观察', closed:'已归档'};
const directions = {in:'外部攻击', out:'失陷破坏', lateral:'内网渗透'};
const severities = ['信息','低危','中危','高危','严重'];
let toastTimer;
function toast(text, error=false) { const el=$('#toast'); el.textContent=text; el.className='toast'+(error?' error':''); el.hidden=false; clearTimeout(toastTimer); toastTimer=setTimeout(()=>el.hidden=true,6000); }
function stamp(seconds) { return seconds ? new Date(seconds*1000).toLocaleString('zh-CN',{hour12:false}) : '未知'; }
function localInput(seconds) {const date=new Date(seconds*1000); date.setMinutes(date.getMinutes()-date.getTimezoneOffset()); return date.toISOString().slice(0,16);}
function windowRange() {const end=Math.floor(Date.now()/1000);return {time_from:end-state.hours*3600,time_to:end};}
function badge(text,tone='') {return `<span class="badge ${tone}">${esc(text)}</span>`;}
function severityBadge(value) {const n=Number(value);return badge(severities[n]||'未知',n>=3?'red':n===2?'orange':'blue');}
function statusBadge(value) {return badge(statuses[value]||value,value==='closed'?'green':value==='monitoring'?'orange':'blue');}
function busy(message='正在查询…') {return `<div class="loading"><span class="spinner"></span>${esc(message)}</div>`;}
function empty(title,text,action='') {return `<div class="empty"><div class="empty-symbol">◎</div><h3>${esc(title)}</h3><p>${esc(text)}</p>${action}</div>`;}
async function api(path, body) {
  const response=await fetch(path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':'application/json','X-TraceLens-Token':state.token},body:body===undefined?undefined:JSON.stringify(body)});
  const data=await response.json();
  if(!response.ok) throw new Error(data.error||'请求失败，请重试。');
  return data;
}
async function action(button, fn) {
  if(button?.disabled) return;
  const original=button?.textContent;
  if(button){button.disabled=true;button.textContent='处理中…';}
  try {await fn();} catch(error){toast(error.message,true);} finally {if(button?.isConnected){button.disabled=false;button.textContent=original;}}
}
function setConfig(config) {state.config=config;const node=$('#connection-badge');node.textContent=config.mode==='demo'?'案例演练 · 合成数据':config.ready?'TDP 已配置':'等待连接 TDP';node.className='badge '+(config.mode==='demo'?'orange':config.ready?'green':'orange');document.body.classList.toggle('demo-mode',config.mode==='demo');}
function heading(eyebrow,title,subtitle,buttons='') {return (state.config.mode==='demo'?`<div class="callout warning demo-banner"><p><strong>案例演练</strong> · 当前使用合成数据，不连接真实 TDP。</p><button class="button small" data-action="live-mode">切换真实环境</button></div>`:'')+`<div class="page-heading"><div><div class="eyebrow">${eyebrow}</div><h1>${title}</h1><p class="subtitle">${subtitle}</p></div><div class="actions">${buttons}</div></div>`;}
function modal(title,body,footer='') {$ ('#dialog-content').innerHTML=`<div class="dialog-header"><h2>${esc(title)}</h2><button class="close-button" data-action="close" aria-label="关闭">×</button></div><div class="dialog-body">${body}</div>${footer?`<div class="dialog-footer">${footer}</div>`:''}`;if(!$('#dialog').open)$('#dialog').showModal();const field=$('input:not([type=checkbox])',$('#dialog'));if(field)field.focus();}
function closeModal() {$('#dialog').close();}
function inputField(label,name,value='',type='text',hint='',extra='') {return `<div class="field"><label for="${name}">${label}</label><input id="${name}" name="${name}" type="${type}" value="${esc(value)}" ${extra}>${hint?`<small>${hint}</small>`:''}</div>`;}
async function route() {
  const version=++state.routeVersion;
  const [page,id]=location.hash.replace('#','').split('/');
  document.querySelectorAll('[data-nav]').forEach(el=>el.classList.toggle('active',el.dataset.nav===(page==='case'?'cases':page||'overview')));
  $('#page-label').textContent=({overview:'调查总览',cases:'调查档案',case:'主机调查',settings:'连接设置'})[page]||'调查总览';
  $('#main').innerHTML=busy('正在加载…');
  try {
    if(page==='settings') return renderSettings();
    if(page==='cases') {const cases=await api('/api/cases');if(version===state.routeVersion) renderCases(cases);return;}
    if(page==='case'&&id) {const data=await api('/api/cases/'+encodeURIComponent(id));if(version===state.routeVersion){state.case=data;state.snapshot=data.snapshots.length-1;renderCase();}return;}
    renderOverview();
    if(state.config.ready) await loadOverview(version);
  } catch(error){if(version===state.routeVersion)$('#main').innerHTML=heading('WORKSPACE','暂时无法加载','请检查连接后重试。')+`<div class="callout error">${esc(error.message)}</div><button class="button" data-action="refresh">重新加载</button>`;}
}
function renderOverview() {
  $('#main').innerHTML=heading('SECURITY INVESTIGATIONS','调查工作台',state.config.mode==='demo'?'当前使用合成演练数据，不连接真实环境。':'查询告警主机、核查关联日志并保存调查记录。',`<button class="button primary" data-action="new" ${state.config.ready?'':'disabled'}>＋ 发起调查</button>`)+(!state.config.ready?`
  <div class="entry-options"><section class="panel entry-card featured"><span class="entry-icon">◈</span><div><div class="entry-kicker">无 TDP 环境</div><h2>使用演练数据</h2><p>内置一组财务终端异常外连的合成记录，可体验查询、证据核查和复查。</p><button class="button primary" data-action="demo-mode">进入演练 <span>→</span></button></div></section><section class="panel entry-card"><span class="entry-icon">⌁</span><div><div class="entry-kicker">已有 TDP 环境</div><h2>连接 TDP</h2><p>使用自己的平台地址与 API 凭据，调查告警主机并保存真实证据。</p><a class="button" href="#settings">配置 TDP 连接 <span>→</span></a></div></section></div>
  <div class="steps"><section class="panel step"><div class="step-no">01</div><h3>确定调查对象</h3><p>从高关注告警中选择主机，或直接输入 IP 和时间范围。</p></section><section class="panel step"><div class="step-no">02</div><h3>沿着证据追查</h3><p>对照原始记录检查假设，区分已知事实与待验证的问题。</p></section><section class="panel step"><div class="step-no">03</div><h3>留档并持续复查</h3><p>记录人工判断和处置时间，在后续窗口复查相关迹象。</p></section></div>`:`
  ${state.config.mode==='demo'?`<div class="exercise-options">${[
['192.0.2.10','异常外连','核查远控与横向活动；注意目标可能是发起方。'],
['192.0.2.30','授权运维','已知背景是授权扫描，核对变更单、时间和目标范围。'],
['192.0.2.40','证据不足','模拟结果缺失与返回截断，练习保留未知结论。']
].map(([ip,title,note])=>`<section class="panel exercise"><h3>${title}</h3><p>${note}</p><button class="button small" data-action="new" data-ip="${ip}">调查 ${ip} →</button></section>`).join('')}</div>`:''}<div class="toolbar panel" id="overview-range"><span class="muted">查询范围</span><select id="hours" aria-label="查询时间范围">${[[24,'过去 24 小时'],[72,'过去 3 天'],[168,'过去 7 天']].map(([v,t])=>`<option value="${v}" ${state.hours===v?'selected':''}>${t}</option>`).join('')}</select><span class="spacer"></span><button class="button small" data-action="refresh-overview">刷新数据</button></div>
  <div id="stats" class="stats">${busy('正在获取安全态势…')}</div>
  <section class="panel"><div class="panel-header"><h2>告警主机</h2>${badge('只读查询','outline')}</div><form id="host-filter" class="toolbar"><input id="keyword" name="keyword" placeholder="搜索 IP、主机或威胁名称" aria-label="搜索告警主机" value="${esc(state.keyword)}"><select name="severity" aria-label="严重级别"><option value="">全部严重级别</option>${severities.map((s,i)=>`<option value="${i}" ${state.severity===String(i)?'selected':''}>${s}</option>`).join('')}</select><button class="button small" type="submit">筛选</button><span class="spacer"></span><small>按严重程度排序</small></form><div id="host-list">${busy()}</div></section>`)+`<p class="footer-note">TraceLens for TDP · 本机工作台 · 非官方项目</p>`;
}
async function loadOverview(version=state.routeVersion) {
  const requestVersion=(state.overviewVersion||0)+1;state.overviewVersion=requestVersion;
  const range=windowRange();state.range=range;
  const results=await Promise.allSettled([api('/api/security',range),api('/api/hosts',{...range,keyword:state.keyword,page:state.page,severity:state.severity===''?null:Number(state.severity)})]);
  if(version!==state.routeVersion||requestVersion!==state.overviewVersion||!$('#stats'))return;
  const [security,hosts]=results;
  if(security.status==='fulfilled') {const d=security.value;$('#stats').innerHTML=[[state.config.mode==='demo'?'合成演练态势':'安全态势',d.level_desc||d.level||'未知','所选时间窗口内的安全级别','◈'],['待处理失陷主机',d.compromised_host_count??'—','优先核查的失陷主机','◎'],['全部待处理主机',d.unhandled_host_count??'—','仍需人工研判和处理','▤'],['阻断中主机',d.block_host_count??'—','平台当前返回的阻断数量','⊘']].map(([label,value,foot,icon],i)=>`<div class="stat"><span class="stat-icon">${icon}</span><div class="stat-label">${label}</div><div class="stat-value ${i===0&&['HIGH','CRITICAL'].includes(d.level)?'danger':''}">${esc(value)}</div><div class="stat-foot">${foot}</div></div>`).join('');}
  else $('#stats').innerHTML=`<div class="callout error">安全态势查询失败：${esc(security.reason.message)}</div>`;
  if(hosts.status==='fulfilled') renderHosts(hosts.value); else $('#host-list').innerHTML=empty('主机查询未完成',hosts.reason.message,`<button class="button" data-action="refresh-overview">重试</button>`);
}
function renderHosts(data) {
  const items=data.items||[];
  $('#host-list').innerHTML=items.length?`<div class="table-wrap"><table><thead><tr><th>告警主机 / 资产</th><th>严重级别</th><th>最近威胁</th><th>最近发现</th><th>处置状态</th><th></th></tr></thead><tbody>${items.map(row=>`<tr><td><span class="ip">${esc(row.machine||'未知')}</span><span class="cell-secondary">${esc(row.asset_name||row.machine_name||'未命名资产')}</span></td><td>${severityBadge(row.max_severity??row.threat?.severity)}</td><td class="row-title">${esc(row.threat_name||row.threat?.name||'—')}<span class="cell-secondary">${esc(directions[row.direction]||row.direction||'')}</span></td><td>${esc(stamp(row.last_occ_time||row.time))}</td><td>${badge(row.host_disposal_status===3?'已处理':'待复核',row.host_disposal_status===3?'green':'orange')}</td><td><button class="button ghost" data-action="new" data-ip="${esc(row.machine||'')}">调查 →</button></td></tr>`).join('')}</tbody></table></div>`:empty('当前范围没有告警主机','可调整时间或筛选条件；无结果不代表环境没有风险。');
  $('#host-list').innerHTML+=`<div class="pagination"><span>第 ${state.page} 页 · 当前返回 ${items.length} 条${data.page?.total_num!==undefined?' · 共 '+esc(data.page.total_num)+' 条':''}</span><div class="actions"><button class="button small" data-action="prev-page" ${state.page<=1?'disabled':''}>上一页</button><button class="button small" data-action="next-page" ${items.length<20?'disabled':''}>下一页</button></div></div>`;
}
function renderCases(cases) {
  $('#main').innerHTML=heading('CASE LIBRARY','调查档案','保留证据快照、人工记录与每次复查，随时继续调查。',`<button class="button primary" data-action="new" ${state.config.ready?'':'disabled'}>＋ 新建调查</button>`)+`<section class="panel"><div class="panel-header"><h2>最近 ${cases.length} 份调查</h2>${badge('存储在本机','green')}</div>${cases.length?`<div class="table-wrap"><table><thead><tr><th>调查对象</th><th>状态</th><th>创建时间</th><th>最后更新</th><th></th></tr></thead><tbody>${cases.map(c=>`<tr><td><a class="ip" href="#case/${esc(c.id)}">${esc(c.ip)}</a><span class="cell-secondary">${esc(c.title)} ${c.source.startsWith('demo:')?'· 合成演练':''}</span></td><td>${statusBadge(c.status)}</td><td>${stamp(c.created_at)}</td><td>${stamp(c.updated_at)}</td><td><a class="button ghost" href="#case/${esc(c.id)}">继续调查 →</a></td></tr>`).join('')}</tbody></table></div>`:empty('还没有调查档案','从告警主机或一个已知 IP 开始，完成查询后会自动保存。',`<a class="button" href="#overview">返回调查总览</a>`)}</section>`;
}
function renderSettings() {
  const c=state.config;
  const attr=k=>c.locked?.includes(k)?'disabled':'autocomplete="off"';
  $('#main').innerHTML=heading('CONNECTIONS','连接你的安全环境','凭据保存在本机服务端，浏览器不会回显已保存的密钥。')+`<div class="settings-layout"><form id="settings-form" class="settings-stack"><section class="panel"><div class="panel-header"><h2>TDP 数据源</h2>${badge(c.ready?'已配置':'待配置',c.ready?'green':'orange')}</div><div class="panel-body"><div class="form-grid"><div class="field full"><label for="tdp_url">TDP 平台地址</label><input id="tdp_url" name="tdp_url" type="url" placeholder="https://your-tdp.example.com" value="${esc(c.tdp_url)}" required ${attr('tdp_url')}><small>填写 HTTPS 地址，不包含页面路径。仅查询开放 API。</small></div>${inputField('API Key','tdp_key','','password',c.tdp_key_set?'已保存，留空保持不变。':'由 TDP 管理员创建专用请求方。',attr('tdp_key'))}${inputField('Secret','tdp_secret','','password',c.tdp_secret_set?'已保存，留空保持不变。':'用于本地生成请求签名。',attr('tdp_secret'))}</div><div class="form-footer"><button class="button primary" type="submit">保存连接配置</button><button type="button" class="button" data-action="test-connection" ${c.ready?'':'disabled'}>验证已保存连接</button></div><div id="connection-result"></div></div></section>
  <section class="panel"><div class="panel-header"><h2>AI 辅助分析</h2>${badge('可选','outline')}</div><div class="panel-body"><div class="callout"><p>未配置模型时仍可使用真实查询、规则判断和调查留档。只有在调查页预览并确认后，才会向模型服务发送证据摘要。</p></div><div class="form-grid"><div class="field full"><label for="ai_url">兼容 Chat Completions 的服务地址</label><input id="ai_url" name="ai_url" type="url" placeholder="https://your-model.example.com/v1" value="${esc(c.ai_url)}" ${attr('ai_url')}><small>填到 API 基础路径，程序追加 /chat/completions。支持配置使用 HTTPS 的内网模型服务。</small></div>${inputField('模型名称','ai_model',c.ai_model,'text','填写服务商实际支持的模型 ID。',attr('ai_model'))}${inputField('模型 API Key','ai_key','','password',c.ai_key_set?'已保存，留空保持不变。':'无鉴权的内网服务可留空。',attr('ai_key'))}<label class="check"><input type="checkbox" name="clear_ai_key" ${c.locked?.includes('ai_key')?'disabled':''}>清除已保存的模型密钥</label></div></div></section></form><aside class="panel aside-note"><h3>配置与数据归属</h3><p>每位使用者连接自己的 TDP。项目代码不附带平台账号、测试地址或 API 密钥。</p><hr><h3>数据存在哪里？</h3><p>连接配置和调查档案保存在本机用户数据目录中，不在项目源码目录内。文件采用仅当前用户可访问的权限；本地配置不是加密保险库。</p><hr><h3>没有 TDP 环境？</h3><p>可以使用内置的合成案例演练，无需任何 Key。</p><button class="button small" type="button" data-action="demo-mode">进入案例演练</button><hr><h3>首版访问范围</h3><p>服务只监听本机回环地址。首版不提供多人登录或远程共享，请在本机使用。</p><hr><h3>接口兼容性</h3><p>按 TDP 3.3.13 开放 API 适配。其他版本需确认日志调查接口兼容性；接口失败会明确报错，不自动替换为演示数据。</p></aside></div>`;
}
function newInvestigation(ip='', chosenRange=null) {
  const range=chosenRange||state.range||windowRange();
  modal('发起调查',`<form id="investigate-form"><div class="field"><label for="target-ip">调查对象</label><input id="target-ip" name="ip" placeholder="输入 IPv4、IPv6 或完整域名" value="${esc(ip)}" required></div><div class="divider"></div><div class="form-grid">${inputField('开始时间','time_from',localInput(range.time_from),'datetime-local','','required')}${inputField('结束时间','time_to',localInput(range.time_to),'datetime-local','','required')}</div><p class="subtitle">使用本机时区。单次不超过 31 天；建议先从最近 24 小时开始。只读查询会自动保存一份调查快照。</p><div class="form-footer"><button class="button primary" type="submit">查询并建立调查</button><button class="button" type="button" data-action="close">取消</button></div><p id="form-error" class="inline-error"></p></form>`);
}
function currentSnapshot(){return state.case?.snapshots[state.snapshot];}
function renderCase() {
  const c=state.case, snap=currentSnapshot(), a=snap.analysis;
  $('#page-label').textContent=a.target_kind==='domain'?'域名调查':'主机调查';
  $('#main').innerHTML=`<a class="back" href="#cases">← 返回调查档案</a>`+heading('HOST INVESTIGATION',`<span class="ip-title">${esc(c.ip)}</span> <span class="muted">/</span> ${a.target_kind==='domain'?'域名调查':'主机调查'}`,'查看关联证据，记录核查结果。',`<button class="button" data-action="export">↓ 导出报告</button><button class="button primary" data-action="recheck">后续窗口复查</button>`)+`<div class="snapshot-bar"><label for="snapshot">证据快照</label><select id="snapshot">${c.snapshots.map((s,i)=>`<option value="${i}" ${state.snapshot===i?'selected':''}>${i+1}. ${s.kind==='initial'?'首次调查':'后续复查'} · ${stamp(s.created_at)}</option>`).join('')}</select>${statusBadge(c.status)}<span>${stamp(a.time_from)} — ${stamp(a.time_to)}</span></div>
  ${c.source.startsWith('demo:')&&state.config.mode!=='demo'?'<div class="callout warning">本档案来自合成案例演练，不代表真实威胁或真实资产。</div>':''}
  <section class="coverage-bar ${a.coverage.partial?'incomplete':''}" aria-label="查询覆盖与来源"><div><strong>${a.coverage.partial?'覆盖不完整 / 未知':'本次返回未发现截断'}</strong><span>返回 ${a.coverage.returned} · 保留 ${a.coverage.retained} · 总量 ${a.coverage.reported_total??'未知'} · 去重 ${a.coverage.duplicate_rows??'未知'}</span></div><div><span>来源：${esc(c.source.startsWith('demo:')?'合成案例':c.source)}</span><span>采集：${stamp(a.collected_at||snap.created_at)}</span></div><small>${esc(a.coverage.scope_note||'仅覆盖当前时间范围和请求方可见数据。')}</small>${a.coverage.partial?'<button class="button small" type="button" data-action="narrow-window">缩小窗口继续查询</button>':''}</section>
  ${snap.comparison?`<div class="callout"><p><strong>复查观察：</strong>${esc(snap.comparison.statement)}<br>前次 ${snap.comparison.before_events} 条 → 本次 ${snap.comparison.after_events} 条。${esc(snap.comparison.note)}</p></div>`:''}
  ${snap.remediation_comparison?remediationResult(snap.remediation_comparison):''}
  <div class="stats">${[['归并事件',a.summary.groups??a.summary.events,`${a.summary.events} 条原始证据`],['目标受害且成功',a.target_kind==='domain'?'不适用':a.summary.success,a.target_kind==='domain'?'域名不是主机身份':'要求明确受害角色字段'],['远控类连接记录',a.target_kind==='domain'?'不适用':a.summary.remote,a.target_kind==='domain'?'请选择关联 IP 继续调查':'原始记录数，重复记录见归并事件'],['目标发起内网通信',a.target_kind==='domain'?'不适用':a.summary.lateral,a.target_kind==='domain'?'域名不具有通信源角色':'通信源角色，不等于攻击成功']].map(([label,v,foot])=>`<div class="stat"><div class="stat-label">${label}</div><div class="stat-value">${v}</div><div class="stat-foot">${foot}</div></div>`).join('')}</div>
  <div class="tabs" role="tablist">${[['overview','调查判断'],['groups','归并事件'],['timeline','证据时间线'],['network','通信关系'],['related','关联调查'],['notes','人工记录'],['remediation','处置与复查'],['ai','AI 辅助分析']].map(([id,label])=>`<button class="tab ${state.tab===id?'active':''}" role="tab" aria-selected="${state.tab===id}" data-action="case-tab" data-tab="${id}">${label}</button>`).join('')}</div><div id="case-content"></div>`;
  renderCaseContent();
}

function renderCaseContent() {
  const c=state.case,snap=currentSnapshot(),a=snap.analysis;
  if(state.tab==='overview') {
    $('#case-content').innerHTML=`<div class="case-layout"><div class="stack"><section class="assessment-card"><div class="assessment-icon">◎</div><div><div class="eyebrow">查询结果摘要</div><h2>${esc(a.assessment)}</h2><p>依据 ${a.summary.events} 条记录整理 · 规则辅助判断 · 尚待人工确认</p></div></section><div class="investigation-progress"><span class="done">✓ 确定对象</span><i></i><span class="done">✓ 收集证据</span><i></i><span class="current">③ 核查判断</span><i></i><span>④ 记录与复查</span></div>${a.hypotheses.map(h=>`<section class="panel question"><div class="question-top"><h3>${esc(h.question)}</h3>${badge(h.state,h.evidence.length?'orange':'outline')}</div><p>${esc(h.finding)}</p><div class="refs">${h.evidence.slice(0,12).map(ref=>`<button class="ref" data-action="evidence" data-ref="${ref}">${ref} ↗</button>`).join('')}${h.evidence.length>12?`<span class="muted">另有 ${h.evidence.length-12} 条，见时间线</span>`:''}</div>${h.opposing_evidence?.length?`<p class="subtitle">对应失败记录（不能否定其他成功事件）：${refButtons(h.opposing_evidence)}</p>`:''}<p class="subtitle">缺失：${esc((h.missing||[]).join('、'))}</p></section>`).join('')}<section class="panel"><div class="panel-header"><h2>待核实事项</h2></div><div class="panel-body"><ul class="checklist">${a.gaps.map(g=>`<li>${esc(g)}</li>`).join('')}</ul></div></section></div><aside class="stack"><section class="panel"><div class="panel-header"><h2>下一步调查</h2></div><div class="panel-body"><ul class="checklist">${a.next_steps.map(g=>`<li>${esc(g)}</li>`).join('')}</ul></div></section><section class="panel"><div class="panel-header"><h2>调查状态</h2></div><div class="panel-body"><select id="case-status" aria-label="调查状态">${Object.entries(statuses).map(([v,t])=>`<option value="${v}" ${c.status===v?'selected':''}>${t}</option>`).join('')}</select><button class="button small" data-action="save-status">更新状态</button><p class="subtitle">只更新本地档案，不修改 TDP 处置状态。归档不代表风险已消除。</p></div></section><section class="panel"><div class="panel-header"><h2>关联资产快照</h2></div><div class="panel-body">${assetCards(a)}</div></section></aside></div>`;
  } else if(state.tab==='groups') {
    renderGroups(a);
  } else if(state.tab==='related') {
    renderRelated(c,a);
  } else if(state.tab==='remediation') {
    renderRemediations(c);
  } else if(state.tab==='timeline') {
    $('#case-content').innerHTML=`<section class="panel"><div class="panel-header"><h2>证据时间线 <small>· ${a.evidence.length} 条</small></h2><span class="muted">按事件时间升序</span></div><div class="toolbar"><input id="evidence-search" placeholder="筛选威胁名称、IP 或 IOC" aria-label="筛选证据"><select id="evidence-direction" aria-label="证据方向"><option value="">全部方向</option>${Object.entries(directions).map(([k,v])=>`<option value="${k}">${v}</option>`).join('')}</select></div><div id="timeline-items"></div></section>`;
    renderTimeline();
  } else if(state.tab==='network') {
    renderNetwork(a);
  } else if(state.tab==='notes') {
    $('#case-content').innerHTML=`<section class="panel narrow"><div class="panel-header"><h2>人工调查记录</h2>${badge('所有快照共享','outline')}</div><div class="panel-body"><form id="note-form"><label for="note" class="block">记录判断、核查结果或处置时间</label><p class="subtitle">明确哪些操作已执行，哪些仍待验证。</p><textarea id="note" name="text" required maxlength="5000" placeholder="例如：已联系资产责任人，确认该外连不属于正常业务。下一步核查终端进程。"></textarea><div class="form-footer"><button class="button primary" type="submit">保存记录</button></div></form><div>${c.notes.length?c.notes.slice().reverse().map(n=>`<div class="note"><small>${stamp(n.created_at)} · 本地人工记录</small><p>${esc(n.text)}</p></div>`).join(''):empty('还没有人工记录','可记录已确认的事实、待查问题和处置时间。')}</div></div></section>`;
  } else {
    const ai=snap.ai, latest=state.snapshot===c.snapshots.length-1&&!c.source.startsWith('demo:');
    $('#case-content').innerHTML=`<section class="panel"><div class="panel-header"><h2>AI 辅助分析</h2>${badge('需人工复核','orange')}</div><div class="panel-body"><div class="callout"><p>AI 只接收所选快照前 100 条证据的字段摘要，不接收原始日志载荷或 TDP 凭据。分析不会自动执行处置操作。</p></div>${ai?`<p class="subtitle">模型：${esc(ai.model)} · ${stamp(ai.created_at)} · 发送 ${ai.sent_evidence} 条证据</p>${ai.warnings.map(w=>`<div class="callout warning">${esc(w)}</div>`).join('')}${ai.claims?ai.claims.map(renderClaim).join(''):`<div class="report-text">${esc(ai.text)}</div>`}<div class="divider"></div>`:empty('尚未生成模型分析',state.config.ai_ready?'可以先预览即将发送的字段，再决定是否分析。':'在连接设置中配置模型后即可使用。真实查询和规则判断不依赖模型。')}${latest?`<button class="button primary" data-action="ai-preview" ${state.config.ai_ready?'':'disabled'}>预览数据并分析</button>`:'<p class="muted">历史快照及合成演练不执行模型调用；真实调查的最新快照可生成分析。</p>'} <a class="button" href="#settings">模型设置</a></div></section>`;
  }
}
function assetCards(a) {
  if(a.target_kind==='domain')return '<p class="subtitle">域名不是主机身份。可从关联调查选择通信 IP 查看资产快照。</p>';
  const seen=new Set(),assets=[];
  for(const e of a.evidence)for(const [ip,asset] of [[e.src_ip,e.assets],[e.dest_ip,e.dest_assets]]) {
    if(ip!==a.ip||!asset||typeof asset!=='object'||!Object.keys(asset).length)continue;
    const name=Array.isArray(asset.name)?asset.name.join(' / '):asset.name||'未命名资产';
    const key=JSON.stringify([name,asset.group_name,asset.section]);
    if(seen.has(key))continue;seen.add(key);assets.push({name,group:asset.group_name,section:asset.section});
  }
  return assets.length?`<div class="asset-list">${assets.slice(0,5).map(a=>`<div class="asset"><strong>${esc(a.name)}</strong><br>${esc(a.group||'未分组')} · ${esc(a.section||'类型未知')}</div>`).join('')}</div>`:'<p class="subtitle">当前证据中没有可关联到该 IP 的资产快照。</p>';
}
function peerGroups(analysis) {
  const peers=new Map();
  for(const event of analysis.evidence) {
    const peer=event.src_ip===analysis.ip?event.dest_ip:event.dest_ip===analysis.ip?event.src_ip:'';
    if(!peer||peer===analysis.ip)continue;
    if(!peers.has(peer))peers.set(peer,[]);
    peers.get(peer).push(event);
  }
  return [...peers.entries()].sort((a,b)=>b[1].length-a[1].length);
}
function renderNetwork(analysis) {
  if(analysis.target_kind==='domain'){$('#case-content').innerHTML='<section class="panel">'+empty('域名查询不推断主机通信拓扑','请从关联调查选择对应 IP，再查看该主机的通信关系。')+'</section>';return;}
  const all=peerGroups(analysis),shown=all.slice(0,8),height=Math.max(280,Math.ceil(shown.length/2)*95+40),cy=height/2;
  const nodes=shown.map(([ip,events],i)=>({ip,events,x:i%2===0?145:755,y:55+Math.floor(i/2)*95}));
  $('#case-content').innerHTML=`<section class="panel"><div class="panel-header"><h2>主机通信关系</h2>${badge('来自当前证据快照','outline')}</div><div class="panel-body"><p class="subtitle">只显示直接涉及目标 IP 的通信。连线代表日志记录，不代表已经证实的攻击路径；点击地址可查看关联证据。</p>${nodes.length?`<div class="network-wrap"><svg class="network-svg" viewBox="0 0 900 ${height}" role="img" aria-label="当前主机与关联地址的通信关系图"><title>目标 ${esc(analysis.ip)} 的通信对端</title>${nodes.map(n=>`<path d="M ${n.x<450?n.x+105:n.x-105} ${n.y} C 380 ${n.y}, 520 ${cy}, 450 ${cy}" fill="none" stroke="#c0d3ce" stroke-width="2"/><text x="${n.x<450?300:600}" y="${(n.y+cy)/2-8}" text-anchor="middle" class="edge-count">${n.events.length} 条</text>`).join('')}<rect x="350" y="${cy-38}" width="200" height="76" rx="9" fill="#254a50"/><text x="450" y="${cy-5}" text-anchor="middle" fill="#ffffff" class="graph-ip">${esc(analysis.ip)}</text><text x="450" y="${cy+17}" text-anchor="middle" fill="#a6c8c0" class="graph-label">当前调查主机</text>${nodes.map(n=>`<g class="graph-node" role="button" tabindex="0" aria-label="查看 ${esc(n.ip)} 的 ${n.events.length} 条证据" data-action="peer" data-peer="${esc(n.ip)}"><rect x="${n.x-105}" y="${n.y-27}" width="210" height="54" rx="7" fill="#f8fbf9" stroke="#d0ded7"/><text x="${n.x}" y="${n.y+4}" text-anchor="middle" fill="#426357" class="graph-ip">${esc(n.ip)}</text></g>`).join('')}</svg></div><div class="peer-list">${shown.map(([ip,events])=>`<button class="peer-chip" data-action="peer" data-peer="${esc(ip)}"><span class="ip">${esc(ip)}</span><span>${events.length} 条记录 →</span></button>`).join('')}</div><p class="subtitle">${all.length} 个直接通信对端，图中最多显示记录数最多的 8 个。完整明细可在证据时间线查询。</p>`:empty('没有可绘制的通信关系','当前记录未包含直接涉及该目标的源 / 目的 IP 对。')}</div></section>`;
}
function peerModal(ip) {
  const pair=peerGroups(currentSnapshot().analysis).find(([peer])=>peer===ip);if(!pair)return;
  modal(ip+' · 关联证据',`<p class="subtitle">以下 ${pair[1].length} 条记录直接涉及该地址与当前调查主机。</p><div class="peer-evidence">${pair[1].slice(0,50).map(e=>`<div class="peer-evidence-row"><div><strong>${esc(e.name)}</strong><small>${stamp(e.time)} · ${esc(e.src_ip)} → ${esc(e.dest_ip)}</small></div><button class="ref" data-action="evidence" data-ref="${e.ref}">${e.ref} ↗</button></div>`).join('')}</div>${pair[1].length>50?'<p class="subtitle">此处显示前 50 条；其余见时间线。</p>':''}`,`<button class="button primary" data-action="pivot" data-target="${esc(ip)}">继续调查该地址</button>`);
}
function renderTimeline() {
  const term=($('#evidence-search')?.value||'').toLowerCase(),direction=$('#evidence-direction')?.value||'';
  const events=currentSnapshot().analysis.evidence.filter(e=>(!direction||e.direction===direction)&&(!term||[e.name,e.src_ip,e.dest_ip,e.indicator,e.ref].join(' ').toLowerCase().includes(term)));
  $('#timeline-items').innerHTML=events.length?`<div class="timeline">${events.map(e=>`<article class="timeline-item"><div class="time">${new Date(e.time*1000).toLocaleTimeString('zh-CN',{hour12:false})}<small>${new Date(e.time*1000).toLocaleDateString('zh-CN')}</small></div><div class="track-dot"></div><div class="timeline-content"><h3>${esc(e.name)}</h3><p><span class="ip">${esc(e.src_ip||'未知')}</span> → <span class="ip">${esc(e.dest_ip||'未知')}</span></p>${e.indicator?`<p class="wrap-anywhere">线索：${esc(e.indicator)}</p>`:''}<div class="timeline-tags">${severityBadge(e.severity)}${badge(e.role?.label||'角色未知','outline')}${badge(directions[e.direction]||'方向未知')}${badge(e.result==='success'?'TDP 标记成功':e.result==='failed'?'TDP 标记失败':'结果待确认',e.result==='success'?'red':'outline')}<button class="ref" data-action="evidence" data-ref="${e.ref}">${e.ref} · 查看原始证据 ↗</button></div></div></article>`).join('')}</div>`:empty('没有匹配的证据','可调整筛选条件或调查时间范围。');
}
function evidenceModal(ref) {const e=currentSnapshot().analysis.evidence.find(e=>e.ref===ref);if(!e)return;modal(ref+' · 原始证据',`<div class="detail-grid"><div><label>事件</label>${esc(e.name)}</div><div><label>时间</label>${stamp(e.time)}</div><div><label>目标角色</label>${esc(e.role?.label||'未知')}</div><div><label>采集时间</label>${stamp(e.provenance?.collected_at)}<small class="block">${esc(e.provenance?.time_basis||'')}</small></div><div><label>来源节点</label>${esc(e.provenance?.node||'未返回')}</div><div><label>平台来源</label><span class="wrap-anywhere">${esc(e.provenance?.source||state.case.source)}</span></div><div class="field full"><label>规范化原始记录 SHA-256</label><span class="wrap-anywhere">${esc(e.provenance?.sha256||'未计算')}</span><small>用于内容一致性核对，不是数字签名或完整取证保全链。</small></div><div><label>原始 ID</label><span class="wrap-anywhere">${esc(e.id)}</span>${e.provenance?.original_id_returned===false?'<small class="block">原记录无 ID，此处使用内容指纹。</small>':''}</div><div><label>记录来源</label>${state.case.source.startsWith('demo:')?'合成案例演练':'TDP 日志调查 API'}</div></div><pre class="code">${esc(JSON.stringify(e.raw,null,2))}</pre><p class="subtitle">原始证据是外部数据，可能包含攻击者控制的内容。此处仅作为文本展示。</p>`);}
async function updateCase(data) {state.case=data;state.snapshot=data.snapshots.length-1;renderCase();}
async function previewAI() {const data=await api(`/api/cases/${state.case.id}/ai-preview`);state.aiPreview=data;modal('确认分析数据的去向',`<div class="callout warning"><p>以下摘要将发送到 <strong class="wrap-anywhere">${esc(data.endpoint)}</strong>。包含调查对象、时间、源/目的 IP、威胁名称与 IOC；云端服务会接收到这些数据。</p></div><pre class="code">${esc(JSON.stringify(data.packet,null,2))}</pre><label class="check"><input id="ai-consent" type="checkbox">我确认可将上述证据摘要发送到该模型服务进行分析。</label>`,`<button class="button" data-action="close">取消</button><button class="button primary" data-action="ai-generate">发送并分析</button>`);}
document.addEventListener('click',event=>{
  const button=event.target.closest('[data-action]');if(!button)return;
  const name=button.dataset.action;
  if(name==='close')return closeModal();
  if(name==='new')return newInvestigation(button.dataset.ip||'');
  if(name==='case-tab'){state.tab=button.dataset.tab;return renderCase();}
  if(name==='evidence')return evidenceModal(button.dataset.ref);
  if(name==='peer')return peerModal(button.dataset.peer);
  if(name==='group')return groupModal(button.dataset.group);
  if(name==='narrow-window')return narrowModal();
  if(name==='recheck')return recheckModal();
  action(button,async()=>{
    if(name==='demo-mode'||name==='live-mode'){setConfig(await api('/api/mode',{mode:name==='demo-mode'?'demo':'live'}));state.page=1;state.keyword='';state.severity='';location.hash='overview';await route();return;}
    if(name==='refresh')return route();
    if(['refresh-overview','next-page','prev-page'].includes(name)){if(name==='next-page')state.page++;if(name==='prev-page')state.page--;return loadOverview();}
    if(name==='test-connection'){const result=await api('/api/connection/test',{});$('#connection-result').innerHTML=`<div class="callout"><p>连接成功 · ${stamp(result.checked_at)}<br>过去 24 小时待处理失陷主机：${esc(result.data.compromised_host_count??'—')} 台。</p></div>`;toast('TDP 签名鉴权和只读查询验证成功');}
    if(name==='pivot'){const parent=state.case.id,snapshot=currentSnapshot().id;const child=await api(`/api/cases/${parent}/pivot`,{target:button.dataset.target,snapshot_id:snapshot});closeModal();state.tab='overview';location.hash='case/'+child.id;toast('已建立关联调查并保留双向来源');return;}
    if(name==='save-status'){await updateCase(await api(`/api/cases/${state.case.id}/status`,{status:$('#case-status').value}));toast('已更新本地调查状态');}
    if(name==='export'){const data=await api(`/api/cases/${state.case.id}/export`);const url=URL.createObjectURL(new Blob([data.markdown],{type:'text/markdown;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download=`TraceLens-${state.case.ip.replaceAll(':','-')}.md`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('已导出最新快照报告，报告包含调查数据，请妥善保存');}
    if(name==='ai-preview')await previewAI();
    if(name==='ai-generate'){if(!$('#ai-consent').checked)throw new Error('请先确认数据发送范围。');const data=await api(`/api/cases/${state.case.id}/ai`,{consent:true,endpoint:state.aiPreview.endpoint,snapshot_id:state.aiPreview.snapshot_id});closeModal();state.tab='ai';await updateCase(data);toast('分析完成，请核对证据引用');}
  });
});
document.addEventListener('submit',event=>{
  event.preventDefault();const form=event.target,button=form.querySelector('button[type="submit"]');
  const values=Object.fromEntries(new FormData(form));
  action(button,async()=>{
    if(form.id==='settings-form'){values.clear_ai_key=values.clear_ai_key==='on';const config=await api('/api/config',values);setConfig(config);renderSettings();toast('配置已保存在本机');}
    if(form.id==='host-filter'){state.keyword=values.keyword;state.severity=values.severity;state.page=1;await loadOverview();}
    if(['investigate-form','recheck-form'].includes(form.id)){
      const payload={...values,time_from:Math.floor(new Date(values.time_from).getTime()/1000),time_to:Math.floor(new Date(values.time_to).getTime()/1000)};
      try {const data=await api(form.id==='investigate-form'?'/api/investigate':`/api/cases/${state.case.id}/recheck`,payload);closeModal();state.tab='overview';if(form.id==='recheck-form')await updateCase(data);else location.hash='case/'+data.id;toast('调查快照已保存');}
      catch(error){$('#form-error').textContent=error.message;throw error;}
    }
    if(form.id==='remediation-form'){await updateCase(await api(`/api/cases/${state.case.id}/remediation`,{...values,performed_at:Math.floor(new Date(values.performed_at).getTime()/1000)}));state.tab='remediation';renderCase();toast('已保存用户声明的处置记录，未执行远端操作');}
    if(form.id==='note-form'){state.tab='notes';await updateCase(await api(`/api/cases/${state.case.id}/note`,{text:values.text}));toast('记录已保存');}
  });
});
document.addEventListener('change',event=>{
  if(event.target.id==='hours'){state.hours=Number(event.target.value);state.page=1;loadOverview().catch(e=>toast(e.message,true));}
  if(event.target.id==='snapshot'){state.snapshot=Number(event.target.value);renderCase();}
  if(event.target.id==='evidence-direction')renderTimeline();
  if(event.target.id==='remediation-select'){const record=state.case.remediations.find(r=>r.id===event.target.value);$('#time_from').value=localInput(Math.ceil((record?record.performed_at:state.case.snapshots.at(-1).analysis.time_to)/60)*60);}
});
document.addEventListener('input',event=>{if(event.target.id==='evidence-search')renderTimeline();});
document.addEventListener('keydown',event=>{if((event.key==='Enter'||event.key===' ')&&event.target.matches('.graph-node')){event.preventDefault();peerModal(event.target.dataset.peer);}});
window.addEventListener('hashchange',()=>{closeModal();route();});
try {const bootstrap=await api('/api/bootstrap');state.token=bootstrap.token;setConfig(bootstrap.config);await route();} catch(error){$('#main').innerHTML=empty('工作台启动失败',error.message);}

function refButtons(refs) {return refs.map(ref=>`<button class="ref" data-action="evidence" data-ref="${esc(ref)}">${esc(ref)} ↗</button>`).join(' ');}
function renderGroups(a) {
  $('#case-content').innerHTML=`<section class="panel"><div class="panel-header"><h2>${a.groups.length} 个归并事件 · ${a.evidence.length} 条原始记录</h2>${badge('保留原始证据','outline')}</div><div class="panel-body"><p class="subtitle">按规则、类型、通信对象、角色、结果及节点归并。不同结果或节点不合并；同组不代表已确认同一攻击活动。</p></div><div class="table-wrap"><table><thead><tr><th>事件</th><th>目标角色</th><th>记录数</th><th>首次 / 最后发现</th><th></th></tr></thead><tbody>${a.groups.map(g=>`<tr><td>${esc(g.name)}<span class="cell-secondary">${esc(g.src_ip)} → ${esc(g.dest_ip)}</span></td><td>${esc(g.role)}</td><td>${g.count}</td><td>${stamp(g.first_seen)}<span class="cell-secondary">${stamp(g.last_seen)}</span></td><td><button class="button ghost" data-action="group" data-group="${g.id}">查看证据</button></td></tr>`).join('')}</tbody></table></div>${a.groups.length?'':empty('没有可归并的记录','请检查查询窗口和数据覆盖。')}</section>`;
}
function groupModal(id) {const group=currentSnapshot().analysis.groups.find(g=>g.id===id);if(!group)return;modal(group.name,`<p>${group.count} 条记录 · ${stamp(group.first_seen)} — ${stamp(group.last_seen)}</p><p class="subtitle">${esc(group.role)} · 结果：${esc(group.result)}</p><div class="refs">${refButtons(group.evidence)}</div>`);}
function renderRelated(c,a) {
  $('#case-content').innerHTML=`<section class="panel"><div class="panel-header"><h2>关联调查</h2>${badge('相同来源与时间窗口','outline')}</div><div class="panel-body"><p class="subtitle">域名使用完整域名精确匹配 data / IOC 字段，不包含 URL 路径子串或子域名模糊检索。</p>${c.links.length?`<div class="related-links">${c.links.map(link=>`<a class="button" href="#case/${esc(link.case_id)}">${link.direction==='parent'?'来源调查':'继续调查'}：${esc(link.target)} →</a>`).join('')}</div>`:''}</div><div class="table-wrap"><table><thead><tr><th>关联对象</th><th>类型</th><th>来源证据</th><th></th></tr></thead><tbody>${a.related_targets.map(item=>`<tr><td class="ip">${esc(item.target)}</td><td>${item.kind==='ip'?'IP':'域名'}</td><td>${refButtons(item.evidence.slice(0,5))}${item.evidence.length>5?` 等 ${item.evidence.length} 条`:''}</td><td><button class="button" data-action="pivot" data-target="${esc(item.target)}">建立关联调查 →</button></td></tr>`).join('')}</tbody></table></div>${a.related_targets.length?'':empty('当前没有可继续调查的对象','相关对象从原始通信 IP 与 IOC 字段中提取。')}</section>`;
}
function renderRemediations(c) {
  $('#case-content').innerHTML=`<section class="panel"><div class="panel-header"><h2>处置记录与复查</h2>${badge('只记录，不执行处置','outline')}</div><div class="panel-body"><div class="callout"><p>记录实际发生的处置动作与时间，再选择基准快照进行复查。这里的记录由用户声明，工具没有执行封禁、隔离或修复。</p></div><form id="remediation-form" class="narrow"><div class="form-grid">${inputField('处置时间','performed_at',localInput(Math.floor(Date.now()/1000)),'datetime-local','','required')}${inputField('处置对象范围','scope','','text','例如某台主机或明确的目的地址。','required maxlength="3000"')}<div class="field full"><label for="remediation-action">已执行的动作</label><textarea id="remediation-action" name="action" required maxlength="3000" placeholder="记录已经执行的动作，不要填写计划。"></textarea></div><div class="field full"><label for="verification">执行依据</label><textarea id="verification" name="verification" required maxlength="3000" placeholder="例如工单号、执行人确认、设备回执，或注明尚未核验。"></textarea></div></div><div class="form-footer"><button class="button primary" type="submit">保存处置记录</button></div></form><hr class="divider">${c.remediations.length?c.remediations.slice().reverse().map(r=>`<article class="note"><h3>${esc(r.action)}</h3><p>处置时间：${stamp(r.performed_at)}<br>对象：${esc(r.scope)}<br>执行依据：${esc(r.verification)}</p><small>记录于 ${stamp(r.recorded_at)} · 用户声明，工具未执行</small></article>`).join(''):empty('暂无处置记录','可先核查证据，实际处置后再记录。')}</div></section>`;
}
function remediationResult(r) {
  return `<section class="callout ${r.baseline_missing||r.coverage_partial?'warning':''}"><div><strong>基于处置时间的复查</strong><p>${esc(r.action)} · ${stamp(r.performed_at)}<br>${esc(r.statement)}<br>处置前基准 ${r.baseline_evidence} 条 · 处置后 ${r.post_evidence} 条 · 相同对象同类记录 ${r.repeated_evidence.length} 条 · 对象变化的同类记录 ${r.changed_peer_evidence.length} 条</p>${r.baseline_missing?'<p>缺少处置前基准证据，无法判断是否复发。</p>':''}${r.coverage_partial?'<p>前后查询存在覆盖缺口，不能据此确认处置有效。</p>':''}<div class="refs">${refButtons([...r.repeated_evidence,...r.changed_peer_evidence].slice(0,12))}</div><small>${esc(r.note)}</small></div></section>`;
}
function recheckModal() {
  const c=state.case,last=c.snapshots.at(-1).analysis,end=Math.floor(Date.now()/1000);
  modal('复查查询',`<form id="recheck-form"><div class="field"><label for="remediation-select">关联处置记录</label><select id="remediation-select" name="remediation_id"><option value="">普通后续窗口复查</option>${c.remediations.map(r=>`<option value="${esc(r.id)}">${stamp(r.performed_at)} · ${esc(r.action)}</option>`).join('')}</select></div><div class="field"><label for="baseline-snapshot">处置前基准快照</label><select id="baseline-snapshot" name="baseline_snapshot_id">${c.snapshots.map((snap,i)=>`<option value="${snap.id}" ${i===state.snapshot?'selected':''}>${i+1}. ${stamp(snap.created_at)}</option>`).join('')}</select><small>关联处置时，仅比较基准快照中早于处置时间的记录。</small></div><div class="form-grid">${inputField('开始时间','time_from',localInput(Math.ceil(last.time_to/60)*60),'datetime-local','','required')}${inputField('结束时间','time_to',localInput(end),'datetime-local','','required')}</div><p class="subtitle">普通复查从上次查询结束后开始；关联处置的复查从处置时间后开始。无记录不能证明风险消失。</p><div class="form-footer"><button class="button primary" type="submit">查询并保存复查</button></div><p id="form-error" class="inline-error"></p></form>`);
}
function narrowModal(){const a=currentSnapshot().analysis;newInvestigation(a.ip,{time_from:Math.max(a.time_from,a.time_to-3600),time_to:a.time_to});}
function renderClaim(claim) {
  const label={supported:'有支持证据',uncertain:'待核实',conflicted:'证据存在分歧'}[claim.status];
  return `<section class="panel question ai-claim"><div class="question-top"><h3>${esc(claim.conclusion)}</h3>${badge(label,'orange')}</div><p>支持证据</p><div class="refs">${claim.support.length?refButtons(claim.support):'无'}</div><p class="subtitle">反对证据</p><div class="refs">${claim.against.length?refButtons(claim.against):'未提供，不代表判断成立'}</div><p class="subtitle">缺失信息：${esc(claim.gaps.join('；'))}</p><p class="subtitle">下一步：${esc(claim.next_steps.join('；'))}</p></section>`;
}

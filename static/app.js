'use strict';

const $ = id => document.getElementById(id);
const labels = {
  host:'Нода', src:'Источник', proto:'Протокол', dport:'Порт назначения', sport:'Исходный порт',
  dst:'IP назначения', asn:'ASN', netname:'Сеть', family:'Семейство IP', iface:'Интерфейс',
  tcp_flags:'TCP-флаги', packet_length:'Длина пакета', ttl:'TTL / Hop Limit',
  icmp_type:'Тип ICMP', icmp_code:'Код ICMP', hour:'Час UTC', day:'День UTC', time:'Время обращения'
};
const selectedHosts = new Set();
const groupingFields = ['host','src','proto','dport','asn','netname','family','tcp_flags','ttl','icmp_type'];
const openDiagnostics = new Set();
const rowFields = ['time','host','src','proto','dport','netname'];
const selectableColumns = [...rowFields,'asn','family','dst','sport','iface','tcp_flags','ttl','packet_length','icmp_type','icmp_code'];
const viewPreferenceKey = 'trafficguard.event-view.v1';
const sortLabels = {count:'Пакетов',first_seen:'Первое событие',last_seen:'Последнее событие'};
let overviewSort = {};
const browserTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
let selectedTimezone = browserTimezone;
let sshGuideLoaded = false;
const dateOptions = {
  year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'
};
let dateFormat = new Intl.DateTimeFormat('ru-RU',{...dateOptions,timeZone:selectedTimezone});
const number = new Intl.NumberFormat('ru-RU');
let model = null;
let columns = [...rowFields];
let groups = [];
try {
  const saved = JSON.parse(localStorage.getItem(viewPreferenceKey));
  if (Array.isArray(saved?.columns)) {
    const selected = selectableColumns.filter(field => saved.columns.includes(field));
    if (selected.length) columns = selected;
  }
  if (Array.isArray(saved?.groups)) {
    groups = [...new Set(saved.groups)].filter(field => columns.includes(field) && groupingFields.includes(field));
  }
} catch { /* Browser storage can be unavailable. */ }
let filters = [];
let page = 1;
let viewRequest = 0;
let expanded = null;
let dialogAction;
let noticeTimer;
let lastView = 0;
let settingsDirty = false;

function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== null && text !== undefined) element.textContent = String(text);
  if (className) element.className = className;
  return element;
}
function button(text, handler, kind='quiet') {
  const element = node('button',text,kind);
  element.type = 'button';
  element.addEventListener('click',handler);
  return element;
}
function values(form) { return Object.fromEntries(new FormData(form)); }
function show(el, content, kind) {
  el.textContent = content || '';
  el.hidden = !content;
  if (kind !== undefined) el.classList.toggle('error',kind);
}
function date(value) { return value ? dateFormat.format(value) : '—'; }
function fieldValue(field, value) {
  if (value === null || value === undefined) return '—';
  if (field === 'host') return model?.hosts.find(item => item.id === value)?.alias || String(value);
  if (field === 'family') return 'IPv' + value;
  if (field === 'time') return date(value);
  if (field === 'hour') return new Date(value).toISOString().slice(0,13).replace('T',' ') + ':00 UTC';
  if (field === 'day') return new Date(value).toISOString().slice(0,10) + ' UTC';
  return String(value);
}
function announce(text, error=false) {
  clearTimeout(noticeTimer);
  show($('notice'),text,error);
  noticeTimer = setTimeout(() => show($('notice'),''),6500);
}
const settingsSections = ['hosts','credentials','storage','audit','account','ssh-guide'];
async function api(path, method='GET', data) {
  const headers = {'Accept':'application/json','X-Panel-Request':'1'};
  if (data !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch('/api/' + path,{method,headers,body:data===undefined ? undefined : JSON.stringify(data)});
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && path !== 'login' && !path.startsWith('enroll')) void showLogin();
    const error = new Error(result.error || 'Не удалось выполнить запрос.');
    error.status = response.status;
    throw error;
  }
  return result;
}
async function showLogin() {
  model = null;
  ++viewRequest;
  if ($('dialog').open) $('dialog').close();
  $('shell').hidden = true;
  $('account-password-form').reset();
  show($('account-password-error'),'');
  $('setup-password-form').hidden = true;
  $('setup-password-form').reset();
  $('login-code-form').hidden = true;
  $('login-code-form').reset();
  $('enroll-form').hidden = true;
  $('enroll-form').reset();
  $('enroll-qr').removeAttribute('src');
  $('login-title').textContent = 'Вход в панель';
  const form = $('login-form');
  form.hidden = false;
  const submit = form.querySelector('button');
  submit.disabled = true;
  show($('login-error'),'');
  $('login').hidden = false;
  try {
    const status = await api('auth/status');
    submit.disabled = !status.configured && !status.enrollment_available;
    if (submit.disabled) show($('login-error'),'Для первой настройки откройте панель по локальному адресу.');
  } catch(error) {
    show($('login-error'),error.message);
  }
}
function showEnrollment() {
  $('login-form').hidden = true;
  $('setup-password-form').hidden = true;
  $('login-title').textContent = 'Настройка двухфакторного входа';
  $('enroll-form').hidden = false;
  $('enroll-qr').src = '/api/enroll/qr';
  $('enroll-form').elements.totp.focus();
}
function showPasswordSetup() {
  $('login-form').hidden = true;
  $('login-code-form').hidden = true;
  $('login-title').textContent = 'Установите новый пароль';
  $('setup-password-form').hidden = false;
  $('setup-password-form').elements.new_password.focus();
}
async function syncState() {
  model = await api('state');
  selectedTimezone = model.settings.timezone || browserTimezone;
  dateFormat = new Intl.DateTimeFormat('ru-RU',{...dateOptions,timeZone:selectedTimezone});
  $('table-timezone').textContent = 'Время в таблице · '+selectedTimezone;
  $('login').hidden = true;
  $('shell').hidden = false;
  const active = model.hosts.filter(host => host.enabled).length;
  $('active-hosts').textContent = number.format(active);
  $('last-sync').textContent = date(Math.max(0,...model.hosts.map(host => host.success_at || 0)));
  $('collect').disabled = active === 0;
}
function route() {
  const hash = location.hash.slice(1);
  const settings = hash.split('/')[0] === 'settings';
  const sub = settingsSections.includes(hash.split('/')[1]) ? hash.split('/')[1] : 'hosts';
  return {settings,sub};
}
function active(el, selected) {
  el.classList.toggle('active',selected);
  if (selected) el.setAttribute('aria-current','page');
  else el.removeAttribute('aria-current');
}
async function renderRoute() {
  if (!model) return;
  const {settings,sub} = route();
  active($('overview-tab'),!settings);
  active($('settings-tab'),settings);
  $('settings').hidden = !settings;
  $('overview').hidden = settings;
  if (!settings) {
    renderChips();
    await loadEvents();
    return;
  }
  for (const link of $('settings-nav').querySelectorAll('a')) active(link,link.hash.endsWith('/'+sub));
  for (const name of settingsSections) $(name+'-panel').hidden = name!==sub;
  if (sub === 'hosts') renderHosts();
  if (sub === 'credentials') renderCredentials();
  if (sub === 'ssh-guide') await renderSshGuide();
  if (sub === 'account') $('timezone-form').elements.timezone.value = selectedTimezone;
  if (sub === 'storage') {
    const form = $('storage-form');
    if (!settingsDirty) for (const key of ['poll_seconds','retention_days']) form.elements[key].value = model.settings[key];
  }
  if (sub === 'audit') await renderAudit();
}
function formField(title,input) {
  const label = node('label',title);
  label.append(input);
  return label;
}
function input(name,value='',opts={}) {
  const element = node(opts.multiline?'textarea':'input');
  element.name = name;
  element.value = value ?? '';
  const {multiline,...attributes} = opts;
  for (const [key,val] of Object.entries(attributes)) element[key] = val;
  return element;
}
function select(name,options,current) {
  const element = node('select');
  element.name = name;
  for (const [value,text] of options) {
    const opt = node('option',text);
    opt.value = value;
    element.append(opt);
  }
  if (current !== undefined) element.value = current;
  return element;
}
function dialog(title,children,action,saveText='Сохранить') {
  $('dialog-title').textContent = title;
  $('dialog-body').replaceChildren(...children);
  show($('dialog-error'),'');
  $('dialog-save').textContent = saveText;
  $('dialog-save').hidden = !action;
  $('dialog-save').disabled = false;
  $('dialog-cancel').textContent = action ? 'Отмена' : 'Закрыть';
  dialogAction = action;
  if (!$('dialog').open) $('dialog').showModal();
}
function confirmAction(title,message,action,saveText) {
  dialog(title,[node('p',message,'muted')],action,saveText);
}
async function afterEdit(text) {
  await syncState();
  await renderRoute();
  if (text) announce(text);
}

function renderHosts() {
  const list = $('hosts-list');
  list.replaceChildren();
  const available = new Set(model.hosts.map(host => host.id));
  for (const id of selectedHosts) if (!available.has(id)) selectedHosts.delete(id);
  $('host-export').hidden = !model.hosts.length;
  if (!model.hosts.length) list.append(node('p','Добавьте хост или импортируйте список.','empty'));
  for (const host of model.hosts) {
    const record = node('article',null,'record');
    const main = node('div',null,'record-main');
    const title = node('strong',host.alias);
    const status = host.collecting ? 'Чтение…' : !host.credential_id ? 'Нет учётных данных' :
      !host.enabled ? 'Опрос выключен' :
      host.error ? 'Требует внимания' : host.success_at ? 'В сборе' : 'Ожидает сбора';
    title.append(node('span',status,'badge'+(host.error?' warn':host.success_at&&host.enabled?' good':'')));
    const address = host.address.includes(':') ? '['+host.address+']' : host.address;
    main.append(title,node('p',address+':'+host.port+(host.credential_name?' · '+host.credential_name:''),'mono'));
    if (host.credential_hint) main.append(node('p','Ожидает привязки: '+host.credential_hint));
    if (host.error) main.append(node('p',host.error,'warn'));
    else if (host.checked_at) main.append(node('p','Проверено: '+date(host.checked_at)));
    if (host.journal_gap) main.append(node('p','В истории журнала обнаружен возможный пропуск.','warn'));
    if (host.diagnostics) {
      const report = host.diagnostics;
      const state = value => value === true ? 'да' : value === false ? 'нет' : 'нет доступа к проверке';
      const result = node('details',null,'host-diagnostics');
      result.append(node('summary','Диагностика · '+date(report.checked_at)+(report.elapsed_ms!=null?' · '+number.format(report.elapsed_ms)+' мс':'')));
      if (report.ssh_error) {
        result.append(node('p',report.ssh_error,'warn'));
      } else {
        result.append(
          node('p','Признаки установки TrafficGuard: '+state(report.installed)),
          node('p','Логирование IPv4: '+state(report.logging.v4)+' · IPv6: '+state(report.logging.v6)),
          node('p','Журнал: '+({events:'доступен, есть события',empty:'доступен, событий нет',unavailable:'недоступен'}[report.journal])),
          node('p','CSV для сведений о сетях: '+(report.csv==='readable'?'читается':'недоступен или неверный формат'))
        );
        for (const [key,label] of [['rules_error','Правила'],['journal_error','Журнал'],['csv_error','CSV']]) {
          if (report[key]) result.append(node('p',label+': '+report[key],'warn'));
        }
      }
      result.open = openDiagnostics.has(host.id) || Boolean(report.ssh_error);
      result.ontoggle = () => result.open ? openDiagnostics.add(host.id) : openDiagnostics.delete(host.id);
      main.append(result);
    }
    const check = button('Проверить',async () => {
      try {
        openDiagnostics.add(host.id);
        const result = await api('hosts/'+host.id+'/check','POST',{});
        await syncState();
        renderHosts();
        announce(result.queued?'Проверка поставлена в очередь.':'Сборщик занят. Повторите чуть позже.');
      } catch(error){ announce(error.message,true); }
    });
    check.disabled = Boolean(host.collecting || !host.credential_id);
    const actions = node('div',null,'actions');
    actions.append(check,button('Изменить',() => editHost(host)),button('Удалить',() => {
      confirmAction('Удалить хост',`Хост «${host.alias}» и его история событий будут удалены.`,async () => {
        await api('hosts/'+host.id,'DELETE');
        await afterEdit('Хост удалён.');
      },'Удалить');
    }));
    const selection = input('host',host.id,{type:'checkbox',checked:selectedHosts.has(host.id)});
    selection.setAttribute('aria-label','Выбрать '+host.alias);
    selection.onchange = () => {
      if (selection.checked) selectedHosts.add(host.id);
      else selectedHosts.delete(host.id);
      renderHostSelection();
    };
    record.classList.add('host-record');
    record.append(selection,main,actions);
    list.append(record);
  }
  renderHostSelection();
}
function renderHostSelection() {
  const count = selectedHosts.size;
  const all = $('select-hosts');
  all.checked = count>0 && count===model.hosts.length;
  all.indeterminate = count>0 && !all.checked;
  all.disabled = model.hosts.length===0;
  $('selected-host-count').textContent = count ? 'Выбрано: '+number.format(count) : '';
  for (const action of ['enable','disable','delete','credential']) {
    $('bulk-'+action).disabled = count===0 || (action==='credential' && model.credentials.length===0);
  }
}
async function runBulk(action,ids,credential_id) {
  const result = await api('hosts/bulk','POST',{action,ids,credential_id});
  for (const id of ids) selectedHosts.delete(id);
  const message = {enable:'Сбор включён',disable:'Сбор отключён',delete:'Хосты удалены',
    credential:'Учётные данные назначены'}[action];
  await afterEdit(message+' · '+number.format(result.count));
}
function editHost(host={}) {
  const credentials = [[ '', 'Выберите учётные данные' ],...model.credentials.map(row => [row.id,row.name+' · '+row.username])];
  const fields = [
    formField('Алиас',input('alias',host.alias,{required:true,maxLength:80,placeholder:'Например, jp-1'})),
    formField('Адрес SSH',input('address',host.address,{required:true,maxLength:253,placeholder:'Домен, IPv4 или IPv6'})),
    formField('Порт SSH',input('port',host.port ?? 22,{type:'number',min:1,max:65535,required:true})),
    formField('Учётные данные',select('credential_id',credentials,host.credential_id ?? '')),
    formField('Доступ к журналу',select('mode',[['direct','Прямое чтение'],['sudo','sudo -n · помощник TrafficGuard']],host.mode || 'direct')),
  ];
  fields.push($('trafficguard-install-help').content.cloneNode(true));
  const check = node('label',null,'check-row');
  const enabled = input('enabled','1',{type:'checkbox',checked:Boolean(host.enabled)});
  check.append(enabled,document.createTextNode('Включить фоновый опрос'));
  fields.push(check);
  dialog(host.id?'Изменить хост':'Добавить хост',fields,async form => {
    const data = values(form);
    data.enabled = enabled.checked;
    data.credential_id = data.credential_id ? Number(data.credential_id) : null;
    data.port = Number(data.port);
    await api('hosts'+(host.id?'/'+host.id:''),host.id?'PUT':'POST',data);
    await afterEdit('Хост сохранён.');
  });
}
function renderCredentials() {
  const list = $('credentials-list');
  list.replaceChildren();
  if (!model.credentials.length) list.append(node('p','Сохраните ключ SSH или логин с паролем.','empty'));
  for (const credential of model.credentials) {
    const record = node('article',null,'record');
    const main = node('div',null,'record-main');
    main.append(node('strong',credential.name),node('p',
      (credential.kind==='key'?'SSH-ключ':'Логин и пароль')+' · '+credential.username));
    if (credential.fingerprint) main.append(node('p',credential.fingerprint,'mono'));
    const actions = node('div',null,'actions');
    actions.append(button('Изменить',() => editCredential(credential)),button('Удалить',() => {
      confirmAction('Удалить учётные данные',`Удалить «${credential.name}»? Сначала отвяжите запись от хостов.`,async () => {
        await api('credentials/'+credential.id,'DELETE');
        await afterEdit('Учётные данные удалены.');
      },'Удалить');
    }));
    record.append(main,actions);
    list.append(record);
  }
}
function editCredential(credential={}) {
  const type = select('kind',[['key','SSH-ключ'],['password','Логин и пароль']],credential.kind || 'key');
  const secretFields = node('div',null,'fields');
  function updateSecretFields() {
    const keep = credential.id && credential.kind===type.value;
    secretFields.replaceChildren();
    if (type.value === 'key') {
      const key = input('value','',{multiline:true,required:!keep,maxLength:32768,spellcheck:false,autocomplete:'off',placeholder:keep?'Оставьте пустым, чтобы сохранить текущий ключ':'-----BEGIN OPENSSH PRIVATE KEY-----'});
      const picker = node('input');
      picker.type = 'file';
      picker.hidden = true;
      const fileStatus = node('small');
      fileStatus.setAttribute('role','status');
      fileStatus.hidden = true;
      let selection = 0;
      picker.addEventListener('change',async () => {
        const file = picker.files[0];
        picker.value = '';
        if (!file) return;
        const current = ++selection;
        key.setCustomValidity('Подождите, пока файл загрузится в поле.');
        show(fileStatus,'Читаем файл…');
        try {
          const tooLarge = 'Приватный ключ должен быть не длиннее 32 768 символов.';
          if (file.size > key.maxLength * 4) throw new Error(tooLarge);
          const contents = await file.text();
          if (current !== selection || !key.isConnected) return;
          if (contents.length > key.maxLength) throw new Error(tooLarge);
          if (!contents.trim()) throw new Error('Файл пуст.');
          key.value = contents;
          show(fileStatus,`Ключ из файла «${file.name}» подставлен в поле.`);
        } catch(error) {
          if (current === selection) show(fileStatus,error instanceof Error ? error.message : 'Не удалось прочитать файл.');
        } finally {
          if (current === selection) key.setCustomValidity('');
        }
      });
      const chooseFile = button('Выбрать файл ключа',() => picker.click(),'secondary key-file');
      secretFields.append(node('p','Для панели заведите отдельного SSH-пользователя с ключом и разрешите ему только чтение событий TrafficGuard.','hint'),
        formField('Приватный SSH-ключ',key),chooseFile,picker,fileStatus,
        formField('Парольная фраза ключа',input('passphrase','',{type:'password',maxLength:1024,autocomplete:'new-password'})));
    } else {
      secretFields.append(node('p','Для безопасности настоятельно рекомендуем перейти на SSH-ключ. Сгенерируйте пару ключей, проверьте вход по ключу в отдельной сессии и затем отключите парольный вход.','hint warning'),
        formField('SSH-пароль',input('value','',{type:'password',required:!keep,maxLength:32768,autocomplete:'new-password',placeholder:keep?'Оставьте пустым, чтобы сохранить текущий пароль':''})));
    }
  }
  type.addEventListener('change',updateSecretFields);
  updateSecretFields();
  dialog(credential.id?'Изменить учётные данные':'Добавить учётные данные',[
    formField('Название',input('name',credential.name,{required:true,maxLength:80})),
    formField('Тип',type),
    formField('SSH-пользователь',input('username',credential.username,{required:true,maxLength:80})),
    secretFields,
    node('small','Секрет сохраняется в зашифрованном виде. В карточке отображаются только название, пользователь и отпечаток ключа.')
  ],async form => {
    await api('credentials'+(credential.id?'/'+credential.id:''),credential.id?'PUT':'POST',values(form));
    await afterEdit('Учётные данные сохранены.');
  });
}
async function previewImport(file) {
  if (!file) return;
  if (file.size>300*1024) throw new Error('Файл импорта должен быть меньше 300 КБ.');
  let bundle;
  try { bundle = JSON.parse(await file.text()); }
  catch { throw new Error('Выберите корректный JSON-файл экспорта.'); }
  const preview = await api('hosts/import','POST',{bundle});
  const list = node('div',null,'records');
  const count = preview.rows.filter(row => row.status==='ready').length;
  const options = [['','Без привязки'],...model.credentials.map(item => [item.id,item.name+' · '+item.username])];
  const missing = [];
  const bindings = [];
  for (const row of preview.rows) {
    const record = node('div',null,'record');
    const main = node('div',null,'record-main');
    main.append(node('strong',row.alias),node('p',row.address+':'+row.port),
                node('p',row.status==='conflict'?'Совпадение · будет пропущен':
                  row.credential_found?'Учётные данные найдены':'Потребуется привязать учётные данные'));
    record.append(main);
    if (row.status === 'ready') {
      const choice = select('',options,row.credential_id ?? '');
      bindings.push([row.index,choice]);
      if (!row.credential_found) missing.push(choice);
      record.append(formField('Учётные данные',choice));
    }
    list.append(record);
  }
  const fields = [node('p',`К добавлению: ${count}. Совпадений: ${preview.rows.length-count}. Опрос новых хостов включается в их настройках.`,'muted')];
  if (missing.length && options.length > 1) {
    const bulk = select('',options,'');
    bulk.onchange = () => { for (const choice of missing) choice.value = bulk.value; };
    fields.push(formField('Учётные данные для всех хостов без совпадения',bulk));
  }
  fields.push(list);
  dialog('Проверить импорт',fields,count?async () => {
    const credentials = Object.fromEntries(bindings
      .map(([index,choice]) => [index,choice.value ? Number(choice.value) : null]));
    const result = await api('hosts/import','POST',{bundle,credentials,confirm:true});
    await afterEdit(`Добавлено хостов: ${result.rows.filter(item => item.status==='ready').length}.`);
  }:null,'Импортировать');
}
async function renderSshGuide() {
  if (sshGuideLoaded) return;
  const response = await fetch('/static/ssh-guide.md');
  if (!response.ok) throw new Error('Не удалось загрузить инструкцию.');
  const blocks = (await response.text()).split(/^~~~[^\n]*\n?/m);
  const article = $('ssh-guide-body');
  article.replaceChildren();
  for (const [index,block] of blocks.entries()) {
    if (index % 2 === 1) {
      const code = block.trimEnd();
      const panel = node('div',null,'guide-command');
      const pre = node('pre');
      pre.append(node('code',code));
      panel.append(pre,button('Копировать',async () => {
        try { await navigator.clipboard.writeText(code); announce('Команды скопированы.'); }
        catch { announce('Выделите и скопируйте команды вручную.',true); }
      }));
      article.append(panel);
    } else {
      for (const line of block.split('\n').filter(Boolean)) {
        if (line.startsWith('### ')) article.append(node('h4',line.slice(4)));
        else if (line.startsWith('## ')) article.append(node('h3',line.slice(3)));
        else article.append(node('p',line));
      }
    }
  }
  sshGuideLoaded = true;
}
async function renderAudit() {
  const {rows} = await api('audit');
  if (!model || route().sub!=='audit') return;
  const list = $('audit-list');
  const actions = {'admin.created':'Создан администратор','admin.reset':'Обновлён доступ администратора',
    'admin.password_changed':'Изменён пароль администратора','login':'Вход','hosts.bulk':'Групповое действие с хостами',
    'logout':'Выход','credential.created':'Добавлены учётные данные','credential.updated':'Изменены учётные данные',
    'credential.deleted':'Удалены учётные данные','host.created':'Добавлен хост','host.updated':'Изменён хост',
    'host.deleted':'Удалён хост','hosts.exported':'Экспортированы хосты','hosts.imported':'Импортированы хосты',
    'settings.updated':'Сохранены параметры сбора'};
  list.replaceChildren(...rows.map(row => {
    const entry = node('div',null,'record');
    entry.append(node('span',(actions[row.action] || row.action)+(row.detail?' · '+row.detail:'')),
      node('span',date(row.stamp),'muted'));
    return entry;
  }));
}

function addFilter(field,value,op) {
  if (!filters.some(item => item.field===field && item.value===value && item.op===op)) {
    filters = [...filters,{field,value,op}];
  }
  page = 1;
  renderChips();
}
function renderChips() {
  $('group-summary').textContent = groups.length?'Группировка: '+groups.map(field => labels[field]).join(' · '):'Построчный просмотр';
  const chips = $('chips');
  chips.replaceChildren();
  for (const [index,item] of filters.entries()) {
    const chip = button((item.op==='out'?'Исключить ': '')+labels[item.field]+': '+fieldValue(item.field,item.value)+' ×',() => {
      filters = filters.filter((_,i) => i!==index);
      page = 1;
      renderChips();
      loadEvents();
    },item.op==='out'?'chip out':'chip');
    chips.append(chip);
  }
  if (filters.length>1) chips.append(button('Сбросить фильтры',() => {
    filters = [];
    page = 1;
    renderChips();
    loadEvents();
  },'text-button'));
}
function filterMenu(field,value) {
  const included = button('Добавить в фильтр',() => {
    addFilter(field,value,'in');
    $('dialog').close();
    loadEvents();
  },'primary');
  const excluded = button('Исключить',() => {
    addFilter(field,value,'out');
    $('dialog').close();
    loadEvents();
  },'secondary');
  const actions = node('div',null,'actions');
  actions.append(included,excluded);
  dialog(labels[field],[node('p',fieldValue(field,value),'mono'),actions],null);
}
function filterEditor() {
  const field = select('field',Object.entries(labels),'host');
  const op = select('op',[['in','Включить'],['out','Исключить']],'in');
  const slot = node('div',null,'fields');
  function update() {
    let value;
    if (field.value==='host') value=select('value',model.hosts.map(host => [host.id,host.alias]));
    else if (field.value==='proto') value=select('value',[['TCP','TCP'],['UDP','UDP'],['ICMP','ICMP'],['ICMPv6','ICMPv6'],['OTHER','Другой']]);
    else if (field.value==='family') value=select('value',[[4,'IPv4'],[6,'IPv6']]);
    else if (['time','hour','day'].includes(field.value)) value=input('value','',{type:'datetime-local',required:true});
    else value=input('value','',{required:true,maxLength:180,placeholder:['src','dst'].includes(field.value)?'IP или CIDR':'Введите значение'});
    slot.replaceChildren(formField('Значение',value));
  }
  field.addEventListener('change',update);
  update();
  dialog('Добавить фильтр',[formField('Поле',field),formField('Условие',op),slot],async form => {
    const data = values(form);
    let value = data.value;
    if (!value) throw new Error('Выберите значение фильтра.');
    if (['host','dport','sport','family','packet_length','ttl','icmp_type','icmp_code'].includes(data.field)) {
      if (!/^\d+$/.test(value)) throw new Error('Введите целое число.');
      value = Number(value);
      const maximum = {dport:65535,sport:65535,ttl:255,icmp_type:255,icmp_code:255,packet_length:4294967295}[data.field];
      if (maximum !== undefined && value>maximum) throw new Error('Значение выходит за допустимый диапазон.');
    }
    if (['time','hour','day'].includes(data.field)) {
      value = new Date(value).getTime();
      const unit = data.field==='day'?86400000:data.field==='hour'?3600000:1;
      value = Math.floor(value/unit)*unit;
    }
    addFilter(data.field,value,data.op);
    await loadEvents();
  },'Добавить');
}
function renderGroupFields() {
  const choices = $('group-fields');
  choices.replaceChildren();
  const available = columns.filter(field => groupingFields.includes(field));
  if (!available.length) choices.append(node('p','Выберите поля через шестерёнку в таблице.','muted'));
  for (const key of available) {
    const label = node('label',null,'check-row');
    const field = input('group',key,{type:'checkbox',checked:groups.includes(key)});
    field.onchange = () => applyGroups(field.checked ? [...groups,key] : groups.filter(item => item!==key));
    label.append(field,document.createTextNode(labels[key]));
    choices.append(label);
  }
  $('clear-groups').disabled = groups.length===0;
}
function applyGroups(next) {
  groups = next;
  try { localStorage.setItem(viewPreferenceKey,JSON.stringify({columns,groups})); }
  catch { /* Continue with the current view. */ }
  overviewSort = {};
  page = 1;
  $('clear-groups').disabled = groups.length===0;
  renderChips();
  loadEvents();
}
function renderColumnSettings() {
  const choices = $('column-settings');
  choices.replaceChildren();
  const fields = [];
  for (const key of selectableColumns) {
    const label = node('label',null,'check-row');
    const field = input('column',key,{type:'checkbox',checked:columns.includes(key)});
    fields.push(field);
    field.disabled = field.checked && columns.length===1;
    field.onchange = () => {
      const selected = fields.filter(item => item.checked).map(item => item.value);
      if (!selected.length) {
        field.checked = true;
        return;
      }
      updateColumns(selected);
      for (const item of fields) item.disabled = item.checked && columns.length===1;
    };
    label.append(field,document.createTextNode(labels[key]));
    choices.append(label);
  }
  choices.append(button('Стандартные колонки',() => {
    updateColumns([...rowFields]);
    renderColumnSettings();
  }));
}
function updateColumns(selected) {
  columns = selected;
  applyGroups(groups.filter(field => columns.includes(field)));
  if (!$('group-sidebar-content').hidden) renderGroupFields();
}
function positionColumnSettings() {
  const menu = $('column-settings');
  const anchor = $('open-columns').getBoundingClientRect();
  const left = Math.max(8, Math.min(anchor.right-menu.offsetWidth, window.innerWidth-menu.offsetWidth-8));
  const below = window.innerHeight-anchor.bottom-8;
  const above = anchor.top-8;
  const opensDown = below>=menu.scrollHeight+6 || below>=above;
  menu.style.setProperty('--columns-left',left+'px');
  menu.style.setProperty('--columns-top',opensDown?anchor.bottom+6+'px':'auto');
  menu.style.setProperty('--columns-bottom',opensDown?'auto':window.innerHeight-anchor.top+6+'px');
  menu.style.setProperty('--columns-height',Math.max(0,(opensDown?below:above)-6)+'px');
}
function query() {
  const period = $('period').value;
  let since;
  let until;
  if (period==='custom') {
    since = $('since').value || undefined;
    until = $('until').value || undefined;
  } else if (period!=='all') since = new Date(Date.now()-Number(period)*86400000).toISOString();
  return {since,until,filters,groups,page,all_time:period==='all',
    timezone:period==='custom'?selectedTimezone:undefined,...overviewSort};
}
function tableHead(fields,grouped,sorting,sortBy) {
  const row = node('tr');
  if (grouped) row.append(node('th',null,'expand-cell'));
  const columns = grouped ? [...fields,'count','first_seen','last_seen'] : fields;
  for (const field of columns) {
    const current = sorting.sort===field || (!sorting.sort && field===(grouped?'count':'time'));
    const direction = current ? (sorting.direction || 'desc') : null;
    const header = node('th');
    if (current) header.setAttribute('aria-sort',direction==='asc'?'ascending':'descending');
    header.append(button((labels[field] || sortLabels[field])+(current?(direction==='asc'?' ↑':' ↓'):''),
      () => sortBy({sort:field,direction:direction==='asc'?'desc':'asc'}),'sort-button'));
    row.append(header);
  }
  if (!grouped) row.append(node('th','Детали'));
  return row;
}
function tableRow(fields,row,grouped,context) {
  const line = node('tr');
  if (grouped) {
    const expand = button('›',() => expandGroup(line,fields,row,context,expand),'expand-button');
    expand.setAttribute('aria-label',`Показать события группы, ${row.count} пакетов`);
    expand.setAttribute('aria-expanded','false');
    const cell = node('td',null,'expand-cell');
    cell.append(expand);
    line.append(cell);
  }
  for (const field of fields) {
    const value = !grouped && field==='host'?row.host_id:!grouped && field==='time'?row.stamp:row[field];
    const cell = node('td',null,['time','hour','day'].includes(field)?'time':undefined);
    if (field==='netname' && grouped && row.netname_mixed) cell.textContent = 'Разные';
    else cell.append(button(fieldValue(field,value),() => filterMenu(field,value),'cell-link'));
    line.append(cell);
  }
  if (grouped) {
    line.append(node('td',number.format(row.count),'number'),node('td',date(row.first_seen),'time'),node('td',date(row.last_seen),'time'));
  } else {
    const cell = node('td');
    cell.append(button('Открыть',() => {
      const blocks = Object.keys(labels).map(field => {
        const value = field==='host'?row.host_id:field==='time'?row.stamp:row[field];
        const entry = node('div',null,'record');
        entry.append(node('span',labels[field]),button(fieldValue(field,value),() => filterMenu(field,value),'cell-link'));
        return entry;
      });
      dialog('Детали пакета',blocks,null);
    },'text-button'));
    line.append(cell);
  }
  return line;
}
function pager(container,current,more,selectPage) {
  container.replaceChildren();
  container.hidden = current===1 && !more;
  const back = button('← Назад',() => selectPage(current-1));
  const next = button('Вперёд →',() => selectPage(current+1));
  back.disabled = current===1;
  next.disabled = !more;
  container.append(back,node('span','Страница '+current),next);
}
async function loadEvents() {
  if (!model) return;
  const counter = ++viewRequest;
  expanded = null;
  try {
    const context = query();
    const result = await api('events','POST',context);
    if (counter!==viewRequest || route().settings || !model) return;
    lastView = Date.now();
    $('total').textContent = number.format(result.total);
    const fields = context.groups.length?[...context.groups]:columns;
    if (context.groups.length && columns.includes('netname') && !fields.includes('netname')) {
      const source = fields.indexOf('src');
      fields.splice(source===-1?fields.length:source+1,0,'netname');
    }
    const headings = tableHead(fields,Boolean(context.groups.length),overviewSort,sort => {
      overviewSort = sort;
      page = 1;
      loadEvents();
    });
    const header = $('events-head');
    for (const cell of Array.from(header.children)) if (cell.id !== 'column-settings-cell') cell.remove();
    header.prepend(...headings.children);
    $('events-body').replaceChildren(...result.rows.map(row => {
      const line = tableRow(fields,row,Boolean(context.groups.length),context);
      line.append(node('td',null,'column-settings-space'));
      return line;
    }));
    if ($('column-settings').matches(':popover-open')) positionColumnSettings();
    show($('events-empty'),result.rows.length?'':'За выбранный период событий нет.');
    pager($('events-pages'),result.page,result.more,next => {page=next;loadEvents();});
  } catch(error) {
    if (counter===viewRequest && model && !route().settings) {
      $('total').textContent = '—';
      $('events-body').replaceChildren();
      $('events-pages').hidden = true;
      show($('events-empty'),error.message);
    }
  }
}
function expandGroup(line,fields,row,context,trigger) {
  if (expanded) {
    const same = expanded.trigger===trigger;
    expanded.trigger.setAttribute('aria-expanded','false');
    expanded.line.remove();
    expanded = null;
    if (same) return;
  }
  const detailLine = node('tr',null,'detail-row');
  const cell = node('td');
  cell.colSpan = fields.length+5;
  const box = node('div',null,'details');
  cell.append(box);
  detailLine.append(cell);
  line.after(detailLine);
  trigger.setAttribute('aria-expanded','true');
  expanded = {trigger,line:detailLine};
  const keys = Object.fromEntries(context.groups.map(field => [field,row[field]]));
  let detailSort = {};
  let detailRequest = 0;
  async function showPage(detailPage) {
    const request = ++detailRequest;
    box.replaceChildren(node('p','Загрузка событий…','muted'));
    try {
      const result = await api('events/detail','POST',{...context,sort:null,...detailSort,keys,page:detailPage});
      if (!detailLine.isConnected || request!==detailRequest) return;
      const table = node('table');
      const head = node('thead');
      const body = node('tbody');
      head.append(tableHead(rowFields,false,detailSort,sort => {
        detailSort = sort;
        showPage(1);
      }));
      body.append(...result.rows.map(event => tableRow(rowFields,event,false,context)));
      table.append(head,body);
      const wrap = node('div',null,'table-scroll');
      wrap.append(table);
      const pages = node('div',null,'pager');
      box.replaceChildren(node('h3','События группы'),result.rows.length?wrap:node('p','События за этот период недоступны.','muted'),pages);
      pager(pages,result.page,result.more,showPage);
    } catch(error) { box.replaceChildren(node('p',error.message,'form-error')); }
  }
  showPage(1);
}

$('login-form').addEventListener('submit',async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button');
  submit.disabled = true;
  show($('login-error'),'');
  try {
    const result = await api('login','POST',values(form));
    form.reset();
    if (result.totp_required) {
      form.hidden = true;
      $('login-title').textContent = 'Подтвердите вход';
      $('login-code-form').hidden = false;
      $('login-code-form').elements.totp.focus();
      return;
    }
    if (result.password_change_required) {
      showPasswordSetup();
      return;
    }
    if (result.enrollment_required) {
      showEnrollment();
      return;
    }
    await syncState();
    await renderRoute();
  } catch(error){ show($('login-error'),error.message); }
  finally { submit.disabled = false; }
});
$('login-code-back').onclick=() => showLogin();
$('login-code-form').onsubmit=async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button');
  submit.disabled = true;
  show($('login-error'),'');
  try {
    const result = await api('enroll/login','POST',values(form));
    form.reset();
    if (result.password_change_required) showPasswordSetup();
    else { await syncState(); await renderRoute(); }
  } catch(error) {
    if (error.status === 410) await showLogin();
    else form.elements.totp.select();
    show($('login-error'),error.message);
  } finally { submit.disabled = false; }
};
$('setup-password-form').addEventListener('submit',async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button');
  submit.disabled = true;
  show($('login-error'),'');
  try {
    const result = await api('enroll/password','POST',values(form));
    form.reset();
    if (result.enrollment_required) {
      showEnrollment();
      return;
    }
    await syncState();
    await renderRoute();
  } catch(error) {
    if (error.status === 410) await showLogin();
    show($('login-error'),error.message);
  } finally { submit.disabled = false; }
});
$('enroll-form').addEventListener('submit',async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button');
  submit.disabled = true;
  show($('login-error'),'');
  try {
    await api('enroll','POST',values(form));
    form.reset();
    await syncState();
    await renderRoute();
  } catch(error) {
    if (error.status === 410) await showLogin();
    else form.elements.totp.select();
    show($('login-error'),error.message);
  } finally { submit.disabled = false; }
});
$('logout').onclick=async () => {
  try { await api('logout','POST',{}); await showLogin(); }
  catch(error) { if (model) announce(error.message,true); }
};
$('dialog-close').onclick=$('dialog-cancel').onclick=() => $('dialog').close();
$('dialog-form').addEventListener('submit',async event => {
  event.preventDefault();
  if (!dialogAction) return;
  $('dialog-save').disabled = true;
  show($('dialog-error'),'');
  try { await dialogAction(event.currentTarget); $('dialog').close(); }
  catch(error){ show($('dialog-error'),error.message); }
  finally { $('dialog-save').disabled = false; }
});
$('open-filter').onclick=filterEditor;
$('open-group').onclick=() => {
  const content = $('group-sidebar-content');
  content.hidden = !content.hidden;
  $('open-group').setAttribute('aria-expanded',String(!content.hidden));
  if (!content.hidden) renderGroupFields();
};
$('column-settings').addEventListener('beforetoggle',event => {
  if (event.newState === 'open') renderColumnSettings();
});
$('column-settings').addEventListener('toggle',event => {
  if (event.newState === 'open') positionColumnSettings();
});
window.addEventListener('resize',() => {
  if ($('column-settings').matches(':popover-open')) positionColumnSettings();
});
window.addEventListener('scroll',event => {
  const menu = $('column-settings');
  if (menu.matches(':popover-open') && !menu.contains(event.target) && event.target !== document) {
    positionColumnSettings();
  } else if (menu.matches(':popover-open') && event.target === document) {
    menu.hidePopover();
  }
},true);
$('clear-groups').onclick=() => { applyGroups([]); renderGroupFields(); };
$('select-hosts').onchange=event => {
  selectedHosts.clear();
  if (event.currentTarget.checked) for (const host of model.hosts) selectedHosts.add(host.id);
  renderHosts();
};
for (const action of ['enable','disable']) {
  $('bulk-'+action).onclick=() => runBulk(action,[...selectedHosts]).catch(error => announce(error.message,true));
}
$('bulk-delete').onclick=() => {
  const ids = [...selectedHosts];
  confirmAction('Удалить выбранные хосты',`Будут удалены хосты (${ids.length}) и их история событий.`,
    () => runBulk('delete',ids),'Удалить');
};
$('bulk-credential').onclick=() => {
  const ids = [...selectedHosts];
  const options = [['','Выберите учётные данные'],...model.credentials.map(row => [row.id,row.name+' · '+row.username])];
  const choice = select('credential_id',options,'');
  choice.required = true;
  dialog('Назначить учётные данные',[formField('Учётные данные',choice)],
    form => runBulk('credential',ids,Number(form.elements.credential_id.value)),'Назначить');
};
$('add-host').onclick=() => editHost();
$('add-credential').onclick=() => editCredential();
$('host-import').onclick=() => $('import-file').click();
$('import-file').onchange=async event => {
  try { await previewImport(event.target.files[0]); }
  catch(error){ announce(error.message,true); }
  finally { event.target.value=''; }
};
$('collect').onclick=async () => {
  try { const res=await api('collect','POST',{}); announce(`В очереди: ${res.queued}.`); }
  catch(error){ announce(error.message,true); }
};
$('period').onchange=() => {
  $('custom-period').hidden = $('period').value!=='custom';
  page=1;
  loadEvents();
};
for (const id of ['since','until']) $(id).onchange=() => {page=1;loadEvents();};
$('refresh-events').onclick=async () => {
  try { await syncState(); await loadEvents(); }
  catch(error) { if (model) announce(error.message,true); }
};
$('auto-refresh').onchange=() => {
  if ($('auto-refresh').checked && !expanded) $('refresh-events').click();
};
$('storage-form').oninput=() => {settingsDirty=true;};
$('storage-form').onsubmit=async event => {
  event.preventDefault();
  const data = values(event.currentTarget);
  try {
    await api('settings','PUT',data);
    settingsDirty=false;
    await afterEdit('Настройки сохранены.');
  } catch(error){ announce(error.message,true); }
};
for (const zone of [...new Set([browserTimezone,'UTC',...(Intl.supportedValuesOf?.('timeZone') || [])])]) {
  const option = node('option');
  option.value = zone;
  $('timezones').append(option);
}
$('timezone-form').onsubmit=async event => {
  event.preventDefault();
  try {
    await api('settings/timezone','PUT',{timezone:event.currentTarget.elements.timezone.value.trim()});
    await afterEdit('Часовой пояс сохранён.');
  } catch(error) { announce(error.message,true); }
};
$('account-password-form').onsubmit=async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector('button');
  submit.disabled = true;
  show($('account-password-error'),'');
  try {
    await api('account/password','POST',values(form));
    form.reset();
    announce('Пароль изменён. Остальные сеансы завершены.');
  } catch(error) {
    if (error.status !== 401) show($('account-password-error'),error.message);
  } finally { submit.disabled = false; }
};
window.addEventListener('hashchange',() => renderRoute().catch(error => announce(error.message,true)));
setInterval(async () => {
  if (!model || document.hidden) return;
  try {
    const view=route();
    if (!view.settings && !$('auto-refresh').checked) return;
    await syncState();
    if (view.settings && view.sub==='hosts' && !$('dialog').open) renderHosts();
    if (!view.settings && $('auto-refresh').checked && !expanded && page===1 && !$('dialog').open && Date.now()-lastView>10000) await loadEvents();
  } catch { /* expired sessions return to the login form */ }
},5000);
syncState().then(renderRoute).catch(async error => {
  if (error.status !== 401) {
    await showLogin();
    show($('login-error'),error.message);
  }
});

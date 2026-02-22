const state = {
  token: localStorage.getItem('token') || '',
  user: JSON.parse(localStorage.getItem('user') || 'null'),
  ministries: [],
  users: [],
  songs: [],
  services: [],
  serviceSearchResults: [],
  currentService: null,
  availabilityBlocks: [],
  approvals: [],
  swapRequests: [],
  notifications: [],
  logs: [],
  dashboard: null,
};

const TABS = ['dashboard', 'voluntarios', 'repertorio', 'cultos', 'planejamento', 'aprovacoes', 'notificacoes', 'registros', 'ministerios'];
const $ = (id) => document.getElementById(id);
const THEME_KEY = 'theme';

function profilePhotoKey() {
  return state.user?.id ? `profilePhoto:${state.user.id}` : '';
}

function renderProfileCard() {
  if (!state.user) return;
  const saved = localStorage.getItem(profilePhotoKey());
  const photoTop = $('profile-photo-preview');
  const photoPanel = $('account-photo-preview');
  if (saved && photoTop) photoTop.src = saved;
  if (saved && photoPanel) photoPanel.src = saved;
  const accountUserLine = $('account-user-line');
  if (accountUserLine) accountUserLine.textContent = `${state.user.name} (${state.user.role})`;
  const ministriesNode = $('account-ministries');
  if (ministriesNode) {
    const byId = new Map(state.ministries.map((m) => [m.id, m.name]));
    const mine = (state.user.ministryIds || []).map((id) => byId.get(id) || id);
    ministriesNode.innerHTML = mine.length ? mine.map((name) => `<li>${name}</li>`).join('') : '<li>Sem ministério vinculado</li>';
  }
}

function applyTheme(theme) {
  const nextTheme = theme === 'dark' ? 'dark' : 'light';
  document.body.setAttribute('data-theme', nextTheme);
  localStorage.setItem(THEME_KEY, nextTheme);
  const btn = $('theme-toggle');
  if (btn) {
    const nextLabel = nextTheme === 'dark' ? 'Tema claro' : 'Tema escuro';
    btn.setAttribute('aria-label', nextLabel);
    btn.setAttribute('title', nextLabel);
  }
}

function hasRole(...roles) {
  return state.user && roles.includes(state.user.role);
}

function formatDate(v) {
  if (!v) return '-';
  const raw = String(v).trim();
  const m = raw.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) return `${m[3]}-${m[2]}-${m[1]}`;
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return 'Data inválida';
  const d = String(dt.getDate()).padStart(2, '0');
  const mo = String(dt.getMonth() + 1).padStart(2, '0');
  const y = dt.getFullYear();
  return `${d}-${mo}-${y}`;
}

function formatTime(v) {
  if (!v) return '';
  return String(v).slice(0, 5);
}

function tagText(tags) {
  if (!tags || !tags.length) return '-';
  return tags.join(', ');
}

function getServiceDateKey(serviceDate) {
  return String(serviceDate || '').slice(0, 10);
}

function getVolunteerPendingServices() {
  if (!state.user) return [];
  return state.services.filter((s) =>
    (s.assignments || []).some((a) => a.user_id === state.user.id && (a.status === 'PENDENTE' || a.approval_status === 'PENDENTE')),
  );
}

function assignmentClass(status) {
  if (status === 'CONFIRMADO') return 'assignment-confirmed';
  if (status === 'RECUSADO') return 'assignment-refused';
  return 'assignment-pending';
}

async function api(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      ...(options.headers || {}),
      ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}),
    },
  });

  if (res.status === 204) return null;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.message || 'Falha na requisição');
  return body;
}

function authHeaders() {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${state.token}`,
  };
}

function applyRoleVisibility() {
  document.querySelectorAll('[data-role]').forEach((el) => {
    const roles = el.dataset.role.split(',').map((x) => x.trim());
    el.classList.toggle('hidden', !roles.includes(state.user.role));
  });

  const canAccessRepertoire = Boolean(state.user?.canAccessRepertoire);
  document.querySelectorAll('[data-feature=\"repertoire\"]').forEach((el) => {
    el.classList.toggle('hidden', !canAccessRepertoire);
  });
}

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === name));
  TABS.forEach((tab) => {
    const node = $(`tab-${tab}`);
    if (node) node.classList.toggle('hidden', tab !== name);
  });
}

function renderDashboard() {
  const d = state.dashboard;
  if (!d) return;
  const totalAssignments = (d.assignments || []).reduce((acc, item) => acc + Number(item.total || 0), 0);
  const byStatus = (d.assignments || []).reduce((acc, item) => {
    acc[item.status] = item.total;
    return acc;
  }, {});

  $('stats').innerHTML = `
    <article class="stat"><span>Usuários</span><b>${d.users}</b></article>
    <article class="stat"><span>Músicas</span><b>${d.songs}</b></article>
    <article class="stat"><span>Cultos</span><b>${d.services}</b></article>
    <article class="stat"><span>Escalas</span><b>${totalAssignments}</b></article>
    <article class="stat ${hasRole('VOLUNTARIO') ? 'clickable' : ''}" ${hasRole('VOLUNTARIO') ? 'id=\"pending-cta\"' : ''}><span>Aprovações pendentes</span><b>${hasRole('VOLUNTARIO') ? getVolunteerPendingServices().length : d.pendingApprovals}</b></article>
    <article class="stat"><span>Bloqueios</span><b>${d.blocks}</b></article>
    ${hasRole('ADMIN', 'LIDER_MINISTERIO') ? `<article class="stat"><span>Trocas pendentes</span><b>${d.pendingSwaps || 0}</b></article>` : ''}
  `;
  const confirmed = Number(byStatus.CONFIRMADO || 0);
  const pending = Number(byStatus.PENDENTE || 0);
  const refused = Number(byStatus.RECUSADO || 0);
  const total = Math.max(1, confirmed + pending + refused);
  $('status-text').textContent = `Confirmações: ${confirmed} confirmados, ${pending} pendentes, ${refused} recusados.`;
  $('status-green').style.flex = String(confirmed || 0.001);
  $('status-yellow').style.flex = String(pending || 0.001);
  $('status-red').style.flex = String(refused || 0.001);
  $('status-green').style.width = `${(confirmed / total) * 100}%`;
  $('status-yellow').style.width = `${(pending / total) * 100}%`;
  $('status-red').style.width = `${(refused / total) * 100}%`;

  const repertoireNode = $('dashboard-repertoire');
  if (repertoireNode) {
    const topSongs = state.songs.slice(0, 6);
    repertoireNode.innerHTML =
      topSongs.map((s) => `<li><b>${s.title}</b> <span class="kicker">${s.key}${s.bpm ? ` | ${s.bpm} bpm` : ''}</span></li>`).join('') ||
      '<li>Sem músicas cadastradas.</li>';
  }

  const servicesNode = $('dashboard-services');
  if (servicesNode) {
    const upcoming = [...state.services]
      .sort((a, b) => String(a.service_date).localeCompare(String(b.service_date)))
      .slice(0, 6);
    servicesNode.innerHTML =
      upcoming.map((s) => `<li><b>${formatDate(s.service_date)}</b> ${formatTime(s.service_time)} - ${s.title}</li>`).join('') ||
      '<li>Sem cultos próximos.</li>';
  }

  const cta = $('pending-cta');
  if (cta) {
    cta.addEventListener('click', async () => {
      state.serviceSearchResults = getVolunteerPendingServices();
      renderServicesList();
      switchTab('cultos');
      if (state.serviceSearchResults[0]?.id) {
        await openService(state.serviceSearchResults[0].id);
      }
    });
  }
}

function renderMinistries() {
  const options = state.ministries.map((m) => `<option value="${m.id}">${m.name}</option>`).join('');
  $('user-ministry').innerHTML = options;
  $('ministries-list').innerHTML = state.ministries.map((m) => `<li><b>${m.name}</b> - ${m.description || 'Sem descrição'}</li>`).join('');
}

function renderUsers() {
  const ministryMap = new Map(state.ministries.map((m) => [m.id, m.name]));
  $('users-table').innerHTML = state.users
    .map(
      (u) => `
      <tr>
        <td>${u.name}</td>
        <td>${u.email}</td>
        <td>${u.role}</td>
        <td>${(u.ministry_ids || []).map((id) => ministryMap.get(id) || id).join(', ') || '-'}</td>
        <td>${u.active ? 'Ativo' : 'Inativo'}</td>
        <td>${
          hasRole('ADMIN')
            ? `<button class="btn small ghost edit-user-ministries" data-id="${u.id}">Ministérios</button>
               <button class="btn small danger toggle-active" data-id="${u.id}" data-next="${!u.active}">${u.active ? 'Desativar' : 'Ativar'}</button>`
            : ''
        }</td>
      </tr>
    `,
    )
    .join('');

  const userOptions =
    '<option value="">Voluntário</option>' + state.users.filter((u) => u.role !== 'ADMIN' && u.active).map((u) => `<option value="${u.id}">${u.name}</option>`).join('');
  $('assign-user').innerHTML = userOptions;
  if (hasRole('VOLUNTARIO')) {
    $('availability-user').innerHTML = `<option value="${state.user.id}">${state.user.name}</option>`;
  } else {
    $('availability-user').innerHTML = userOptions;
  }
}

function renderAvailabilityBlocks() {
  $('availability-table').innerHTML = state.availabilityBlocks
    .map(
      (b) => `
      <tr>
        <td>${b.user_name || '-'}</td>
        <td>${formatDate(b.start_date)} até ${formatDate(b.end_date)}</td>
        <td>${b.reason || '-'}</td>
        <td><button class="btn small danger availability-delete" data-id="${b.id}">Remover</button></td>
      </tr>
    `,
    )
    .join('');
}

function renderSongsTable() {
  $('songs-table').innerHTML = state.songs
    .map(
      (s) => `
      <tr>
        <td>${s.title}</td>
        <td>${s.key}</td>
        <td>${s.bpm || '-'}</td>
        <td>${s.web_link ? `<a href="${s.web_link}" target="_blank" rel="noopener noreferrer">Abrir</a>` : '-'}</td>
        <td>${tagText(s.tags)}</td>
        <td>${hasRole('ADMIN', 'LIDER_MINISTERIO') ? `<button class="btn small danger song-delete" data-id="${s.id}">Remover</button>` : ''}</td>
      </tr>
    `,
    )
    .join('');
}

function renderSetlistSongOptions(filtered = state.songs) {
  $('setlist-song').innerHTML = '<option value="">Selecione a música</option>' + filtered.map((s) => `<option value="${s.id}">${s.title} (${s.key})</option>`).join('');
}

function renderServicesList() {
  const list = state.serviceSearchResults.length ? state.serviceSearchResults : state.services;
  $('repeat-source-service').innerHTML = '<option value=\"\">Selecione o culto base</option>' + state.services.map((s) => `<option value=\"${s.id}\">${formatDate(s.service_date)} ${formatTime(s.service_time)} - ${s.title}</option>`).join('');
  $('services-list').innerHTML = list
    .map(
      (s) => `
      <article class="service-card" data-open-service-id="${s.id}">
        <h3>${formatDate(s.service_date)} ${formatTime(s.service_time)} - ${s.title}</h3>
        <p>${s.notes || 'Sem observações'}</p>
        <p><b>Tags:</b> ${tagText(s.tags)}</p>
      </article>
    `,
    )
    .join('');
}

function renderServiceDetail() {
  const modal = $('service-modal');
  const s = state.currentService;
  if (!s) {
    modal.classList.add('hidden');
    document.body.classList.remove('modal-open');
    return;
  }

  modal.classList.remove('hidden');
  document.body.classList.add('modal-open');
  $('service-detail-empty').classList.add('hidden');
  $('service-detail-content').classList.remove('hidden');
  $('service-detail-title').textContent = `${formatDate(s.service_date)} ${formatTime(s.service_time)} - ${s.title}`;

  $('detail-service-date').value = String(s.service_date).slice(0, 10);
  $('detail-service-time').value = formatTime(s.service_time);
  $('detail-service-title-input').value = s.title || '';
  $('detail-service-notes').value = s.notes || '';
  $('detail-service-tags').value = (s.tags || []).join(', ');

  $('service-detail-boards').innerHTML = `
    <div class="service-card">
      <h3>Repertório</h3>
      <ol>
        ${
          (s.setlist || [])
            .map(
              (i) => `<li>
                ${i.position}. ${i.song_title} (${i.song_key}) ${i.note ? `- ${i.note}` : ''}
                ${
                  hasRole('ADMIN', 'LIDER_MINISTERIO')
                    ? `<button class="btn small ghost setlist-edit" data-item-id="${i.id}">Editar</button>
                       <button class="btn small danger setlist-delete" data-item-id="${i.id}">Remover</button>`
                    : ''
                }
              </li>`,
            )
            .join('') || '<li>Nenhuma música</li>'
        }
      </ol>
    </div>
    <div class="service-card">
      <h3>Voluntários</h3>
      <ul>
        ${(s.assignments || [])
          .map((a) => {
            const canUpdateOwn = hasRole('VOLUNTARIO') && state.user.id === a.user_id;
            const canUpdateAll = hasRole('ADMIN', 'LIDER_MINISTERIO');
            const actions =
              canUpdateOwn || canUpdateAll
                ? `<button class="btn small ghost assignment-status" data-id="${a.id}" data-status="CONFIRMADO">Confirmar</button>
                   <button class="btn small ghost assignment-status" data-id="${a.id}" data-status="RECUSADO">Recusar</button>
                   ${
                     canUpdateOwn
                       ? `<button class="btn small ghost assignment-swap" data-id="${a.id}">Solicitar troca</button>`
                       : ''
                   }`
                : '';
            return `<li><span class="assignment-row ${assignmentClass(a.status)}">${a.status}</span>${a.team_role}: ${a.user_name} [aprov.: ${a.approval_status}] ${actions}</li>`;
          })
          .join('') || '<li>Ninguém escalado</li>'}
      </ul>
    </div>
  `;
}

function checkAssignAvailabilityWarning() {
  const warning = $('assign-availability-warning');
  const submitBtn = $('assign-submit');
  if (!warning || !submitBtn) return;

  warning.classList.add('hidden');
  warning.textContent = '';
  submitBtn.disabled = false;

  if (!state.currentService) return;
  const selectedUser = $('assign-user')?.value;
  if (!selectedUser) return;

  const serviceDate = getServiceDateKey(state.currentService.service_date);
  const blocked = state.availabilityBlocks.find((b) => {
    if (b.user_id !== selectedUser) return false;
    const start = getServiceDateKey(b.start_date);
    const end = getServiceDateKey(b.end_date);
    return serviceDate >= start && serviceDate <= end;
  });

  if (blocked) {
    warning.textContent = `Indisponível em ${formatDate(serviceDate)}${blocked.reason ? `: ${blocked.reason}` : ''}.`;
    warning.classList.remove('hidden');
    submitBtn.disabled = true;
  }
}

function closeServiceModal() {
  state.currentService = null;
  $('service-modal').classList.add('hidden');
  document.body.classList.remove('modal-open');
}

function openAccountModal() {
  $('account-modal')?.classList.remove('hidden');
  document.body.classList.add('modal-open');
  renderProfileCard();
}

function closeAccountModal() {
  $('account-modal')?.classList.add('hidden');
  document.body.classList.remove('modal-open');
}

function renderApprovals() {
  $('approvals-table').innerHTML = state.approvals
    .map(
      (a) => `
      <tr>
        <td>${formatDate(a.service_date)}</td>
        <td>${a.service_title}</td>
        <td>${a.user_name}</td>
        <td>${a.team_role}</td>
        <td>
          <button class="btn small primary approval-decision" data-assignment-id="${a.assignment_id}" data-decision="APROVAR">Aprovar</button>
          <button class="btn small danger approval-decision" data-assignment-id="${a.assignment_id}" data-decision="REJEITAR">Rejeitar</button>
        </td>
      </tr>
    `,
    )
    .join('');

  const swapTable = $('swap-requests-table');
  if (!swapTable) return;
  swapTable.innerHTML = state.swapRequests
    .map(
      (s) => `
      <tr>
        <td>${formatDate(s.service_date)}</td>
        <td>${s.service_title}</td>
        <td>${s.requester_name}</td>
        <td>${s.team_role}</td>
        <td>${s.reason}</td>
        <td>
          ${
            hasRole('ADMIN', 'LIDER_MINISTERIO')
              ? `<button class="btn small primary swap-decision" data-id="${s.id}" data-decision="APROVAR">Aprovar</button>
                 <button class="btn small danger swap-decision" data-id="${s.id}" data-decision="REJEITAR">Rejeitar</button>`
              : s.status
          }
        </td>
      </tr>
    `,
    )
    .join('');
}

function renderNotifications() {
  $('notifications-table').innerHTML = state.notifications
    .map(
      (n) => `
      <tr>
        <td>${new Date(n.created_at).toLocaleString('pt-BR')}</td>
        <td>${n.channel}</td>
        <td>${n.event}</td>
        <td>${n.user_name || 'Sistema'}</td>
        <td>${n.status}</td>
      </tr>
    `,
    )
    .join('');
}

function renderLogs() {
  $('logs-table').innerHTML = state.logs
    .map(
      (log) => `
      <tr>
        <td>${new Date(log.created_at).toLocaleString('pt-BR')}</td>
        <td>${log.action}</td>
        <td>${log.entity}</td>
        <td>${log.actor_name || 'Sistema'}</td>
        <td>${JSON.stringify(log.payload || {})}</td>
      </tr>
    `,
    )
    .join('');
}

async function openService(serviceId) {
  state.currentService = await api(`/api/services/${serviceId}`);
  renderServiceDetail();
  checkAssignAvailabilityWarning();
}

async function loadAll() {
  const safe = async (p, fallback = []) => {
    try {
      return await p;
    } catch (_e) {
      return fallback;
    }
  };

  const [ministries, users, songs, services, availabilityBlocks, approvals, swapRequests, notifications, logs, dashboard] = await Promise.all([
    safe(api('/api/ministries'), []),
    hasRole('ADMIN', 'LIDER_MINISTERIO') ? safe(api('/api/users'), []) : Promise.resolve([]),
    safe(api('/api/songs'), []),
    safe(api('/api/services'), []),
    safe(api('/api/availability-blocks'), []),
    hasRole('ADMIN', 'LIDER_MINISTERIO') ? safe(api('/api/approvals/pending'), []) : Promise.resolve([]),
    safe(api('/api/swap-requests?status=PENDENTE'), []),
    safe(api('/api/notifications'), []),
    hasRole('ADMIN', 'LIDER_MINISTERIO') ? safe(api('/api/audit-logs'), []) : Promise.resolve([]),
    safe(api('/api/dashboard'), { users: 0, songs: 0, services: 0, blocks: 0, pendingApprovals: 0, pendingSwaps: 0, assignments: [] }),
  ]);

  state.ministries = ministries;
  state.users = users;
  state.songs = songs;
  state.services = services;
  state.serviceSearchResults = [];
  state.availabilityBlocks = availabilityBlocks;
  state.approvals = approvals;
  state.swapRequests = swapRequests;
  state.notifications = notifications;
  state.logs = logs;
  state.dashboard = dashboard;

  renderDashboard();
  renderMinistries();
  renderUsers();
  renderAvailabilityBlocks();
  renderSongsTable();
  renderSetlistSongOptions();
  renderServicesList();
  renderServiceDetail();
  renderApprovals();
  renderNotifications();
  renderLogs();
  renderProfileCard();
}

async function doLogin(email, password) {
  const result = await api('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  state.token = result.token;
  state.user = result.user;
  localStorage.setItem('token', state.token);
  localStorage.setItem('user', JSON.stringify(state.user));

  $('auth-card').classList.add('hidden');
  $('workspace').classList.remove('hidden');
  $('logged-user').textContent = `${state.user.name} (${state.user.role})`;
  applyRoleVisibility();
  renderProfileCard();
  await loadAll();
}

function wireEvents() {
  $('open-account-panel')?.addEventListener('click', () => openAccountModal());
  $('account-modal-close')?.addEventListener('click', () => closeAccountModal());
  $('account-modal')?.addEventListener('click', (e) => {
    if (e.target.id === 'account-modal') closeAccountModal();
  });

  $('profile-photo-btn')?.addEventListener('click', () => $('profile-photo-input')?.click());
  $('profile-photo-input')?.addEventListener('change', async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.type.startsWith('image/')) return alert('Selecione uma imagem válida');
    const reader = new FileReader();
    reader.onload = () => {
      const value = String(reader.result || '');
      localStorage.setItem(profilePhotoKey(), value);
      renderProfileCard();
    };
    reader.readAsDataURL(file);
  });

  $('change-password-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const currentPassword = $('current-password').value;
    const newPassword = $('new-password').value;
    const confirmPassword = $('confirm-password').value;
    if (newPassword !== confirmPassword) {
      return alert('A confirmação da nova senha não confere');
    }
    try {
      const result = await api('/api/auth/change-password', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      e.target.reset();
      alert(result.message || 'Senha atualizada');
      closeAccountModal();
    } catch (err) {
      alert(err.message);
    }
  });

  $('theme-toggle')?.addEventListener('click', () => {
    const current = document.body.getAttribute('data-theme') || 'light';
    applyTheme(current === 'dark' ? 'light' : 'dark');
  });

  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await doLogin($('login-email').value, $('login-password').value);
    } catch (err) {
      alert(err.message);
    }
  });

  $('logout-btn').addEventListener('click', () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    location.reload();
  });

  document.querySelectorAll('.tab').forEach((btn) => btn.addEventListener('click', () => switchTab(btn.dataset.tab)));

  $('service-search-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const q = $('service-query').value.trim();
      const d = $('service-query-date').value;
      const params = new URLSearchParams();
      if (q) params.set('q', q);
      if (d) params.set('serviceDate', d);
      state.serviceSearchResults = await api(`/api/services?${params.toString()}`);
      renderServicesList();
    } catch (err) {
      alert(err.message);
    }
  });

  $('setlist-song-query').addEventListener('input', async (e) => {
    try {
      const q = e.target.value.trim();
      const list = q ? await api(`/api/songs?q=${encodeURIComponent(q)}`) : state.songs;
      renderSetlistSongOptions(list);
    } catch (_err) {
      renderSetlistSongOptions(state.songs);
    }
  });

  $('assign-user-query').addEventListener('input', (e) => {
    const q = e.target.value.trim().toLowerCase();
    const filtered = state.users.filter((u) => u.role !== 'ADMIN' && u.active && (!q || u.name.toLowerCase().includes(q)));
    $('assign-user').innerHTML = '<option value="">Voluntário</option>' + filtered.map((u) => `<option value="${u.id}">${u.name}</option>`).join('');
    checkAssignAvailabilityWarning();
  });

  $('assign-user').addEventListener('change', () => {
    checkAssignAvailabilityWarning();
  });

  $('ministry-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/ministries', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ name: $('ministry-name').value, description: $('ministry-description').value }),
      });
      e.target.reset();
      await loadAll();
    } catch (err) {
      alert(err.message);
    }
  });

  $('user-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/users', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          name: $('user-name').value,
          email: $('user-email').value,
          phone: $('user-phone').value,
          password: $('user-password').value,
          role: $('user-role').value,
          ministryIds: Array.from($('user-ministry').selectedOptions).map((opt) => opt.value).filter(Boolean),
        }),
      });
      e.target.reset();
      await loadAll();
    } catch (err) {
      alert(err.message);
    }
  });

  $('availability-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/availability-blocks', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          userId: $('availability-user').value || null,
          startDate: $('availability-start').value,
          endDate: $('availability-end').value,
          reason: $('availability-reason').value,
        }),
      });
      e.target.reset();
      await loadAll();
    } catch (err) {
      alert(err.message);
    }
  });

  $('song-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/songs', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          title: $('song-title').value,
          key: $('song-key').value,
          bpm: $('song-bpm').value || null,
          webLink: $('song-link').value || '',
          tags: $('song-tags').value,
        }),
      });
      e.target.reset();
      await loadAll();
    } catch (err) {
      alert(err.message);
    }
  });

  $('service-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/services', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          serviceDate: $('service-date').value,
          serviceTime: $('service-time').value || null,
          title: $('service-title').value,
          notes: $('service-notes').value,
          tags: $('service-tags').value,
        }),
      });
      e.target.reset();
      await loadAll();
    } catch (err) {
      alert(err.message);
    }
  });

  $('service-edit-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!state.currentService) return;
    try {
      await api(`/api/services/${state.currentService.id}`, {
        method: 'PATCH',
        headers: authHeaders(),
        body: JSON.stringify({
          serviceDate: $('detail-service-date').value,
          serviceTime: $('detail-service-time').value || null,
          title: $('detail-service-title-input').value,
          notes: $('detail-service-notes').value,
          tags: $('detail-service-tags').value,
        }),
      });
      await loadAll();
      await openService(state.currentService.id);
    } catch (err) {
      alert(err.message);
    }
  });

  $('setlist-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!state.currentService) return alert('Selecione um culto primeiro');
    try {
      await api(`/api/services/${state.currentService.id}/setlist`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          songId: $('setlist-song').value,
          position: $('setlist-position').value,
          note: $('setlist-note').value,
        }),
      });
      e.target.reset();
      await loadAll();
      await openService(state.currentService.id);
    } catch (err) {
      alert(err.message);
    }
  });

  $('assign-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!state.currentService) return alert('Selecione um culto primeiro');
    try {
      await api(`/api/services/${state.currentService.id}/assignments`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          userId: $('assign-user').value,
          teamRole: $('assign-role').value,
        }),
      });
      e.target.reset();
      await loadAll();
      await openService(state.currentService.id);
    } catch (err) {
      alert(err.message);
    }
  });

  $('self-assign-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!state.currentService) return alert('Selecione um culto primeiro');
    try {
      await api(`/api/services/${state.currentService.id}/self-assign`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ teamRole: $('self-assign-role').value }),
      });
      e.target.reset();
      await loadAll();
      await openService(state.currentService.id);
    } catch (err) {
      alert(err.message);
    }
  });

  $('repeat-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const result = await api('/api/planning/repeat-service', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          sourceServiceId: $('repeat-source-service').value,
          startDate: $('repeat-start').value,
          endDate: $('repeat-end').value,
          intervalDays: Number($('repeat-interval').value || 7),
          titlePrefix: $('repeat-prefix').value,
          copySetlist: true,
          copyAssignments: true,
        }),
      });
      $('repeat-result').textContent = `Criados: ${result.createdServices.length} | Ignorados: ${result.skipped.length}`;
      await loadAll();
    } catch (err) {
      alert(err.message);
    }
  });

  $('bulk-service-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const weekdays = $('bulk-weekdays')
        .value.split(',')
        .map((v) => Number(v.trim()))
        .filter((v) => Number.isInteger(v) && v >= 0 && v <= 6);

      const timeSlots = [];
      if ($('bulk-morning-title').value.trim()) {
        timeSlots.push({
          title: $('bulk-morning-title').value.trim(),
          serviceTime: $('bulk-morning-time').value || null,
          notes: $('bulk-notes').value || '',
        });
      }
      if ($('bulk-night-title').value.trim()) {
        timeSlots.push({
          title: $('bulk-night-title').value.trim(),
          serviceTime: $('bulk-night-time').value || null,
          notes: $('bulk-notes').value || '',
        });
      }

      const result = await api('/api/services/bulk', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({
          startDate: $('bulk-start').value,
          endDate: $('bulk-end').value,
          weekdays,
          notes: $('bulk-notes').value || '',
          tags: $('service-tags').value || '',
          timeSlots,
        }),
      });

      $('bulk-result').textContent = `Criados: ${result.createdServices.length} | Ignorados: ${result.skipped.length}`;
      await loadAll();
    } catch (err) {
      alert(err.message);
    }
  });

  $('notify-test-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/notifications/test', {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ channel: $('notify-channel').value }),
      });
      await loadAll();
      alert('Notificação de teste registrada.');
    } catch (err) {
      alert(err.message);
    }
  });

  $('notify-reminders-btn')?.addEventListener('click', async () => {
    try {
      const result = await api('/api/notifications/reminders/pending-confirmations', {
        method: 'POST',
        headers: authHeaders(),
      });
      await loadAll();
      alert(`Lembretes enviados: ${result.reminders || 0}`);
    } catch (err) {
      alert(err.message);
    }
  });

  $('detail-delete-service').addEventListener('click', async () => {
    if (!state.currentService) return;
    const ok = confirm('Tem certeza que deseja excluir este culto?');
    if (!ok) return;
    try {
      const deletedId = state.currentService.id;
      await api(`/api/services/${deletedId}`, { method: 'DELETE', headers: authHeaders() });
      state.currentService = null;
      await loadAll();
      renderServiceDetail();
    } catch (err) {
      alert(err.message);
    }
  });

  $('service-modal-close').addEventListener('click', () => {
    closeServiceModal();
  });

  $('volunteer-pending-tab')?.addEventListener('click', async () => {
    if (!hasRole('VOLUNTARIO')) return;
    state.serviceSearchResults = getVolunteerPendingServices();
    renderServicesList();
    if (state.serviceSearchResults[0]?.id) {
      await openService(state.serviceSearchResults[0].id);
    }
  });

  $('service-modal').addEventListener('click', (e) => {
    if (e.target.id === 'service-modal') closeServiceModal();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('service-modal').classList.contains('hidden')) {
      closeServiceModal();
    }
    if (e.key === 'Escape' && !$('account-modal')?.classList.contains('hidden')) {
      closeAccountModal();
    }
  });

  document.body.addEventListener('click', async (e) => {
    const toggle = e.target.closest('.toggle-active');
    const songDelete = e.target.closest('.song-delete');
    const assignmentStatus = e.target.closest('.assignment-status');
    const approvalDecision = e.target.closest('.approval-decision');
    const availabilityDelete = e.target.closest('.availability-delete');
    const serviceCard = e.target.closest('[data-open-service-id]');
    const setlistEdit = e.target.closest('.setlist-edit');
    const setlistDelete = e.target.closest('.setlist-delete');
    const assignmentSwap = e.target.closest('.assignment-swap');
    const swapDecision = e.target.closest('.swap-decision');
    const editUserMinistries = e.target.closest('.edit-user-ministries');

    try {
      if (serviceCard) {
        await openService(serviceCard.dataset.openServiceId);
      }

      if (toggle) {
        await api(`/api/users/${toggle.dataset.id}/active`, {
          method: 'PATCH',
          headers: authHeaders(),
          body: JSON.stringify({ active: toggle.dataset.next === 'true' }),
        });
      }

      if (editUserMinistries) {
        const user = state.users.find((u) => u.id === editUserMinistries.dataset.id);
        if (!user) throw new Error('Usuário não encontrado');
        if (user.role === 'ADMIN') throw new Error('Usuário ADMIN não pode ter ministérios alterados');

        const current = new Set(user.ministry_ids || []);
        const optionsText = state.ministries
          .map((m, i) => `${i + 1}. ${m.name}${current.has(m.id) ? ' [x]' : ''}`)
          .join('\n');
        const answer = prompt(
          `Informe os números dos ministérios separados por vírgula para ${user.name}:\n\n${optionsText}\n\nExemplo: 1,3`,
        );
        if (answer === null) return;
        const pickedIndexes = answer
          .split(',')
          .map((v) => Number(v.trim()))
          .filter((n) => Number.isInteger(n) && n >= 1 && n <= state.ministries.length);
        const ministryIds = Array.from(new Set(pickedIndexes.map((n) => state.ministries[n - 1].id)));

        await api(`/api/users/${user.id}/ministries`, {
          method: 'PATCH',
          headers: authHeaders(),
          body: JSON.stringify({ ministryIds }),
        });
      }

      if (songDelete) {
        await api(`/api/songs/${songDelete.dataset.id}`, { method: 'DELETE', headers: authHeaders() });
      }

      if (assignmentStatus) {
        await api(`/api/assignments/${assignmentStatus.dataset.id}/status`, {
          method: 'PATCH',
          headers: authHeaders(),
          body: JSON.stringify({ status: assignmentStatus.dataset.status }),
        });
      }

      if (assignmentSwap) {
        const reason = prompt('Informe o motivo da troca:') || '';
        if (!reason.trim()) return;
        await api(`/api/assignments/${assignmentSwap.dataset.id}/swap-request`, {
          method: 'POST',
          headers: authHeaders(),
          body: JSON.stringify({ reason }),
        });
      }

      if (approvalDecision) {
        const note = prompt('Observação da decisão (opcional):') || '';
        await api(`/api/approvals/${approvalDecision.dataset.assignmentId}`, {
          method: 'PATCH',
          headers: authHeaders(),
          body: JSON.stringify({ decision: approvalDecision.dataset.decision, note }),
        });
      }

      if (availabilityDelete) {
        await api(`/api/availability-blocks/${availabilityDelete.dataset.id}`, { method: 'DELETE', headers: authHeaders() });
      }

      if (setlistEdit) {
        if (!state.currentService) throw new Error('Selecione um culto');
        const item = (state.currentService.setlist || []).find((x) => x.id === setlistEdit.dataset.itemId);
        if (!item) throw new Error('Item de repertório não encontrado');

        const newPosition = prompt('Nova posição do repertório:', String(item.position));
        if (newPosition === null) return;
        const newNote = prompt('Nova observação:', item.note || '');
        if (newNote === null) return;

        await api(`/api/services/${state.currentService.id}/setlist/${item.id}`, {
          method: 'PATCH',
          headers: authHeaders(),
          body: JSON.stringify({
            position: Number(newPosition),
            note: newNote,
          }),
        });
      }

      if (setlistDelete) {
        if (!state.currentService) throw new Error('Selecione um culto');
        const ok = confirm('Remover esta música do repertório deste culto?');
        if (!ok) return;
        await api(`/api/services/${state.currentService.id}/setlist/${setlistDelete.dataset.itemId}`, {
          method: 'DELETE',
          headers: authHeaders(),
        });
      }

      if (swapDecision) {
        const note = prompt('Observação da decisão (opcional):') || '';
        await api(`/api/swap-requests/${swapDecision.dataset.id}`, {
          method: 'PATCH',
          headers: authHeaders(),
          body: JSON.stringify({ decision: swapDecision.dataset.decision, note }),
        });
      }

      if (
        toggle ||
        songDelete ||
        assignmentStatus ||
        assignmentSwap ||
        approvalDecision ||
        availabilityDelete ||
        setlistEdit ||
        setlistDelete ||
        swapDecision
        || editUserMinistries
      ) {
        const currentId = state.currentService?.id;
        await loadAll();
        if (currentId) {
          try {
            await openService(currentId);
          } catch (_e) {
            closeServiceModal();
          }
        }
      }
    } catch (err) {
      alert(err.message);
    }
  });
}

async function bootstrap() {
  applyTheme(localStorage.getItem(THEME_KEY) || 'light');
  wireEvents();
  switchTab('dashboard');

  if (state.token && state.user) {
    $('auth-card').classList.add('hidden');
    $('workspace').classList.remove('hidden');
    try {
      const me = await api('/api/auth/me');
      state.user = {
        ...state.user,
        id: me.id,
        name: me.name,
        email: me.email,
        role: me.role,
        ministryId: me.ministry_id,
        ministryIds: me.ministry_ids || [],
        leaderMinistryIds: me.leader_ministry_ids || [],
        canAccessRepertoire: Boolean(me.can_access_repertoire),
      };
      localStorage.setItem('user', JSON.stringify(state.user));
      $('logged-user').textContent = `${state.user.name} (${state.user.role})`;
      applyRoleVisibility();
      renderProfileCard();
      await loadAll();
    } catch (_error) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      location.reload();
    }
  }
}

bootstrap();

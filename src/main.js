import { createEncryptedVault, encryptVaultWithKey, lockKey, unlockVault } from './crypto.js';
import { generatePassword, passwordScore } from './password.js';
import {
  deleteEncryptedVault,
  downloadJson,
  hasStoredVault,
  loadEncryptedVault,
  readJsonFile,
  saveEncryptedVault
} from './storage.js';

const app = document.querySelector('#app');
const state = {
  payload: null,
  vault: null,
  key: null,
  selectedId: null,
  search: '',
  lockMinutes: 5,
  lockTimer: null,
  notice: ''
};

const emptyEntry = {
  title: '',
  username: '',
  password: '',
  url: '',
  category: '',
  notes: '',
  favorite: false
};

window.addEventListener('pointerdown', scheduleAutoLock, { passive: true });
window.addEventListener('keydown', scheduleAutoLock);
window.addEventListener('visibilitychange', () => {
  if (document.hidden && state.vault) {
    scheduleAutoLock();
  }
});

renderLocked();

function renderLocked(error = '') {
  clearAutoLock();
  app.replaceChildren(
    el('main', { className: 'auth-shell' }, [
      el('section', { className: 'auth-panel' }, [
        el('div', { className: 'brand-lock', ariaHidden: 'true' }, ['']),
        el('p', { className: 'eyebrow' }, ['Secure Password Vault']),
        el('h1', {}, ['Sifre kasaniz sadece ana parolanizla acilir']),
        el('p', { className: 'lede' }, [
          hasStoredVault()
            ? 'Bu cihazda sifreli bir kasa var. Ana parolanizi girerek acin.'
            : 'Yeni kasa olusturun. Ana parola saklanmaz; unutulursa kasa acilamaz.'
        ]),
        error ? el('div', { className: 'alert danger', role: 'alert' }, [error]) : null,
        hasStoredVault() ? unlockForm() : createVaultForm(),
        el('div', { className: 'auth-actions' }, [
          importButton(),
          hasStoredVault()
            ? button('Yerel kasayi sil', 'danger ghost', () => {
                const ok = confirm('Bu cihazdaki sifreli kasa silinecek. Export dosyaniz yoksa geri alinamaz.');
                if (ok) {
                  deleteEncryptedVault();
                  renderLocked('Yerel kasa silindi.');
                }
              })
            : null
        ]),
        el('p', { className: 'security-note' }, [
          'Argon2id + XChaCha20-Poly1305 kullanilir. Veriler yalnizca sifreli bicimde saklanir.'
        ])
      ])
    ])
  );
}

function createVaultForm() {
  const passwordInput = input('password', 'Ana parola', 'En az 12 karakter');
  const confirmInput = input('password', 'Ana parolayi tekrar girin', '');
  const submit = button('Kasayi olustur', 'primary', async () => {
    try {
      if (passwordInput.value !== confirmInput.value) {
        throw new Error('Ana parola tekrar alani eslesmiyor.');
      }
      const vault = {
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        entries: []
      };
      const result = await createEncryptedVault(passwordInput.value, vault);
      state.payload = result.payload;
      state.vault = vault;
      state.key = result.key;
      saveEncryptedVault(result.payload);
      renderVault('Kasa olusturuldu.');
    } catch (error) {
      renderLocked(error.message);
    }
  });

  return el('form', { className: 'stack', onSubmit: prevent(() => submit.click()) }, [passwordInput, confirmInput, submit]);
}

function unlockForm() {
  const passwordInput = input('password', 'Ana parola', '');
  const submit = button('Kasayi ac', 'primary', async () => {
    try {
      const payload = loadEncryptedVault();
      const result = await unlockVault(passwordInput.value, payload);
      state.payload = payload;
      state.vault = normalizeVault(result.vault);
      state.key = result.key;
      state.selectedId = state.vault.entries[0]?.id || null;
      renderVault('Kasa acildi.');
    } catch (error) {
      renderLocked('Ana parola hatali veya kasa bozuk.');
    }
  });

  return el('form', { className: 'stack', onSubmit: prevent(() => submit.click()) }, [passwordInput, submit]);
}

function renderVault(notice = '') {
  state.notice = notice;
  scheduleAutoLock();
  const selected = state.vault.entries.find((entry) => entry.id === state.selectedId) || null;
  app.replaceChildren(
    el('main', { className: 'vault-shell' }, [
      el('aside', { className: 'sidebar' }, [
        el('div', { className: 'topline' }, [
          el('div', {}, [el('p', { className: 'eyebrow' }, ['Kasa']), el('h1', {}, ['Sifreler'])]),
          button('+', 'icon primary', () => editEntry(null), 'Yeni kayit')
        ]),
        searchBox(),
        entryList(),
        el('div', { className: 'side-actions' }, [
          button('Export', 'ghost', exportVault),
          importButton(),
          button('Kilitle', 'ghost', () => lockVault('Kasa kilitlendi.'))
        ])
      ]),
      el('section', { className: 'detail' }, [
        notice ? el('div', { className: 'alert success', role: 'status' }, [notice]) : null,
        securityBar(),
        selected ? entryDetail(selected) : emptyState()
      ])
    ])
  );
}

function searchBox() {
  const field = input('search', 'Ara', 'site, kullanici, kategori');
  field.value = state.search;
  field.addEventListener('input', () => {
    state.search = field.value;
    renderVault();
  });
  return field;
}

function entryList() {
  const query = state.search.trim().toLowerCase();
  const entries = state.vault.entries
    .filter((entry) => [entry.title, entry.username, entry.category, entry.url].join(' ').toLowerCase().includes(query))
    .sort((a, b) => Number(b.favorite) - Number(a.favorite) || a.title.localeCompare(b.title));

  if (!entries.length) {
    return el('div', { className: 'empty-list' }, ['Kayit bulunamadi.']);
  }

  return el(
    'div',
    { className: 'entry-list' },
    entries.map((entry) =>
      button('', `entry-row ${entry.id === state.selectedId ? 'active' : ''}`, () => {
        state.selectedId = entry.id;
        renderVault();
      }, `${entry.title} kaydini ac`, [
        el('span', { className: 'entry-title' }, [entry.favorite ? '* ' : '', entry.title || 'Adsiz kayit']),
        el('span', { className: 'entry-subtitle' }, [entry.username || entry.url || 'Kullanici yok'])
      ])
    )
  );
}

function securityBar() {
  const select = el('select', { ariaLabel: 'Otomatik kilit suresi' }, [
    option('1', '1 dk'),
    option('5', '5 dk'),
    option('15', '15 dk'),
    option('30', '30 dk')
  ]);
  select.value = String(state.lockMinutes);
  select.addEventListener('change', () => {
    state.lockMinutes = Number(select.value);
    scheduleAutoLock();
  });

  return el('div', { className: 'security-bar' }, [
    el('span', {}, ['Yerel sifreli kasa']),
    el('label', { className: 'inline-field' }, ['Oto kilit', select])
  ]);
}

function entryDetail(entry) {
  return el('article', { className: 'entry-detail' }, [
    el('div', { className: 'detail-header' }, [
      el('div', {}, [
        el('p', { className: 'eyebrow' }, [entry.category || 'Genel']),
        el('h2', {}, [entry.title || 'Adsiz kayit'])
      ]),
      el('div', { className: 'button-row' }, [
        button('Duzenle', 'secondary', () => editEntry(entry)),
        button('Sil', 'danger ghost', () => deleteEntry(entry.id))
      ])
    ]),
    secretLine('Kullanici', entry.username, false),
    secretLine('Sifre', entry.password, true),
    entry.url ? linkLine('Adres', entry.url) : secretLine('Adres', '-', false),
    secretLine('Not', entry.notes || '-', false),
    el('dl', { className: 'meta-grid' }, [
      el('dt', {}, ['Olusturma']),
      el('dd', {}, [formatDate(entry.createdAt)]),
      el('dt', {}, ['Guncelleme']),
      el('dd', {}, [formatDate(entry.updatedAt)])
    ])
  ]);
}

function secretLine(label, value, masked) {
  const text = el('span', { className: 'secret-value' }, [masked ? '••••••••••••' : value]);
  let visible = false;
  const controls = masked
    ? [
        button('Goster', 'ghost compact', () => {
          visible = !visible;
          text.textContent = visible ? value : '••••••••••••';
        }),
        button('Kopyala', 'secondary compact', () => copySecret(value))
      ]
    : value && value !== '-'
      ? [button('Kopyala', 'ghost compact', () => copySecret(value))]
      : [];

  return el('div', { className: 'secret-line' }, [el('span', { className: 'label' }, [label]), text, ...controls]);
}

function linkLine(label, value) {
  const link = el('a', { href: value, target: '_blank', rel: 'noreferrer noopener' }, [value]);
  return el('div', { className: 'secret-line' }, [
    el('span', { className: 'label' }, [label]),
    link,
    button('Kopyala', 'ghost compact', () => copySecret(value))
  ]);
}

function emptyState() {
  return el('div', { className: 'empty-state' }, [
    el('h2', {}, ['Kasa bos']),
    el('p', {}, ['Ilk kaydinizi ekleyin veya sifreli export dosyanizi import edin.']),
    button('Yeni kayit ekle', 'primary', () => editEntry(null))
  ]);
}

function editEntry(entry) {
  const draft = { ...emptyEntry, ...entry };
  const fields = {
    title: input('text', 'Baslik', 'or. GitHub'),
    username: input('text', 'Kullanici adi', 'or. mail@domain.com'),
    password: input('text', 'Sifre', ''),
    url: input('url', 'Adres', 'https://'),
    category: input('text', 'Kategori', 'Is, kisisel, banka'),
    notes: el('textarea', { placeholder: 'Not', rows: 4 }),
    favorite: el('input', { type: 'checkbox' })
  };

  Object.entries(fields).forEach(([key, field]) => {
    if (field.type === 'checkbox') {
      field.checked = Boolean(draft[key]);
    } else {
      field.value = draft[key] || '';
    }
  });

  const generatorLength = input('number', 'Uzunluk', '');
  generatorLength.min = '16';
  generatorLength.max = '64';
  generatorLength.value = '24';

  const generatedScore = el('span', { className: 'score' }, ['']);
  const generate = button('Guclu sifre uret', 'secondary', () => {
    fields.password.value = generatePassword({ length: Number(generatorLength.value) });
    generatedScore.textContent = `Guc: ${passwordScore(fields.password.value)}/5`;
  });

  const save = button('Kaydet', 'primary', async () => {
    const now = new Date().toISOString();
    const next = {
      id: entry?.id || crypto.randomUUID(),
      title: fields.title.value.trim(),
      username: fields.username.value.trim(),
      password: fields.password.value,
      url: fields.url.value.trim(),
      category: fields.category.value.trim(),
      notes: fields.notes.value.trim(),
      favorite: fields.favorite.checked,
      createdAt: entry?.createdAt || now,
      updatedAt: now
    };

    if (!next.title || !next.password) {
      state.notice = 'Baslik ve sifre zorunlu.';
      renderVault(state.notice);
      return;
    }

    const index = state.vault.entries.findIndex((item) => item.id === next.id);
    if (index >= 0) {
      state.vault.entries[index] = next;
    } else {
      state.vault.entries.push(next);
    }
    state.vault.updatedAt = now;
    state.selectedId = next.id;
    await persistAndRender('Kayit sifreli olarak kaydedildi.');
  });

  app.querySelector('.detail').replaceChildren(
    securityBar(),
    el('form', { className: 'edit-form', onSubmit: prevent(() => save.click()) }, [
      el('div', { className: 'form-grid' }, [
        fields.title,
        fields.username,
        fields.password,
        fields.url,
        fields.category,
        el('label', { className: 'check-line' }, [fields.favorite, el('span', {}, ['Favori'])])
      ]),
      fields.notes,
      el('div', { className: 'generator' }, [generatorLength, generate, generatedScore]),
      el('div', { className: 'button-row' }, [
        save,
        button('Vazgec', 'ghost', () => renderVault())
      ])
    ])
  );
}

async function deleteEntry(id) {
  const ok = confirm('Bu kayit silinecek.');
  if (!ok) return;
  state.vault.entries = state.vault.entries.filter((entry) => entry.id !== id);
  state.vault.updatedAt = new Date().toISOString();
  state.selectedId = state.vault.entries[0]?.id || null;
  await persistAndRender('Kayit silindi.');
}

async function persistAndRender(notice) {
  state.payload = await encryptVaultWithKey(state.vault, state.key, state.payload);
  saveEncryptedVault(state.payload);
  renderVault(notice);
}

function exportVault() {
  if (!state.payload) return;
  downloadJson(`secure-password-vault-${new Date().toISOString().slice(0, 10)}.json`, state.payload);
  renderVault('Sifreli export hazirlandi.');
}

function importButton() {
  const fileInput = el('input', { type: 'file', accept: 'application/json', className: 'visually-hidden' });
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    try {
      const payload = await readJsonFile(file);
      if (hasStoredVault()) {
        const ok = confirm('Import edilen sifreli kasa bu cihazdaki kasanin yerine gececek.');
        if (!ok) return;
      }
      saveEncryptedVault(payload);
      lockVault('Sifreli kasa import edildi. Ana parola ile acin.');
    } catch (error) {
      renderLocked(error.message);
    }
  });

  return el('span', {}, [
    fileInput,
    button('Import', 'ghost', () => fileInput.click())
  ]);
}

async function copySecret(value) {
  if (!value || value === '-') return;
  await navigator.clipboard.writeText(value);
  state.notice = 'Panoya kopyalandi. 30 saniye sonra temizleme denenecek.';
  renderVault(state.notice);
  window.setTimeout(async () => {
    try {
      await navigator.clipboard.writeText('');
    } catch {
      // Browser izin vermezse sessizce gecilir.
    }
  }, 30000);
}

function lockVault(message = '') {
  if (state.key) {
    lockKey(state.key);
  }
  state.payload = null;
  state.vault = null;
  state.key = null;
  state.selectedId = null;
  state.search = '';
  renderLocked(message);
}

function scheduleAutoLock() {
  if (!state.vault) return;
  clearAutoLock();
  state.lockTimer = window.setTimeout(() => lockVault('Oturum otomatik kilitlendi.'), state.lockMinutes * 60 * 1000);
}

function clearAutoLock() {
  if (state.lockTimer) {
    window.clearTimeout(state.lockTimer);
    state.lockTimer = null;
  }
}

function normalizeVault(vault) {
  return {
    createdAt: vault.createdAt || new Date().toISOString(),
    updatedAt: vault.updatedAt || new Date().toISOString(),
    entries: Array.isArray(vault.entries) ? vault.entries.map((entry) => ({ ...emptyEntry, ...entry })) : []
  };
}

function input(type, label, placeholder) {
  const field = el('input', { type, placeholder, ariaLabel: label });
  return field;
}

function button(text, className, onClick, ariaLabel = text, children = null) {
  const control = el('button', { type: 'button', className: `btn ${className}`, ariaLabel }, children || [text]);
  control.addEventListener('click', onClick);
  return control;
}

function option(value, text) {
  return el('option', { value }, [text]);
}

function prevent(action) {
  return (event) => {
    event.preventDefault();
    action();
  };
}

function formatDate(value) {
  if (!value) return '-';
  return new Intl.DateTimeFormat('tr-TR', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
}

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  Object.entries(attrs || {}).forEach(([key, value]) => {
    if (value === null || value === undefined || value === false) return;
    if (key === 'className') node.className = value;
    else if (key === 'ariaLabel') node.setAttribute('aria-label', value);
    else if (key === 'ariaHidden') node.setAttribute('aria-hidden', String(value));
    else if (key === 'onSubmit') node.addEventListener('submit', value);
    else node.setAttribute(key, value);
  });
  children.filter(Boolean).forEach((child) => {
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  });
  return node;
}

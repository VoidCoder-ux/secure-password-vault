import { createEncryptedVault, encryptVaultWithKey, lockKey, unlockVault, validateEncryptedPayload } from './crypto.js';
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
  notice: '',
  noticeType: 'success'
};
const MASK = '************';
let clipboardClearTimer = null;
let clipboardClearToken = 0;
let fieldIdCounter = 0;

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

registerServiceWorker();
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
          'Argon2id + AES-256-GCM kullanilir. Veriler yalnizca sifreli bicimde saklanir.'
        ])
      ])
    ])
  );
}

function createVaultForm() {
  const passwordInput = input('password', 'Ana parola', 'En az 12 karakter', {
    autocomplete: 'new-password',
    minlength: '12',
    required: true
  });
  const confirmInput = input('password', 'Ana parolayi tekrar girin', '', {
    autocomplete: 'new-password',
    minlength: '12',
    required: true
  });
  const acknowledgeInput = el('input', { type: 'checkbox', required: true });
  const strengthText = el('span', { className: 'score', ariaLive: 'polite' }, ['Ana parola gucu: -']);
  const matchText = el('span', { className: 'field-help', ariaLive: 'polite' }, [
    'Ana parola tekrar alani eslesince kasa olusturulabilir.'
  ]);
  const formError = el('div', { className: 'field-error', role: 'alert' }, ['']);
  let pending = false;
  const updateHints = () => {
    strengthText.textContent = `Ana parola gucu: ${passwordScore(passwordInput.value)}/5`;
    matchText.textContent =
      confirmInput.value && passwordInput.value !== confirmInput.value
        ? 'Ana parola tekrar alani eslesmiyor.'
        : 'Ana parola tekrar alani eslesince kasa olusturulabilir.';
  };
  passwordInput.addEventListener('input', updateHints);
  confirmInput.addEventListener('input', updateHints);
  const submit = button('Kasayi olustur', 'primary', async () => {
    if (pending) return;
    try {
      formError.textContent = '';
      if (!passwordInput.checkValidity()) {
        passwordInput.reportValidity();
        passwordInput.focus();
        return;
      }
      if (!confirmInput.checkValidity()) {
        confirmInput.reportValidity();
        confirmInput.focus();
        return;
      }
      if (passwordInput.value !== confirmInput.value) {
        formError.textContent = 'Ana parola tekrar alani eslesmiyor.';
        confirmInput.focus();
        return;
      }
      if (!acknowledgeInput.checked) {
        formError.textContent = 'Ana parolanin kurtarilamayacagini onaylamalisiniz.';
        acknowledgeInput.focus();
        return;
      }
      pending = true;
      submit.disabled = true;
      submit.textContent = 'Kasa olusturuluyor...';
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
      formError.textContent = error.message;
      submit.disabled = false;
      submit.textContent = 'Kasayi olustur';
      pending = false;
    }
  });

  return el('form', { className: 'stack', onSubmit: prevent(() => submit.click()) }, [
    fieldWrap('Ana parola', passwordInput, 'En az 12 karakter kullanin. Bu parola cihaz disina gonderilmez.'),
    strengthText,
    fieldWrap('Ana parolayi tekrar girin', confirmInput),
    matchText,
    el('label', { className: 'check-line recovery-check' }, [
      acknowledgeInput,
      el('span', {}, ['Ana parolayi unutursam kasanin kurtarilamayacagini anliyorum.'])
    ]),
    formError,
    submit
  ]);
}

function unlockForm() {
  const passwordInput = input('password', 'Ana parola', '', {
    autocomplete: 'current-password',
    required: true
  });
  const formHelp = el('div', { className: 'field-help' }, [
    'Ana parola bizde saklanmaz. Dogru parola veya dogru yedek dosyasi olmadan kasa acilamaz.'
  ]);
  let pending = false;
  const submit = button('Kasayi ac', 'primary', async () => {
    if (pending) return;
    try {
      if (!passwordInput.checkValidity()) {
        passwordInput.reportValidity();
        passwordInput.focus();
        return;
      }
      pending = true;
      submit.disabled = true;
      submit.textContent = 'Kasa aciliyor...';
      const payload = loadEncryptedVault();
      const result = await unlockVault(passwordInput.value, payload);
      state.payload = payload;
      state.vault = normalizeVault(result.vault);
      state.key = result.key;
      state.selectedId = state.vault.entries[0]?.id || null;
      renderVault('Kasa acildi.');
    } catch (error) {
      renderLocked('Ana parola hatali, yedek dosyasi bozuk veya kasa formati desteklenmiyor.');
    }
  });

  return el('form', { className: 'stack', onSubmit: prevent(() => submit.click()) }, [
    fieldWrap('Ana parola', passwordInput),
    formHelp,
    submit
  ]);
}

function renderVault(notice = '', noticeType = 'success') {
  state.notice = notice;
  state.noticeType = noticeType;
  scheduleAutoLock();
  const visibleEntries = getFilteredEntries();
  const selected = visibleEntries.find((entry) => entry.id === state.selectedId) || null;
  const totalEntries = state.vault.entries.length;
  const favoriteEntries = state.vault.entries.filter((entry) => entry.favorite).length;
  app.replaceChildren(
    el('main', { className: 'vault-shell' }, [
      el('header', { className: 'vault-hero' }, [
        el('div', { className: 'vault-title' }, [
          el('p', { className: 'eyebrow' }, ['Yerel sifreli kasa']),
          el('h1', {}, ['Sifre kasasi']),
          el('p', { className: 'lede' }, [
            'Kayitlariniz bu cihazda sifreli tutulur. Ana parola olmadan kasa acilamaz.'
          ])
        ]),
        el('div', { className: 'vault-actions' }, [
          button('Yeni kayit', 'primary', () => editEntry(null)),
          button('Yedek indir', 'ghost', exportVault),
          importButton(),
          button('Kilitle', 'ghost', () => lockVault('Kasa kilitlendi.'))
        ])
      ]),
      el('section', { className: 'vault-summary' }, [
        statTile('Toplam kayit', String(totalEntries)),
        statTile('Favori', String(favoriteEntries)),
        statTile('Oto kilit', `${state.lockMinutes} dk`)
      ]),
      el('section', { className: 'vault-workspace' }, [
        el('section', { className: 'list-panel' }, [
          el('div', { className: 'list-panel-header' }, [
            el('div', {}, [
              el('p', { className: 'eyebrow' }, ['Kayitlar']),
              el('h2', {}, [state.search ? 'Arama sonuclari' : 'Tum sifreler'])
            ]),
            button('+', 'icon primary', () => editEntry(null), 'Yeni kayit')
          ]),
          searchBox(),
          entryList()
        ]),
        el('section', { className: 'detail' }, [
          notice ? el('div', { className: `alert ${noticeType}`, role: noticeType === 'danger' ? 'alert' : 'status' }, [notice]) : null,
          securityBar(),
          selected ? entryDetail(selected) : emptyState()
        ])
      ])
    ])
  );
}

function statTile(label, value) {
  return el('div', { className: 'stat-tile' }, [
    el('span', { className: 'stat-value' }, [value]),
    el('span', { className: 'stat-label' }, [label])
  ]);
}

function searchBox() {
  const field = input('search', 'Ara', 'site, kullanici, kategori');
  field.value = state.search;
  field.addEventListener('input', () => {
    const caret = field.selectionStart ?? field.value.length;
    state.search = field.value;
    renderVault();
    const nextField = app.querySelector('input[aria-label="Ara"]');
    nextField?.focus();
    nextField?.setSelectionRange(caret, caret);
  });
  return field;
}

function entryList() {
  const entries = getFilteredEntries();

  if (!entries.length) {
    return el('div', { className: 'empty-list' }, [
      state.search ? `"${state.search}" icin kayit bulunamadi. ` : 'Kayit bulunamadi.',
      state.search ? button('Aramayi temizle', 'ghost compact', () => {
        state.search = '';
        renderVault();
      }) : ''
    ]);
  }

  return el(
    'div',
    { className: 'entry-list' },
    entries.map((entry) => {
      const row = button('', `entry-row ${entry.id === state.selectedId ? 'active' : ''}`, () => {
        state.selectedId = entry.id;
        renderVault();
      }, `${entry.title} kaydini ac`, [
        el('span', { className: 'entry-title' }, [entry.favorite ? '* ' : '', entry.title || 'Adsiz kayit']),
        el('span', { className: 'entry-subtitle' }, [entry.username || entry.url || 'Kullanici yok'])
      ]);
      if (entry.id === state.selectedId) {
        row.setAttribute('aria-current', 'true');
      }
      return row;
    })
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
  const text = el('span', { className: 'secret-value' }, [masked ? MASK : value]);
  let visible = false;
  let toggleButton;
  const controls = masked
    ? [
        (toggleButton = button('Goster', 'ghost compact', () => {
          visible = !visible;
          text.textContent = visible ? value : MASK;
          toggleButton.textContent = visible ? 'Gizle' : 'Goster';
          toggleButton.setAttribute('aria-pressed', String(visible));
        })),
        button('Kopyala', 'secondary compact', () => copySecret(value))
      ]
    : value && value !== '-'
      ? [button('Kopyala', 'ghost compact', () => copySecret(value))]
      : [];
  if (toggleButton) {
    toggleButton.setAttribute('aria-pressed', 'false');
  }

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
    el('h2', {}, [state.search ? 'Arama sonucu yok' : 'Kasa bos']),
    el('p', {}, [
      state.search
        ? 'Arama terimini temizleyebilir veya bu bilgiyle yeni bir kayit ekleyebilirsiniz.'
        : 'Ilk kaydinizi ekleyin. Ardindan sifreli yedek dosyanizi indirip guvenli bir yerde saklayin.'
    ]),
    el('div', { className: 'button-row' }, [
      state.search ? button('Aramayi temizle', 'ghost', () => {
        state.search = '';
        renderVault();
      }) : null,
      button('Yeni kayit ekle', 'primary', () => editEntry(null))
    ])
  ]);
}

function editEntry(entry) {
  const draft = { ...emptyEntry, ...entry };
  const fields = {
    title: input('text', 'Baslik', 'or. GitHub', { required: true }),
    username: input('text', 'Kullanici adi', 'or. mail@domain.com', { autocomplete: 'username' }),
    password: input('password', 'Sifre', '', { required: true, autocomplete: 'new-password' }),
    url: input('url', 'Adres', 'https://'),
    category: input('text', 'Kategori', 'Is, kisisel, banka'),
    notes: el('textarea', { placeholder: 'Not', rows: 4, ariaLabel: 'Not' }),
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

  const generatedScore = el('span', { className: 'score', ariaLive: 'polite' }, ['']);
  const formError = el('div', { className: 'field-error', role: 'alert' }, ['']);
  const togglePassword = button('Goster', 'ghost compact', () => {
    const visible = fields.password.type === 'password';
    fields.password.type = visible ? 'text' : 'password';
    togglePassword.textContent = visible ? 'Gizle' : 'Goster';
    togglePassword.setAttribute('aria-pressed', String(visible));
  });
  togglePassword.setAttribute('aria-pressed', 'false');
  const generate = button('Guclu sifre uret', 'secondary', () => {
    try {
      fields.password.value = generatePassword({ length: Number(generatorLength.value) });
      generatedScore.textContent = `Guc: ${passwordScore(fields.password.value)}/5`;
    } catch (error) {
      generatedScore.textContent = error.message;
    }
  });

  const save = button('Kaydet', 'primary', async () => {
    formError.textContent = '';
    if (!fields.title.checkValidity()) {
      formError.textContent = 'Baslik zorunlu.';
      fields.title.focus();
      return;
    }
    if (!fields.password.checkValidity()) {
      formError.textContent = 'Sifre zorunlu.';
      fields.password.focus();
      return;
    }
    if (!fields.url.checkValidity()) {
      fields.url.reportValidity();
      return;
    }
    const normalizedUrl = normalizeUrl(fields.url.value.trim());
    if (fields.url.value.trim() && !normalizedUrl) {
      fields.url.setCustomValidity('Yalnizca http:// veya https:// adresleri kabul edilir.');
      fields.url.reportValidity();
      fields.url.setCustomValidity('');
      return;
    }
    const now = new Date().toISOString();
    const next = {
      id: entry?.id || crypto.randomUUID(),
      title: fields.title.value.trim(),
      username: fields.username.value.trim(),
      password: fields.password.value,
      url: normalizedUrl,
      category: fields.category.value.trim(),
      notes: fields.notes.value.trim(),
      favorite: fields.favorite.checked,
      createdAt: entry?.createdAt || now,
      updatedAt: now
    };

    if (!next.title || !next.password) {
      formError.textContent = 'Baslik ve sifre zorunlu.';
      fields.title.focus();
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
        fieldWrap('Baslik', fields.title, 'Kaydi listede taniyabileceginiz bir ad yazin.'),
        fieldWrap('Kullanici adi', fields.username),
        fieldWrap('Sifre', el('div', { className: 'password-field' }, [fields.password, togglePassword])),
        fieldWrap('Adres', fields.url, 'Yalnizca http veya https adresleri kabul edilir.'),
        fieldWrap('Kategori', fields.category),
        el('label', { className: 'check-line' }, [fields.favorite, el('span', {}, ['Favori'])])
      ]),
      fieldWrap('Not', fields.notes),
      el('div', { className: 'generator' }, [fieldWrap('Uzunluk', generatorLength), generate, generatedScore]),
      formError,
      el('div', { className: 'button-row' }, [
        save,
        button('Vazgec', 'ghost', () => renderVault())
      ])
    ])
  );
  fields.title.focus();
}

async function deleteEntry(id) {
  const ok = confirm('Bu kayit silinecek.');
  if (!ok) return;
  state.vault.entries = state.vault.entries.filter((entry) => entry.id !== id);
  state.vault.updatedAt = new Date().toISOString();
  state.selectedId = getFilteredEntries()[0]?.id || state.vault.entries[0]?.id || null;
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
      validateEncryptedPayload(payload);
      if (hasStoredVault()) {
        const ok = confirm('Yedekten geri yukleme bu cihazdaki kasanin yerine gececek. Once mevcut kasayi yedeklediginizden emin olun.');
        if (!ok) return;
      }
      saveEncryptedVault(payload);
      lockVault('Sifreli kasa import edildi. Ana parola ile acin.');
    } catch (error) {
      if (state.vault) {
        renderVault(error.message, 'danger');
      } else {
        renderLocked(error.message);
      }
    }
  });

  return el('span', {}, [
    fileInput,
    button('Yedekten yukle', 'ghost', () => fileInput.click())
  ]);
}

async function copySecret(value) {
  if (!value || value === '-') return;
  if (!navigator.clipboard?.writeText) {
    renderVault('Clipboard API bu ortamda kullanilamiyor.', 'danger');
    return;
  }
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    renderVault('Pano izni reddedildi veya kullanilamiyor.', 'danger');
    return;
  }
  const token = ++clipboardClearToken;
  if (clipboardClearTimer) {
    window.clearTimeout(clipboardClearTimer);
  }
  renderVault('Panoya kopyalandi. 30 saniye sonra temizleme denenecek.');
  clipboardClearTimer = window.setTimeout(async () => {
    if (token !== clipboardClearToken) return;
    try {
      await navigator.clipboard.writeText('');
    } catch {
      // Browser izin vermezse sessizce gecilir.
    }
    clipboardClearTimer = null;
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

function getFilteredEntries() {
  const query = state.search.trim().toLowerCase();
  return state.vault.entries
    .filter((entry) =>
      [entry.title, entry.username, entry.category, entry.url, entry.notes].join(' ').toLowerCase().includes(query)
    )
    .sort((a, b) => Number(b.favorite) - Number(a.favorite) || a.title.localeCompare(b.title));
}

function normalizeUrl(value) {
  if (!value) return '';
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) ? url.href : '';
  } catch {
    return '';
  }
}

function registerServiceWorker() {
  if (!('serviceWorker' in navigator)) return;
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(() => {
      // PWA destegi olmadiginda uygulama normal web uygulamasi olarak calisir.
    });
  });
}

function input(type, label, placeholder, attrs = {}) {
  const field = el('input', { type, placeholder, ariaLabel: label, ...attrs });
  return field;
}

function fieldWrap(label, control, help = '') {
  const target = control.matches?.('input, textarea, select') ? control : control.querySelector?.('input, textarea, select');
  const id = target ? ensureId(target) : '';
  return el('div', { className: 'field-label' }, [
    el('label', { className: 'field-title', for: id }, [label]),
    control,
    help ? el('span', { className: 'field-help' }, [help]) : null
  ]);
}

function ensureId(control) {
  if (!control.id) {
    fieldIdCounter += 1;
    control.id = `field-${fieldIdCounter}`;
  }
  return control.id;
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
    else if (key === 'ariaLive') node.setAttribute('aria-live', value);
    else if (key === 'onSubmit') node.addEventListener('submit', value);
    else if (key in node) node[key] = value;
    else node.setAttribute(key, value);
  });
  children.filter(Boolean).forEach((child) => {
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  });
  return node;
}

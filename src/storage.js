const STORAGE_KEY = 'secure-password-vault:v1';

export function hasStoredVault() {
  return Boolean(localStorage.getItem(STORAGE_KEY));
}

export function loadEncryptedVault() {
  const raw = localStorage.getItem(STORAGE_KEY);
  return raw ? JSON.parse(raw) : null;
}

export function saveEncryptedVault(payload) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
}

export function deleteEncryptedVault() {
  localStorage.removeItem(STORAGE_KEY);
}

export function downloadJson(filename, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.rel = 'noopener';
  link.click();
  URL.revokeObjectURL(url);
}

export function readJsonFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        resolve(JSON.parse(String(reader.result)));
      } catch (error) {
        reject(new Error('JSON dosyasi okunamadi.'));
      }
    };
    reader.onerror = () => reject(new Error('Dosya okunamadi.'));
    reader.readAsText(file);
  });
}

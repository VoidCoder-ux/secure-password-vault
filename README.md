# Secure Password Vault

Yerel ve sıfır-bilgi mantığında çalışan şifre kasası.

## Güvenlik modeli

- Ana parola saklanmaz ve ağ üzerinden gönderilmez.
- Kasa anahtarı Argon2id ile türetilir.
- Kasa verisi AES-256-GCM ile şifrelenir ve doğrulanır.
- Her kaydetmede yeni nonce kullanılır.
- Kasa cihazda yalnızca şifreli JSON olarak tutulur.
- Oturum otomatik kilitlenir ve pano temizleme denenir.

Ana parola unutulursa kasa açılamaz. Bu bilerek tasarlanmış bir özelliktir; arka kapı veya reset mekanizması yoktur.

## Geliştirme

```bash
npm install
npm test
npm run dev
```

## Yayınlama

Repo GitHub Pages Actions ile yayınlanacak şekilde hazırlanmıştır. Settings > Pages bölümünde kaynak olarak GitHub Actions seçilmelidir.

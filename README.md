# Secure Password Vault

Yerel ve sifir-bilgi mantiginda calisan sifre kasasi.

## Guvenlik modeli

- Ana parola saklanmaz ve ag uzerinden gonderilmez.
- Kasa anahtari Argon2id ile turetilir.
- Kasa verisi AES-256-GCM ile sifrelenir ve dogrulanir.
- Her kaydetmede yeni nonce kullanilir.
- Kasa cihazda yalnizca sifreli JSON olarak tutulur.
- Oturum otomatik kilitlenir ve pano temizleme denenir.

Ana parola unutulursa kasa acilamaz. Bu bilerek tasarlanmis bir ozelliktir; arka kapi veya reset mekanizmasi yoktur.

## Gelistirme

```bash
npm install
npm test
npm run dev
```

## Yayinlama

Repo GitHub Pages Actions ile yayinlanacak sekilde hazirlanmistir. Settings > Pages bolumunde kaynak olarak GitHub Actions secilmelidir.

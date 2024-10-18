# Kullanıcı Ekleme ve Yönetim Scripti (PowerShell)

## Uygulamanın Amacı
Bu PowerShell scripti, Windows işletim sisteminde otomatik olarak yeni bir kullanıcı eklemek, bu kullanıcıya yönetici (admin) yetkisi vermek, Windows Defender'ı devre dışı bırakmak, Windows Güvenlik Duvarı'nı kapatmak ve Uzak Masaüstü'nü (RDP) etkinleştirmek için kullanılmaktadır. Script ayrıca, sunucu IP adresini içeriden alarak Uzak Masaüstü (RDP) bağlantısını otomatik olarak başlatır.

## Uygulamanın Özellikleri
- Yeni bir kullanıcı ekler.
- Eklenen kullanıcıya yönetici (admin) yetkisi verir.
- Windows Defender'ı devre dışı bırakır.
- Windows Güvenlik Duvarı'nı devre dışı bırakır.
- Uzak Masaüstü'nü (RDP) etkinleştirir.
- Sunucu IP adresini içeriden alarak, RDP bağlantısını başlatır.

## Nasıl Çalışır?
1. **Yönetici Yetkisiyle Çalıştırma:** Bu script yalnızca yönetici yetkilerine sahip bir PowerShell oturumu ile çalıştırılmalıdır. 
2. **Kullanıcı Ekleme:** Belirtilen kullanıcı adı ve şifre ile yeni bir kullanıcı oluşturur. Eğer kullanıcı zaten mevcutsa, yeniden eklemez.
3. **Yönetici Yetkisi Verme:** Eklenen kullanıcıya "Administrators" grubuna ekleyerek yönetici yetkisi verir.
4. **Windows Defender'ı Devre Dışı Bırakma:** Windows Defender'ın gerçek zamanlı izleme özelliğini kapatır.
5. **Güvenlik Duvarını Kapatma:** Tüm ağ profilleri (Domain, Public, Private) için Windows Güvenlik Duvarı'nı devre dışı bırakır.
6. **Uzak Masaüstü'nü (RDP) Etkinleştirme:** Uzak Masaüstü'nü etkinleştirir ve gerekli güvenlik duvarı kurallarını açar.
7. **Sunucu IP'sini Alma:** Sunucuya ait IPv4 adresini alır ve ekrana yazdırır.
8. **RDP Bağlantısı:** Uzak Masaüstü bağlantısı (mstsc) başlatarak sunucuya otomatik bağlanır.

## Nasıl Kullanılır?
1. PowerShell'i **yönetici olarak** açın.
2. Script'i çalıştırmadan önce `ExecutionPolicy` ayarını şu komutla düzenleyin:
    ```powershell
    Set-ExecutionPolicy RemoteSigned
    ```
3. Script'i şu komutla çalıştırın:
    ```powershell
    .\rootwin.ps1
    ```

## Gereksinimler
- Windows işletim sistemi
- Yönetici yetkileriyle çalıştırılmalı
- PowerShell versiyon 5.0 ve üstü



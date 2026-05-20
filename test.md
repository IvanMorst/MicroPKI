Предварительная настройка
powershell
# Создаем директории
```bash
```
New-Item -ItemType Directory -Force -Path .\secrets
New-Item -ItemType Directory -Force -Path .\logs
New-Item -ItemType Directory -Force -Path .\pki

# Создаем файлы с парольными фразами
"root_secret_password" | Out-File -FilePath .\secrets\root.pass -Encoding ascii -NoNewline
"intermediate_secret_password" | Out-File -FilePath .\secrets\intermediate.pass -Encoding ascii -NoNewline
"ocsp_secret_password" | Out-File -FilePath .\secrets\ocsp.pass -Encoding ascii -NoNewline
1. Инициализация базы данных
powershell
micropki db init --db-path .\pki\micropki.db --force
Ожидаемый результат: Database initialised at .\pki\micropki.db

2. Создание корневого CA
powershell
```bash
micropki init `
    --subject "/CN=MicroPKI Root CA/O=MicroPKI/C=RU" `
    --key-type rsa `
    --key-size 4096 `
    --passphrase-file .\secrets\root.pass `
    --out-dir .\pki `
    --validity-days 3650 `
    --db-path .\pki\micropki.db `
    --log-file .\logs\root-ca.log
  ```
Ожидаемый результат: Успешное создание корневого CA

3. Создание промежуточного CA
powershell
micropki issue-intermediate `
    --root-cert .\pki\certs\ca.cert.pem `
    --root-key .\pki\private\ca.key.pem `
    --root-pass-file .\secrets\root.pass `
    --subject "CN=MicroPKI Intermediate CA,O=MicroPKI" `
    --key-type rsa `
    --key-size 4096 `
    --passphrase-file .\secrets\intermediate.pass `
    --out-dir .\pki `
    --validity-days 1825 `
    --pathlen 0 `
    --db-path .\pki\micropki.db `
    --log-file .\logs\intermediate-ca.log
4. Выпуск сертификатов
4.1 Серверный сертификат
powershell
micropki issue-cert `
    --ca-cert .\pki\certs\intermediate.cert.pem `
    --ca-key .\pki\private\intermediate.key.pem `
    --ca-pass-file .\secrets\intermediate.pass `
    --template server `
    --subject "CN=api.example.com,O=MicroPKI" `
    --san dns:api.example.com `
    --san dns:api2.example.com `
    --san ip:10.0.0.1 `
    --out-dir .\pki\certs `
    --validity-days 365 `
    --db-path .\pki\micropki.db `
    --log-file .\logs\issue-server.log
4.2 Клиентский сертификат
powershell
micropki issue-cert `
    --ca-cert .\pki\certs\intermediate.cert.pem `
    --ca-key .\pki\private\intermediate.key.pem `
    --ca-pass-file .\secrets\intermediate.pass `
    --template client `
    --subject "CN=Alice Smith" `
    --san email:alice@example.com `
    --san dns:alice-client `
    --out-dir .\pki\certs `
    --validity-days 365 `
    --db-path .\pki\micropki.db

4.3 Сертификат для подписи кода
powershell
micropki issue-cert `
    --ca-cert .\pki\certs\intermediate.cert.pem `
    --ca-key .\pki\private\intermediate.key.pem `
    --ca-pass-file .\secrets\intermediate.pass `
    --template code_signing `
    --subject "CN=MicroPKI Code Signing" `
    --out-dir .\pki\certs `
    --validity-days 365 `
    --db-path .\pki\micropki.db
5. Выпуск OCSP сертификата
powershell
micropki issue-ocsp-cert `
    --ca-cert .\pki\certs\intermediate.cert.pem `
    --ca-key .\pki\private\intermediate.key.pem `
    --ca-pass-file .\secrets\intermediate.pass `
    --subject "CN=OCSP Responder,O=MicroPKI" `
    --key-type rsa `
    --key-size 2048 `
    --san dns:ocsp.example.com `
    --out-dir .\pki\certs `
    --validity-days 365 `
    --db-path .\pki\micropki.db
6. Просмотр списка сертификатов
powershell
# Табличный формат
micropki list-certs --db-path .\pki\micropki.db --format table

# JSON формат
micropki list-certs --db-path .\pki\micropki.db --format json

# Только валидные
micropki list-certs --db-path .\pki\micropki.db --status valid --format table

7. Просмотр конкретного сертификата
powershell
# Сначала получите серийный номер из списка, затем выполните:
# micropki show-cert BFDCBDA2A5A0906 --db-path .\pki\micropki.db
8. Генерация CRL
powershell
micropki gen-crl `
    --ca intermediate `
    --next-update 14 `
    --out-dir .\pki `
    --db-path .\pki\micropki.db `
    --passphrase-file .\secrets\intermediate.pass
9. Отзыв сертификата
powershell
# Замените <SERIAL> на серийный номер из списка
micropki revoke BFDCBDA2A5A0906 `
    --reason keyCompromise `
    --force `
    --db-path .\pki\micropki.db
10. Повторная генерация CRL
powershell
micropki gen-crl `
    --ca intermediate `
    --next-update 14 `
    --out-dir .\pki `
    --db-path .\pki\micropki.db `
    --passphrase-file .\secrets\intermediate.pass
11. Проверка статуса отзыва
powershell
micropki check-revoked BFDCBDA2A5A0906 --db-path .\pki\micropki.db
12. Запуск репозитория (в отдельном окне PowerShell)
powershell
micropki repo serve `
    --host 127.0.0.1 `
    --port 8080 `
    --db-path .\pki\micropki.db `
    --cert-dir .\pki\certs `
    --crl-dir .\pki\crl `
    --log-file .\logs\repo.log
13. Запуск OCSP респондера (в отдельном окне PowerShell)
powershell
micropki ocsp serve `
    --host 127.0.0.1 `
    --port 8081 `
    --db-path .\pki\micropki.db `
    --responder-cert .\pki\certs\ocsp.cert.pem `
    --responder-key .\pki\certs\ocsp.key.pem `
    --ca-cert .\pki\certs\intermediate.cert.pem `
    --cache-ttl 120 `
    --log-file .\logs\ocsp.log
14. Проверка цепочки сертификатов
powershell
micropki validate-chain `
    --leaf .\pki\certs\api.example.com.cert.pem `
    --intermediate .\pki\certs\intermediate.cert.pem `
    --root .\pki\certs\ca.cert.pem
15. Тестирование API (в другом окне)
powershell
# Получение корневого сертификата
Invoke-WebRequest -Uri "http://127.0.0.1:8080/ca/root" -OutFile "root-test.pem"

# Получение промежуточного сертификата
Invoke-WebRequest -Uri "http://127.0.0.1:8080/ca/intermediate" -OutFile "intermediate-test.pem"

# Получение CRL
Invoke-WebRequest -Uri "http://127.0.0.1:8080/crl?ca=intermediate" -OutFile "crl-test.pem"
16. Тестирование OCSP (требуется OpenSSL)
powershell
# Убедитесь, что OpenSSL установлен и доступен в PATH
openssl ocsp -issuer .\pki\certs\intermediate.cert.pem `
    -cert .\pki\certs\api.example.com.cert.pem `
    -url http://127.0.0.1:8081 `
    -resp_text -no_nonce
Остановка серверов
powershell
# В окнах с запущенными серверами нажмите Ctrl+C
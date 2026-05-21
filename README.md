

# MicroPKI

**Минимальная реализация Public Key Infrastructure (PKI) для образовательных целей**

MicroPKI - это легковесная утилита командной строки для создания самоподписанного корневого центра сертификации (Root CA) с соблюдением всех криптографических стандартов. Проект демонстрирует правильную работу с X.509 сертификатами, безопасное хранение ключей и аудит операций.

---

## Содержание
- [Архитектура проекта](#архитектура-проекта)
- [Требования к системе](#требования-к-системе)
- [Установка](#установка)
- [Использование](#использование)
  - [Инициализация корневого CA](#инициализация-корневого-ca)
  - [Создание промежуточного CA](#создание-промежуточного-ca)
  - [Выпуск сертификатов](#выпуск-сертификатов)
  - [Выпуск сертификата OCSP-responder](#выпуск-сертификата-ocsp-responder)
  - [Управление отзывом сертификатов](#управление-отзывом-сертификатов)
  - [Генерация списка отзыва (CRL)](#генерация-списка-отзыва-crl)
  - [Управление базой данных](#управление-базой-данных)
  - [Запуск репозитория](#запуск-репозитория)
  - [Параметры команды](#параметры-команды)
- [Структура выходных файлов](#структура-выходных-файлов)
- [Верификация результатов](#верификация-результатов)
  - [Проверка сертификата через OpenSSL](#проверка-сертификата-через-openssl)
  - [Проверка цепочки сертификатов](#проверка-цепочки-сертификатов)
  - [Проверка соответствия ключа и сертификата](#проверка-соответствия-ключа-и-сертификата)
  - [Проверка списка отзыва (CRL)](#проверка-списка-отзыва-crl)
  - [Генерация CSR и приватного ключа](#Генерация-CSR-и-приватного-ключа)
  - [Аудит, политики безопасности и усиление PKI](Аудит-политики-безопасности-и-усиление-PKI)
  - [Загрузка зашифрованного ключа](#загрузка-зашифрованного-ключа)
- [Тестирование](#тестирование)
- [Лицензия](#лицензия)

---

## Архитектура проекта
````
micropki/
├── micropki/
│   ├── __init__.py
│   ├── cli.py
│   ├── ca.py
│   ├── certificates.py
│   ├── crypto_utils.py
│   ├── csr.py                 CSR generation and handling
│   ├── templates.py           Certificate templates
│   ├── chain.py               Chain validation
│   ├── database.py 
│   ├── repository.py 
│   ├── serial.py
│   ├── crl.py
│   ├── ocsp.py
│   ├── ocsp_responder.py
│   ├── revocation.py
│   ├── validation.py
│   ├── revocation_check.py
│   ├── client.py
│   ├── transparency.py
│   ├── ratelimit.py
│   ├── policy.py
│   ├── compromise.py
│   ├── audit.py
│   └── logger.py
├── tests/
│   ├── __init__.py
│   ├── test_ca.py
│   ├── test_certificates.py
│   ├── test_csr.py             
│   ├── test_database.py
│   ├── test_repository.py
│   ├── test_serial.py 
│   ├── test_ocsp.py
│   ├── test_templates.py       
│   ├── test_crl.py 
│   ├── test_revocation.py 
│   ├── test_validation.py
│   └── test_chain.py            
├── requirements.txt
├── setup.py
├── README.md
└── .gitignore
````


## Требования к системе
````
- **Python**: версия 3.8 или выше
- **Зависимости**: см. `requirements.txt`
  - `cryptography>=3.0` - все криптографические операции
  - `pytest>=6.0` - для запуска тестов (опционально)
- **Операционная система**: Linux/Unix , macOS, Windows (с ограниченной поддержкой прав доступа)
````
## Установка

### 1. Клонирование репозитория
```bash

git clone https://github.com/IvanMorst/MicroPKI.git
````

```bash

cd micropki
```
2. Создание виртуального окружения

```bash

python -m venv venv
```

```bash

source venv/bin/activate      # Для Linux/macOS
```

# или

```bash

venv\Scripts\activate         # Для Windows
````
3. Установка зависимостей


```bash
pip install -r requirements.txt
````
4. Установка пакета в режиме разработки

```bash

pip install -e .
````
### После установки команда micropki станет доступна в терминале.

## Использование
### Инициализация корневого CA
Минимальная команда для создания корневого центра сертификации:

```bash

micropki init 
    --subject "/CN=Demo Root CA" 
    --key-type rsa 
    --key-size 4096 
    --passphrase-file ./secrets/ca.pass 
    --out-dir ./pki 
    --validity-days 7300 
    --log-file ./logs/ca-init.log
    
```
### Создание промежуточного CA
```bash

bash
micropki issue-intermediate \
    --root-cert ./pki/certs/ca.cert.pem \
    --root-key ./pki/private/ca.key.pem \
    --root-pass-file ./secrets/ca.pass \
    --subject "CN=MicroPKI Intermediate CA,O=MicroPKI" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./secrets/intermediate.pass \
    --out-dir ./pki \
    --validity-days 1825 \
    --pathlen 0
    ```

````
### Выпуск сертификатов

```bash

# Серверный сертификат
micropki issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --subject "CN=example.com,O=MicroPKI" \
    --san dns:example.com \
    --san dns:www.example.com \
    --san ip:192.168.1.10 \
    --out-dir ./pki/certs \
    --validity-days 365

# Клиентский сертификат
micropki issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template client \
    --subject "CN=Alice Smith,EMAIL=alice@example.com" \
    --san email:alice@example.com \
    --out-dir ./pki/certs

# Сертификат для подписи кода
micropki issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template code_signing \
    --subject "CN=MicroPKI Code Signer" \
    --out-dir ./pki/certs
```
## Выпуск сертификата OCSP-responder
```bash
micropki issue-ocsp-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --subject "CN=OCSP Responder,O=MicroPKI" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:ocsp.example.com \
    --out-dir ./pki/certs \
    --validity-days 365
````
### Управление отзывом сертификатов (Revocation)

```bash
# Отзыв сертификата по серийному номеру
micropki revoke 2A7F3B8E... --reason keyCompromise

# Отзыв с указанием причины и без подтверждения
micropki revoke 3B8E5F1A... --reason superseded --force

# Проверка статуса сертификата
micropki check-revoked 2A7F3B8E...
````
### Генерация списка отзыва сертификатов (CRL)
```bash
# Генерация CRL для промежуточного CA (обновление каждые 14 дней)
micropki gen-crl --ca intermediate --next-update 14

# Генерация CRL для корневого CA с сохранением в указанный файл
micropki gen-crl --ca root --out-file ./backup/root.crl.pem
```
### Управление базой данных

```bash
# Инициализация базы данных сертификатов
micropki db init --db-path ./pki/micropki.db

# Список всех выданных сертификатов
micropki list-certs --status valid --format table

# Просмотр сертификата по серийному номеру
micropki show-cert 3A7F... --db-path ./pki/micropki.db
```
### Запуск репозитория
````bash
# Запуск HTTP сервера
micropki repo serve \
    --host 127.0.0.1 \
    --port 8080 \
    --db-path ./pki/micropki.db \
    --cert-dir ./pki/certs
````
## Запуск OCSP responder
````bash
micropki ocsp serve \
    --host 127.0.0.1 \
    --port 8081 \
    --db-path ./pki/micropki.db \
    --responder-cert ./pki/certs/ocsp.cert.pem \
    --responder-key ./pki/certs/ocsp.key.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --cache-ttl 120
````
### Параметры команды
| Параметр             | Описание                                                              | Обязательный | Значение по умолчанию |
|----------------------|-----------------------------------------------------------------------|--------------|-----------------------|
| `--subject`          | Distinguished Name в формате `/CN=.../O=...` или `CN=...,O=...`       | Да           | —                     |
| `--key-type`         | Тип ключа: `rsa` или `ecc`                                            | Нет          | `rsa`                 |
| `--key-size`         | Размер ключа: для RSA - 4096, для ECC - 384                           | Нет          | `4096`                |
| `--passphrase-file`  | Путь к файлу с парольной фразой для шифрования ключа                  | Да           | —                     |
| `--out-dir`          | Директория для выходных файлов                                        | Нет          | `./pki`               |
| `--validity-days`    | Срок действия сертификата в днях                                      | Нет          | `3650` (10 лет)       |
| `--log-file`         | Файл для логирования (если не указан, вывод в stderr)                 | Нет          | —                     |
| **revoke** | | | |
| `serial` | Серийный номер сертификата в hex | Да | — |
| `--reason` | Причина отзыва: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn`, `aACompromise` | Нет | `unspecified` |
| `--force` | Пропустить подтверждение | Нет | — |
| `--db-path` | Путь к SQLite базе данных | Нет | `./pki/micropki.db` |
| **gen-crl** | | | |
| `--ca` | Тип CA: `root` или `intermediate` | Да | — |
| `--next-update` | Дней до следующего обновления CRL | Нет | `7` |
| `--out-file` | Путь для сохранения CRL файла | Нет | автоопределение |
| `--out-dir` | Выходная директория | Нет | `./pki` |
| `--db-path` | Путь к SQLite базе данных | Нет | `<out-dir>/micropki.db` |
| `--passphrase-file` | Файл с парольной фразой для ключа CA | Нет | автоопределение |

## Примеры использования
RSA-ключ с длительным сроком действия:

```bash

micropki init \
    --subject "/CN=Production Root CA/O=My Company/C=US" \
    --key-type rsa \
    --key-size 4096 \
    --passphrase-file ./secrets/root.pass \
    --out-dir ./production-pki \
    --validity-days 7300 \
    --log-file ./logs/ca-init.log
```
ECC-ключ на кривой P-384:

```bash

micropki init \
    --subject "CN=ECC Root CA,O=Demo" \
    --key-type ecc \
    --key-size 384 \
    --passphrase-file ./secrets/ecc.pass \
    --out-dir ./ecc-pki
````

## Структура выходных файлов

### После успешного выполнения команды в директории --out-dir создается следующая структура:
````
text
<out-dir>/
├── private/
│   └── ca.key.pem           # Зашифрованный приватный ключ (права 0600)
├── certs/
│   └── ca.cert.pem          # Самоподписанный сертификат (PEM)
└── policy.txt               # Документ с политикой сертификации
policy.txt
````
### Пример содержимого:

````
Certificate Policy for MicroPKI Root CA
===================================
CA Name (Subject): CN=Demo Root CA
Certificate Serial Number (hex): 3A9F5C8E2B7D461F
Validity Period:
  Not Before: 2025-02-26T10:30:00.123456+00:00
  Not After : 2035-02-23T10:30:00.123456+00:00
Key Algorithm: RSA-4096
Purpose: Root CA for MicroPKI demonstration
Policy Version: 1.0
Creation Date: 2025-02-26T10:30:00.123456+00:00
````

## Верификация результатов
### vПроверка сертификата через OpenSSL

### Просмотр содержимого сертификата:

```bash

openssl x509 -in ./pki/certs/ca.cert.pem -text -noout
```

### Проверка самоподписанного сертификата:

```bash

openssl verify -CAfile ./pki/certs/ca.cert.pem ./pki/certs/ca.cert.pem
```
#### Ожидаемый результат: stdin: OK

### Проверка цепочки сертификатов

#### Проверка полной цепочки доверия:

```bash
# Создаем файл с цепочкой
cat ./pki/certs/example.com.cert.pem ./pki/certs/intermediate.cert.pem > chain.pem

# Проверяем цепочку
openssl verify -CAfile ./pki/certs/ca.cert.pem -untrusted ./pki/certs/intermediate.cert.pem ./pki/certs/example.com.cert.pem
Встроенная команда MicroPKI для проверки цепочки:

bash
micropki validate-chain \
    --leaf ./pki/certs/example.com.cert.pem \
    --intermediate ./pki/certs/intermediate.cert.pem \
    --root ./pki/certs/ca.cert.pem
````
### Проверка соответствия ключа и сертификата
Извлечение публичного ключа из сертификата:

```bash
openssl x509 -in ./pki/certs/ca.cert.pem -pubkey -noout > cert.pub
```
Извлечение публичного ключа из приватного ключа:

```bash
openssl pkey -in ./pki/private/ca.key.pem -pubout -passin file:./secrets/ca.pass -out key.pub

```
## Сравнение хешей:

```bash
sha256sum cert.pub key.pub
```
### Хеши должны совпадать.

## Загрузка зашифрованного ключа

### Проверка, что ключ зашифрован:

```bash

openssl pkey -in ./pki/private/ca.key.pem -passin file:./secrets/ca.pass -noout -text
```
### Создание тестовой подписи (демонстрация работы ключа):

```bash

echo "test data" > test.txt
openssl dgst -sha256 -sign ./pki/private/ca.key.pem -passin file:./secrets/ca.pass -out test.sig test.txt
openssl dgst -sha256 -verify cert.pub -signature test.sig test.txt
```
Ожидаемый результат: Verified OK

### Проверка списка отзыва (CRL)

**Просмотр содержимого CRL:**
```bash
openssl crl -inform PEM -in ./pki/crl/intermediate.crl.pem -text -noout
Проверка подписи CRL:

bash
openssl crl -in ./pki/crl/intermediate.crl.pem -inform PEM -CAfile ./pki/certs/intermediate.cert.pem -noout
Ожидаемый результат: verify OK

Проверка, что сертификат отозван:

bash
# Извлечение серийного номера из сертификата
SERIAL=$(openssl x509 -in ./pki/certs/example.com.cert.pem -serial -noout | cut -d= -f2)

# Поиск серийного номера в CRL
openssl crl -inform PEM -in ./pki/crl/intermediate.crl.pem -text -noout | grep -i $SERIAL

Если сертификат отозван, серийный номер будет найден в выводе.
````

## Аудит политики безопасности и усиление PKI

### Управление аудитом
```bash
# Просмотр логов с фильтрацией
micropki audit query --from 2026-05-01T00:00:00Z --operation issue --format table
```

```bash
# Проверка целостности всего лога
micropki audit verify --log-file ./pki/audit/audit.log
```
```bash
# Поиск по серийному номеру
micropki audit query --serial 2A7F8B3C...
````

### Симуляция компрометации ключа
```bash
# Отметить сертификат как скомпрометированный (отзыв + блокировка ключа)
micropki ca compromise --cert ./pki/certs/example.com.cert.pem --reason keyCompromise
````
Сертификат немедленно отзывается

Публичный ключ попадает в таблицу compromised_keys

Все последующие CSR с этим ключом будут отклонены

### Ограничение частоты запросов (Rate Limiting)

```bash

# Запуск репозитория с лимитом 5 запросов/сек на IP, burst 10
micropki repo serve --host 0.0.0.0 --port 8080 --rate-limit 5 --rate-burst 10
````
При превышении клиент получает HTTP 429 Too Many Requests с заголовком Retry-After.
### Certificate Transparency (CT) симуляция
 
Для каждого выданного сертификата в ./pki/audit/ct.log добавляется строка:


2026-05-21T10:30:00.123456Z | 2A7F... | CN=example.com | SHA256:... | CN=Intermediate CA

Это позволяет аудиторам проверять наличие сертификата в публичном логе (имитация).

### Проверка целостности лога

```bash

# Проверка всей цепочки (включая проверку prev_hash)
micropki audit verify
```

## Client Tools & Path Validation

### Генерация CSR и приватного ключа

```bash
# Генерация ключа и CSR для серверного сертификата
micropki client gen-csr \
    --subject "CN=app.example.com" \
    --key-type rsa \
    --key-size 2048 \
    --san dns:app.example.com \
    --san dns:api.example.com \
    --out-key ./app.key.pem \
    --out-csr ./app.csr.pem
    
```
Ожидаемый результат: Созданы приватный ключ и CSR файл.


### Запрос сертификата через API

```bash
# Отправка CSR в CA через репозиторий
micropki client request-cert \
    --csr ./app.csr.pem \
    --template server \
    --ca-url http://localhost:8080 \
    --out-cert ./app.cert.pem
```

Ожидаемый результат: Получен подписанный сертификат от CA.


### Валидация цепочки сертификатов

```bash

# Полная проверка цепочки с проверкой отзыва
micropki client validate \
    --cert ./app.cert.pem \
    --untrusted ./pki/certs/intermediate.cert.pem \
    --trusted ./pki/certs/ca.cert.pem \
    --crl-url http://localhost:8080/crl?ca=intermediate \
    --ocsp-url http://localhost:8081 \
    --mode full
    
```
Ожидаемый результат: Вывод результата валидации с перечнем проверенных шагов.

### Проверка статуса отзыва (OCSP + CRL fallback)

```bash

# Проверка статуса сертификата (OCSP first, CRL fallback)
micropki client check-status \
    --cert ./app.cert.pem \
    --ca-cert ./pki/certs/intermediate.cert.pem
Ожидаемый результат: Статус сертификата (good/revoked/unknown) с деталями.
```

### Выпуск сертификата из CSR (CA-side)

```bash

# CA может подписать внешний CSR
micropki ca issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template server \
    --csr ./app.csr.pem \
    --out-dir ./pki/certs
```    
    
### API Endpoint для запроса сертификатов

Репозиторий предоставляет endpoint для автоматической выдачи сертификатов:

```bash
# POST запрос с CSR в теле
curl -X POST http://localhost:8080/request-cert?template=server \
    -H "Content-Type: application/x-pem-file" \
    --data-binary @./app.csr.pem \
    --output ./app.cert.pem
```    
    
### Тестирование

Запуск модульных тестов

```bash
# Установка pytest (если ещё не установлен)
pip install pytest
```
## Запуск всех тестов
```bash

pytest tests/ -v
```
## Запуск конкретного тестового файла
```bash
pytest tests/test_certificates.py -v
```
## Тестовые сценарии
````
Проект включает автоматические тесты для проверки:

Парсинга DN в различных форматах (slash и comma)

Генерации ключей и создания сертификатов

Обработки некорректных входных данных
````
Пример ручного тестирования ошибок
```bash
# Попытка создать CA с неподдерживаемым размером ECC-ключа
micropki init --subject "/CN=Test" --key-type ecc --key-size 256 --passphrase-file ./test.pass

```
Ожидается: Validation error: ECC key size must be 384

 Попытка использовать несуществующий файл с паролем
```
micropki init --subject "/CN=Test" --passphrase-file ./nonexistent.pass

```
 Ожидается: Validation error: Passphrase file does not exist

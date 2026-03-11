

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
  - [Параметры команды](#параметры-команды)
- [Структура выходных файлов](#структура-выходных-файлов)
- [Верификация результатов](#верификация-результатов)
  - [Проверка сертификата через OpenSSL](#проверка-сертификата-через-openssl)
  - [Проверка цепочки сертификатов](#проверка-цепочки-сертификатов)
  - [Проверка соответствия ключа и сертификата](#проверка-соответствия-ключа-и-сертификата)
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
│   ├── csr.py                 # New: CSR generation and handling
│   ├── templates.py            # New: Certificate templates
│   ├── chain.py                # New: Chain validation
│   └── logger.py
├── tests/
│   ├── __init__.py
│   ├── test_ca.py
│   ├── test_certificates.py
│   ├── test_csr.py             # New
│   ├── test_templates.py        # New
│   └── test_chain.py            # New
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

git clone https://github.com/yourusername/micropki.git
````

```bash

cd micropki
```
2. Создание виртуального окружения

```bash

python3 -m venv venv
source venv/bin/activate      # Для Linux/macOS
# или
venv\Scripts\activate         # Для Windows
3. Установка зависимостей
bash
pip install -r requirements.txt
4. Установка пакета в режиме разработки
bash
pip install -e .
После установки команда micropki станет доступна в терминале.
```
## Использование
Инициализация корневого CA
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
Параметры команды
````
| Параметр             | Описание                                                              | Обязательный | Значение по умолчанию |
|----------------------|-----------------------------------------------------------------------|--------------|-----------------------|
| `--subject`          | Distinguished Name в формате `/CN=.../O=...` или `CN=...,O=...`       | Да           | —                     |
| `--key-type`         | Тип ключа: `rsa` или `ecc`                                            | Нет          | `rsa`                 |
| `--key-size`         | Размер ключа: для RSA - 4096, для ECC - 384                           | Нет          | `4096`                |
| `--passphrase-file`  | Путь к файлу с парольной фразой для шифрования ключа                  | Да           | —                     |
| `--out-dir`          | Директория для выходных файлов                                        | Нет          | `./pki`               |
| `--validity-days`    | Срок действия сертификата в днях                                      | Нет          | `3650` (10 лет)       |
| `--log-file`         | Файл для логирования (если не указан, вывод в stderr)                 | Нет          | —                     |
````
## Примеры использования
RSA-ключ с длительным сроком действия:
```
bash
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
````
bash
micropki init \
    --subject "CN=ECC Root CA,O=Demo" \
    --key-type ecc \
    --key-size 384 \
    --passphrase-file ./secrets/ecc.pass \
    --out-dir ./ecc-pki
````
## Структура выходных файлов
После успешного выполнения команды в директории --out-dir создается следующая структура:
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
Пример содержимого:
````
text
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
Создание тестовой подписи (демонстрация работы ключа):

```bash
echo "test data" > test.txt
openssl dgst -sha256 -sign ./pki/private/ca.key.pem -passin file:./secrets/ca.pass -out test.sig test.txt
openssl dgst -sha256 -verify cert.pub -signature test.sig test.txt
```
Ожидаемый результат: Verified OK

### Тестирование

Запуск модульных тестов

```bash
# Установка pytest (если ещё не установлен)
pip install pytest
```
Запуск всех тестов
```
pytest tests/ -v
```
Запуск конкретного тестового файла
```
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

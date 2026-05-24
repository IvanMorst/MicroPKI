#!/bin/bash

# ============================================================
# MicroPKI - Полная демонстрация всех возможностей
# Sprint 1-7: Root CA, Intermediate CA, Issuance, CRL, OCSP, Audit
# ============================================================

set -e  # Остановка при любой ошибке

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Функции для красивого вывода
print_section() {
    echo ""
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${BLUE}============================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}ℹ $1${NC}"
}

print_command() {
    echo -e "${MAGENTA}$ $1${NC}"
}

# Очистка предыдущих данных
cleanup() {
    print_section "Очистка предыдущих данных"
    rm -rf pki secrets logs
    print_success "Очистка выполнена"
}

# Создание директорий и паролей
setup_directories() {
    print_section "1. Подготовка окружения"

    mkdir -p secrets logs

    echo -n "root_ca_secret_password" > secrets/root.pass
    echo -n "intermediate_ca_secret_password" > secrets/intermediate.pass
    echo -n "ocsp_secret_password" > secrets/ocsp.pass

    print_success "Директории и пароли созданы"
}

# Инициализация базы данных
init_database() {
    print_section "2. Инициализация базы данных"

    print_command "micropki db init --db-path ./pki/micropki.db"
    micropki db init --db-path ./pki/micropki.db --force

    print_success "База данных инициализирована"
}

# Создание корневого CA
create_root_ca() {
    print_section "3. Создание корневого CA (Sprint 1)"

    print_command "micropki init --subject \"/CN=MicroPKI Root CA/O=MicroPKI/C=RU\" --key-type rsa --key-size 4096 ..."

    micropki init \
        --subject "/CN=MicroPKI Root CA/O=MicroPKI/C=RU" \
        --key-type rsa \
        --key-size 4096 \
        --passphrase-file ./secrets/root.pass \
        --out-dir ./pki \
        --validity-days 3650 \
        --db-path ./pki/micropki.db \
        --log-file ./logs/root-ca.log

    print_success "Корневой CA создан"
    print_info "Сертификат: ./pki/certs/ca.cert.pem"
}

# Создание промежуточного CA
create_intermediate_ca() {
    print_section "4. Создание промежуточного CA (Sprint 2)"

    print_command "micropki issue-intermediate ..."

    micropki issue-intermediate \
        --root-cert ./pki/certs/ca.cert.pem \
        --root-key ./pki/private/ca.key.pem \
        --root-pass-file ./secrets/root.pass \
        --subject "CN=MicroPKI Intermediate CA,O=MicroPKI" \
        --key-type rsa \
        --key-size 4096 \
        --passphrase-file ./secrets/intermediate.pass \
        --out-dir ./pki \
        --validity-days 1825 \
        --pathlen 0 \
        --db-path ./pki/micropki.db \
        --log-file ./logs/intermediate-ca.log

    print_success "Промежуточный CA создан"
    print_info "Сертификат: ./pki/certs/intermediate.cert.pem"
}

# Выпуск сертификатов
issue_certificates() {
    print_section "5. Выпуск сертификатов (Sprint 2)"

    # Серверный сертификат
    print_info "5.1 Выпуск серверного сертификата"
    print_command "micropki issue-cert --template server ..."

    micropki issue-cert \
        --ca-cert ./pki/certs/intermediate.cert.pem \
        --ca-key ./pki/private/intermediate.key.pem \
        --ca-pass-file ./secrets/intermediate.pass \
        --template server \
        --subject "CN=api.example.com,O=MicroPKI" \
        --san dns:api.example.com \
        --san dns:api2.example.com \
        --san ip:10.0.0.1 \
        --out-dir ./pki/certs \
        --validity-days 365 \
        --db-path ./pki/micropki.db

    print_success "Серверный сертификат создан: ./pki/certs/api.example.com.cert.pem"

    # 5.2 Клиентский сертификат
print_info "5.2 Выпуск клиентского сертификата"

micropki issue-cert \
    --ca-cert ./pki/certs/intermediate.cert.pem \
    --ca-key ./pki/private/intermediate.key.pem \
    --ca-pass-file ./secrets/intermediate.pass \
    --template client \
    --subject "/CN=Alice Smith/EMAIL=alice@example.com" \
    --san email:alice@example.com \
    --san dns:alice-client \
    --out-dir ./pki/certs \
    --validity-days 365 \
    --db-path ./pki/micropki.db

print_success "Клиентский сертификат создан"


    # Сертификат для подписи кода
    print_info "5.3 Выпуск сертификата для подписи кода"

    micropki issue-cert \
        --ca-cert ./pki/certs/intermediate.cert.pem \
        --ca-key ./pki/private/intermediate.key.pem \
        --ca-pass-file ./secrets/intermediate.pass \
        --template code_signing \
        --subject "CN=MicroPKI Code Signing" \
        --out-dir ./pki/certs \
        --validity-days 365 \
        --db-path ./pki/micropki.db

    print_success "Сертификат для подписи кода создан"
}

# Выпуск OCSP сертификата
issue_ocsp_cert() {
    print_section "6. Выпуск OCSP сертификата (Sprint 5)"

    micropki issue-ocsp-cert \
        --ca-cert ./pki/certs/intermediate.cert.pem \
        --ca-key ./pki/private/intermediate.key.pem \
        --ca-pass-file ./secrets/intermediate.pass \
        --subject "CN=OCSP Responder,O=MicroPKI" \
        --key-type rsa \
        --key-size 2048 \
        --san dns:ocsp.example.com \
        --out-dir ./pki/certs \
        --validity-days 365 \
        --db-path ./pki/micropki.db

    print_success "OCSP сертификат создан: ./pki/certs/ocsp.cert.pem"
    print_info "ВНИМАНИЕ: Приватный ключ OCSP сохранён НЕЗАШИФРОВАННЫМ"
}

# Генерация CSR и запрос сертификата через API
client_workflow() {
    print_section "7. Клиентский workflow: CSR -> запрос -> получение сертификата (Sprint 6)"

    # Генерация CSR
    print_info "7.1 Генерация CSR"
    micropki client gen-csr \
        --subject "CN=client-app.example.com" \
        --key-type rsa \
        --key-size 2048 \
        --san dns:client-app.example.com \
        --out-key ./client.key.pem \
        --out-csr ./client.csr.pem

    print_success "CSR создан: ./client.csr.pem"

    print_info "7.2 Запрос сертификата через API (требуется запущенный сервер)"
    print_info "   Для полного теста API запустите в отдельном терминале:"
    print_info "   micropki repo serve --host 127.0.0.1 --port 8080"
    print_info "   Затем выполните: micropki client request-cert --csr ./client.csr.pem --template server --ca-url http://localhost:8080"
}

# Просмотр списка сертификатов
list_certificates() {
    print_section "8. Просмотр сертификатов в БД (Sprint 3)"

    print_command "micropki list-certs --format table"
    micropki list-certs --db-path ./pki/micropki.db --format table

    print_success "Всего сертификатов в БД: $(micropki list-certs --db-path ./pki/micropki.db --format json | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')"
}

# Генерация CRL
generate_crl() {
    print_section "9. Генерация CRL (Sprint 4)"

    micropki gen-crl \
        --ca intermediate \
        --next-update 14 \
        --out-dir ./pki \
        --db-path ./pki/micropki.db \
        --passphrase-file ./secrets/intermediate.pass

    print_success "CRL создан: ./pki/crl/intermediate.crl.pem"

    # Просмотр содержимого CRL
    if command -v openssl &> /dev/null; then
        print_info "Содержимое CRL:"
        openssl crl -in ./pki/crl/intermediate.crl.pem -text -noout | head -30
    fi
}

# Отзыв сертификата
revoke_certificate() {
    print_section "10. Отзыв сертификата (Sprint 4)"

    # Получаем серийный номер сертификата и удаляем ведущие нули
    SERIAL=$(openssl x509 -in ./pki/certs/api.example.com.cert.pem -serial -noout | cut -d= -f2 | sed 's/^0*//')

    print_info "Отзыв сертификата с серийным номером: $SERIAL"

    micropki revoke "$SERIAL" \
        --reason keyCompromise \
        --force \
        --db-path ./pki/micropki.db

    print_success "Сертификат отозван"

    # Повторная генерация CRL
    print_info "Обновление CRL после отзыва"
    micropki gen-crl \
        --ca intermediate \
        --next-update 14 \
        --out-dir ./pki \
        --db-path ./pki/micropki.db \
        --passphrase-file ./secrets/intermediate.pass

    print_success "CRL обновлён с отозванным сертификатом"
}

# Проверка статуса отзыва
check_revocation_status() {
    print_section "11. Проверка статуса отзыва (Sprint 4)"

    SERIAL=$(openssl x509 -in ./pki/certs/api.example.com.cert.pem -serial -noout | cut -d= -f2)

    micropki check-revoked "$SERIAL" --db-path ./pki/micropki.db
}

# Симуляция компрометации
simulate_compromise() {
    print_section "12. Симуляция компрометации ключа (Sprint 7)"

    print_info "Симуляция компрометации сертификата"

    micropki compromise \
        --cert ./pki/certs/api.example.com.cert.pem \
        --reason keyCompromise \
        --force

    print_success "Сертификат помечен как скомпрометированный"
}

# Просмотр аудит лога
view_audit_log() {
    print_section "13. Просмотр аудит лога (Sprint 7)"

    print_info "Последние аудит записи:"
    micropki audit query --format table 2>/dev/null | head -20 || echo "Аудит лог пуст"

    print_info ""
    print_info "Проверка целостности аудит лога:"
    micropki audit verify 2>/dev/null && print_success "Аудит лог не повреждён" || print_error "Аудит лог повреждён"
}

# Проверка цепочки сертификатов
validate_chain() {
    print_section "14. Валидация цепочки сертификатов (Sprint 6)"

    if command -v openssl &> /dev/null; then
        print_info "Проверка через OpenSSL:"
        openssl verify -CAfile ./pki/certs/ca.cert.pem -untrusted ./pki/certs/intermediate.cert.pem ./pki/certs/api.example.com.cert.pem
    fi

    print_info "Проверка через MicroPKI:"
    micropki client validate \
        --cert ./pki/certs/api.example.com.cert.pem \
        --untrusted ./pki/certs/intermediate.cert.pem \
        --trusted ./pki/certs/ca.cert.pem \
        --mode chain
}

# Просмотр Certificate Transparency лога
view_ct_log() {
    print_section "15. Certificate Transparency лог (Sprint 7)"

    if [ -f ./pki/audit/ct.log ]; then
        echo "Содержимое CT лога:"
        cat ./pki/audit/ct.log
        print_success "CT лог содержит $(wc -l < ./pki/audit/ct.log) записей"
    else
        print_info "CT лог ещё не создан (будет заполнен при выпуске сертификатов)"
    fi
}

# Информация о структуре
show_structure() {
    print_section "16. Структура созданных файлов"

    echo "Директория pki/:"
    find ./pki -type f -name "*.pem" -o -name "*.db" -o -name "*.log" -o -name "*.txt" 2>/dev/null | head -30
    echo ""
    echo "Директория secrets/:"
    ls -la ./secrets/ 2>/dev/null || echo "  (пусто)"
    echo ""
    echo "Директория logs/:"
    ls -la ./logs/ 2>/dev/null || echo "  (пусто)"
}

# Тест политик безопасности
test_policy_enforcement() {
    print_section "17. Тест политик безопасности (Sprint 7)"

    print_info "Попытка выпустить сертификат с wildcard SAN (должно быть отклонено)"
    if micropki issue-cert \
        --ca-cert ./pki/certs/intermediate.cert.pem \
        --ca-key ./pki/private/intermediate.key.pem \
        --ca-pass-file ./secrets/intermediate.pass \
        --template server \
        --subject "CN=wildcard.example.com" \
        --san dns:*.example.com \
        --out-dir ./pki/certs \
        --validity-days 365 \
        --db-path ./pki/micropki.db 2>/dev/null; then
        print_error "ОШИБКА: wildcard сертификат не должен был быть выпущен!"
    else
        print_success "wildcard сертификат правильно отклонён политикой"
    fi

    print_info ""
    print_info "Попытка выпустить сертификат с превышением срока действия (366 дней > 365)"
    if micropki issue-cert \
        --ca-cert ./pki/certs/intermediate.cert.pem \
        --ca-key ./pki/private/intermediate.key.pem \
        --ca-pass-file ./secrets/intermediate.pass \
        --template server \
        --subject "CN=test.example.com" \
        --san dns:test.example.com \
        --out-dir ./pki/certs \
        --validity-days 366 \
        --db-path ./pki/micropki.db 2>/dev/null; then
        print_error "ОШИБКА: сертификат с превышением срока не должен был быть выпущен!"
    else
        print_success "Сертификат с превышением срока правильно отклонён политикой"
    fi
}

# Запуск сервера в фоне (опционально)
start_server() {
    print_section "Запуск репозитория (опционально)"
    print_info "Для запуска сервера выполните в отдельном терминале:"
    echo ""
    echo "  cd $(pwd)"
    echo "  source venv/bin/activate"
    echo "  micropki repo serve --host 127.0.0.1 --port 8080 --rate-limit 10"
    echo "  micropki ocsp serve --host 127.0.0.1 --port 8081 --responder-cert ./pki/certs/ocsp.cert.pem --responder-key ./pki/certs/ocsp.key.pem --ca-cert ./pki/certs/intermediate.cert.pem"
    echo ""
    print_info "Затем можно выполнить запросы:"
    echo "  curl http://127.0.0.1:8080/ca/root"
    echo "  micropki client request-cert --csr ./client.csr.pem --template server --ca-url http://localhost:8080"
}

# Основная функция
main() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                 MicroPKI - Демонстрация                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    cleanup
    setup_directories
    init_database
    create_root_ca
    create_intermediate_ca
    issue_certificates
    issue_ocsp_cert
    list_certificates
    generate_crl
    revoke_certificate
    check_revocation_status
    simulate_compromise
    view_audit_log
    view_ct_log
    validate_chain
    show_structure
    test_policy_enforcement
    client_workflow
    start_server

    print_section "Демонстрация завершена!"
    echo -e "${GREEN}✓ Все компоненты MicroPKI успешно протестированы${NC}"
    echo ""
    echo "Созданные файлы:"
    echo "  - Сертификаты:      ./pki/certs/*.pem"
    echo "  - Приватные ключи:  ./pki/private/*.pem"
    echo "  - CRL:              ./pki/crl/*.crl.pem"
    echo "  - База данных:      ./pki/micropki.db"
    echo "  - Аудит лог:        ./pki/audit/audit.log"
    echo "  - CT лог:           ./pki/audit/ct.log"
    echo ""
    echo "Для просмотра сертификатов:"
    echo "  openssl x509 -in ./pki/certs/ca.cert.pem -text -noout"
    echo ""
    echo "Для запуска сервера: micropki repo serve --host 127.0.0.1 --port 8080"
}

# Запуск
main "$@"
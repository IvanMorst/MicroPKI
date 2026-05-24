.PHONY: help clean demo init test server ocsp

# Цвета для вывода
GREEN  := $(shell echo -e "\033[32m")
YELLOW := $(shell echo -e "\033[33m")
BLUE   := $(shell echo -e "\033[34m")
RESET  := $(shell echo -e "\033[0m")

help:
	@echo "$(BLUE)MicroPKI - Команды$(RESET)"
	@echo ""
	@echo "  $(GREEN)make clean$(RESET)   - Очистка всех сгенерированных файлов"
	@echo "  $(GREEN)make demo$(RESET)    - Полная демонстрация всех возможностей"
	@echo "  $(GREEN)make init$(RESET)    - Быстрая инициализация (Root + Intermediate CA)"
	@echo "  $(GREEN)make test$(RESET)    - Запуск всех тестов"
	@echo "  $(GREEN)make server$(RESET)  - Запуск репозитория"
	@echo "  $(GREEN)make ocsp$(RESET)    - Запуск OCSP респондера"

clean:
	@echo "$(YELLOW)Очистка...$(RESET)"
	rm -rf pki secrets logs
	@echo "$(GREEN)Готово$(RESET)"

init: clean
	@echo "$(YELLOW)Инициализация CA...$(RESET)"
	mkdir -p secrets logs
	echo -n "root_pass" > secrets/root.pass
	echo -n "intermediate_pass" > secrets/intermediate.pass
	micropki db init --db-path ./pki/micropki.db --force
	micropki init --subject "/CN=Root CA" --key-type rsa --key-size 4096 --passphrase-file ./secrets/root.pass --out-dir ./pki --db-path ./pki/micropki.db
	micropki issue-intermediate --root-cert ./pki/certs/ca.cert.pem --root-key ./pki/private/ca.key.pem --root-pass-file ./secrets/root.pass --subject "CN=Intermediate CA" --key-type rsa --key-size 4096 --passphrase-file ./secrets/intermediate.pass --out-dir ./pki --db-path ./pki/micropki.db
	@echo "$(GREEN)Готово$(RESET)"

demo:
	@./demo.sh

test:
	pytest tests/ -v

server:
	@echo "$(YELLOW)Запуск репозитория на http://127.0.0.1:8080$(RESET)"
	micropki repo serve --host 127.0.0.1 --port 8080 --db-path ./pki/micropki.db --cert-dir ./pki/certs --crl-dir ./pki/crl

ocsp:
	@echo "$(YELLOW)Запуск OCSP респондера на http://127.0.0.1:8081$(RESET)"
	micropki ocsp serve --host 127.0.0.1 --port 8081 --db-path ./pki/micropki.db --responder-cert ./pki/certs/ocsp.cert.pem --responder-key ./pki/certs/ocsp.key.pem --ca-cert ./pki/certs/intermediate.cert.pem
VENV_DIR=authscanner/venv
REQ_FILE=requirements.txt
MAIN_SCRIPT=authscanner/main.py
DOMAIN ?= example.com

.PHONY: setup clean run reset test

setup:
	@echo "🛠️ Creating virtual environment (if needed)..."
	@if [ ! -d "$(VENV_DIR)" ]; then \
		python3 -m venv $(VENV_DIR); \
	fi
	@echo "📦 Installing dependencies..."
	@. $(VENV_DIR)/bin/activate && pip install -r $(REQ_FILE)

clean:
	@echo "🧹 Removing virtual environment..."
	rm -rf $(VENV_DIR)

run:
	@echo "🚀 Running the main authscanner program..."
	@. $(VENV_DIR)/bin/activate && python $(MAIN_SCRIPT)

reset: clean setup
	@echo "🔁 Environment fully reset."

test:
	@echo "🧪 Running authscanner on domain: $(DOMAIN)"
	@. $(VENV_DIR)/bin/activate && python $(MAIN_SCRIPT) $(DOMAIN)

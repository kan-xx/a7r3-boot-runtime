CC        = clang
PYTHON   ?= python3
SANFLAGS ?= -fsanitize=address,undefined -fno-omit-frame-pointer
CFLAGS   := -O1 -Wall -Wextra -Werror -Wno-misleading-indentation $(SANFLAGS)
ASAN_ENV := ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1
BUILD_DIR := build/tests

.PHONY: all test verify-fw clean

all: test

test:
	@mkdir -p $(BUILD_DIR)
	@echo "==> [1/8] Python synthetic ELF32 libIMDB.so PT_LOAD table-extension test"
	$(PYTHON) tests/test_imdb_synthetic.py
	@echo "==> [2/8] Python dual-slot 256B journal & observer record decoder test"
	$(PYTHON) tests/test_decode.py
	@echo "==> [3/8] Host Clang ASan/UBSan: SENSER ProductInfo canary (libproFA)"
	$(CC) $(CFLAGS) -DCANARY_HOST_TEST loader-canary/canary.c -o $(BUILD_DIR)/test_canary
	$(ASAN_ENV) ./$(BUILD_DIR)/test_canary
	@echo "==> [4/8] Host Clang ASan/UBSan: Boot-Guard V21 35-scenario transaction & fault injection"
	$(CC) $(CFLAGS) -Iboot-guard tests/test_guard_original.c -o $(BUILD_DIR)/test_guard_original
	$(ASAN_ENV) ./$(BUILD_DIR)/test_guard_original | tail -n 1
	@echo "==> [5/8] Host Clang ASan/UBSan: Boot-Guard V17 narrow 1-boot retry & power-cut suite"
	$(CC) $(CFLAGS) -Iboot-guard tests/test_guard_retry.c -o $(BUILD_DIR)/test_guard_retry
	$(ASAN_ENV) ./$(BUILD_DIR)/test_guard_retry
	@echo "==> [6/8] Host Clang ASan/UBSan: Cold battery-pull pre-start LO_INACT bootstrap gate"
	$(CC) $(CFLAGS) \
		tests/test_gate.c \
		startup-owner/bootstrap/bootstrap_gate.c \
		startup-owner/bootstrap/ingress.c \
		startup-owner/lifecycle/owner.c \
		startup-owner/lifecycle/power_lifecycle.c \
		startup-owner/lifecycle/admission.c \
		-o $(BUILD_DIR)/test_gate
	$(ASAN_ENV) ./$(BUILD_DIR)/test_gate
	@echo "==> [7/8] Host Clang ASan/UBSan: A7TBM001 manifest & 48 KiB chunked optional autoloader"
	$(CC) $(CFLAGS) \
		tests/test_optional_loader.c \
		startup-owner/autoload/optional_loader.c \
		startup-owner/autoload/boot_manifest.c \
		-o $(BUILD_DIR)/test_optional_loader
	$(ASAN_ENV) ./$(BUILD_DIR)/test_optional_loader
	@echo "==> [8/8] Host Clang ASan/UBSan: Fixed-inode cleanup engine & post-dlopen exit-bridge loader"
	$(CC) $(CFLAGS) tests/test_cleanup_engine.c -o $(BUILD_DIR)/test_cleanup_engine
	$(ASAN_ENV) ./$(BUILD_DIR)/test_cleanup_engine
	$(CC) $(CFLAGS) tests/test_exit_loader.c -o $(BUILD_DIR)/test_exit_loader
	$(ASAN_ENV) ./$(BUILD_DIR)/test_exit_loader
	@echo "==> All offline host unit tests passed (zero firmware blobs required)."

verify-fw:
	@if [ -z "$(A7R3_FW_ROOT)" ]; then \
		echo "ERROR: Set A7R3_FW_ROOT=/path/to/verified-3.10/filesystems" >&2; \
		exit 2; \
	fi
	$(PYTHON) tests/verify_firmware.py --fw-root "$(A7R3_FW_ROOT)"

clean:
	rm -rf build dist out *.dSYM

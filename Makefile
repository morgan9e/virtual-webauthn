NMH_DIR ?= $(HOME)/.librewolf/native-messaging-hosts
BIN_DIR ?= $(HOME)/.librewolf/external_application
EXT_ID  ?= com.example.virtual_webauthn

.PHONY: build clean install extension

build:
	cargo build --release

extension:
	@mkdir -p target
	cd extension && zip -r ../target/virtual-webauthn.xpi . -x '.*'

clean:
	cargo clean

install: build
	@mkdir -p $(BIN_DIR) $(NMH_DIR)
	install -m755 target/release/virtual-webauthn $(BIN_DIR)/virtual-webauthn
	cp virtual_webauthn.json $(NMH_DIR)/$(EXT_ID).json
	@sed -i "s,/PLACEHOLDER,$(BIN_DIR)," $(NMH_DIR)/$(EXT_ID).json

# ============================================================
# ZEKRA Embench-IoT Makefile (with status messages)
# ============================================================

ZEKRA_DIR       = zekra_java/zekra
COMPONENTS_DIR  = zekra_java/components
APPS_DIR        = ./embench-iot-applications
EXPERIMENTS_DIR = ../experiments/experiments

ADJLIST_LEVELS  = 15
STACK_DEPTH     = 15

NONCE_VERIFIER   = 12353
NONCE_PATH       = 123
NONCE_TRANSLATOR = 123
NONCE_ADJLIST    = 123

LABEL_SMALL   = 10
BUCKET_SMALL  = 7
LABEL_LARGE   = 11
BUCKET_LARGE  = 8

BENCHES = \
	aha-mont64 crc32 cubic edn huffbench matmult-int md5sum minver nbody \
	nettle-aes nettle-sha256 nsichneu picojpeg primecount qrduino \
	sglib-combined slre st statemate tcpblaster ud wikisort

.PHONY: all $(BENCHES)

all: $(BENCHES)

# --------------------------------------------------------------------
# Macro with status messages
# --------------------------------------------------------------------
define RUN_CFG
	@echo ""
	@echo "==============================================================="
	@echo "[ $(1) ] → ADJ=$(2) PATH=$(3) LABEL=$(4) BUCKET=$(5) ADDR=$(6)"
	@echo "==============================================================="
	@echo ""

	python3 scripts/circuit_input_formatter.py \
	  -a $(APPS_DIR)/$(1)/ \
	  --pad-adjlist-to $(2) \
	  --pad-path-to $(3) \
	  --adjlist-levels $(ADJLIST_LEVELS) \
	  --nonce-verifier $(NONCE_VERIFIER) \
	  --nonce-path $(NONCE_PATH) \
	  --nonce-translator $(NONCE_TRANSLATOR) \
	  --nonce-adjlist $(NONCE_ADJLIST) \
	  --label-bitwidth $(4) \
	  --bucket-bitwidth $(5) \
	  --address-bitwidth $(6)

	python3 scripts/compile_circuit.py \
	  --zekra-dir $(ZEKRA_DIR) \
	  --adjlist-len $(2) \
	  --adjlist-levels $(ADJLIST_LEVELS) \
	  --path-len $(3) \
	  --stack-depth $(STACK_DEPTH) \
	  --label-bitwidth $(4) \
	  --bucket-bitwidth $(5) \
	  --address-bitwidth $(6) \
	  --input-dir $(APPS_DIR)/$(1) \
	  --components-dir $(COMPONENTS_DIR) -v

	mkdir -p $(EXPERIMENTS_DIR)/$(1)/$(6)/$(3)
	cp zekra.arith                  $(EXPERIMENTS_DIR)/$(1)/$(6)/$(3)
	cp zekra_Sample_Run1.in         $(EXPERIMENTS_DIR)/$(1)/$(6)/$(3)
	cp $(APPS_DIR)/$(1)/numified_adjlist $(EXPERIMENTS_DIR)/$(1)/$(6)/$(3)
	cp $(APPS_DIR)/$(1)/numified_path    $(EXPERIMENTS_DIR)/$(1)/$(6)/$(3)

	@echo ""
	@echo "[ $(1) ] → Finished: ADJ=$(2), PATH=$(3), ADDR=$(6)"
	@echo ""
endef

# --------------------------------------------------------------------
# One target per benchmark
# (same configuration grid for all)
# --------------------------------------------------------------------

aha-mont64:
	$(call RUN_CFG,aha-mont64,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,aha-mont64,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,aha-mont64,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,aha-mont64,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,aha-mont64,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,aha-mont64,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

crc32:
	$(call RUN_CFG,crc32,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,crc32,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,crc32,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,crc32,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,crc32,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,crc32,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

cubic:
	$(call RUN_CFG,cubic,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,cubic,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,cubic,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,cubic,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,cubic,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,cubic,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

edn:
	$(call RUN_CFG,edn,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,edn,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,edn,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,edn,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,edn,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,edn,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

huffbench:
	$(call RUN_CFG,huffbench,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,huffbench,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,huffbench,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,huffbench,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,huffbench,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,huffbench,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

matmult-int:
	$(call RUN_CFG,matmult-int,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,matmult-int,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,matmult-int,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,matmult-int,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,matmult-int,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,matmult-int,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

md5sum:
	$(call RUN_CFG,md5sum,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,md5sum,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,md5sum,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,md5sum,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,md5sum,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,md5sum,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

minver:
	$(call RUN_CFG,minver,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,minver,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,minver,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,minver,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,minver,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,minver,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

nbody:
	$(call RUN_CFG,nbody,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,nbody,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,nbody,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,nbody,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,nbody,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,nbody,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

nettle-aes:
	$(call RUN_CFG,nettle-aes,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,nettle-aes,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,nettle-aes,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,nettle-aes,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,nettle-aes,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,nettle-aes,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

nettle-sha256:
	$(call RUN_CFG,nettle-sha256,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,nettle-sha256,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,nettle-sha256,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,nettle-sha256,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,nettle-sha256,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,nettle-sha256,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

nsichneu:
	$(call RUN_CFG,nsichneu,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,nsichneu,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,nsichneu,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,nsichneu,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,nsichneu,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,nsichneu,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

picojpeg:
	$(call RUN_CFG,picojpeg,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,picojpeg,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,picojpeg,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,picojpeg,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,picojpeg,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,picojpeg,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

primecount:
	$(call RUN_CFG,primecount,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,primecount,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,primecount,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,primecount,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,primecount,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,primecount,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

qrduino:
	$(call RUN_CFG,qrduino,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,qrduino,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,qrduino,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,qrduino,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,qrduino,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,qrduino,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

sglib-combined:
	$(call RUN_CFG,sglib-combined,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,sglib-combined,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,sglib-combined,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,sglib-combined,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,sglib-combined,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,sglib-combined,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

slre:
	$(call RUN_CFG,slre,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,slre,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,slre,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,slre,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,slre,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,slre,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

st:
	$(call RUN_CFG,st,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,st,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,st,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,st,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,st,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,st,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

statemate:
	$(call RUN_CFG,statemate,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,statemate,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,statemate,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,statemate,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,statemate,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,statemate,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

tcpblaster:
	$(call RUN_CFG,tcpblaster,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,tcpblaster,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,tcpblaster,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,tcpblaster,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,tcpblaster,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,tcpblaster,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

ud:
	$(call RUN_CFG,ud,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,ud,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,ud,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,ud,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,ud,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,ud,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)

wikisort:
	$(call RUN_CFG,wikisort,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,wikisort,500,500,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,wikisort,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),24)
	$(call RUN_CFG,wikisort,1000,1000,$(LABEL_SMALL),$(BUCKET_SMALL),88)
	$(call RUN_CFG,wikisort,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),24)
	$(call RUN_CFG,wikisort,1000,1200,$(LABEL_LARGE),$(BUCKET_LARGE),88)


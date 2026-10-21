# Build the 8 workload-class binaries (static x86) into bin/.
# Each target selects a victim + attacker via -D macros.
#
#   make            # build all
#   make clean
#   make USE_M5OPS=1 M5_INC=... M5_LIB=...   # link gem5 ROI markers (optional)

CC      ?= gcc
CFLAGS  ?= -O2 -static -msse2 -std=gnu11 -Wall -Isrc
SRC      = src/driver.c
DEPS     = src/common.h src/victims.h src/attackers.h

ifdef USE_M5OPS
CFLAGS  += -DUSE_M5OPS -I$(M5_INC)
LDLIBS  += -L$(M5_LIB) -lm5
endif

BIN = bin
BINS = \
  $(BIN)/aes_ttable_fr $(BIN)/aes_ttable_pp $(BIN)/aes_ct_fr \
  $(BIN)/rsa_sqmul_fr  $(BIN)/chacha20_pp \
  $(BIN)/spectre_v1    $(BIN)/benign_matmul $(BIN)/benign_memcpy

all: $(BINS)

$(BIN):
	mkdir -p $(BIN)

# victim , attacker  ->  -D flags
$(BIN)/aes_ttable_fr: $(SRC) $(DEPS) | $(BIN)
	$(CC) $(CFLAGS) -DRUN_ITERS=150 -DVICTIM_AES_TTABLE -DATTACKER_FLUSH_RELOAD $(SRC) -o $@ $(LDLIBS)
$(BIN)/aes_ttable_pp: $(SRC) $(DEPS) | $(BIN)
	$(CC) $(CFLAGS) -DRUN_ITERS=25 -DVICTIM_AES_TTABLE -DATTACKER_PRIME_PROBE  $(SRC) -o $@ $(LDLIBS)
$(BIN)/aes_ct_fr: $(SRC) $(DEPS) | $(BIN)
	$(CC) $(CFLAGS) -DRUN_ITERS=150 -DVICTIM_AES_CT     -DATTACKER_FLUSH_RELOAD $(SRC) -o $@ $(LDLIBS)
$(BIN)/rsa_sqmul_fr: $(SRC) $(DEPS) | $(BIN)
	$(CC) $(CFLAGS) -DRUN_ITERS=150 -DVICTIM_RSA_SQMUL  -DATTACKER_FLUSH_RELOAD $(SRC) -o $@ $(LDLIBS)
$(BIN)/chacha20_pp: $(SRC) $(DEPS) | $(BIN)
	$(CC) $(CFLAGS) -DRUN_ITERS=25 -DVICTIM_CHACHA20   -DATTACKER_PRIME_PROBE  $(SRC) -o $@ $(LDLIBS)
$(BIN)/spectre_v1: $(SRC) $(DEPS) | $(BIN)
	$(CC) $(CFLAGS) -DRUN_ITERS=25 -DVICTIM_BOUNDS     -DATTACKER_SPECTRE_V1   $(SRC) -o $@ $(LDLIBS)
$(BIN)/benign_matmul: $(SRC) $(DEPS) | $(BIN)
	$(CC) $(CFLAGS) -DRUN_ITERS=25 -DVICTIM_MATMUL     -DATTACKER_NONE         $(SRC) -o $@ $(LDLIBS)
$(BIN)/benign_memcpy: $(SRC) $(DEPS) | $(BIN)
	$(CC) $(CFLAGS) -DRUN_ITERS=25 -DVICTIM_MEMCPY     -DATTACKER_NONE         $(SRC) -o $@ $(LDLIBS)

clean:
	rm -rf $(BIN)

.PHONY: all clean

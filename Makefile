ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := ps5-tls-verify.elf

CFLAGS += -Wall -Wextra -Os

# Deploy target host/port. elfldr listens on 9021 (the SDK default).
PS5_HOST ?= ps5
PS5_PORT ?= 9021

all: $(ELF)

$(ELF): src/main.c
	$(CC) $(CFLAGS) -o $@ src/main.c

# Send the payload to elfldr (one-shot run, no persistence on disk).
deploy: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $(ELF)

clean:
	rm -f $(ELF)

.PHONY: all clean deploy

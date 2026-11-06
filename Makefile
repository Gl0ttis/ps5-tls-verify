ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := ps5-tls-verify.elf

CFLAGS += -Wall -Wextra -Os

all: $(ELF)

$(ELF): src/main.c
	$(CC) $(CFLAGS) -o $@ src/main.c

clean:
	rm -f $(ELF)

.PHONY: all clean

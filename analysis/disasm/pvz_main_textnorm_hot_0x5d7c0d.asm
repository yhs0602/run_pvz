
/Users/yanghyeonseo/Developer/pvz/pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  5d7bc0: 0c 55                        	or	al, 0x55
  5d7bc2: 56                           	push	esi
  5d7bc3: a1 e8 9f 69 00               	mov	eax, dword ptr [0x699fe8]
  5d7bc8: 33 c4                        	xor	eax, esp
  5d7bca: 50                           	push	eax
  5d7bcb: 8d 44 24 18                  	lea	eax, [esp + 0x18]
  5d7bcf: 64 a3 00 00 00 00            	mov	dword ptr fs:[0x0], eax
  5d7bd5: 33 c9                        	xor	ecx, ecx
  5d7bd7: 89 4c 24 10                  	mov	dword ptr [esp + 0x10], ecx
  5d7bdb: c7 47 18 0f 00 00 00         	mov	dword ptr [edi + 0x18], 0xf
  5d7be2: 89 4f 14                     	mov	dword ptr [edi + 0x14], ecx
  5d7be5: 89 7c 24 14                  	mov	dword ptr [esp + 0x14], edi
  5d7be9: 88 4f 04                     	mov	byte ptr [edi + 0x4], cl
  5d7bec: 89 4c 24 20                  	mov	dword ptr [esp + 0x20], ecx
  5d7bf0: 8b 43 14                     	mov	eax, dword ptr [ebx + 0x14]
  5d7bf3: 33 f6                        	xor	esi, esi
  5d7bf5: 3b c1                        	cmp	eax, ecx
  5d7bf7: c7 44 24 10 01 00 00 00      	mov	dword ptr [esp + 0x10], 0x1
  5d7bff: 76 42                        	jbe	0x5d7c43 <.text+0x1d6c43>
  5d7c01: 3b f0                        	cmp	esi, eax
  5d7c03: 8d 6b 04                     	lea	ebp, [ebx + 0x4]
  5d7c06: 76 05                        	jbe	0x5d7c0d <.text+0x1d6c0d>
  5d7c08: e8 32 4a 04 00               	call	0x61c63f <.text+0x21b63f>
  5d7c0d: 83 7b 18 10                  	cmp	dword ptr [ebx + 0x18], 0x10
  5d7c11: 72 05                        	jb	0x5d7c18 <.text+0x1d6c18>
  5d7c13: 8b 45 00                     	mov	eax, dword ptr [ebp]
  5d7c16: eb 02                        	jmp	0x5d7c1a <.text+0x1d6c1a>
  5d7c18: 8b c5                        	mov	eax, ebp
  5d7c1a: 0f be 04 30                  	movsx	eax, byte ptr [eax + esi]
  5d7c1e: 50                           	push	eax
  5d7c1f: e8 c2 68 04 00               	call	0x61e4e6 <.text+0x21d4e6>
  5d7c24: 88 44 24 10                  	mov	byte ptr [esp + 0x10], al
  5d7c28: 8b 4c 24 10                  	mov	ecx, dword ptr [esp + 0x10]
  5d7c2c: 83 c4 04                     	add	esp, 0x4
  5d7c2f: 51                           	push	ecx
  5d7c30: 6a 01                        	push	0x1
  5d7c32: 8b cf                        	mov	ecx, edi
  5d7c34: e8 e7 a0 e6 ff               	call	0x441d20 <.text+0x40d20>
  5d7c39: 8b 43 14                     	mov	eax, dword ptr [ebx + 0x14]
  5d7c3c: 83 c6 01                     	add	esi, 0x1
  5d7c3f: 3b f0                        	cmp	esi, eax
  5d7c41: 72 ca                        	jb	0x5d7c0d <.text+0x1d6c0d>
  5d7c43: 8b c7                        	mov	eax, edi
  5d7c45: 8b 4c 24 18                  	mov	ecx, dword ptr [esp + 0x18]
  5d7c49: 64 89 0d 00 00 00 00         	mov	dword ptr fs:[0x0], ecx
  5d7c50: 59                           	pop	ecx
  5d7c51: 5e                           	pop	esi
  5d7c52: 5d                           	pop	ebp
  5d7c53: 83 c4 18                     	add	esp, 0x18
  5d7c56: c3                           	ret
  5d7c57: cc                           	int3
  5d7c58: cc                           	int3
  5d7c59: cc                           	int3
  5d7c5a: cc                           	int3
  5d7c5b: cc                           	int3
  5d7c5c: cc                           	int3
  5d7c5d: cc                           	int3
  5d7c5e: cc                           	int3
  5d7c5f: cc                           	int3
  5d7c60: 6a ff                        	push	-0x1
  5d7c62: 68 4b 3e 64 00               	push	0x643e4b
  5d7c67: 64 a1 00 00 00 00            	mov	eax, dword ptr fs:[0x0]
  5d7c6d: 50                           	push	eax
  5d7c6e: 51                           	push	ecx
  5d7c6f: a1 e8 9f 69 00               	mov	eax, dword ptr [0x699fe8]
  5d7c74: 33 c4                        	xor	eax, esp
  5d7c76: 50                           	push	eax
  5d7c77: 8d 44 24 08                  	lea	eax, [esp + 0x8]
  5d7c7b: 64 a3 00 00 00 00            	mov	dword ptr fs:[0x0], eax
  5d7c81: c7 44 24 04 10 b4 75 00      	mov	dword ptr [esp + 0x4], 0x75b410
  5d7c89: c7 05 10 b4 75 00 a4 6a 67 00	mov	dword ptr [0x75b410], 0x676aa4
  5d7c93: e8 f8 14 00 00               	call	0x5d9190 <.text+0x1d8190>
  5d7c98: a3 18 b4 75 00               	mov	dword ptr [0x75b418], eax
  5d7c9d: c7 05 1c b4 75 00 00 00 00 00	mov	dword ptr [0x75b41c], 0x0
  5d7ca7: c7 44 24 10 00 00 00 00      	mov	dword ptr [esp + 0x10], 0x0
  5d7caf: e8 3c 1e 00 00               	call	0x5d9af0 <.text+0x1d8af0>
  5d7cb4: a3 24 b4 75 00               	mov	dword ptr [0x75b424], eax
  5d7cb9: c6 40 59 01                  	mov	byte ptr [eax + 0x59], 0x1
  5d7cbd: a1 24 b4 75 00               	mov	eax, dword ptr [0x75b424]
  5d7cc2: 89 40 04                     	mov	dword ptr [eax + 0x4], eax
  5d7cc5: a1 24 b4 75 00               	mov	eax, dword ptr [0x75b424]
  5d7cca: 89 00                        	mov	dword ptr [eax], eax
  5d7ccc: a1 24 b4 75 00               	mov	eax, dword ptr [0x75b424]
  5d7cd1: 89 40 08                     	mov	dword ptr [eax + 0x8], eax
  5d7cd4: c7 05 28 b4 75 00 00 00 00 00	mov	dword ptr [0x75b428], 0x0
  5d7cde: e8 2d fe ff ff               	call	0x5d7b10 <.text+0x1d6b10>


/Users/yanghyeonseo/Developer/pvz/pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  61fca0: f6 00 00                     	test	byte ptr [eax], 0x0
  61fca3: 59                           	pop	ecx
  61fca4: 59                           	pop	ecx
  61fca5: c7 45 fc fe ff ff ff         	mov	dword ptr [ebp - 0x4], 0xfffffffe
  61fcac: e8 0b 00 00 00               	call	0x61fcbc <.text+0x21ecbc>
  61fcb1: 83 7d e4 00                  	cmp	dword ptr [ebp - 0x1c], 0x0
  61fcb5: 75 37                        	jne	0x61fcee <.text+0x21ecee>
  61fcb7: ff 75 08                     	push	dword ptr [ebp + 0x8]
  61fcba: eb 0a                        	jmp	0x61fcc6 <.text+0x21ecc6>
  61fcbc: 6a 04                        	push	0x4
  61fcbe: e8 c5 d1 00 00               	call	0x62ce88 <.text+0x22be88>
  61fcc3: 59                           	pop	ecx
  61fcc4: c3                           	ret
  61fcc5: 56                           	push	esi
  61fcc6: 6a 00                        	push	0x0
  61fcc8: ff 35 d4 6d 6a 00            	push	dword ptr [0x6a6dd4]
  61fcce: ff 15 98 21 65 00            	call	dword ptr [0x652198]
  61fcd4: 85 c0                        	test	eax, eax
  61fcd6: 75 16                        	jne	0x61fcee <.text+0x21ecee>
  61fcd8: e8 32 15 00 00               	call	0x62120f <.text+0x22020f>
  61fcdd: 8b f0                        	mov	esi, eax
  61fcdf: ff 15 b4 20 65 00            	call	dword ptr [0x6520b4]
  61fce5: 50                           	push	eax
  61fce6: e8 e9 14 00 00               	call	0x6211d4 <.text+0x2201d4>
  61fceb: 89 06                        	mov	dword ptr [esi], eax
  61fced: 59                           	pop	ecx
  61fcee: e8 9e ab 00 00               	call	0x62a891 <.text+0x229891>
  61fcf3: c3                           	ret
  61fcf4: 53                           	push	ebx
  61fcf5: 56                           	push	esi
  61fcf6: 8b 74 24 0c                  	mov	esi, dword ptr [esp + 0xc]
  61fcfa: 8b 46 0c                     	mov	eax, dword ptr [esi + 0xc]
  61fcfd: 8b c8                        	mov	ecx, eax
  61fcff: 80 e1 03                     	and	cl, 0x3
  61fd02: 33 db                        	xor	ebx, ebx
  61fd04: 80 f9 02                     	cmp	cl, 0x2
  61fd07: 75 3f                        	jne	0x61fd48 <.text+0x21ed48>
  61fd09: 66 a9 08 01                  	test	ax, 0x108
  61fd0d: 74 39                        	je	0x61fd48 <.text+0x21ed48>
  61fd0f: 8b 46 08                     	mov	eax, dword ptr [esi + 0x8]
  61fd12: 57                           	push	edi
  61fd13: 8b 3e                        	mov	edi, dword ptr [esi]
  61fd15: 2b f8                        	sub	edi, eax
  61fd17: 85 ff                        	test	edi, edi
  61fd19: 7e 2c                        	jle	0x61fd47 <.text+0x21ed47>
  61fd1b: 57                           	push	edi
  61fd1c: 50                           	push	eax
  61fd1d: 56                           	push	esi
  61fd1e: e8 d9 af 00 00               	call	0x62acfc <.text+0x229cfc>
  61fd23: 59                           	pop	ecx
  61fd24: 50                           	push	eax
  61fd25: e8 2f bf 00 00               	call	0x62bc59 <.text+0x22ac59>
  61fd2a: 83 c4 0c                     	add	esp, 0xc
  61fd2d: 3b c7                        	cmp	eax, edi
  61fd2f: 75 0f                        	jne	0x61fd40 <.text+0x21ed40>
  61fd31: 8b 46 0c                     	mov	eax, dword ptr [esi + 0xc]
  61fd34: 84 c0                        	test	al, al
  61fd36: 79 0f                        	jns	0x61fd47 <.text+0x21ed47>
  61fd38: 83 e0 fd                     	and	eax, -0x3
  61fd3b: 89 46 0c                     	mov	dword ptr [esi + 0xc], eax
  61fd3e: eb 07                        	jmp	0x61fd47 <.text+0x21ed47>


pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  5a17a0: e8 86 bf 07 00               	call	0x61d72b <.text+0x21c72b>
  5a17a5: 83 c4 0c                     	add	esp, 0xc
  5a17a8: c3                           	ret
  5a17a9: cc                           	int3
  5a17aa: cc                           	int3
  5a17ab: cc                           	int3
  5a17ac: cc                           	int3
  5a17ad: cc                           	int3
  5a17ae: cc                           	int3
  5a17af: cc                           	int3
  5a17b0: e8 8b fe ff ff               	call	0x5a1640 <.text+0x1a0640>
  5a17b5: 85 c0                        	test	eax, eax
  5a17b7: 74 10                        	je	0x5a17c9 <.text+0x1a07c9>
  5a17b9: a1 74 9f 6a 00               	mov	eax, dword ptr [0x6a9f74]
  5a17be: 8b 08                        	mov	ecx, dword ptr [eax]
  5a17c0: 8b 11                        	mov	edx, dword ptr [ecx]
  5a17c2: 8b 42 10                     	mov	eax, dword ptr [edx + 0x10]
  5a17c5: 56                           	push	esi
  5a17c6: ff d0                        	call	eax
  5a17c8: c3                           	ret
  5a17c9: 8b 4e 08                     	mov	ecx, dword ptr [esi + 0x8]
  5a17cc: 51                           	push	ecx
  5a17cd: e8 76 c1 07 00               	call	0x61d948 <.text+0x21c948>
  5a17d2: 83 c4 04                     	add	esp, 0x4
  5a17d5: c3                           	ret
  5a17d6: cc                           	int3
  5a17d7: cc                           	int3
  5a17d8: cc                           	int3
  5a17d9: cc                           	int3
  5a17da: cc                           	int3
  5a17db: cc                           	int3
  5a17dc: cc                           	int3
  5a17dd: cc                           	int3
  5a17de: cc                           	int3
  5a17df: cc                           	int3
  5a17e0: e8 5b fe ff ff               	call	0x5a1640 <.text+0x1a0640>
  5a17e5: 85 c0                        	test	eax, eax
  5a17e7: 74 14                        	je	0x5a17fd <.text+0x1a07fd>
  5a17e9: a1 74 9f 6a 00               	mov	eax, dword ptr [0x6a9f74]
  5a17ee: 8b 08                        	mov	ecx, dword ptr [eax]
  5a17f0: 8b 11                        	mov	edx, dword ptr [ecx]
  5a17f2: 8b 42 14                     	mov	eax, dword ptr [edx + 0x14]
  5a17f5: 56                           	push	esi
  5a17f6: 6a 01                        	push	0x1
  5a17f8: 57                           	push	edi
  5a17f9: 53                           	push	ebx
  5a17fa: ff d0                        	call	eax
  5a17fc: c3                           	ret
  5a17fd: 8b 4e 08                     	mov	ecx, dword ptr [esi + 0x8]
  5a1800: 51                           	push	ecx
  5a1801: 6a 01                        	push	0x1
  5a1803: 57                           	push	edi
  5a1804: 53                           	push	ebx
  5a1805: e8 44 ba 07 00               	call	0x61d24e <.text+0x21c24e>
  5a180a: 83 c4 10                     	add	esp, 0x10
  5a180d: c3                           	ret
  5a180e: cc                           	int3
  5a180f: cc                           	int3

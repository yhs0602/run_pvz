
pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  5a1600: 46                           	inc	esi
  5a1601: 04 83                        	add	al, -0x7d
  5a1603: f8                           	clc
  5a1604: ff 73 06                     	push	dword ptr [ebx + 0x6]
  5a1607: 83 c0 01                     	add	eax, 0x1
  5a160a: 89 46 04                     	mov	dword ptr [esi + 0x4], eax
  5a160d: 8d 4c 24 08                  	lea	ecx, [esp + 0x8]
  5a1611: e8 85 9f 06 00               	call	0x60b59b <.text+0x20a59b>
  5a1616: 5e                           	pop	esi
  5a1617: b8 0c a9 75 00               	mov	eax, 0x75a90c
  5a161c: 5f                           	pop	edi
  5a161d: 59                           	pop	ecx
  5a161e: c3                           	ret
  5a161f: cc                           	int3
  5a1620: 56                           	push	esi
  5a1621: 8b f1                        	mov	esi, ecx
  5a1623: e8 e8 fc ff ff               	call	0x5a1310 <.text+0x1a0310>
  5a1628: f6 44 24 08 01               	test	byte ptr [esp + 0x8], 0x1
  5a162d: 74 09                        	je	0x5a1638 <.text+0x1a0638>
  5a162f: 56                           	push	esi
  5a1630: e8 65 ab 07 00               	call	0x61c19a <.text+0x21b19a>
  5a1635: 83 c4 04                     	add	esp, 0x4
  5a1638: 8b c6                        	mov	eax, esi
  5a163a: 5e                           	pop	esi
  5a163b: c2 04 00                     	ret	0x4
  5a163e: cc                           	int3
  5a163f: cc                           	int3
  5a1640: 81 ec 04 01 00 00            	sub	esp, 0x104
  5a1646: a1 e8 9f 69 00               	mov	eax, dword ptr [0x699fe8]
  5a164b: 33 c4                        	xor	eax, esp
  5a164d: 89 84 24 00 01 00 00         	mov	dword ptr [esp + 0x100], eax
  5a1654: 83 3d 70 9f 6a 00 00         	cmp	dword ptr [0x6a9f70], 0x0
  5a165b: 75 60                        	jne	0x5a16bd <.text+0x1a06bd>
  5a165d: ff 15 80 20 65 00            	call	dword ptr [0x652080]
  5a1663: 50                           	push	eax
  5a1664: 8d 44 24 04                  	lea	eax, [esp + 0x4]
  5a1668: 68 a8 86 65 00               	push	0x6586a8
  5a166d: 50                           	push	eax
  5a166e: e8 73 be 07 00               	call	0x61d4e6 <.text+0x21c4e6>
  5a1673: 83 c4 0c                     	add	esp, 0xc
  5a1676: 8d 0c 24                     	lea	ecx, [esp]
  5a1679: 51                           	push	ecx
  5a167a: 6a 04                        	push	0x4
  5a167c: 6a 00                        	push	0x0
  5a167e: 6a 04                        	push	0x4
  5a1680: 6a 00                        	push	0x0
  5a1682: 6a ff                        	push	-0x1
  5a1684: ff 15 7c 20 65 00            	call	dword ptr [0x65207c]
  5a168a: 6a 04                        	push	0x4
  5a168c: 6a 00                        	push	0x0
  5a168e: 6a 00                        	push	0x0
  5a1690: 68 1f 00 0f 00               	push	0xf001f
  5a1695: 50                           	push	eax
  5a1696: a3 70 9f 6a 00               	mov	dword ptr [0x6a9f70], eax
  5a169b: ff 15 78 20 65 00            	call	dword ptr [0x652078]
  5a16a1: a3 74 9f 6a 00               	mov	dword ptr [0x6a9f74], eax
  5a16a6: 8b 00                        	mov	eax, dword ptr [eax]
  5a16a8: 8b 8c 24 00 01 00 00         	mov	ecx, dword ptr [esp + 0x100]
  5a16af: 33 cc                        	xor	ecx, esp
  5a16b1: e8 1b d9 07 00               	call	0x61efd1 <.text+0x21dfd1>
  5a16b6: 81 c4 04 01 00 00            	add	esp, 0x104
  5a16bc: c3                           	ret
  5a16bd: 8b 8c 24 00 01 00 00         	mov	ecx, dword ptr [esp + 0x100]
  5a16c4: 8b 15 74 9f 6a 00            	mov	edx, dword ptr [0x6a9f74]
  5a16ca: 8b 02                        	mov	eax, dword ptr [edx]
  5a16cc: 33 cc                        	xor	ecx, esp
  5a16ce: e8 fe d8 07 00               	call	0x61efd1 <.text+0x21dfd1>
  5a16d3: 81 c4 04 01 00 00            	add	esp, 0x104
  5a16d9: c3                           	ret
  5a16da: cc                           	int3
  5a16db: cc                           	int3
  5a16dc: cc                           	int3
  5a16dd: cc                           	int3
  5a16de: cc                           	int3
  5a16df: cc                           	int3
  5a16e0: 56                           	push	esi
  5a16e1: 8b f0                        	mov	esi, eax
  5a16e3: e8 58 ff ff ff               	call	0x5a1640 <.text+0x1a0640>
  5a16e8: 85 c0                        	test	eax, eax
  5a16ea: 68 a8 e3 66 00               	push	0x66e3a8
  5a16ef: 56                           	push	esi

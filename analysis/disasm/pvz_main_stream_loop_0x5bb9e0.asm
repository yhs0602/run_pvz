
pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  5bb9e0: 56                           	push	esi
  5bb9e1: 51                           	push	ecx
  5bb9e2: 33 c0                        	xor	eax, eax
  5bb9e4: 50                           	push	eax
  5bb9e5: 57                           	push	edi
  5bb9e6: 33 d2                        	xor	edx, edx
  5bb9e8: 52                           	push	edx
  5bb9e9: c6 44 24 24 00               	mov	byte ptr [esp + 0x24], 0x0
  5bb9ee: 8b 44 24 24                  	mov	eax, dword ptr [esp + 0x24]
  5bb9f2: 8b 4c 24 24                  	mov	ecx, dword ptr [esp + 0x24]
  5bb9f6: 8b 54 24 24                  	mov	edx, dword ptr [esp + 0x24]
  5bb9fa: 50                           	push	eax
  5bb9fb: 51                           	push	ecx
  5bb9fc: 52                           	push	edx
  5bb9fd: 8d 44 24 44                  	lea	eax, [esp + 0x44]
  5bba01: 50                           	push	eax
  5bba02: e8 89 8f 00 00               	call	0x5c4990 <.text+0x1c3990>
  5bba07: 83 c4 28                     	add	esp, 0x28
  5bba0a: 5f                           	pop	edi
  5bba0b: 5e                           	pop	esi
  5bba0c: b0 01                        	mov	al, 0x1
  5bba0e: 5b                           	pop	ebx
  5bba0f: 8b e5                        	mov	esp, ebp
  5bba11: 5d                           	pop	ebp
  5bba12: c2 04 00                     	ret	0x4
  5bba15: cc                           	int3
  5bba16: cc                           	int3
  5bba17: cc                           	int3
  5bba18: cc                           	int3
  5bba19: cc                           	int3
  5bba1a: cc                           	int3
  5bba1b: cc                           	int3
  5bba1c: cc                           	int3
  5bba1d: cc                           	int3
  5bba1e: cc                           	int3
  5bba1f: cc                           	int3
  5bba20: 83 ec 10                     	sub	esp, 0x10
  5bba23: 83 7e 18 10                  	cmp	dword ptr [esi + 0x18], 0x10
  5bba27: 53                           	push	ebx
  5bba28: 55                           	push	ebp
  5bba29: 8b 6c 24 1c                  	mov	ebp, dword ptr [esp + 0x1c]
  5bba2d: 57                           	push	edi
  5bba2e: 8d 5e 04                     	lea	ebx, [esi + 0x4]
  5bba31: 72 04                        	jb	0x5bba37 <.text+0x1baa37>
  5bba33: 8b 03                        	mov	eax, dword ptr [ebx]
  5bba35: eb 02                        	jmp	0x5bba39 <.text+0x1baa39>
  5bba37: 8b c3                        	mov	eax, ebx
  5bba39: 56                           	push	esi
  5bba3a: 50                           	push	eax
  5bba3b: 8d 4c 24 18                  	lea	ecx, [esp + 0x18]
  5bba3f: e8 cc ab e9 ff               	call	0x456610 <.text+0x55610>
  5bba44: 8b 7c 24 2c                  	mov	edi, dword ptr [esp + 0x2c]
  5bba48: 85 ff                        	test	edi, edi
  5bba4a: 74 1c                        	je	0x5bba68 <.text+0x1baa68>
  5bba4c: 8b 44 24 28                  	mov	eax, dword ptr [esp + 0x28]
  5bba50: 83 f8 fe                     	cmp	eax, -0x2
  5bba53: 74 0f                        	je	0x5bba64 <.text+0x1baa64>
  5bba55: 85 c0                        	test	eax, eax
  5bba57: 74 06                        	je	0x5bba5f <.text+0x1baa5f>
  5bba59: 3b 44 24 10                  	cmp	eax, dword ptr [esp + 0x10]
  5bba5d: 74 05                        	je	0x5bba64 <.text+0x1baa64>
  5bba5f: e8 db 0b 06 00               	call	0x61c63f <.text+0x21b63f>
  5bba64: 2b 7c 24 14                  	sub	edi, dword ptr [esp + 0x14]
  5bba68: 8b 44 24 24                  	mov	eax, dword ptr [esp + 0x24]
  5bba6c: 50                           	push	eax
  5bba6d: 6a 01                        	push	0x1
  5bba6f: 57                           	push	edi
  5bba70: 8b ce                        	mov	ecx, esi
  5bba72: e8 99 19 fa ff               	call	0x55d410 <.text+0x15c410>
  5bba77: 83 7e 18 10                  	cmp	dword ptr [esi + 0x18], 0x10
  5bba7b: 72 04                        	jb	0x5bba81 <.text+0x1baa81>
  5bba7d: 8b 03                        	mov	eax, dword ptr [ebx]
  5bba7f: eb 02                        	jmp	0x5bba83 <.text+0x1baa83>
  5bba81: 8b c3                        	mov	eax, ebx
  5bba83: 56                           	push	esi
  5bba84: 50                           	push	eax
  5bba85: 8d 4c 24 18                  	lea	ecx, [esp + 0x18]
  5bba89: e8 82 ab e9 ff               	call	0x456610 <.text+0x55610>
  5bba8e: 8b 4c 24 10                  	mov	ecx, dword ptr [esp + 0x10]
  5bba92: 8b 54 24 14                  	mov	edx, dword ptr [esp + 0x14]
  5bba96: 89 4c 24 28                  	mov	dword ptr [esp + 0x28], ecx
  5bba9a: 57                           	push	edi
  5bba9b: 8d 4c 24 2c                  	lea	ecx, [esp + 0x2c]
  5bba9f: 89 54 24 30                  	mov	dword ptr [esp + 0x30], edx
  5bbaa3: e8 38 3a 00 00               	call	0x5bf4e0 <.text+0x1be4e0>
  5bbaa8: 8b 44 24 28                  	mov	eax, dword ptr [esp + 0x28]
  5bbaac: 8b 4c 24 2c                  	mov	ecx, dword ptr [esp + 0x2c]
  5bbab0: 89 45 00                     	mov	dword ptr [ebp], eax
  5bbab3: 5f                           	pop	edi
  5bbab4: 89 4d 04                     	mov	dword ptr [ebp + 0x4], ecx
  5bbab7: 8b c5                        	mov	eax, ebp
  5bbab9: 5d                           	pop	ebp
  5bbaba: 5b                           	pop	ebx
  5bbabb: 83 c4 10                     	add	esp, 0x10
  5bbabe: c2 10 00                     	ret	0x10
  5bbac1: cc                           	int3
  5bbac2: cc                           	int3
  5bbac3: cc                           	int3
  5bbac4: cc                           	int3
  5bbac5: cc                           	int3
  5bbac6: cc                           	int3
  5bbac7: cc                           	int3
  5bbac8: cc                           	int3
  5bbac9: cc                           	int3
  5bbaca: cc                           	int3
  5bbacb: cc                           	int3
  5bbacc: cc                           	int3
  5bbacd: cc                           	int3
  5bbace: cc                           	int3
  5bbacf: cc                           	int3
  5bbad0: 55                           	push	ebp
  5bbad1: 8b ec                        	mov	ebp, esp
  5bbad3: 83 e4 f8                     	and	esp, -0x8
  5bbad6: 83 ec 0c                     	sub	esp, 0xc
  5bbad9: 56                           	push	esi
  5bbada: 8b f0                        	mov	esi, eax
  5bbadc: 83 7e 18 10                  	cmp	dword ptr [esi + 0x18], 0x10
  5bbae0: 72 05                        	jb	0x5bbae7 <.text+0x1baae7>
  5bbae2: 8b 46 04                     	mov	eax, dword ptr [esi + 0x4]
  5bbae5: eb 03                        	jmp	0x5bbaea <.text+0x1baaea>
  5bbae7: 8d 46 04                     	lea	eax, [esi + 0x4]
  5bbaea: 8b 4e 14                     	mov	ecx, dword ptr [esi + 0x14]
  5bbaed: 03 c8                        	add	ecx, eax
  5bbaef: 56                           	push	esi
  5bbaf0: 51                           	push	ecx
  5bbaf1: 8d 4c 24 10                  	lea	ecx, [esp + 0x10]
  5bbaf5: e8 16 ab e9 ff               	call	0x456610 <.text+0x55610>
  5bbafa: 8b 54 24 0c                  	mov	edx, dword ptr [esp + 0xc]
  5bbafe: 8b 44 24 08                  	mov	eax, dword ptr [esp + 0x8]
  5bbb02: 8b 4d 08                     	mov	ecx, dword ptr [ebp + 0x8]
  5bbb05: 52                           	push	edx
  5bbb06: 50                           	push	eax
  5bbb07: 51                           	push	ecx
  5bbb08: 8d 54 24 14                  	lea	edx, [esp + 0x14]
  5bbb0c: 52                           	push	edx
  5bbb0d: e8 0e ff ff ff               	call	0x5bba20 <.text+0x1baa20>
  5bbb12: 5e                           	pop	esi
  5bbb13: 8b e5                        	mov	esp, ebp
  5bbb15: 5d                           	pop	ebp
  5bbb16: c2 04 00                     	ret	0x4
  5bbb19: cc                           	int3
  5bbb1a: cc                           	int3
  5bbb1b: cc                           	int3
  5bbb1c: cc                           	int3
  5bbb1d: cc                           	int3
  5bbb1e: cc                           	int3
  5bbb1f: cc                           	int3
  5bbb20: 6a ff                        	push	-0x1
  5bbb22: 68 18 9f 64 00               	push	0x649f18
  5bbb27: 64 a1 00 00 00 00            	mov	eax, dword ptr fs:[0x0]
  5bbb2d: 50                           	push	eax
  5bbb2e: 51                           	push	ecx
  5bbb2f: 56                           	push	esi
  5bbb30: 57                           	push	edi
  5bbb31: a1 e8 9f 69 00               	mov	eax, dword ptr [0x699fe8]
  5bbb36: 33 c4                        	xor	eax, esp
  5bbb38: 50                           	push	eax
  5bbb39: 8d 44 24 10                  	lea	eax, [esp + 0x10]
  5bbb3d: 64 a3 00 00 00 00            	mov	dword ptr fs:[0x0], eax

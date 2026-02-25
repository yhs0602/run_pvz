
pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  5bf470: 8b c1                        	mov	eax, ecx
  5bf472: 8b 4c 24 08                  	mov	ecx, dword ptr [esp + 0x8]
  5bf476: 83 f9 01                     	cmp	ecx, 0x1
  5bf479: 75 2c                        	jne	0x5bf4a7 <.text+0x1be4a7>
  5bf47b: 83 78 18 08                  	cmp	dword ptr [eax + 0x18], 0x8
  5bf47f: 72 13                        	jb	0x5bf494 <.text+0x1be494>
  5bf481: 8b 40 04                     	mov	eax, dword ptr [eax + 0x4]
  5bf484: 8b 4c 24 04                  	mov	ecx, dword ptr [esp + 0x4]
  5bf488: 66 8b 54 24 0c               	mov	dx, word ptr [esp + 0xc]
  5bf48d: 66 89 14 48                  	mov	word ptr [eax + 2*ecx], dx
  5bf491: c2 0c 00                     	ret	0xc
  5bf494: 8b 4c 24 04                  	mov	ecx, dword ptr [esp + 0x4]
  5bf498: 66 8b 54 24 0c               	mov	dx, word ptr [esp + 0xc]
  5bf49d: 83 c0 04                     	add	eax, 0x4
  5bf4a0: 66 89 14 48                  	mov	word ptr [eax + 2*ecx], dx
  5bf4a4: c2 0c 00                     	ret	0xc
  5bf4a7: 83 78 18 08                  	cmp	dword ptr [eax + 0x18], 0x8
  5bf4ab: 72 05                        	jb	0x5bf4b2 <.text+0x1be4b2>
  5bf4ad: 8b 40 04                     	mov	eax, dword ptr [eax + 0x4]
  5bf4b0: eb 03                        	jmp	0x5bf4b5 <.text+0x1be4b5>
  5bf4b2: 83 c0 04                     	add	eax, 0x4
  5bf4b5: 85 c9                        	test	ecx, ecx
  5bf4b7: 8b 54 24 04                  	mov	edx, dword ptr [esp + 0x4]
  5bf4bb: 57                           	push	edi
  5bf4bc: 8d 3c 50                     	lea	edi, [eax + 2*edx]
  5bf4bf: 76 18                        	jbe	0x5bf4d9 <.text+0x1be4d9>
  5bf4c1: 8b 44 24 10                  	mov	eax, dword ptr [esp + 0x10]
  5bf4c5: 66 8b d0                     	mov	dx, ax
  5bf4c8: c1 e2 10                     	shl	edx, 0x10
  5bf4cb: 66 8b d0                     	mov	dx, ax
  5bf4ce: d1 e9                        	shr	ecx
  5bf4d0: 8b c2                        	mov	eax, edx
  5bf4d2: f3 ab                        	rep		stosd	dword ptr es:[edi], eax
  5bf4d4: 13 c9                        	adc	ecx, ecx
  5bf4d6: 66 f3 ab                     	rep		stosw	word ptr es:[edi], ax
  5bf4d9: 5f                           	pop	edi
  5bf4da: c2 0c 00                     	ret	0xc
  5bf4dd: cc                           	int3
  5bf4de: cc                           	int3
  5bf4df: cc                           	int3
  5bf4e0: 56                           	push	esi
  5bf4e1: 8b f1                        	mov	esi, ecx
  5bf4e3: 8b 06                        	mov	eax, dword ptr [esi]
  5bf4e5: 83 f8 fe                     	cmp	eax, -0x2
  5bf4e8: 57                           	push	edi
  5bf4e9: 8b 7c 24 0c                  	mov	edi, dword ptr [esp + 0xc]
  5bf4ed: 74 40                        	je	0x5bf52f <.text+0x1be52f>
  5bf4ef: 85 c0                        	test	eax, eax
  5bf4f1: 75 05                        	jne	0x5bf4f8 <.text+0x1be4f8>
  5bf4f3: e8 47 d1 05 00               	call	0x61c63f <.text+0x21b63f>
  5bf4f8: 8b 06                        	mov	eax, dword ptr [esi]
  5bf4fa: 83 78 18 10                  	cmp	dword ptr [eax + 0x18], 0x10
  5bf4fe: 72 05                        	jb	0x5bf505 <.text+0x1be505>
  5bf500: 8b 50 04                     	mov	edx, dword ptr [eax + 0x4]
  5bf503: eb 03                        	jmp	0x5bf508 <.text+0x1be508>
  5bf505: 8d 50 04                     	lea	edx, [eax + 0x4]
  5bf508: 8b 4e 04                     	mov	ecx, dword ptr [esi + 0x4]
  5bf50b: 55                           	push	ebp
  5bf50c: 8b 68 14                     	mov	ebp, dword ptr [eax + 0x14]
  5bf50f: 03 ea                        	add	ebp, edx
  5bf511: 03 cf                        	add	ecx, edi
  5bf513: 3b cd                        	cmp	ecx, ebp
  5bf515: 5d                           	pop	ebp
  5bf516: 77 12                        	ja	0x5bf52a <.text+0x1be52a>
  5bf518: 83 78 18 10                  	cmp	dword ptr [eax + 0x18], 0x10
  5bf51c: 72 05                        	jb	0x5bf523 <.text+0x1be523>
  5bf51e: 8b 40 04                     	mov	eax, dword ptr [eax + 0x4]
  5bf521: eb 03                        	jmp	0x5bf526 <.text+0x1be526>
  5bf523: 83 c0 04                     	add	eax, 0x4
  5bf526: 3b c8                        	cmp	ecx, eax
  5bf528: 73 05                        	jae	0x5bf52f <.text+0x1be52f>
  5bf52a: e8 10 d1 05 00               	call	0x61c63f <.text+0x21b63f>
  5bf52f: 01 7e 04                     	add	dword ptr [esi + 0x4], edi
  5bf532: 5f                           	pop	edi
  5bf533: 8b c6                        	mov	eax, esi
  5bf535: 5e                           	pop	esi
  5bf536: c2 04 00                     	ret	0x4
  5bf539: cc                           	int3
  5bf53a: cc                           	int3
  5bf53b: cc                           	int3
  5bf53c: cc                           	int3
  5bf53d: cc                           	int3
  5bf53e: cc                           	int3
  5bf53f: cc                           	int3
  5bf540: 53                           	push	ebx
  5bf541: 8b 5c 24 08                  	mov	ebx, dword ptr [esp + 0x8]
  5bf545: 56                           	push	esi
  5bf546: 8b 74 24 10                  	mov	esi, dword ptr [esp + 0x10]
  5bf54a: 85 f6                        	test	esi, esi
  5bf54c: 57                           	push	edi
  5bf54d: 8b f9                        	mov	edi, ecx
  5bf54f: c7 07 00 00 00 00            	mov	dword ptr [edi], 0x0
  5bf555: 74 2a                        	je	0x5bf581 <.text+0x1be581>
  5bf557: 85 db                        	test	ebx, ebx
  5bf559: 74 26                        	je	0x5bf581 <.text+0x1be581>
  5bf55b: 8b 56 18                     	mov	edx, dword ptr [esi + 0x18]
  5bf55e: 83 fa 08                     	cmp	edx, 0x8
  5bf561: 8d 46 04                     	lea	eax, [esi + 0x4]
  5bf564: 72 04                        	jb	0x5bf56a <.text+0x1be56a>
  5bf566: 8b 08                        	mov	ecx, dword ptr [eax]
  5bf568: eb 02                        	jmp	0x5bf56c <.text+0x1be56c>
  5bf56a: 8b c8                        	mov	ecx, eax
  5bf56c: 3b cb                        	cmp	ecx, ebx
  5bf56e: 77 11                        	ja	0x5bf581 <.text+0x1be581>
  5bf570: 83 fa 08                     	cmp	edx, 0x8
  5bf573: 72 02                        	jb	0x5bf577 <.text+0x1be577>
  5bf575: 8b 00                        	mov	eax, dword ptr [eax]
  5bf577: 8b 4e 14                     	mov	ecx, dword ptr [esi + 0x14]
  5bf57a: 8d 14 48                     	lea	edx, [eax + 2*ecx]
  5bf57d: 3b da                        	cmp	ebx, edx
  5bf57f: 76 05                        	jbe	0x5bf586 <.text+0x1be586>
  5bf581: e8 b9 d0 05 00               	call	0x61c63f <.text+0x21b63f>
  5bf586: 89 37                        	mov	dword ptr [edi], esi
  5bf588: 89 5f 04                     	mov	dword ptr [edi + 0x4], ebx
  5bf58b: 8b c7                        	mov	eax, edi
  5bf58d: 5f                           	pop	edi
  5bf58e: 5e                           	pop	esi
  5bf58f: 5b                           	pop	ebx
  5bf590: c2 08 00                     	ret	0x8
  5bf593: cc                           	int3
  5bf594: cc                           	int3
  5bf595: cc                           	int3
  5bf596: cc                           	int3
  5bf597: cc                           	int3
  5bf598: cc                           	int3
  5bf599: cc                           	int3
  5bf59a: cc                           	int3
  5bf59b: cc                           	int3
  5bf59c: cc                           	int3
  5bf59d: cc                           	int3
  5bf59e: cc                           	int3
  5bf59f: cc                           	int3

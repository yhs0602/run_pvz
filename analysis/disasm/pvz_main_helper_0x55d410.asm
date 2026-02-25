
pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  55d3c0: 56                           	push	esi
  55d3c1: 8b f1                        	mov	esi, ecx
  55d3c3: 8b 46 08                     	mov	eax, dword ptr [esi + 0x8]
  55d3c6: 50                           	push	eax
  55d3c7: c7 06 d4 27 65 00            	mov	dword ptr [esi], 0x6527d4
  55d3cd: e8 cd ed 0b 00               	call	0x61c19f <.text+0x21b19f>
  55d3d2: 8b 4e 10                     	mov	ecx, dword ptr [esi + 0x10]
  55d3d5: 51                           	push	ecx
  55d3d6: e8 c4 ed 0b 00               	call	0x61c19f <.text+0x21b19f>
  55d3db: 8b 56 14                     	mov	edx, dword ptr [esi + 0x14]
  55d3de: 52                           	push	edx
  55d3df: e8 bb ed 0b 00               	call	0x61c19f <.text+0x21b19f>
  55d3e4: 83 c4 0c                     	add	esp, 0xc
  55d3e7: f6 44 24 08 01               	test	byte ptr [esp + 0x8], 0x1
  55d3ec: c7 06 88 26 65 00            	mov	dword ptr [esi], 0x652688
  55d3f2: 74 09                        	je	0x55d3fd <.text+0x15c3fd>
  55d3f4: 56                           	push	esi
  55d3f5: e8 a0 ed 0b 00               	call	0x61c19a <.text+0x21b19a>
  55d3fa: 83 c4 04                     	add	esp, 0x4
  55d3fd: 8b c6                        	mov	eax, esi
  55d3ff: 5e                           	pop	esi
  55d400: c2 04 00                     	ret	0x4
  55d403: cc                           	int3
  55d404: cc                           	int3
  55d405: cc                           	int3
  55d406: cc                           	int3
  55d407: cc                           	int3
  55d408: cc                           	int3
  55d409: cc                           	int3
  55d40a: cc                           	int3
  55d40b: cc                           	int3
  55d40c: cc                           	int3
  55d40d: cc                           	int3
  55d40e: cc                           	int3
  55d40f: cc                           	int3
  55d410: 55                           	push	ebp
  55d411: 56                           	push	esi
  55d412: 57                           	push	edi
  55d413: 8b 7c 24 10                  	mov	edi, dword ptr [esp + 0x10]
  55d417: 8b f1                        	mov	esi, ecx
  55d419: 39 7e 14                     	cmp	dword ptr [esi + 0x14], edi
  55d41c: 73 05                        	jae	0x55d423 <.text+0x15c423>
  55d41e: e8 39 da 0a 00               	call	0x60ae5c <.text+0x209e5c>
  55d423: 8b 6c 24 14                  	mov	ebp, dword ptr [esp + 0x14]
  55d427: 83 c8 ff                     	or	eax, -0x1
  55d42a: 2b 46 14                     	sub	eax, dword ptr [esi + 0x14]
  55d42d: 3b c5                        	cmp	eax, ebp
  55d42f: 77 05                        	ja	0x55d436 <.text+0x15c436>
  55d431: e8 e7 d9 0a 00               	call	0x60ae1d <.text+0x209e1d>
  55d436: 85 ed                        	test	ebp, ebp
  55d438: 0f 86 c7 00 00 00            	jbe	0x55d505 <.text+0x15c505>
  55d43e: 53                           	push	ebx
  55d43f: 8b 5e 14                     	mov	ebx, dword ptr [esi + 0x14]
  55d442: 03 dd                        	add	ebx, ebp
  55d444: 83 fb fe                     	cmp	ebx, -0x2
  55d447: 76 05                        	jbe	0x55d44e <.text+0x15c44e>
  55d449: e8 cf d9 0a 00               	call	0x60ae1d <.text+0x209e1d>
  55d44e: 8b 46 18                     	mov	eax, dword ptr [esi + 0x18]
  55d451: 3b c3                        	cmp	eax, ebx
  55d453: 73 25                        	jae	0x55d47a <.text+0x15c47a>
  55d455: 8b 4e 14                     	mov	ecx, dword ptr [esi + 0x14]
  55d458: 51                           	push	ecx
  55d459: 53                           	push	ebx
  55d45a: 8b ce                        	mov	ecx, esi
  55d45c: e8 1f 6c ea ff               	call	0x404080 <.text+0x3080>
  55d461: 85 db                        	test	ebx, ebx
  55d463: 0f 86 9b 00 00 00            	jbe	0x55d504 <.text+0x15c504>
  55d469: 8b 46 18                     	mov	eax, dword ptr [esi + 0x18]
  55d46c: 83 f8 10                     	cmp	eax, 0x10
  55d46f: 72 32                        	jb	0x55d4a3 <.text+0x15c4a3>
  55d471: 8b 56 04                     	mov	edx, dword ptr [esi + 0x4]
  55d474: 89 54 24 14                  	mov	dword ptr [esp + 0x14], edx
  55d478: eb 30                        	jmp	0x55d4aa <.text+0x15c4aa>
  55d47a: 85 db                        	test	ebx, ebx
  55d47c: 75 e5                        	jne	0x55d463 <.text+0x15c463>
  55d47e: 83 f8 10                     	cmp	eax, 0x10
  55d481: 89 5e 14                     	mov	dword ptr [esi + 0x14], ebx
  55d484: 72 0e                        	jb	0x55d494 <.text+0x15c494>
  55d486: 8b 46 04                     	mov	eax, dword ptr [esi + 0x4]
  55d489: 88 18                        	mov	byte ptr [eax], bl
  55d48b: 5b                           	pop	ebx
  55d48c: 5f                           	pop	edi
  55d48d: 8b c6                        	mov	eax, esi
  55d48f: 5e                           	pop	esi
  55d490: 5d                           	pop	ebp
  55d491: c2 0c 00                     	ret	0xc
  55d494: 8d 46 04                     	lea	eax, [esi + 0x4]
  55d497: 5b                           	pop	ebx
  55d498: 5f                           	pop	edi
  55d499: c6 00 00                     	mov	byte ptr [eax], 0x0
  55d49c: 8b c6                        	mov	eax, esi
  55d49e: 5e                           	pop	esi
  55d49f: 5d                           	pop	ebp
  55d4a0: c2 0c 00                     	ret	0xc
  55d4a3: 8d 4e 04                     	lea	ecx, [esi + 0x4]
  55d4a6: 89 4c 24 14                  	mov	dword ptr [esp + 0x14], ecx
  55d4aa: 83 f8 10                     	cmp	eax, 0x10
  55d4ad: 72 05                        	jb	0x55d4b4 <.text+0x15c4b4>
  55d4af: 8b 4e 04                     	mov	ecx, dword ptr [esi + 0x4]
  55d4b2: eb 03                        	jmp	0x55d4b7 <.text+0x15c4b7>
  55d4b4: 8d 4e 04                     	lea	ecx, [esi + 0x4]
  55d4b7: 8b 56 14                     	mov	edx, dword ptr [esi + 0x14]
  55d4ba: 2b d7                        	sub	edx, edi
  55d4bc: 52                           	push	edx
  55d4bd: 8b 54 24 18                  	mov	edx, dword ptr [esp + 0x18]
  55d4c1: 03 d7                        	add	edx, edi
  55d4c3: 2b c7                        	sub	eax, edi
  55d4c5: 52                           	push	edx
  55d4c6: 2b c5                        	sub	eax, ebp
  55d4c8: 03 cf                        	add	ecx, edi
  55d4ca: 50                           	push	eax
  55d4cb: 03 cd                        	add	ecx, ebp
  55d4cd: 51                           	push	ecx
  55d4ce: e8 c3 e9 0b 00               	call	0x61be96 <.text+0x21ae96>
  55d4d3: 8b 44 24 2c                  	mov	eax, dword ptr [esp + 0x2c]
  55d4d7: 83 c4 10                     	add	esp, 0x10
  55d4da: 50                           	push	eax
  55d4db: 55                           	push	ebp
  55d4dc: 57                           	push	edi
  55d4dd: 8b ce                        	mov	ecx, esi
  55d4df: e8 ec 48 ee ff               	call	0x441dd0 <.text+0x40dd0>
  55d4e4: 83 7e 18 10                  	cmp	dword ptr [esi + 0x18], 0x10
  55d4e8: 89 5e 14                     	mov	dword ptr [esi + 0x14], ebx
  55d4eb: 72 10                        	jb	0x55d4fd <.text+0x15c4fd>
  55d4ed: 8b 46 04                     	mov	eax, dword ptr [esi + 0x4]
  55d4f0: c6 04 18 00                  	mov	byte ptr [eax + ebx], 0x0
  55d4f4: 5b                           	pop	ebx
  55d4f5: 5f                           	pop	edi
  55d4f6: 8b c6                        	mov	eax, esi
  55d4f8: 5e                           	pop	esi
  55d4f9: 5d                           	pop	ebp
  55d4fa: c2 0c 00                     	ret	0xc
  55d4fd: 8d 46 04                     	lea	eax, [esi + 0x4]
  55d500: c6 04 18 00                  	mov	byte ptr [eax + ebx], 0x0
  55d504: 5b                           	pop	ebx
  55d505: 5f                           	pop	edi
  55d506: 8b c6                        	mov	eax, esi
  55d508: 5e                           	pop	esi
  55d509: 5d                           	pop	ebp
  55d50a: c2 0c 00                     	ret	0xc
  55d50d: cc                           	int3
  55d50e: cc                           	int3
  55d50f: cc                           	int3
  55d510: 53                           	push	ebx
  55d511: 8b 5c 24 08                  	mov	ebx, dword ptr [esp + 0x8]
  55d515: 81 fb fe ff ff 7f            	cmp	ebx, 0x7ffffffe
  55d51b: 56                           	push	esi
  55d51c: 8b f1                        	mov	esi, ecx
  55d51e: 76 05                        	jbe	0x55d525 <.text+0x15c525>

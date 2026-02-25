
/Users/yanghyeonseo/Developer/pvz/pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  621120: 8b 1d 9c 21 65 00            	mov	ebx, dword ptr [0x65219c]
  621126: 56                           	push	esi
  621127: 57                           	push	edi
  621128: 33 f6                        	xor	esi, esi
  62112a: 39 35 d4 6d 6a 00            	cmp	dword ptr [0x6a6dd4], esi
  621130: 8b fd                        	mov	edi, ebp
  621132: 75 18                        	jne	0x62114c <.text+0x22014c>
  621134: e8 78 bc 00 00               	call	0x62cdb1 <.text+0x22bdb1>
  621139: 6a 1e                        	push	0x1e
  62113b: e8 d1 ba 00 00               	call	0x62cc11 <.text+0x22bc11>
  621140: 68 ff 00 00 00               	push	0xff
  621145: e8 02 ca ff ff               	call	0x61db4c <.text+0x21cb4c>
  62114a: 59                           	pop	ecx
  62114b: 59                           	pop	ecx
  62114c: a1 c0 ca 75 00               	mov	eax, dword ptr [0x75cac0]
  621151: 83 f8 01                     	cmp	eax, 0x1
  621154: 75 0e                        	jne	0x621164 <.text+0x220164>
  621156: 3b ee                        	cmp	ebp, esi
  621158: 74 04                        	je	0x62115e <.text+0x22015e>
  62115a: 8b c5                        	mov	eax, ebp
  62115c: eb 03                        	jmp	0x621161 <.text+0x220161>
  62115e: 33 c0                        	xor	eax, eax
  621160: 40                           	inc	eax
  621161: 50                           	push	eax
  621162: eb 1e                        	jmp	0x621182 <.text+0x220182>
  621164: 83 f8 03                     	cmp	eax, 0x3
  621167: 75 0b                        	jne	0x621174 <.text+0x220174>
  621169: 55                           	push	ebp
  62116a: e8 53 ff ff ff               	call	0x6210c2 <.text+0x2200c2>
  62116f: 3b c6                        	cmp	eax, esi
  621171: 59                           	pop	ecx
  621172: 75 17                        	jne	0x62118b <.text+0x22018b>
  621174: 3b ee                        	cmp	ebp, esi
  621176: 75 03                        	jne	0x62117b <.text+0x22017b>
  621178: 33 ff                        	xor	edi, edi
  62117a: 47                           	inc	edi
  62117b: 83 c7 0f                     	add	edi, 0xf
  62117e: 83 e7 f0                     	and	edi, -0x10
  621181: 57                           	push	edi
  621182: 56                           	push	esi
  621183: ff 35 d4 6d 6a 00            	push	dword ptr [0x6a6dd4]
  621189: ff d3                        	call	ebx
  62118b: 8b f0                        	mov	esi, eax
  62118d: 85 f6                        	test	esi, esi
  62118f: 75 26                        	jne	0x6211b7 <.text+0x2201b7>
  621191: 39 05 04 71 6a 00            	cmp	dword ptr [0x6a7104], eax
  621197: 6a 0c                        	push	0xc
  621199: 5f                           	pop	edi
  62119a: 74 0d                        	je	0x6211a9 <.text+0x2201a9>
  62119c: 55                           	push	ebp
  62119d: e8 c0 73 00 00               	call	0x628562 <.text+0x227562>
  6211a2: 85 c0                        	test	eax, eax
  6211a4: 59                           	pop	ecx
  6211a5: 75 81                        	jne	0x621128 <.text+0x220128>
  6211a7: eb 07                        	jmp	0x6211b0 <.text+0x2201b0>
  6211a9: e8 61 00 00 00               	call	0x62120f <.text+0x22020f>
  6211ae: 89 38                        	mov	dword ptr [eax], edi
  6211b0: e8 5a 00 00 00               	call	0x62120f <.text+0x22020f>
  6211b5: 89 38                        	mov	dword ptr [eax], edi
  6211b7: 5f                           	pop	edi
  6211b8: 8b c6                        	mov	eax, esi
  6211ba: 5e                           	pop	esi
  6211bb: 5b                           	pop	ebx
  6211bc: 5d                           	pop	ebp
  6211bd: c3                           	ret
  6211be: 55                           	push	ebp
  6211bf: e8 9e 73 00 00               	call	0x628562 <.text+0x227562>
  6211c4: 59                           	pop	ecx
  6211c5: e8 45 00 00 00               	call	0x62120f <.text+0x22020f>
  6211ca: c7 00 0c 00 00 00            	mov	dword ptr [eax], 0xc
  6211d0: 33 c0                        	xor	eax, eax
  6211d2: 5d                           	pop	ebp
  6211d3: c3                           	ret
  6211d4: 8b 44 24 04                  	mov	eax, dword ptr [esp + 0x4]
  6211d8: 33 c9                        	xor	ecx, ecx
  6211da: 3b 04 cd d0 9b 69 00         	cmp	eax, dword ptr [8*ecx + 0x699bd0]
  6211e1: 74 12                        	je	0x6211f5 <.text+0x2201f5>
  6211e3: 41                           	inc	ecx
  6211e4: 83 f9 2d                     	cmp	ecx, 0x2d
  6211e7: 72 f1                        	jb	0x6211da <.text+0x2201da>
  6211e9: 8d 48 ed                     	lea	ecx, [eax - 0x13]
  6211ec: 83 f9 11                     	cmp	ecx, 0x11
  6211ef: 77 0c                        	ja	0x6211fd <.text+0x2201fd>
  6211f1: 6a 0d                        	push	0xd
  6211f3: 58                           	pop	eax
  6211f4: c3                           	ret
  6211f5: 8b 04 cd d4 9b 69 00         	mov	eax, dword ptr [8*ecx + 0x699bd4]
  6211fc: c3                           	ret
  6211fd: 05 44 ff ff ff               	add	eax, 0xffffff44
  621202: 6a 0e                        	push	0xe
  621204: 59                           	pop	ecx
  621205: 3b c8                        	cmp	ecx, eax
  621207: 1b c0                        	sbb	eax, eax
  621209: 23 c1                        	and	eax, ecx
  62120b: 83 c0 08                     	add	eax, 0x8
  62120e: c3                           	ret
  62120f: e8 b2 77 00 00               	call	0x6289c6 <.text+0x2279c6>
  621214: 85 c0                        	test	eax, eax
  621216: 75 06                        	jne	0x62121e <.text+0x22021e>
  621218: b8 38 9d 69 00               	mov	eax, 0x699d38
  62121d: c3                           	ret
  62121e: 83 c0 08                     	add	eax, 0x8

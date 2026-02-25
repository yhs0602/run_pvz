
pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  5a1f40: 00 00                        	add	byte ptr [eax], al
  5a1f42: 89 84 24 18 01 00 00         	mov	dword ptr [esp + 0x118], eax
  5a1f49: 89 9c 24 14 01 00 00         	mov	dword ptr [esp + 0x114], ebx
  5a1f50: 66 89 9c 24 04 01 00 00      	mov	word ptr [esp + 0x104], bx
  5a1f58: c6 84 24 80 01 00 00 03      	mov	byte ptr [esp + 0x180], 0x3
  5a1f60: 8b 7c 24 2c                  	mov	edi, dword ptr [esp + 0x2c]
  5a1f64: 8b 17                        	mov	edx, dword ptr [edi]
  5a1f66: 8b 52 18                     	mov	edx, dword ptr [edx + 0x18]
  5a1f69: 8d 44 24 24                  	lea	eax, [esp + 0x24]
  5a1f6d: 50                           	push	eax
  5a1f6e: 8b cf                        	mov	ecx, edi
  5a1f70: ff d2                        	call	edx
  5a1f72: 83 e8 00                     	sub	eax, 0x0
  5a1f75: 0f 85 fd 0f 00 00            	jne	0x5a2f78 <.text+0x1a1f78>
  5a1f7b: 8b 54 24 24                  	mov	edx, dword ptr [esp + 0x24]
  5a1f7f: 32 db                        	xor	bl, bl
  5a1f81: 66 83 fa 0a                  	cmp	dx, 0xa
  5a1f85: 75 04                        	jne	0x5a1f8b <.text+0x1a0f8b>
  5a1f87: 83 47 58 01                  	add	dword ptr [edi + 0x58], 0x1
  5a1f8b: 8b 4c 24 18                  	mov	ecx, dword ptr [esp + 0x18]
  5a1f8f: 8b 01                        	mov	eax, dword ptr [ecx]
  5a1f91: 83 f8 05                     	cmp	eax, 0x5
  5a1f94: 0f 85 b8 00 00 00            	jne	0x5a2052 <.text+0x1a1052>
  5a1f9a: 8b 74 24 28                  	mov	esi, dword ptr [esp + 0x28]
  5a1f9e: 52                           	push	edx
  5a1f9f: 6a 01                        	push	0x1
  5a1fa1: 8b ce                        	mov	ecx, esi
  5a1fa3: e8 78 fd e9 ff               	call	0x441d20 <.text+0x40d20>
  5a1fa8: 66 83 7c 24 24 3e            	cmp	word ptr [esp + 0x24], 0x3e
  5a1fae: 8b 7e 14                     	mov	edi, dword ptr [esi + 0x14]
  5a1fb1: 75 ad                        	jne	0x5a1f60 <.text+0x1a0f60>
  5a1fb3: 83 ff 03                     	cmp	edi, 0x3
  5a1fb6: 7c a8                        	jl	0x5a1f60 <.text+0x1a0f60>
  5a1fb8: 8d 5f fe                     	lea	ebx, [edi - 0x2]
  5a1fbb: 3b df                        	cmp	ebx, edi
  5a1fbd: 76 05                        	jbe	0x5a1fc4 <.text+0x1a0fc4>
  5a1fbf: e8 7b a6 07 00               	call	0x61c63f <.text+0x21b63f>
  5a1fc4: 83 7e 18 10                  	cmp	dword ptr [esi + 0x18], 0x10
  5a1fc8: 72 08                        	jb	0x5a1fd2 <.text+0x1a0fd2>
  5a1fca: 8b 46 04                     	mov	eax, dword ptr [esi + 0x4]
  5a1fcd: 83 c6 04                     	add	esi, 0x4
  5a1fd0: eb 05                        	jmp	0x5a1fd7 <.text+0x1a0fd7>
  5a1fd2: 83 c6 04                     	add	esi, 0x4
  5a1fd5: 8b c6                        	mov	eax, esi
  5a1fd7: 80 3c 18 2d                  	cmp	byte ptr [eax + ebx], 0x2d
  5a1fdb: 75 83                        	jne	0x5a1f60 <.text+0x1a0f60>
  5a1fdd: 8b 44 24 28                  	mov	eax, dword ptr [esp + 0x28]
  5a1fe1: 8d 5f fd                     	lea	ebx, [edi - 0x3]
  5a1fe4: 3b 58 14                     	cmp	ebx, dword ptr [eax + 0x14]
  5a1fe7: 76 05                        	jbe	0x5a1fee <.text+0x1a0fee>
  5a1fe9: e8 51 a6 07 00               	call	0x61c63f <.text+0x21b63f>
  5a1fee: 8b 4c 24 28                  	mov	ecx, dword ptr [esp + 0x28]
  5a1ff2: 83 79 18 10                  	cmp	dword ptr [ecx + 0x18], 0x10
  5a1ff6: 72 02                        	jb	0x5a1ffa <.text+0x1a0ffa>
  5a1ff8: 8b 36                        	mov	esi, dword ptr [esi]
  5a1ffa: 80 3c 33 2d                  	cmp	byte ptr [ebx + esi], 0x2d
  5a1ffe: 0f 85 5c ff ff ff            	jne	0x5a1f60 <.text+0x1a0f60>
  5a2004: 83 c7 fd                     	add	edi, -0x3
  5a2007: 57                           	push	edi
  5a2008: 8b 7c 24 2c                  	mov	edi, dword ptr [esp + 0x2c]
  5a200c: 33 c9                        	xor	ecx, ecx
  5a200e: 8d 74 24 34                  	lea	esi, [esp + 0x34]
  5a2012: 8b d7                        	mov	edx, edi
  5a2014: e8 47 db e8 ff               	call	0x42fb60 <.text+0x2eb60>
  5a2019: 6a ff                        	push	-0x1
  5a201b: 6a 00                        	push	0x0
  5a201d: 50                           	push	eax
  5a201e: 8b cf                        	mov	ecx, edi
  5a2020: c6 84 24 8c 01 00 00 06      	mov	byte ptr [esp + 0x18c], 0x6
  5a2028: e8 f3 1d e6 ff               	call	0x403e20 <.text+0x2e20>
  5a202d: c6 84 24 80 01 00 00 03      	mov	byte ptr [esp + 0x180], 0x3
  5a2035: 83 7c 24 48 10               	cmp	dword ptr [esp + 0x48], 0x10
  5a203a: 0f 82 20 0c 00 00            	jb	0x5a2c60 <.text+0x1a1c60>
  5a2040: 8b 44 24 34                  	mov	eax, dword ptr [esp + 0x34]
  5a2044: 50                           	push	eax
  5a2045: e8 50 a1 07 00               	call	0x61c19a <.text+0x21b19a>
  5a204a: 83 c4 04                     	add	esp, 0x4
  5a204d: e9 0e 0c 00 00               	jmp	0x5a2c60 <.text+0x1a1c60>
  5a2052: 83 f8 04                     	cmp	eax, 0x4
  5a2055: 0f 85 af 00 00 00            	jne	0x5a210a <.text+0x1a110a>
  5a205b: 83 79 6c 00                  	cmp	dword ptr [ecx + 0x6c], 0x0
  5a205f: 8b 7c 24 20                  	mov	edi, dword ptr [esp + 0x20]
  5a2063: 75 11                        	jne	0x5a2076 <.text+0x1a1076>
  5a2065: 52                           	push	edx
  5a2066: e8 1c e8 07 00               	call	0x620887 <.text+0x21f887>
  5a206b: 8b 54 24 28                  	mov	edx, dword ptr [esp + 0x28]
  5a206f: 83 c4 04                     	add	esp, 0x4
  5a2072: 85 c0                        	test	eax, eax
  5a2074: 74 04                        	je	0x5a207a <.text+0x1a107a>
  5a2076: 8b 7c 24 28                  	mov	edi, dword ptr [esp + 0x28]
  5a207a: 52                           	push	edx
  5a207b: 6a 01                        	push	0x1
  5a207d: 8b cf                        	mov	ecx, edi
  5a207f: e8 9c fc e9 ff               	call	0x441d20 <.text+0x40d20>
  5a2084: 66 83 7c 24 24 3e            	cmp	word ptr [esp + 0x24], 0x3e
  5a208a: 8b 77 14                     	mov	esi, dword ptr [edi + 0x14]
  5a208d: 0f 85 cd fe ff ff            	jne	0x5a1f60 <.text+0x1a0f60>
  5a2093: 83 fe 02                     	cmp	esi, 0x2
  5a2096: 0f 8c c4 fe ff ff            	jl	0x5a1f60 <.text+0x1a0f60>
  5a209c: 8d 5e fe                     	lea	ebx, [esi - 0x2]
  5a209f: 3b de                        	cmp	ebx, esi
  5a20a1: 76 05                        	jbe	0x5a20a8 <.text+0x1a10a8>
  5a20a3: e8 97 a5 07 00               	call	0x61c63f <.text+0x21b63f>
  5a20a8: 83 7f 18 10                  	cmp	dword ptr [edi + 0x18], 0x10
  5a20ac: 72 05                        	jb	0x5a20b3 <.text+0x1a10b3>
  5a20ae: 8b 47 04                     	mov	eax, dword ptr [edi + 0x4]
  5a20b1: eb 03                        	jmp	0x5a20b6 <.text+0x1a10b6>
  5a20b3: 8d 47 04                     	lea	eax, [edi + 0x4]
  5a20b6: 80 3c 03 3f                  	cmp	byte ptr [ebx + eax], 0x3f
  5a20ba: 0f 85 a0 fe ff ff            	jne	0x5a1f60 <.text+0x1a0f60>
  5a20c0: 83 c6 fe                     	add	esi, -0x2
  5a20c3: 56                           	push	esi
  5a20c4: 33 c9                        	xor	ecx, ecx
  5a20c6: 8d 74 24 34                  	lea	esi, [esp + 0x34]
  5a20ca: 8b d7                        	mov	edx, edi
  5a20cc: e8 8f da e8 ff               	call	0x42fb60 <.text+0x2eb60>
  5a20d1: 6a ff                        	push	-0x1
  5a20d3: 6a 00                        	push	0x0
  5a20d5: 50                           	push	eax
  5a20d6: 8b cf                        	mov	ecx, edi
  5a20d8: c6 84 24 8c 01 00 00 07      	mov	byte ptr [esp + 0x18c], 0x7
  5a20e0: e8 3b 1d e6 ff               	call	0x403e20 <.text+0x2e20>
  5a20e5: c6 84 24 80 01 00 00 03      	mov	byte ptr [esp + 0x180], 0x3
  5a20ed: 83 7c 24 48 10               	cmp	dword ptr [esp + 0x48], 0x10
  5a20f2: 0f 82 68 0b 00 00            	jb	0x5a2c60 <.text+0x1a1c60>
  5a20f8: 8b 4c 24 34                  	mov	ecx, dword ptr [esp + 0x34]
  5a20fc: 51                           	push	ecx
  5a20fd: e8 98 a0 07 00               	call	0x61c19a <.text+0x21b19a>
  5a2102: 83 c4 04                     	add	esp, 0x4
  5a2105: e9 56 0b 00 00               	jmp	0x5a2c60 <.text+0x1a1c60>
  5a210a: 66 83 fa 22                  	cmp	dx, 0x22
  5a210e: 75 6d                        	jne	0x5a217d <.text+0x1a117d>
  5a2110: 80 7c 24 1f 00               	cmp	byte ptr [esp + 0x1f], 0x0
  5a2115: 0f 94 c1                     	sete	cl
  5a2118: 85 c0                        	test	eax, eax
  5a211a: 88 4c 24 1f                  	mov	byte ptr [esp + 0x1f], cl
  5a211e: 74 05                        	je	0x5a2125 <.text+0x1a1125>
  5a2120: 83 f8 03                     	cmp	eax, 0x3
  5a2123: 75 02                        	jne	0x5a2127 <.text+0x1a1127>
  5a2125: b3 01                        	mov	bl, 0x1
  5a2127: 84 c9                        	test	cl, cl
  5a2129: 75 05                        	jne	0x5a2130 <.text+0x1a1130>
  5a212b: c6 44 24 10 01               	mov	byte ptr [esp + 0x10], 0x1
  5a2130: 84 db                        	test	bl, bl
  5a2132: 0f 84 28 fe ff ff            	je	0x5a1f60 <.text+0x1a0f60>
  5a2138: 8b 74 24 20                  	mov	esi, dword ptr [esp + 0x20]
  5a213c: 8b 4c 24 18                  	mov	ecx, dword ptr [esp + 0x18]
  5a2140: 8b 01                        	mov	eax, dword ptr [ecx]
  5a2142: 85 c0                        	test	eax, eax
  5a2144: 0f 85 68 01 00 00            	jne	0x5a22b2 <.text+0x1a12b2>
  5a214a: c7 01 03 00 00 00            	mov	dword ptr [ecx], 0x3
  5a2150: 80 7c 24 16 00               	cmp	byte ptr [esp + 0x16], 0x0
  5a2155: 74 17                        	je	0x5a216e <.text+0x1a116e>
  5a2157: 6a 01                        	push	0x1
  5a2159: 68 cc 68 65 00               	push	0x6568cc
  5a215e: 8b ce                        	mov	ecx, esi
  5a2160: e8 7b c2 e7 ff               	call	0x41e3e0 <.text+0x1d3e0>
  5a2165: 8b 54 24 24                  	mov	edx, dword ptr [esp + 0x24]
  5a2169: c6 44 24 16 00               	mov	byte ptr [esp + 0x16], 0x0
  5a216e: 52                           	push	edx
  5a216f: 6a 01                        	push	0x1
  5a2171: 8b ce                        	mov	ecx, esi
  5a2173: e8 a8 fb e9 ff               	call	0x441d20 <.text+0x40d20>
  5a2178: e9 e3 fd ff ff               	jmp	0x5a1f60 <.text+0x1a0f60>
  5a217d: 80 7c 24 1f 00               	cmp	byte ptr [esp + 0x1f], 0x0
  5a2182: 75 b4                        	jne	0x5a2138 <.text+0x1a1138>
  5a2184: 66 83 fa 3c                  	cmp	dx, 0x3c
  5a2188: 75 1c                        	jne	0x5a21a6 <.text+0x1a11a6>
  5a218a: 83 f8 03                     	cmp	eax, 0x3
  5a218d: 0f 84 ba 03 00 00            	je	0x5a254d <.text+0x1a154d>
  5a2193: 85 c0                        	test	eax, eax
  5a2195: 0f 85 b1 0f 00 00            	jne	0x5a314c <.text+0x1a214c>
  5a219b: c7 01 01 00 00 00            	mov	dword ptr [ecx], 0x1
  5a21a1: e9 ba fd ff ff               	jmp	0x5a1f60 <.text+0x1a0f60>
  5a21a6: 66 83 fa 3e                  	cmp	dx, 0x3e
  5a21aa: 0f 84 b0 03 00 00            	je	0x5a2560 <.text+0x1a1560>
  5a21b0: 66 83 fa 2f                  	cmp	dx, 0x2f
  5a21b4: 8b 74 24 20                  	mov	esi, dword ptr [esp + 0x20]
  5a21b8: 75 30                        	jne	0x5a21ea <.text+0x1a11ea>
  5a21ba: 83 f8 01                     	cmp	eax, 0x1
  5a21bd: 75 65                        	jne	0x5a2224 <.text+0x1a1224>
  5a21bf: 8b 56 14                     	mov	edx, dword ptr [esi + 0x14]
  5a21c2: 6a 00                        	push	0x0
  5a21c4: 68 0c 54 65 00               	push	0x65540c
  5a21c9: 52                           	push	edx
  5a21ca: 6a 00                        	push	0x0
  5a21cc: 8b ce                        	mov	ecx, esi
  5a21ce: e8 cd 43 eb ff               	call	0x4565a0 <.text+0x555a0>
  5a21d3: 85 c0                        	test	eax, eax
  5a21d5: 75 0f                        	jne	0x5a21e6 <.text+0x1a11e6>
  5a21d7: 8b 44 24 18                  	mov	eax, dword ptr [esp + 0x18]
  5a21db: c7 00 02 00 00 00            	mov	dword ptr [eax], 0x2
  5a21e1: e9 7a fd ff ff               	jmp	0x5a1f60 <.text+0x1a0f60>
  5a21e6: 8b 54 24 24                  	mov	edx, dword ptr [esp + 0x24]
  5a21ea: 66 83 fa 3f                  	cmp	dx, 0x3f
  5a21ee: 75 34                        	jne	0x5a2224 <.text+0x1a1224>
  5a21f0: 8b 4c 24 18                  	mov	ecx, dword ptr [esp + 0x18]
  5a21f4: 83 39 01                     	cmp	dword ptr [ecx], 0x1
  5a21f7: 75 2b                        	jne	0x5a2224 <.text+0x1a1224>
  5a21f9: 8b 56 14                     	mov	edx, dword ptr [esi + 0x14]
  5a21fc: 6a 00                        	push	0x0
  5a21fe: 68 0c 54 65 00               	push	0x65540c
  5a2203: 52                           	push	edx
  5a2204: 6a 00                        	push	0x0
  5a2206: 8b ce                        	mov	ecx, esi
  5a2208: e8 93 43 eb ff               	call	0x4565a0 <.text+0x555a0>
  5a220d: 85 c0                        	test	eax, eax
  5a220f: 75 0f                        	jne	0x5a2220 <.text+0x1a1220>
  5a2211: 8b 44 24 18                  	mov	eax, dword ptr [esp + 0x18]
  5a2215: c7 00 04 00 00 00            	mov	dword ptr [eax], 0x4
  5a221b: e9 40 fd ff ff               	jmp	0x5a1f60 <.text+0x1a0f60>


pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  4565c0: 02 8b f0 8b 5c 24            	add	cl, byte ptr [ebx + 0x245c8bf0]
  4565c6: 20 3b                        	and	byte ptr [ebx], bh
  4565c8: f3 8b c6                     	rep		mov	eax, esi
  4565cb: 72 02                        	jb	0x4565cf <.text+0x555cf>
  4565cd: 8b c3                        	mov	eax, ebx
  4565cf: 83 7f 18 10                  	cmp	dword ptr [edi + 0x18], 0x10
  4565d3: 72 05                        	jb	0x4565da <.text+0x555da>
  4565d5: 8b 7f 04                     	mov	edi, dword ptr [edi + 0x4]
  4565d8: eb 03                        	jmp	0x4565dd <.text+0x555dd>
  4565da: 83 c7 04                     	add	edi, 0x4
  4565dd: 50                           	push	eax
  4565de: 8b 44 24 20                  	mov	eax, dword ptr [esp + 0x20]
  4565e2: 50                           	push	eax
  4565e3: 03 fd                        	add	edi, ebp
  4565e5: 57                           	push	edi
  4565e6: e8 75 b4 fe ff               	call	0x441a60 <.text+0x40a60>
  4565eb: 83 c4 0c                     	add	esp, 0xc
  4565ee: 85 c0                        	test	eax, eax
  4565f0: 75 15                        	jne	0x456607 <.text+0x55607>
  4565f2: 3b f3                        	cmp	esi, ebx
  4565f4: 73 0a                        	jae	0x456600 <.text+0x55600>
  4565f6: 5f                           	pop	edi
  4565f7: 5e                           	pop	esi
  4565f8: 5d                           	pop	ebp
  4565f9: 83 c8 ff                     	or	eax, -0x1
  4565fc: 5b                           	pop	ebx
  4565fd: c2 10 00                     	ret	0x10
  456600: 33 c0                        	xor	eax, eax
  456602: 3b f3                        	cmp	esi, ebx
  456604: 0f 95 c0                     	setne	al
  456607: 5f                           	pop	edi
  456608: 5e                           	pop	esi
  456609: 5d                           	pop	ebp
  45660a: 5b                           	pop	ebx
  45660b: c2 10 00                     	ret	0x10
  45660e: cc                           	int3
  45660f: cc                           	int3
  456610: 53                           	push	ebx
  456611: 8b 5c 24 08                  	mov	ebx, dword ptr [esp + 0x8]
  456615: 56                           	push	esi
  456616: 8b 74 24 10                  	mov	esi, dword ptr [esp + 0x10]
  45661a: 85 f6                        	test	esi, esi
  45661c: 57                           	push	edi
  45661d: 8b f9                        	mov	edi, ecx
  45661f: c7 07 00 00 00 00            	mov	dword ptr [edi], 0x0
  456625: 74 29                        	je	0x456650 <.text+0x55650>
  456627: 85 db                        	test	ebx, ebx
  456629: 74 25                        	je	0x456650 <.text+0x55650>
  45662b: 8b 56 18                     	mov	edx, dword ptr [esi + 0x18]
  45662e: 83 fa 10                     	cmp	edx, 0x10
  456631: 8d 46 04                     	lea	eax, [esi + 0x4]
  456634: 72 04                        	jb	0x45663a <.text+0x5563a>
  456636: 8b 08                        	mov	ecx, dword ptr [eax]
  456638: eb 02                        	jmp	0x45663c <.text+0x5563c>
  45663a: 8b c8                        	mov	ecx, eax
  45663c: 3b cb                        	cmp	ecx, ebx
  45663e: 77 10                        	ja	0x456650 <.text+0x55650>
  456640: 83 fa 10                     	cmp	edx, 0x10
  456643: 72 02                        	jb	0x456647 <.text+0x55647>
  456645: 8b 00                        	mov	eax, dword ptr [eax]
  456647: 8b 4e 14                     	mov	ecx, dword ptr [esi + 0x14]
  45664a: 03 c8                        	add	ecx, eax
  45664c: 3b d9                        	cmp	ebx, ecx
  45664e: 76 05                        	jbe	0x456655 <.text+0x55655>
  456650: e8 ea 5f 1c 00               	call	0x61c63f <.text+0x21b63f>
  456655: 89 37                        	mov	dword ptr [edi], esi
  456657: 89 5f 04                     	mov	dword ptr [edi + 0x4], ebx
  45665a: 8b c7                        	mov	eax, edi
  45665c: 5f                           	pop	edi
  45665d: 5e                           	pop	esi
  45665e: 5b                           	pop	ebx
  45665f: c2 08 00                     	ret	0x8
  456662: cc                           	int3
  456663: cc                           	int3
  456664: cc                           	int3
  456665: cc                           	int3
  456666: cc                           	int3
  456667: cc                           	int3
  456668: cc                           	int3
  456669: cc                           	int3
  45666a: cc                           	int3
  45666b: cc                           	int3
  45666c: cc                           	int3
  45666d: cc                           	int3
  45666e: cc                           	int3
  45666f: cc                           	int3
  456670: 83 79 18 10                  	cmp	dword ptr [ecx + 0x18], 0x10
  456674: 72 17                        	jb	0x45668d <.text+0x5568d>
  456676: 8b 41 04                     	mov	eax, dword ptr [ecx + 0x4]
  456679: 56                           	push	esi
  45667a: 8b 74 24 08                  	mov	esi, dword ptr [esp + 0x8]
  45667e: 51                           	push	ecx
  45667f: 50                           	push	eax
  456680: 8b ce                        	mov	ecx, esi
  456682: e8 89 ff ff ff               	call	0x456610 <.text+0x55610>
  456687: 8b c6                        	mov	eax, esi
  456689: 5e                           	pop	esi
  45668a: c2 04 00                     	ret	0x4
  45668d: 56                           	push	esi
  45668e: 8b 74 24 08                  	mov	esi, dword ptr [esp + 0x8]
  456692: 8d 41 04                     	lea	eax, [ecx + 0x4]
  456695: 51                           	push	ecx
  456696: 50                           	push	eax
  456697: 8b ce                        	mov	ecx, esi
  456699: e8 72 ff ff ff               	call	0x456610 <.text+0x55610>
  45669e: 8b c6                        	mov	eax, esi
  4566a0: 5e                           	pop	esi
  4566a1: c2 04 00                     	ret	0x4
  4566a4: cc                           	int3
  4566a5: cc                           	int3
  4566a6: cc                           	int3
  4566a7: cc                           	int3
  4566a8: cc                           	int3
  4566a9: cc                           	int3
  4566aa: cc                           	int3
  4566ab: cc                           	int3
  4566ac: cc                           	int3
  4566ad: cc                           	int3
  4566ae: cc                           	int3
  4566af: cc                           	int3
  4566b0: 83 79 18 10                  	cmp	dword ptr [ecx + 0x18], 0x10
  4566b4: 72 05                        	jb	0x4566bb <.text+0x556bb>
  4566b6: 8b 41 04                     	mov	eax, dword ptr [ecx + 0x4]
  4566b9: eb 03                        	jmp	0x4566be <.text+0x556be>
  4566bb: 8d 41 04                     	lea	eax, [ecx + 0x4]
  4566be: 56                           	push	esi
  4566bf: 8b 74 24 08                  	mov	esi, dword ptr [esp + 0x8]
  4566c3: 51                           	push	ecx
  4566c4: 8b 49 14                     	mov	ecx, dword ptr [ecx + 0x14]
  4566c7: 03 c8                        	add	ecx, eax
  4566c9: 51                           	push	ecx
  4566ca: 8b ce                        	mov	ecx, esi
  4566cc: e8 3f ff ff ff               	call	0x456610 <.text+0x55610>
  4566d1: 8b c6                        	mov	eax, esi
  4566d3: 5e                           	pop	esi
  4566d4: c2 04 00                     	ret	0x4
  4566d7: cc                           	int3
  4566d8: cc                           	int3
  4566d9: cc                           	int3
  4566da: cc                           	int3
  4566db: cc                           	int3
  4566dc: cc                           	int3
  4566dd: cc                           	int3
  4566de: cc                           	int3
  4566df: cc                           	int3
  4566e0: e9 eb 36 0e 00               	jmp	0x539dd0 <.text+0x138dd0>
  4566e5: cc                           	int3
  4566e6: cc                           	int3
  4566e7: cc                           	int3
  4566e8: cc                           	int3
  4566e9: cc                           	int3
  4566ea: cc                           	int3
  4566eb: cc                           	int3
  4566ec: cc                           	int3
  4566ed: cc                           	int3
  4566ee: cc                           	int3
  4566ef: cc                           	int3
  4566f0: c2 08 00                     	ret	0x8
  4566f3: cc                           	int3
  4566f4: cc                           	int3
  4566f5: cc                           	int3
  4566f6: cc                           	int3
  4566f7: cc                           	int3
  4566f8: cc                           	int3
  4566f9: cc                           	int3
  4566fa: cc                           	int3
  4566fb: cc                           	int3
  4566fc: cc                           	int3
  4566fd: cc                           	int3
  4566fe: cc                           	int3
  4566ff: cc                           	int3
  456700: 56                           	push	esi
  456701: 8b f1                        	mov	esi, ecx
  456703: e8 88 66 0e 00               	call	0x53cd90 <.text+0x13bd90>
  456708: f6 44 24 08 01               	test	byte ptr [esp + 0x8], 0x1
  45670d: 74 09                        	je	0x456718 <.text+0x55718>
  45670f: 56                           	push	esi
  456710: e8 85 5a 1c 00               	call	0x61c19a <.text+0x21b19a>
  456715: 83 c4 04                     	add	esp, 0x4
  456718: 8b c6                        	mov	eax, esi
  45671a: 5e                           	pop	esi
  45671b: c2 04 00                     	ret	0x4
  45671e: cc                           	int3
  45671f: cc                           	int3
  456720: 56                           	push	esi
  456721: 57                           	push	edi
  456722: 8b 7c 24 0c                  	mov	edi, dword ptr [esp + 0xc]
  456726: 57                           	push	edi
  456727: 8b f1                        	mov	esi, ecx
  456729: e8 d2 81 0e 00               	call	0x53e900 <.text+0x13d900>
  45672e: 83 ff 1b                     	cmp	edi, 0x1b
  456731: 5f                           	pop	edi
  456732: 75 19                        	jne	0x45674d <.text+0x5574d>
  456734: 8b 8e 24 01 00 00            	mov	ecx, dword ptr [esi + 0x124]
  45673a: 8b 01                        	mov	eax, dword ptr [ecx]
  45673c: 5e                           	pop	esi
  45673d: c7 44 24 04 1b 00 00 00      	mov	dword ptr [esp + 0x4], 0x1b
  456745: 8b 90 c0 00 00 00            	mov	edx, dword ptr [eax + 0xc0]
  45674b: ff e2                        	jmp	edx
  45674d: 5e                           	pop	esi
  45674e: c2 04 00                     	ret	0x4
  456751: cc                           	int3
  456752: cc                           	int3
  456753: cc                           	int3
  456754: cc                           	int3
  456755: cc                           	int3
  456756: cc                           	int3
  456757: cc                           	int3
  456758: cc                           	int3
  456759: cc                           	int3
  45675a: cc                           	int3
  45675b: cc                           	int3
  45675c: cc                           	int3
  45675d: cc                           	int3
  45675e: cc                           	int3
  45675f: cc                           	int3

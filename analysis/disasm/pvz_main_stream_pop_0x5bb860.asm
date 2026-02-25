
pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  5bb860: 66 8b 0c 78                  	mov	cx, word ptr [eax + 2*edi]
  5bb864: 66 89 0c 72                  	mov	word ptr [edx + 2*esi], cx
  5bb868: 83 c6 01                     	add	esi, 0x1
  5bb86b: 3b f3                        	cmp	esi, ebx
  5bb86d: 7c a1                        	jl	0x5bb810 <.text+0x1ba810>
  5bb86f: 5f                           	pop	edi
  5bb870: 5e                           	pop	esi
  5bb871: 5d                           	pop	ebp
  5bb872: 5b                           	pop	ebx
  5bb873: 59                           	pop	ecx
  5bb874: c2 04 00                     	ret	0x4
  5bb877: cc                           	int3
  5bb878: cc                           	int3
  5bb879: cc                           	int3
  5bb87a: cc                           	int3
  5bb87b: cc                           	int3
  5bb87c: cc                           	int3
  5bb87d: cc                           	int3
  5bb87e: cc                           	int3
  5bb87f: cc                           	int3
  5bb880: 53                           	push	ebx
  5bb881: 8b 5c 24 08                  	mov	ebx, dword ptr [esp + 0x8]
  5bb885: 85 db                        	test	ebx, ebx
  5bb887: 57                           	push	edi
  5bb888: 8b f9                        	mov	edi, ecx
  5bb88a: 75 08                        	jne	0x5bb894 <.text+0x1ba894>
  5bb88c: 5f                           	pop	edi
  5bb88d: 8d 43 03                     	lea	eax, [ebx + 0x3]
  5bb890: 5b                           	pop	ebx
  5bb891: c2 04 00                     	ret	0x4
  5bb894: 8b 47 0c                     	mov	eax, dword ptr [edi + 0xc]
  5bb897: 85 c0                        	test	eax, eax
  5bb899: 56                           	push	esi
  5bb89a: 8d 77 08                     	lea	esi, [edi + 0x8]
  5bb89d: 74 36                        	je	0x5bb8d5 <.text+0x1ba8d5>
  5bb89f: 8b 4e 08                     	mov	ecx, dword ptr [esi + 0x8]
  5bb8a2: 2b c8                        	sub	ecx, eax
  5bb8a4: d1 f9                        	sar	ecx
  5bb8a6: 74 2d                        	je	0x5bb8d5 <.text+0x1ba8d5>
  5bb8a8: 8b c6                        	mov	eax, esi
  5bb8aa: e8 d1 04 00 00               	call	0x5bbd80 <.text+0x1bad80>
  5bb8af: 66 8b 10                     	mov	dx, word ptr [eax]
  5bb8b2: 66 89 13                     	mov	word ptr [ebx], dx
  5bb8b5: 8b 46 04                     	mov	eax, dword ptr [esi + 0x4]
  5bb8b8: 85 c0                        	test	eax, eax
  5bb8ba: 74 11                        	je	0x5bb8cd <.text+0x1ba8cd>
  5bb8bc: 8b 4e 08                     	mov	ecx, dword ptr [esi + 0x8]
  5bb8bf: 8b d1                        	mov	edx, ecx
  5bb8c1: 2b d0                        	sub	edx, eax
  5bb8c3: d1 fa                        	sar	edx
  5bb8c5: 74 06                        	je	0x5bb8cd <.text+0x1ba8cd>
  5bb8c7: 83 c1 fe                     	add	ecx, -0x2
  5bb8ca: 89 4e 08                     	mov	dword ptr [esi + 0x8], ecx
  5bb8cd: 5e                           	pop	esi
  5bb8ce: 5f                           	pop	edi
  5bb8cf: 33 c0                        	xor	eax, eax
  5bb8d1: 5b                           	pop	ebx
  5bb8d2: c2 04 00                     	ret	0x4
  5bb8d5: 8b 77 04                     	mov	esi, dword ptr [edi + 0x4]
  5bb8d8: 85 f6                        	test	esi, esi
  5bb8da: 74 2f                        	je	0x5bb90b <.text+0x1ba90b>
  5bb8dc: e8 8f 5f fe ff               	call	0x5a1870 <.text+0x1a0870>
  5bb8e1: 85 c0                        	test	eax, eax
  5bb8e3: 75 26                        	jne	0x5bb90b <.text+0x1ba90b>
  5bb8e5: 8b 57 18                     	mov	edx, dword ptr [edi + 0x18]
  5bb8e8: 88 44 24 10                  	mov	byte ptr [esp + 0x10], al
  5bb8ec: 8d 44 24 10                  	lea	eax, [esp + 0x10]
  5bb8f0: 50                           	push	eax
  5bb8f1: 53                           	push	ebx
  5bb8f2: 8b cf                        	mov	ecx, edi
  5bb8f4: ff d2                        	call	edx
  5bb8f6: 84 c0                        	test	al, al
  5bb8f8: 75 d3                        	jne	0x5bb8cd <.text+0x1ba8cd>
  5bb8fa: 8a 44 24 10                  	mov	al, byte ptr [esp + 0x10]
  5bb8fe: f6 d8                        	neg	al
  5bb900: 5e                           	pop	esi
  5bb901: 5f                           	pop	edi
  5bb902: 5b                           	pop	ebx
  5bb903: 1b c0                        	sbb	eax, eax
  5bb905: 83 c0 02                     	add	eax, 0x2
  5bb908: c2 04 00                     	ret	0x4
  5bb90b: 5e                           	pop	esi
  5bb90c: 5f                           	pop	edi
  5bb90d: b8 02 00 00 00               	mov	eax, 0x2
  5bb912: 5b                           	pop	ebx
  5bb913: c2 04 00                     	ret	0x4
  5bb916: cc                           	int3
  5bb917: cc                           	int3
  5bb918: cc                           	int3
  5bb919: cc                           	int3
  5bb91a: cc                           	int3
  5bb91b: cc                           	int3
  5bb91c: cc                           	int3
  5bb91d: cc                           	int3
  5bb91e: cc                           	int3
  5bb91f: cc                           	int3
  5bb920: 53                           	push	ebx
  5bb921: 8b 5c 24 08                  	mov	ebx, dword ptr [esp + 0x8]
  5bb925: 56                           	push	esi
  5bb926: 8d 71 08                     	lea	esi, [ecx + 0x8]
  5bb929: e8 a2 04 00 00               	call	0x5bbdd0 <.text+0x1badd0>
  5bb92e: 5e                           	pop	esi
  5bb92f: b0 01                        	mov	al, 0x1
  5bb931: 5b                           	pop	ebx
  5bb932: c2 04 00                     	ret	0x4
  5bb935: cc                           	int3
  5bb936: cc                           	int3
  5bb937: cc                           	int3
  5bb938: cc                           	int3
  5bb939: cc                           	int3
  5bb93a: cc                           	int3
  5bb93b: cc                           	int3
  5bb93c: cc                           	int3
  5bb93d: cc                           	int3
  5bb93e: cc                           	int3
  5bb93f: cc                           	int3
  5bb940: 55                           	push	ebp
  5bb941: 8b ec                        	mov	ebp, esp
  5bb943: 83 e4 f8                     	and	esp, -0x8
  5bb946: 8b 41 0c                     	mov	eax, dword ptr [ecx + 0xc]
  5bb949: 83 ec 1c                     	sub	esp, 0x1c
  5bb94c: 85 c0                        	test	eax, eax
  5bb94e: 53                           	push	ebx
  5bb94f: 56                           	push	esi
  5bb950: 8d 71 08                     	lea	esi, [ecx + 0x8]
  5bb953: 57                           	push	edi
  5bb954: 75 04                        	jne	0x5bb95a <.text+0x1ba95a>
  5bb956: 33 db                        	xor	ebx, ebx
  5bb958: eb 07                        	jmp	0x5bb961 <.text+0x1ba961>
  5bb95a: 8b 5e 08                     	mov	ebx, dword ptr [esi + 0x8]
  5bb95d: 2b d8                        	sub	ebx, eax
  5bb95f: d1 fb                        	sar	ebx

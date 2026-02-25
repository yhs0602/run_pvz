
pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  621540: ce                           	into
  621541: 5f                           	pop	edi
  621542: 33 c0                        	xor	eax, eax
  621544: 5e                           	pop	esi
  621545: c3                           	ret
  621546: e8 7a e9 ff ff               	call	0x61fec5 <.text+0x21eec5>
  62154b: 80 3d b8 66 6a 00 00         	cmp	byte ptr [0x6a66b8], 0x0
  621552: 74 05                        	je	0x621559 <.text+0x220559>
  621554: e8 eb ee 00 00               	call	0x630444 <.text+0x22f444>
  621559: ff 35 ec cb 75 00            	push	dword ptr [0x75cbec]
  62155f: e8 02 e7 ff ff               	call	0x61fc66 <.text+0x21ec66>
  621564: 59                           	pop	ecx
  621565: c3                           	ret
  621566: 56                           	push	esi
  621567: 8b 74 24 08                  	mov	esi, dword ptr [esp + 0x8]
  62156b: b8 40 9d 69 00               	mov	eax, 0x699d40
  621570: 3b f0                        	cmp	esi, eax
  621572: 72 22                        	jb	0x621596 <.text+0x220596>
  621574: 81 fe a0 9f 69 00            	cmp	esi, 0x699fa0
  62157a: 77 1a                        	ja	0x621596 <.text+0x220596>
  62157c: 8b ce                        	mov	ecx, esi
  62157e: 2b c8                        	sub	ecx, eax
  621580: c1 f9 05                     	sar	ecx, 0x5
  621583: 83 c1 10                     	add	ecx, 0x10
  621586: 51                           	push	ecx
  621587: e8 d4 b9 00 00               	call	0x62cf60 <.text+0x22bf60>
  62158c: 81 4e 0c 00 80 00 00         	or	dword ptr [esi + 0xc], 0x8000
  621593: 59                           	pop	ecx
  621594: 5e                           	pop	esi
  621595: c3                           	ret
  621596: 83 c6 20                     	add	esi, 0x20
  621599: 56                           	push	esi
  62159a: ff 15 f8 20 65 00            	call	dword ptr [0x6520f8]
  6215a0: 5e                           	pop	esi
  6215a1: c3                           	ret
  6215a2: 8b 44 24 04                  	mov	eax, dword ptr [esp + 0x4]
  6215a6: 83 f8 14                     	cmp	eax, 0x14
  6215a9: 7d 16                        	jge	0x6215c1 <.text+0x2205c1>
  6215ab: 83 c0 10                     	add	eax, 0x10
  6215ae: 50                           	push	eax
  6215af: e8 ac b9 00 00               	call	0x62cf60 <.text+0x22bf60>
  6215b4: 8b 44 24 0c                  	mov	eax, dword ptr [esp + 0xc]
  6215b8: 81 48 0c 00 80 00 00         	or	dword ptr [eax + 0xc], 0x8000
  6215bf: 59                           	pop	ecx
  6215c0: c3                           	ret
  6215c1: 8b 44 24 08                  	mov	eax, dword ptr [esp + 0x8]
  6215c5: 83 c0 20                     	add	eax, 0x20
  6215c8: 50                           	push	eax
  6215c9: ff 15 f8 20 65 00            	call	dword ptr [0x6520f8]
  6215cf: c3                           	ret
  6215d0: 8b 44 24 04                  	mov	eax, dword ptr [esp + 0x4]
  6215d4: b9 40 9d 69 00               	mov	ecx, 0x699d40
  6215d9: 3b c1                        	cmp	eax, ecx
  6215db: 72 1e                        	jb	0x6215fb <.text+0x2205fb>
  6215dd: 3d a0 9f 69 00               	cmp	eax, 0x699fa0
  6215e2: 77 17                        	ja	0x6215fb <.text+0x2205fb>
  6215e4: 81 60 0c ff 7f ff ff         	and	dword ptr [eax + 0xc], 0xffff7fff
  6215eb: 2b c1                        	sub	eax, ecx
  6215ed: c1 f8 05                     	sar	eax, 0x5
  6215f0: 83 c0 10                     	add	eax, 0x10
  6215f3: 50                           	push	eax
  6215f4: e8 8f b8 00 00               	call	0x62ce88 <.text+0x22be88>
  6215f9: 59                           	pop	ecx
  6215fa: c3                           	ret
  6215fb: 83 c0 20                     	add	eax, 0x20
  6215fe: 50                           	push	eax
  6215ff: ff 15 ec 20 65 00            	call	dword ptr [0x6520ec]
  621605: c3                           	ret
  621606: 8b 4c 24 04                  	mov	ecx, dword ptr [esp + 0x4]
  62160a: 83 f9 14                     	cmp	ecx, 0x14
  62160d: 8b 44 24 08                  	mov	eax, dword ptr [esp + 0x8]
  621611: 7d 12                        	jge	0x621625 <.text+0x220625>
  621613: 81 60 0c ff 7f ff ff         	and	dword ptr [eax + 0xc], 0xffff7fff
  62161a: 83 c1 10                     	add	ecx, 0x10
  62161d: 51                           	push	ecx
  62161e: e8 65 b8 00 00               	call	0x62ce88 <.text+0x22be88>
  621623: 59                           	pop	ecx
  621624: c3                           	ret
  621625: 83 c0 20                     	add	eax, 0x20
  621628: 50                           	push	eax
  621629: ff 15 ec 20 65 00            	call	dword ptr [0x6520ec]
  62162f: c3                           	ret
  621630: 83 3d 08 dc 75 00 00         	cmp	dword ptr [0x75dc08], 0x0
  621637: 56                           	push	esi
  621638: 8b 35 a0 66 6a 00            	mov	esi, dword ptr [0x6a66a0]
  62163e: 75 04                        	jne	0x621644 <.text+0x220644>
  621640: 33 c0                        	xor	eax, eax
  621642: 5e                           	pop	esi
  621643: c3                           	ret
  621644: 85 f6                        	test	esi, esi
  621646: 53                           	push	ebx
  621647: 57                           	push	edi
  621648: 75 1b                        	jne	0x621665 <.text+0x220665>
  62164a: 39 35 a8 66 6a 00            	cmp	dword ptr [0x6a66a8], esi
  621650: 74 51                        	je	0x6216a3 <.text+0x2206a3>
  621652: e8 8f ef 00 00               	call	0x6305e6 <.text+0x22f5e6>
  621657: 85 c0                        	test	eax, eax
  621659: 75 48                        	jne	0x6216a3 <.text+0x2206a3>
  62165b: 8b 35 a0 66 6a 00            	mov	esi, dword ptr [0x6a66a0]

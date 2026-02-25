
/Users/yanghyeonseo/Developer/pvz/pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  61e4b0: e8 a9 5b 00 00               	call	0x62405e <.text+0x22305e>
  61e4b5: 83 c4 24                     	add	esp, 0x24
  61e4b8: 85 c0                        	test	eax, eax
  61e4ba: 0f 84 6b ff ff ff            	je	0x61e42b <.text+0x21d42b>
  61e4c0: 83 f8 01                     	cmp	eax, 0x1
  61e4c3: 75 06                        	jne	0x61e4cb <.text+0x21d4cb>
  61e4c5: 0f b6 45 f8                  	movzx	eax, byte ptr [ebp - 0x8]
  61e4c9: eb 0b                        	jmp	0x61e4d6 <.text+0x21d4d6>
  61e4cb: 0f b6 4d f9                  	movzx	ecx, byte ptr [ebp - 0x7]
  61e4cf: 33 c0                        	xor	eax, eax
  61e4d1: 8a 65 f8                     	mov	ah, byte ptr [ebp - 0x8]
  61e4d4: 0b c1                        	or	eax, ecx
  61e4d6: 80 7d f4 00                  	cmp	byte ptr [ebp - 0xc], 0x0
  61e4da: 74 07                        	je	0x61e4e3 <.text+0x21d4e3>
  61e4dc: 8b 4d f0                     	mov	ecx, dword ptr [ebp - 0x10]
  61e4df: 83 61 70 fd                  	and	dword ptr [ecx + 0x70], -0x3
  61e4e3: 5b                           	pop	ebx
  61e4e4: c9                           	leave
  61e4e5: c3                           	ret
  61e4e6: 83 3d f4 66 6a 00 00         	cmp	dword ptr [0x6a66f4], 0x0
  61e4ed: 75 10                        	jne	0x61e4ff <.text+0x21d4ff>
  61e4ef: 8b 44 24 04                  	mov	eax, dword ptr [esp + 0x4]
  61e4f3: 8d 48 9f                     	lea	ecx, [eax - 0x61]
  61e4f6: 83 f9 19                     	cmp	ecx, 0x19
  61e4f9: 77 11                        	ja	0x61e50c <.text+0x21d50c>
  61e4fb: 83 c0 e0                     	add	eax, -0x20
  61e4fe: c3                           	ret
  61e4ff: 6a 00                        	push	0x0
  61e501: ff 74 24 08                  	push	dword ptr [esp + 0x8]
  61e505: e8 c4 fe ff ff               	call	0x61e3ce <.text+0x21d3ce>
  61e50a: 59                           	pop	ecx
  61e50b: 59                           	pop	ecx
  61e50c: c3                           	ret
  61e50d: cc                           	int3
  61e50e: cc                           	int3
  61e50f: cc                           	int3
  61e510: 8b 4c 24 08                  	mov	ecx, dword ptr [esp + 0x8]
  61e514: 57                           	push	edi
  61e515: 53                           	push	ebx
  61e516: 56                           	push	esi
  61e517: 8a 11                        	mov	dl, byte ptr [ecx]
  61e519: 8b 7c 24 10                  	mov	edi, dword ptr [esp + 0x10]
  61e51d: 84 d2                        	test	dl, dl
  61e51f: 74 6f                        	je	0x61e590 <.text+0x21d590>

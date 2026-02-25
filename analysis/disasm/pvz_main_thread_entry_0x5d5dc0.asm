
/Users/yanghyeonseo/Developer/pvz/pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  5d5d80: 8b 4e 30                     	mov	ecx, dword ptr [esi + 0x30]
  5d5d83: 50                           	push	eax
  5d5d84: 51                           	push	ecx
  5d5d85: 68 ff ff 00 00               	push	0xffff
  5d5d8a: ff 15 0c 23 65 00            	call	dword ptr [0x65230c]
  5d5d90: 8b 56 14                     	mov	edx, dword ptr [esi + 0x14]
  5d5d93: 6a 64                        	push	0x64
  5d5d95: 52                           	push	edx
  5d5d96: ff 15 d4 20 65 00            	call	dword ptr [0x6520d4]
  5d5d9c: 8b 46 14                     	mov	eax, dword ptr [esi + 0x14]
  5d5d9f: 50                           	push	eax
  5d5da0: ff 15 b8 20 65 00            	call	dword ptr [0x6520b8]
  5d5da6: c7 46 14 00 00 00 00         	mov	dword ptr [esi + 0x14], 0x0
  5d5dad: 8a 46 10                     	mov	al, byte ptr [esi + 0x10]
  5d5db0: c3                           	ret
  5d5db1: cc                           	int3
  5d5db2: cc                           	int3
  5d5db3: cc                           	int3
  5d5db4: cc                           	int3
  5d5db5: cc                           	int3
  5d5db6: cc                           	int3
  5d5db7: cc                           	int3
  5d5db8: cc                           	int3
  5d5db9: cc                           	int3
  5d5dba: cc                           	int3
  5d5dbb: cc                           	int3
  5d5dbc: cc                           	int3
  5d5dbd: cc                           	int3
  5d5dbe: cc                           	int3
  5d5dbf: cc                           	int3
  5d5dc0: 55                           	push	ebp
  5d5dc1: 8b ec                        	mov	ebp, esp
  5d5dc3: 83 e4 f8                     	and	esp, -0x8
  5d5dc6: 83 ec 44                     	sub	esp, 0x44
  5d5dc9: 33 c0                        	xor	eax, eax
  5d5dcb: 53                           	push	ebx
  5d5dcc: 56                           	push	esi
  5d5dcd: 8b 35 70 20 65 00            	mov	esi, dword ptr [0x652070]
  5d5dd3: 57                           	push	edi
  5d5dd4: 89 44 24 2c                  	mov	dword ptr [esp + 0x2c], eax
  5d5dd8: 89 44 24 4c                  	mov	dword ptr [esp + 0x4c], eax
  5d5ddc: 50                           	push	eax
  5d5ddd: c7 44 24 2c 00 00 00 00      	mov	dword ptr [esp + 0x2c], 0x0
  5d5de5: 89 44 24 34                  	mov	dword ptr [esp + 0x34], eax
  5d5de9: 89 44 24 38                  	mov	dword ptr [esp + 0x38], eax
  5d5ded: 89 44 24 3c                  	mov	dword ptr [esp + 0x3c], eax
  5d5df1: 89 44 24 40                  	mov	dword ptr [esp + 0x40], eax
  5d5df5: 89 44 24 44                  	mov	dword ptr [esp + 0x44], eax
  5d5df9: 89 44 24 48                  	mov	dword ptr [esp + 0x48], eax
  5d5dfd: 89 44 24 4c                  	mov	dword ptr [esp + 0x4c], eax
  5d5e01: c7 44 24 30 c0 5e 5d 00      	mov	dword ptr [esp + 0x30], 0x5d5ec0
  5d5e09: c7 44 24 50 7c 6a 67 00      	mov	dword ptr [esp + 0x50], 0x676a7c
  5d5e11: ff d6                        	call	esi
  5d5e13: 89 44 24 38                  	mov	dword ptr [esp + 0x38], eax
  5d5e17: 8d 44 24 28                  	lea	eax, [esp + 0x28]
  5d5e1b: 50                           	push	eax
  5d5e1c: ff 15 6c 23 65 00            	call	dword ptr [0x65236c]
  5d5e22: 6a 00                        	push	0x0
  5d5e24: 6a 00                        	push	0x0
  5d5e26: ff d6                        	call	esi
  5d5e28: 50                           	push	eax
  5d5e29: 6a 00                        	push	0x0
  5d5e2b: 6a 00                        	push	0x0
  5d5e2d: 6a 00                        	push	0x0
  5d5e2f: 6a 00                        	push	0x0
  5d5e31: 6a 00                        	push	0x0
  5d5e33: 6a 00                        	push	0x0
  5d5e35: 6a 00                        	push	0x0
  5d5e37: 6a 00                        	push	0x0
  5d5e39: 68 7c 6a 67 00               	push	0x676a7c
  5d5e3e: 6a 00                        	push	0x0
  5d5e40: ff 15 34 23 65 00            	call	dword ptr [0x652334]
  5d5e46: 8b 7d 08                     	mov	edi, dword ptr [ebp + 0x8]
  5d5e49: 50                           	push	eax
  5d5e4a: 89 07                        	mov	dword ptr [edi], eax
  5d5e4c: ff 15 b0 23 65 00            	call	dword ptr [0x6523b0]
  5d5e52: 85 c0                        	test	eax, eax
  5d5e54: 74 49                        	je	0x5d5e9f <.text+0x1d4e9f>
  5d5e56: 8b 0f                        	mov	ecx, dword ptr [edi]
  5d5e58: 57                           	push	edi
  5d5e59: 6a eb                        	push	-0x15
  5d5e5b: 51                           	push	ecx
  5d5e5c: ff 15 5c 23 65 00            	call	dword ptr [0x65235c]
  5d5e62: 8b 57 14                     	mov	edx, dword ptr [edi + 0x14]
  5d5e65: 52                           	push	edx
  5d5e66: ff 15 58 21 65 00            	call	dword ptr [0x652158]
  5d5e6c: 8b 1d 98 23 65 00            	mov	ebx, dword ptr [0x652398]
  5d5e72: 6a 00                        	push	0x0
  5d5e74: 6a 00                        	push	0x0
  5d5e76: 6a 00                        	push	0x0
  5d5e78: 8d 44 24 18                  	lea	eax, [esp + 0x18]
  5d5e7c: 50                           	push	eax
  5d5e7d: ff d3                        	call	ebx
  5d5e7f: 8b f0                        	mov	esi, eax
  5d5e81: 85 f6                        	test	esi, esi
  5d5e83: 7e 18                        	jle	0x5d5e9d <.text+0x1d4e9d>
  5d5e85: 8d 4c 24 0c                  	lea	ecx, [esp + 0xc]
  5d5e89: 51                           	push	ecx
  5d5e8a: ff 15 a4 22 65 00            	call	dword ptr [0x6522a4]
  5d5e90: 8d 54 24 0c                  	lea	edx, [esp + 0xc]
  5d5e94: 52                           	push	edx
  5d5e95: ff 15 d0 22 65 00            	call	dword ptr [0x6522d0]
  5d5e9b: 85 f6                        	test	esi, esi
  5d5e9d: 75 d3                        	jne	0x5d5e72 <.text+0x1d4e72>
  5d5e9f: 8b 07                        	mov	eax, dword ptr [edi]
  5d5ea1: 50                           	push	eax
  5d5ea2: ff 15 b0 23 65 00            	call	dword ptr [0x6523b0]
  5d5ea8: 85 c0                        	test	eax, eax
  5d5eaa: 74 09                        	je	0x5d5eb5 <.text+0x1d4eb5>
  5d5eac: 8b 0f                        	mov	ecx, dword ptr [edi]
  5d5eae: 51                           	push	ecx
  5d5eaf: ff 15 18 23 65 00            	call	dword ptr [0x652318]
  5d5eb5: 5f                           	pop	edi
  5d5eb6: 5e                           	pop	esi
  5d5eb7: 5b                           	pop	ebx
  5d5eb8: 8b e5                        	mov	esp, ebp
  5d5eba: 5d                           	pop	ebp
  5d5ebb: c3                           	ret
  5d5ebc: cc                           	int3
  5d5ebd: cc                           	int3
  5d5ebe: cc                           	int3
  5d5ebf: cc                           	int3
  5d5ec0: 53                           	push	ebx
  5d5ec1: 55                           	push	ebp
  5d5ec2: 56                           	push	esi
  5d5ec3: 57                           	push	edi
  5d5ec4: 8b 7c 24 14                  	mov	edi, dword ptr [esp + 0x14]
  5d5ec8: 6a eb                        	push	-0x15
  5d5eca: 57                           	push	edi
  5d5ecb: ff 15 e4 22 65 00            	call	dword ptr [0x6522e4]
  5d5ed1: 8b 5c 24 20                  	mov	ebx, dword ptr [esp + 0x20]
  5d5ed5: 8b 6c 24 18                  	mov	ebp, dword ptr [esp + 0x18]
  5d5ed9: 8b f0                        	mov	esi, eax
  5d5edb: 85 f6                        	test	esi, esi
  5d5edd: 74 26                        	je	0x5d5f05 <.text+0x1d4f05>
  5d5edf: 3b 6e 34                     	cmp	ebp, dword ptr [esi + 0x34]
  5d5ee2: 75 21                        	jne	0x5d5f05 <.text+0x1d4f05>
  5d5ee4: ff 15 80 20 65 00            	call	dword ptr [0x652080]
  5d5eea: 39 44 24 1c                  	cmp	dword ptr [esp + 0x1c], eax
  5d5eee: 75 15                        	jne	0x5d5f05 <.text+0x1d4f05>
  5d5ef0: 89 5e 04                     	mov	dword ptr [esi + 0x4], ebx
  5d5ef3: c6 46 10 01                  	mov	byte ptr [esi + 0x10], 0x1
  5d5ef7: 8b 76 14                     	mov	esi, dword ptr [esi + 0x14]
  5d5efa: 85 f6                        	test	esi, esi
  5d5efc: 74 07                        	je	0x5d5f05 <.text+0x1d4f05>
  5d5efe: 56                           	push	esi
  5d5eff: ff 15 58 21 65 00            	call	dword ptr [0x652158]
  5d5f05: 8b 44 24 1c                  	mov	eax, dword ptr [esp + 0x1c]
  5d5f09: 53                           	push	ebx
  5d5f0a: 50                           	push	eax
  5d5f0b: 55                           	push	ebp
  5d5f0c: 57                           	push	edi
  5d5f0d: ff 15 b0 22 65 00            	call	dword ptr [0x6522b0]
  5d5f13: 5f                           	pop	edi
  5d5f14: 5e                           	pop	esi
  5d5f15: 5d                           	pop	ebp
  5d5f16: 5b                           	pop	ebx
  5d5f17: c2 10 00                     	ret	0x10
  5d5f1a: cc                           	int3
  5d5f1b: cc                           	int3
  5d5f1c: cc                           	int3
  5d5f1d: cc                           	int3
  5d5f1e: cc                           	int3
  5d5f1f: cc                           	int3
  5d5f20: 83 ec 1c                     	sub	esp, 0x1c
  5d5f23: 83 7c 24 24 00               	cmp	dword ptr [esp + 0x24], 0x0
  5d5f28: 75 06                        	jne	0x5d5f30 <.text+0x1d4f30>
  5d5f2a: 33 c0                        	xor	eax, eax
  5d5f2c: 83 c4 1c                     	add	esp, 0x1c
  5d5f2f: c3                           	ret
  5d5f30: 8b 44 24 20                  	mov	eax, dword ptr [esp + 0x20]
  5d5f34: 53                           	push	ebx
  5d5f35: 55                           	push	ebp
  5d5f36: 56                           	push	esi
  5d5f37: 8b 30                        	mov	esi, dword ptr [eax]
  5d5f39: 0f b6 16                     	movzx	edx, byte ptr [esi]
  5d5f3c: 83 c6 01                     	add	esi, 0x1
  5d5f3f: 84 d2                        	test	dl, dl
  5d5f41: 57                           	push	edi
  5d5f42: 0f 89 df 00 00 00            	jns	0x5d6027 <.text+0x1d5027>
  5d5f48: 8b ca                        	mov	ecx, edx
  5d5f4a: 81 e1 c0 00 00 00            	and	ecx, 0xc0
  5d5f50: 80 f9 c0                     	cmp	cl, -0x40
  5d5f53: 0f 85 b8 00 00 00            	jne	0x5d6011 <.text+0x1d5011>
  5d5f59: 8b da                        	mov	ebx, edx
  5d5f5b: 89 5c 24 14                  	mov	dword ptr [esp + 0x14], ebx
  5d5f5f: 8d 7c 24 18                  	lea	edi, [esp + 0x18]
  5d5f63: 33 c9                        	xor	ecx, ecx
  5d5f65: eb 09                        	jmp	0x5d5f70 <.text+0x1d4f70>
  5d5f67: 8d a4 24 00 00 00 00         	lea	esp, [esp]
  5d5f6e: 8b ff                        	mov	edi, edi
  5d5f70: 0f b7 04 4d 8c 6a 67 00      	movzx	eax, word ptr [2*ecx + 0x676a8c]
  5d5f78: 8d 2c 00                     	lea	ebp, [eax + eax]
  5d5f7b: 23 e8                        	and	ebp, eax
  5d5f7d: 23 c2                        	and	eax, edx
  5d5f7f: 3b c5                        	cmp	eax, ebp


pvz/main.exe:	file format coff-i386

Disassembly of section .text:

00401000 <.text>:
  5a1860: 15 df 07 00 83               	adc	eax, 0x830007df
  5a1865: c4 08                        	les	ecx, [eax]
  5a1867: c3                           	ret
  5a1868: cc                           	int3
  5a1869: cc                           	int3
  5a186a: cc                           	int3
  5a186b: cc                           	int3
  5a186c: cc                           	int3
  5a186d: cc                           	int3
  5a186e: cc                           	int3
  5a186f: cc                           	int3
  5a1870: e8 cb fd ff ff               	call	0x5a1640 <.text+0x1a0640>
  5a1875: 85 c0                        	test	eax, eax
  5a1877: 74 10                        	je	0x5a1889 <.text+0x1a0889>
  5a1879: a1 74 9f 6a 00               	mov	eax, dword ptr [0x6a9f74]
  5a187e: 8b 08                        	mov	ecx, dword ptr [eax]
  5a1880: 8b 11                        	mov	edx, dword ptr [ecx]
  5a1882: 8b 42 28                     	mov	eax, dword ptr [edx + 0x28]
  5a1885: 56                           	push	esi
  5a1886: ff d0                        	call	eax
  5a1888: c3                           	ret
  5a1889: 8b 4e 08                     	mov	ecx, dword ptr [esi + 0x8]
  5a188c: 51                           	push	ecx
  5a188d: e8 8f ec 07 00               	call	0x620521 <.text+0x21f521>
  5a1892: 83 c4 04                     	add	esp, 0x4
  5a1895: c3                           	ret
  5a1896: cc                           	int3
  5a1897: cc                           	int3
  5a1898: cc                           	int3
  5a1899: cc                           	int3
  5a189a: cc                           	int3
  5a189b: cc                           	int3
  5a189c: cc                           	int3
  5a189d: cc                           	int3
  5a189e: cc                           	int3
  5a189f: cc                           	int3
  5a18a0: 51                           	push	ecx
  5a18a1: e8 aa 97 01 00               	call	0x5bb050 <.text+0x1ba050>
  5a18a6: 33 c9                        	xor	ecx, ecx
  5a18a8: c7 00 d8 52 67 00            	mov	dword ptr [eax], 0x6752d8
  5a18ae: 89 48 34                     	mov	dword ptr [eax + 0x34], ecx

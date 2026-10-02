	.file	"rdcwtest.c"
	.text
	.def	sprintf_s;	.scl	3;	.type	32;	.endef
	.seh_proc	sprintf_s
sprintf_s:
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$64, %rsp
	.seh_stackalloc	64
	.seh_endprologue
	movq	%rcx, 80(%rsp)
	movq	%rdx, 88(%rsp)
	movq	%r8, 96(%rsp)
	movq	%r9, 104(%rsp)
	leaq	104(%rsp), %rbx
	movq	%rbx, 56(%rsp)
	call	__local_stdio_printf_options
	movq	(%rax), %rcx
	movq	%rbx, 40(%rsp)
	movq	$0, 32(%rsp)
	movq	96(%rsp), %r9
	movq	88(%rsp), %r8
	movq	80(%rsp), %rdx
	call	__stdio_common_vsprintf_s
	addq	$64, %rsp
	popq	%rbx
	ret
	.seh_endproc
	.section .rdata,"dr"
.LC1:
	.ascii "rdcw-c-test\0"
.LC2:
	.ascii "  %-30s CreateFile err=%lu\12\0"
.LC5:
	.ascii "%s\\w%lu.txt\0"
.LC6:
	.ascii "    call#%lu ok=%d ret=%lu%s\12\0"
.LC7:
	.ascii "   <-- \346\227\240\346\225\260\346\215\256\0"
.LC8:
	.ascii "      (0 bytes)\0"
.LC9:
	.ascii "      action=%lu name=%.*ls\12\0"
	.align 8
.LC10:
	.ascii "  %-30s \346\234\211\346\225\260\346\215\256=%lu \346\227\240\346\225\260\346\215\256=%lu \347\253\213\345\215\263\350\277\224\345\233\236=%lu\12\0"
.LC11:
	.ascii "\0"
	.text
	.def	run_case;	.scl	3;	.type	32;	.endef
	.seh_proc	run_case
run_case:
	pushq	%r15
	.seh_pushreg	%r15
	pushq	%r14
	.seh_pushreg	%r14
	pushq	%r13
	.seh_pushreg	%r13
	pushq	%r12
	.seh_pushreg	%r12
	pushq	%rbp
	.seh_pushreg	%rbp
	pushq	%rdi
	.seh_pushreg	%rdi
	pushq	%rsi
	.seh_pushreg	%rsi
	pushq	%rbx
	.seh_pushreg	%rbx
	subq	$744, %rsp
	.seh_stackalloc	744
	movaps	%xmm6, 704(%rsp)
	.seh_savexmm	%xmm6, 704
	movaps	%xmm7, 720(%rsp)
	.seh_savexmm	%xmm7, 720
	.seh_endprologue
	movq	%rcx, 816(%rsp)
	movl	%edx, %r13d
	leaq	432(%rsp), %rbx
	movq	%rbx, %rdx
	movl	$260, %ecx
	call	*__imp_GetTempPathA(%rip)
	leaq	.LC1(%rip), %r8
	movl	$260, %edx
	movq	%rbx, %rcx
	call	*__imp_strcat_s(%rip)
	movl	$0, %edx
	movq	%rbx, %rcx
	call	*__imp_CreateDirectoryA(%rip)
	movq	$0, 48(%rsp)
	movl	$33554432, 40(%rsp)
	movl	$3, 32(%rsp)
	movl	$0, %r9d
	movl	$7, %r8d
	movl	$-2147483648, %edx
	movq	%rbx, %rcx
	call	*__imp_CreateFileA(%rip)
	movq	%rax, 72(%rsp)
	cmpq	$-1, %rax
	je	.L28
	movq	$0, 400(%rsp)
	movq	$0, 408(%rsp)
	movq	$0, 416(%rsp)
	movq	$0, 424(%rsp)
	pxor	%xmm6, %xmm6
	movl	$0, %r15d
	movl	$0, 88(%rsp)
	movl	$0, %r12d
	movl	$0, %ebp
	movq	__imp_QueryPerformanceFrequency(%rip), %rbx
	movq	__imp_QueryPerformanceCounter(%rip), %r14
	movq	__imp_ReadDirectoryChangesW(%rip), %rax
	movq	%rax, 80(%rsp)
	movsd	.LC3(%rip), %xmm7
	jmp	.L18
.L28:
	call	*__imp_GetLastError(%rip)
	movl	%eax, %r8d
	movq	816(%rsp), %rdx
	leaq	.LC2(%rip), %rcx
	call	printf
	jmp	.L2
.L31:
	call	*__imp_GetProcessHeap(%rip)
	movq	%rax, %rcx
	movl	$262144, %r8d
	movl	$0, %edx
	call	*__imp_HeapAlloc(%rip)
	movq	%rax, %rbp
	cmpl	$1, %r13d
	jne	.L5
	leaq	400(%rsp), %rdx
	movl	$6, %ecx
	movl	$0, %eax
	movq	%rdx, %rdi
	rep stosl
	jmp	.L5
.L32:
	addsd	%xmm1, %xmm6
	jmp	.L8
.L23:
	leaq	.LC7(%rip), %rax
	movq	%rax, 32(%rsp)
	movl	%esi, %r8d
	movl	%r12d, %edx
	leaq	.LC6(%rip), %rcx
	call	printf
	testl	%esi, %esi
	jne	.L20
.L13:
	addl	$1, %r15d
.L16:
	leaq	128(%rsp), %rcx
	call	*__imp_DeleteFileA(%rip)
	movl	$130, %ecx
	call	*__imp_Sleep(%rip)
	testl	%r13d, %r13d
	jne	.L29
.L17:
	addl	$1, %r12d
	cmpl	$5, %r12d
	je	.L30
.L18:
	movl	$0, 100(%rsp)
	movq	$0, 120(%rsp)
	testl	%r13d, %r13d
	jne	.L31
.L5:
	movq	$0, 424(%rsp)
	leaq	104(%rsp), %rcx
	call	*%rbx
	leaq	112(%rsp), %rcx
	call	*%r14
	movq	$0, 56(%rsp)
	leaq	400(%rsp), %rax
	movq	%rax, 48(%rsp)
	leaq	100(%rsp), %rax
	movq	%rax, 40(%rsp)
	movl	$351, 32(%rsp)
	movl	$1, %r9d
	movl	$262144, %r8d
	movq	%rbp, %rdx
	movq	72(%rsp), %rcx
	movq	80(%rsp), %rax
	call	*%rax
	movl	%eax, %esi
	leaq	120(%rsp), %rcx
	call	*%r14
	movq	120(%rsp), %rax
	subq	112(%rsp), %rax
	pxor	%xmm0, %xmm0
	cvtsi2sdq	%rax, %xmm0
	mulsd	%xmm7, %xmm0
	pxor	%xmm1, %xmm1
	cvtsi2sdq	104(%rsp), %xmm1
	divsd	%xmm1, %xmm0
	movsd	.LC4(%rip), %xmm1
	comisd	%xmm0, %xmm1
	ja	.L32
.L8:
	leaq	128(%rsp), %rdi
	movl	%r12d, 32(%rsp)
	leaq	432(%rsp), %r9
	leaq	.LC5(%rip), %r8
	movl	$260, %edx
	movq	%rdi, %rcx
	call	sprintf_s
	movq	$0, 48(%rsp)
	movl	$128, 40(%rsp)
	movl	$2, 32(%rsp)
	movl	$0, %r9d
	movl	$0, %r8d
	movl	$1073741824, %edx
	movq	%rdi, %rcx
	call	*__imp_CreateFileA(%rip)
	cmpq	$-1, %rax
	je	.L10
	movq	%rax, %rcx
	call	*__imp_CloseHandle(%rip)
.L10:
	movl	$180, %ecx
	call	*__imp_Sleep(%rip)
	movl	100(%rsp), %r9d
	testl	%esi, %esi
	je	.L23
	testl	%r9d, %r9d
	je	.L23
	leaq	.LC11(%rip), %rax
	movq	%rax, 32(%rsp)
	movl	%esi, %r8d
	movl	%r12d, %edx
	leaq	.LC6(%rip), %rcx
	call	printf
.L20:
	movl	$0, %esi
	leaq	.LC9(%rip), %rdi
	cmpl	$0, 100(%rsp)
	je	.L33
	movl	%r15d, 92(%rsp)
.L14:
	movl	%esi, %r15d
	addq	%rbp, %r15
	movl	4(%r15), %edx
	leaq	12(%r15), %r9
	movl	8(%r15), %r8d
	shrl	%r8d
	movq	%rdi, %rcx
	call	printf
	movl	(%r15), %eax
	testl	%eax, %eax
	je	.L27
	addl	%eax, %esi
	jmp	.L14
.L33:
	leaq	.LC8(%rip), %rcx
	call	printf
	jmp	.L15
.L27:
	movl	92(%rsp), %r15d
.L15:
	cmpl	$0, 100(%rsp)
	je	.L13
	addl	$1, 88(%rsp)
	jmp	.L16
.L29:
	call	*__imp_GetProcessHeap(%rip)
	movq	%rax, %rcx
	movq	%rbp, %r8
	movl	$0, %edx
	call	*__imp_HeapFree(%rip)
	movl	$0, %ebp
	jmp	.L17
.L30:
	cvttsd2siq	%xmm6, %rax
	movl	%eax, 32(%rsp)
	movl	%r15d, %r9d
	movl	88(%rsp), %r8d
	movq	816(%rsp), %rdx
	leaq	.LC10(%rip), %rcx
	call	printf
	movq	72(%rsp), %rcx
	call	*__imp_CloseHandle(%rip)
	testl	%r13d, %r13d
	jne	.L19
	testq	%rbp, %rbp
	jne	.L34
.L19:
	leaq	432(%rsp), %rcx
	call	*__imp_RemoveDirectoryA(%rip)
	nop
.L2:
	movaps	704(%rsp), %xmm6
	movaps	720(%rsp), %xmm7
	addq	$744, %rsp
	popq	%rbx
	popq	%rsi
	popq	%rdi
	popq	%rbp
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	ret
.L34:
	call	*__imp_GetProcessHeap(%rip)
	movq	%rax, %rcx
	movq	%rbp, %r8
	movl	$0, %edx
	call	*__imp_HeapFree(%rip)
	jmp	.L19
	.seh_endproc
	.section .rdata,"dr"
	.align 8
.LC12:
	.ascii "sizeof(OVERLAPPED)=%d, sizeof(FILE_NOTIFY_INFORMATION)=%d\12\0"
.LC13:
	.ascii "mode0 reuse both\0"
.LC14:
	.ascii "mode1 fresh both\0"
.LC15:
	.ascii "mode2 reuse ov, fresh buf\0"
	.text
	.globl	main
	.def	main;	.scl	2;	.type	32;	.endef
	.seh_proc	main
main:
	subq	$40, %rsp
	.seh_stackalloc	40
	.seh_endprologue
	call	__main
	movl	$16, %r8d
	movl	$32, %edx
	leaq	.LC12(%rip), %rcx
	call	printf
	movl	$0, %edx
	leaq	.LC13(%rip), %rcx
	call	run_case
	movl	$1, %edx
	leaq	.LC14(%rip), %rcx
	call	run_case
	movl	$2, %edx
	leaq	.LC15(%rip), %rcx
	call	run_case
	movl	$0, %eax
	addq	$40, %rsp
	ret
	.seh_endproc
	.section .rdata,"dr"
	.align 8
.LC3:
	.long	0
	.long	1083129856
	.align 8
.LC4:
	.long	0
	.long	1072693248
	.def	__main;	.scl	2;	.type	32;	.endef
	.ident	"GCC: (x86_64-win32-seh-rev1, Built by MinGW-Builds project) 16.1.0"
	.def	__local_stdio_printf_options;	.scl	2;	.type	32;	.endef
	.def	__stdio_common_vsprintf_s;	.scl	2;	.type	32;	.endef
	.def	printf;	.scl	2;	.type	32;	.endef

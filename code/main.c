#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


void unreachable(){
    system("/bin/sh");
    
}

void read_where(unsigned long address){
    printf("Your leak: %p\n",*(long*)address);
}

void write_what_where(unsigned long address, unsigned long item){
    *((long*)address) = item;
}

void fflush_stderr(){
    fflush(stderr);
}

void print_menu(){
    printf("What would you like to do?\n");
    printf("1. read\n");
    printf("2. write\n");
    printf("3. fflush(stderr)\n");
}

unsigned long get_choice(){
    char buf[256] = {0};
    fgets(buf,256,stdin);
    return strtoul(buf,NULL,10);
}

int main(void){
    while(1){
        int choice;
        long address, what;
        print_menu();
        choice = get_choice();
        switch(choice){
            case 1:
                printf("Where?\n");
                address = get_choice();
                read_where(address);
                break;
            case 2:
                printf("Where?\n");
                address = get_choice();
                printf("What?\n");
                what = get_choice();
                write_what_where(address,what);
                break;
            case 3:
                fflush_stderr();
                break;
            default:
                break;
        }
    }
}
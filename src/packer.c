#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/md5.h>
#include "read_nanomites.h"
#include "nanomites_encrypted.h"
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/err.h>

char *get_file_path(int pid)
{ // construct filepath to /proc/[pid]/maps
    char pid_str[13];
    sprintf(pid_str, "%d", pid); // transform pid int to string
    char path[30] = "/proc/";
    strcat(path, pid_str); // concatenate /proc/, [pid] and /maps
    strcat(path, "/maps");
    char *memory = (char *)malloc(sizeof(char) * (strlen(path) + 1)); // allocate memory for filepath on heap
    strcpy(memory, path);                                             // copy string onto heap
    return memory;
}

unsigned long int get_base_address(int pid)
{ // returns base address of process
    char base_address[24];

    char *path = get_file_path(pid); // get /proc/[pid]/maps string
    FILE *fp;

    fp = fopen(path, "r");       // open /proc/[pid]/maps
    fgets(base_address, 20, fp); // read in first line
    fclose(fp);                  // example of first line: 55d89e865000-55d89e866000 r--p 00000000 08:05 131446
    free(path);                  // free allocated memory on heap for filepath

    unsigned long int base = strtoul(strtok(base_address, "-"), NULL, 16); // take everything before '-' and convert it to unsigned long. This is the base address
    return base;
}

unsigned long int get_end_of_nanomite_section(pid_t child, unsigned long int start_addr)
{ // search for nanomite section end marker and return that address
    unsigned long int code;
    unsigned long int end_addr = 0;
    char *breakpoint;
    int offset;
    char hex_string[17];

    start_addr += 10;     // skip past start marker
    while (end_addr == 0) // while the end marker has not been found
    {
        code = ptrace(PTRACE_PEEKTEXT, child, start_addr); // get code from child
        sprintf(hex_string, "%016lx", code);               // convert it to hex string
        breakpoint = strstr(hex_string, "cc");             // search for breakpoint in hexstring
        if (breakpoint != NULL)                            // if there is one
        {
            offset = (unsigned long int)breakpoint - (unsigned long int)hex_string; // get offset of breakpoint in that string
            end_addr = start_addr + (7 - offset / 2);                               // calculate address of breakpoint (takes into account endianness)
            if (ptrace(PTRACE_PEEKTEXT, child, end_addr) != 0xcafe1055bfcc)         // check if the code at this position is actually the end marker, could be a random 0xcc in encrypted code
            {
                end_addr = 0; // if it's not the end marker, reset end address
            }
        }
        start_addr += 8;
    }
    return end_addr;
}

// --------- decrypt_code (ChaCha20, safe KDF) ----------
void decrypt_code(pid_t child,
                  unsigned long int start_addr,
                  unsigned long int base,
                  struct packed_file packed)
{
    unsigned long int end_addr = get_end_of_nanomite_section(child, start_addr);
    int code_steals = (end_addr - start_addr - 10) / 16;
    start_addr += 10;

    for (int i = 0; i < code_steals; i++)
    {
        /* Read encrypted 8-byte block from child */
        unsigned long raw = ptrace(PTRACE_PEEKTEXT, child, start_addr);
        unsigned char encrypted[8];
        memcpy(encrypted, &raw, 8);

        /* Get seed */
        unsigned int seed = 0x12345678; // fixed seed

        /* === derive key and nonce deterministically (little-endian) === */
        unsigned char s4[4], s5[5], s6[6];
        s4[0] = (seed >> 0) & 0xff;
        s4[1] = (seed >> 8) & 0xff;
        s4[2] = (seed >> 16) & 0xff;
        s4[3] = (seed >> 24) & 0xff;
        /* s5 = s4 + 0x00 */
        memcpy(s5, s4, 4);
        s5[4] = 0x00;
        /* s6 = s4 + 0x00 + 0x00 */
        memcpy(s6, s4, 4);
        s6[4] = 0x00;
        s6[5] = 0x00;

        unsigned char md1[16], md2[16], md3[16];
        MD5(s4, 4, md1);
        MD5(s5, 5, md2);
        MD5(s6, 6, md3);

        unsigned char key[32], nonce16[16];
        memcpy(key, md1, 16);
        memcpy(key + 16, md2, 16);
        /* build 16-byte nonce: first 12 bytes from md3, last 4 bytes zero */
        memcpy(nonce16, md3, 12);
        memset(nonce16 + 12, 0x00, 4);

        /* ChaCha20 decrypt (EVP) */
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            unsigned long err = ERR_get_error();
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            fprintf(stderr, "EVP_CIPHER_CTX_new failed: %s\n", buf);
            exit(1);
        }

        /* Pass the 16-byte nonce to the EVP API */
        if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce16))
        {
            unsigned long err = ERR_get_error(); /* pop error code from OpenSSL error queue */
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            fprintf(stderr, "EVP_DecryptInit_ex failed: %s\n", buf);
            EVP_CIPHER_CTX_free(ctx);
            exit(1);
        }
        EVP_CIPHER_CTX_set_padding(ctx, 0);

        unsigned char decrypted[8];
        int outlen = 0, finallen = 0;

        if (1 != EVP_DecryptUpdate(ctx, decrypted, &outlen, encrypted, 8))
        {
            unsigned long err = ERR_get_error();
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            fprintf(stderr, "EVP_DecryptUpdate failed: %s\n", buf);
            EVP_CIPHER_CTX_free(ctx);
            exit(1);
        }

        EVP_CIPHER_CTX_free(ctx);

        /* Patch decrypted bytes into child memory */
        unsigned long patched = 0;
        memcpy(&patched, decrypted, 8);
        if (ptrace(PTRACE_POKETEXT, child, start_addr, patched) == -1)
        {
            perror("PTRACE_POKETEXT");
            /* continue despite error? you may want to exit */
        }

        start_addr += 16;
    }
}

// --------- encrypt_code (ChaCha20, safe KDF) ----------
void encrypt_code(pid_t child,
                  unsigned long int start_addr,
                  unsigned long int end_addr,
                  unsigned long int base,
                  struct packed_file packed)
{
    int code_steals = (end_addr - start_addr - 10) / 16;
    start_addr += 10;

    for (int i = 0; i < code_steals; i++)
    {
        /* Read plaintext 8-byte block */
        unsigned long raw = ptrace(PTRACE_PEEKTEXT, child, start_addr);
        unsigned char plain[8];
        memcpy(plain, &raw, 8);

        /* Get seed */
        /* fixed seed (must match prepare_packer.py) */
        unsigned int seed = 0x12345678;

        /* derive key/nonce (same as decrypt) */
        unsigned char s4[4], s5[5], s6[6];
        s4[0] = (seed >> 0) & 0xff;
        s4[1] = (seed >> 8) & 0xff;
        s4[2] = (seed >> 16) & 0xff;
        s4[3] = (seed >> 24) & 0xff;
        memcpy(s5, s4, 4);
        s5[4] = 0x00;
        memcpy(s6, s4, 4);
        s6[4] = 0x00;
        s6[5] = 0x00;

        unsigned char md1[16], md2[16], md3[16];
        MD5(s4, 4, md1);
        MD5(s5, 5, md2);
        MD5(s6, 6, md3);

        unsigned char key[32], nonce16[16];
        memcpy(key, md1, 16);
        memcpy(key + 16, md2, 16);
        /* build 16-byte nonce: first 12 bytes from md3, last 4 bytes zero */
        memcpy(nonce16, md3, 12);
        memset(nonce16 + 12, 0x00, 4);

        /* ChaCha20 decrypt (EVP) */
        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            unsigned long err = ERR_get_error();
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            fprintf(stderr, "EVP_CIPHER_CTX_new failed: %s\n", buf);
            exit(1);
        }

        /* Pass the 16-byte nonce to the EVP API */
        if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, nonce16))
        {
            unsigned long err = ERR_get_error();
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            fprintf(stderr, "EVP_EncryptInit_ex failed: %s\n", buf);
            EVP_CIPHER_CTX_free(ctx);
            exit(1);
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0);

        unsigned char encrypted[8];
        int outlen = 0, finallen = 0;

        if (1 != EVP_EncryptUpdate(ctx, encrypted, &outlen, plain, 8))
        {
            unsigned long err = ERR_get_error();
            char buf[256];
            ERR_error_string_n(err, buf, sizeof(buf));
            fprintf(stderr, "EVP_EncryptUpdate failed: %s\n", buf);
            EVP_CIPHER_CTX_free(ctx);
            exit(1);
        }

        EVP_CIPHER_CTX_free(ctx);

        unsigned long patched = 0;
        memcpy(&patched, encrypted, 8);

        if (ptrace(PTRACE_POKETEXT, child, start_addr, patched) == -1)
        {
            perror("PTRACE_POKETEXT");
        }

        start_addr += 16;
    }
}

void tracer(pid_t child)
{
    struct user_regs_struct regs;
    int seed, status;
    unsigned long int rip_addr, base;
    unsigned long int start_addr;

    waitpid(child, NULL, 0); // ignore first trap to parent
    ptrace(PTRACE_CONT, child, NULL, NULL);

    base = get_base_address((int)child); // get base address of child process

    struct packed_file packed = read_in_nanomites(); // read in nanomites details from nanomites_dump file created by the preparation python script

    for (int i = 0; i < 3; i++)
    {
        status = 0;
        waitpid(child, &status, 0); // Wait for child to trap to parent

        if (WIFEXITED(status))
        { // If child has exited, stop loop
            break;
        }

        ptrace(PTRACE_GETREGS, child, NULL, &regs); // get regs from child
        rip_addr = regs.rip - 1;                    // set rip_addr to address of 0xcc
        unsigned long int code;
        code = ptrace(PTRACE_PEEKTEXT, child, rip_addr, 0); // get code from child at breakpoint address

        if (code == 0xcafeb055bfcc) // if code is nanomites section start marker
        {
            start_addr = rip_addr;                       // save start_addr of nanomites section for later
            decrypt_code(child, rip_addr, base, packed); // decrypt nanomites in current nanomites section
            regs.rip = rip_addr + 10;                    // set rip addr to the first real instruction after nanomite section start marker
            ptrace(PTRACE_SETREGS, child, NULL, &regs);  // change rip of child
        }
        else if (code == 0xcafe1055bfcc) // if code is nanomites section end marker
        {
            encrypt_code(child, start_addr, rip_addr, base, packed); // encrypt current nanomite section again
            regs.rip = rip_addr + 10;                                // set rip addr to the first real instruction after nanomite section end marker
            ptrace(PTRACE_SETREGS, child, NULL, &regs);              // change rip of child
        }
        ptrace(PTRACE_CONT, child, NULL, NULL); // let child continue execution
    }
}

void write_nanomites_file() // write unsigned char array that represents ELF to file so it can be executed
{
    FILE *fp;
    fp = fopen("child_elf", "wb");
    fwrite(linux_resc_nanomites_encrypted, 1, linux_resc_nanomites_encrypted_len, fp);
    fclose(fp);
    chmod("child_elf", 0777); // make file executable
}

int main()
{
    write_nanomites_file();
    pid_t child;
    child = fork();
    if (child == 0)
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // ask parent to trace
        execl("child_elf", "child_elf", NULL); // execute nanomite encrypted ELF
    }
    else
    {
        tracer(child);       // parent traces child
        remove("child_elf"); // remove child file after execution has finished
    }
    return 0;
}

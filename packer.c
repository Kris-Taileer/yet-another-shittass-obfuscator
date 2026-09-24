#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <sys/stat.h>
#include "container.h"
#include "ks.h"


static unsigned char *read_whole_file(const char *path, size_t *out_size) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *buffer = malloc(size);
    if (fread(buffer, 1, size, file) != (size_t)size) {
        perror("oshibochka. couldn't read the file");
        exit(1);
    }
    fclose(file);

    *out_size = size;
    return buffer;
}

static void ensure_supported_elf(const Elf64_Ehdr *header) {
    int is_elf = memcmp(header->e_ident, "\x7f""ELF", 4) == 0;
    int is_64bit= header->e_ident[EI_CLASS] == ELFCLASS64;
    int is_x86_64 = header->e_machine == EM_X86_64;
    int is_non_pie = header->e_type == ET_EXEC;

    if (!(is_elf && is_64bit && is_x86_64 && is_non_pie)) {
        fprintf(stderr, "oshibochka. either this isn't an elf or not a x86_64 arc nor non_pie\n");
        exit(1);
    }
}

static size_t lzss_compress(const unsigned char *input, size_t input_size, unsigned char *output) {
    size_t read_pos = 0;
    size_t write_pos = 0;

    while (read_pos < input_size) {
        size_t flags_pos = write_pos;
        write_pos++;
        unsigned char flags = 0;

        for (int bit = 0; bit < 8 && read_pos < input_size; bit++) {
            unsigned best_length = 0;
            unsigned best_distance = 0;
            size_t window_start = (read_pos > 4096) ? read_pos - 4096 : 0;

            for (size_t candidate = window_start; candidate < read_pos; candidate++) {
                unsigned length = 0;
                while (length < 18 &&
                       read_pos + length < input_size &&
                       input[candidate + length] == input[read_pos + length]) {
                    length++;
                }
                if (length > best_length) {
                    best_length = length;
                    best_distance = read_pos - candidate;
                }
            }
            if (best_length >= 3) {
                unsigned distance = best_distance - 1;
                unsigned length = best_length   - 3;
                output[write_pos++] = distance & 0xFF;
                output[write_pos++] = ((distance >> 8) << 4) | length;
                read_pos += best_length;
            } else {
                flags |= (1 << bit);
                output[write_pos++] = input[read_pos++];
            }
        }

        output[flags_pos] = flags;
    }
    return write_pos;
}


int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <your binary> <output binary name>\n", argv[0]);
        return 1;
    }
    size_t target_size, stub_size, stub_elf_size;
    unsigned char *target = read_whole_file(argv[1], &target_size);
    unsigned char *stub_code= read_whole_file("stub.bin", &stub_size);
    unsigned char *stub_elf = read_whole_file("stub.elf", &stub_elf_size);

    Elf64_Ehdr *target_header = (Elf64_Ehdr *)target;
    ensure_supported_elf(target_header);

    uint64_t stub_entry_address = ((Elf64_Ehdr *)stub_elf)->e_entry;
    Container container;
    memset(&container, 0, sizeof(container));
    container.magic= CONTAINER_MAGIC;
    container.orig_entry = target_header->e_entry;
    container.nsegs = 0;

    unsigned char *blob = malloc(target_size * 2 + 4096);
    size_t blob_size = 0;

    Elf64_Phdr *program_headers = (Elf64_Phdr *)(target + target_header->e_phoff);
    for (int i = 0; i < target_header->e_phnum; i++) {
        Elf64_Phdr *ph = &program_headers[i];

        if (ph->p_type != PT_LOAD) continue;
        if (ph->p_filesz == 0)continue;

        SegDesc *segment = &container.segs[container.nsegs];
        segment->vaddr = ph->p_vaddr;
        segment->memsz = ph->p_memsz;
        segment->filesz = ph->p_filesz;
        segment->flags = ph->p_flags;
        segment->raw_len = ph->p_filesz;
        segment->blob_off = blob_size;

        size_t compressed = lzss_compress(target + ph->p_offset, ph->p_filesz, blob + blob_size);
        segment->blob_len = compressed;
        blob_size += compressed;

        printf("segment %u: address=%#lx size=%#lx --> obf=%#lx\n", container.nsegs, (unsigned long)segment->vaddr, (unsigned long)segment->filesz, (unsigned long)compressed);
        container.nsegs++;
    }

    for (size_t i = 0; i < blob_size; i++) {
        blob[i] ^= keystream_byte(CLEAN_KEY, i);
    }
    const uint64_t BASE = 0x200000;
    const size_t   STUB_OFFSET = 0x100;
    const size_t   CONTAINER_OFF  = 0x2000;
    size_t blob_offset = CONTAINER_OFF + sizeof(Container);
    size_t total_size  = blob_offset + blob_size;

    if (stub_size > CONTAINER_OFF - STUB_OFFSET) {
        fprintf(stderr, "stub is too large.\n");
        return 1;
    }

    unsigned char *output = calloc(1, total_size);

    Elf64_Ehdr out_header;
    memset(&out_header, 0, sizeof(out_header));
    memcpy(out_header.e_ident, "\x7f""ELF", 4);
    out_header.e_ident[EI_CLASS] = ELFCLASS64;
    out_header.e_ident[EI_DATA]= ELFDATA2LSB;
    out_header.e_ident[EI_VERSION] = EV_CURRENT;
    out_header.e_type = ET_EXEC;
    out_header.e_machine = EM_X86_64;
    out_header.e_version = EV_CURRENT;
    out_header.e_entry = stub_entry_address;
    out_header.e_phoff = sizeof(Elf64_Ehdr);
    out_header.e_ehsize = sizeof(Elf64_Ehdr);
    out_header.e_phentsize = sizeof(Elf64_Phdr);
    out_header.e_phnum = 1;
    memcpy(output, &out_header, sizeof(out_header));

    Elf64_Phdr out_ph;
    memset(&out_ph, 0, sizeof(out_ph));
    out_ph.p_type= PT_LOAD;
    out_ph.p_flags = PF_R | PF_W | PF_X;
    out_ph.p_offset = 0;
    out_ph.p_vaddr = BASE;
    out_ph.p_paddr = BASE;
    out_ph.p_filesz = total_size;
    out_ph.p_memsz = total_size;
    out_ph.p_align = 0x1000;
    memcpy(output + sizeof(Elf64_Ehdr), &out_ph, sizeof(out_ph));

    memcpy(output + STUB_OFFSET, stub_code,stub_size);
    memcpy(output + CONTAINER_OFF, &container, sizeof(Container));
    memcpy(output + blob_offset, blob,blob_size);

    FILE *out_file = fopen(argv[2], "wb");
    fwrite(output, 1, total_size, out_file);
    fclose(out_file);
    chmod(argv[2], 0755);

    printf("greatfully done: %s\n", argv[2]);
    return 0;
}

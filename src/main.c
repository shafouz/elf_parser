#include <alloca.h>
#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define E_NHDR 64   /* Header size */
#define E_NIDENT 16 /* Ident size */
#define E_NMAGIC 4  /* Magic size */
#define E_NPAD 8    /* Ident pad size */

const u_char ELF32 = 1;
const u_char ELF64 = 2;
const u_char LSB = 1;
const u_char MSB = 2;
const u_char E_MAGIC[E_NMAGIC] = {0x7f, 'E', 'L', 'F'};

typedef struct {
  u_char magic[4];
  u_char class;
  u_char data;
  u_char version;
  u_char os_abi;
  u_char pad[8];
} e_ident;

typedef struct {
  e_ident ident;
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr *e_entry;
  Elf64_Off e_phoff;
  Elf64_Off e_shoff;
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} ElfHeader;

void err_msg(const char *msg) {
  fprintf(stderr, "Error: %s\n", msg);
  exit(1);
}

void err_exit() {
  fprintf(stderr, "Error: %s\n", strerror(errno));
  exit(1);
}

typedef struct {
  u_char *data;
  u_char *start;
  size_t size;
  size_t curr;
} stream;

void offset_str(stream *str, size_t n) {
  if (n >= str->size) {
    err_msg("Error: EOF.");
  }

  str->data = str->start + n;
  str->curr = n;
}

void next_str(stream *str, size_t n) {
  if (str->curr > SIZE_MAX - n) {
    err_msg("Error: Overflow.");
  }

  if (str->curr + n >= str->size) {
    err_msg("Error: EOF.");
  }

  str->curr += n;
  str->data += n;
}

void print_str(stream *str) {
  u_char *msg2 = malloc(str->size + 1);
  msg2[str->size] = '\0';

  for (size_t i = 0; i < str->size; i++) {
    if (str->data[i] == '\0') {
      msg2[i] = '_';
    } else {
      msg2[i] = str->data[i];
    }
  }

  printf("%s", msg2);
  free(msg2);
}

stream *read_to_string(const char *filename) {
  FILE *file = fopen(filename, "r");
  if (!file) {
    err_exit();
  }

  fseek(file, 0, SEEK_END);
  long length = ftell(file);
  fseek(file, 0, SEEK_SET);

  stream *file_contents = malloc(sizeof(stream));
  file_contents->curr = 0;
  file_contents->size = length;
  file_contents->data = malloc(length);
  file_contents->start = file_contents->data;

  if (!file_contents) {
    err_exit();
  }

  fread(file_contents->data, 1, length, file);

  fclose(file);
  return file_contents;
}

e_ident parse_ident(stream *stream) {
  if (memcmp(stream->data, E_MAGIC, E_NMAGIC) != 0) {
    err_msg("Invalid E_MAGIC.");
  };

  e_ident ident = {};

  memcpy(ident.magic, E_MAGIC, E_NMAGIC);
  next_str(stream, E_NMAGIC);

  if (!(*stream->data == ELF32 || *stream->data == ELF64)) {
    err_msg("Invalid E_CLASS.");
  }

  ident.class = *stream->data;
  next_str(stream, 1);

  if (!(*stream->data == LSB || *stream->data == MSB)) {
    err_msg("Invalid E_DATA.");
  }

  ident.data = *stream->data;
  next_str(stream, 1);

  ident.version = 1;
  next_str(stream, 1);

  // System V for now
  ident.os_abi = 0;
  next_str(stream, 1);

  bzero(ident.pad, E_NPAD);
  next_str(stream, E_NPAD);

  return ident;
}

ElfHeader parse_elf_header(stream *stream) {
  e_ident ident = parse_ident(stream);
  assert(stream->curr == E_NIDENT);

  Elf64_Half e_type = 0;
  memcpy(&e_type, stream->data, sizeof(e_type));
  switch (e_type) {
  case ET_NONE:
  case ET_REL:
  case ET_EXEC:
  case ET_DYN:
  case ET_CORE:
  case ET_NUM:
  case ET_LOOS:
  case ET_HIOS:
  case ET_LOPROC:
  case ET_HIPROC:
    break;
  default:
    err_msg("Invalid E_TYPE.");
  }
  next_str(stream, sizeof(e_type));

  // only 32 or 64
  Elf64_Half e_machine = 0;
  memcpy(&e_machine, stream->data, sizeof(e_machine));
  switch (e_machine) {
  case EM_NONE:
  case EM_386:
  case EM_X86_64:
    break;
  default:
    err_msg("Invalid E_MACHINE.");
  }
  next_str(stream, sizeof(e_machine));

  Elf64_Word e_version = 0;
  memcpy(&e_version, stream->data, sizeof(e_version));
  if (e_version != 1) {
    err_msg("Invalid E_VERSION.");
  }
  next_str(stream, sizeof(e_version));

  Elf64_Addr *e_entry = 0;
  memcpy(&e_entry, stream->data, sizeof(e_entry));
  next_str(stream, sizeof(e_entry));

  Elf64_Off e_phoff = 0;
  memcpy(&e_phoff, stream->data, sizeof(e_phoff));
  next_str(stream, sizeof(e_phoff));

  Elf64_Off e_shoff = 0;
  memcpy(&e_shoff, stream->data, sizeof(e_shoff));
  next_str(stream, sizeof(e_shoff));

  Elf64_Word e_flags = 0;
  memcpy(&e_flags, stream->data, sizeof(e_flags));
  next_str(stream, sizeof(e_flags));

  Elf64_Half e_ehsize = 0;
  memcpy(&e_ehsize, stream->data, sizeof(e_ehsize));
  next_str(stream, sizeof(e_ehsize));

  Elf64_Half e_phentsize = 0;
  memcpy(&e_phentsize, stream->data, sizeof(e_phentsize));
  next_str(stream, sizeof(e_phentsize));

  Elf64_Half e_phnum = 0;
  memcpy(&e_phnum, stream->data, sizeof(e_phnum));
  next_str(stream, sizeof(e_phnum));

  Elf64_Half e_shentsize = 0;
  memcpy(&e_shentsize, stream->data, sizeof(e_shentsize));
  next_str(stream, sizeof(e_shentsize));

  Elf64_Half e_shnum = 0;
  memcpy(&e_shnum, stream->data, sizeof(e_shnum));
  next_str(stream, sizeof(e_shnum));

  Elf64_Half e_shstrndx = 0;
  memcpy(&e_shstrndx, stream->data, sizeof(e_shstrndx));
  next_str(stream, sizeof(e_shstrndx));

  ElfHeader header = {.e_type = e_type,
                      .e_machine = e_machine,
                      .e_version = e_version,
                      .e_entry = e_entry,
                      .e_phoff = e_phoff,
                      .e_shoff = e_shoff,
                      .e_flags = e_flags,
                      .e_ehsize = e_ehsize,
                      .e_phentsize = e_phentsize,
                      .e_phnum = e_phnum,
                      .e_shentsize = e_shentsize,
                      .e_shnum = e_shnum,
                      .e_shstrndx = e_shstrndx};

  return header;
}

void parse_program_headers(stream *stream) {}

void parse_sections(stream *stream, ElfHeader *hdr) {
  Elf64_Shdr *sections = calloc(hdr->e_shentsize, hdr->e_shnum);
  u_char *zero;

  for (int idx = 0; idx < hdr->e_shnum; idx++) {
    offset_str(stream, hdr->e_shoff + (hdr->e_shentsize * idx));

    switch (idx) {
    case SHN_UNDEF:
      zero = calloc(hdr->e_shentsize, 1);
      if (memcmp(stream->data, zero, hdr->e_shentsize) != 0) {
        err_msg("SHN_UNDEF should be null.");
      };
      free(zero);
      break;
    // SHN_LOPROC
    case SHN_LORESERVE:
    case SHN_HIPROC:
    case SHN_ABS:
    case SHN_COMMON:
    case SHN_HIRESERVE:
      err_msg("Using reserved section.");
    }

    Elf64_Word sh_name = 0;
    memcpy(&sh_name, stream->data, sizeof(sh_name));
    next_str(stream, sizeof(sh_name));

    Elf64_Word sh_type = 0;
    memcpy(&sh_type, stream->data, sizeof(sh_type));
    switch (sh_type) {
    case SHT_NULL:
    case SHT_PROGBITS:
    case SHT_SYMTAB:
    case SHT_STRTAB:
    case SHT_RELA:
    case SHT_HASH:
    case SHT_DYNAMIC:
    case SHT_NOTE:
    case SHT_NOBITS:
    case SHT_REL:
    case SHT_SHLIB:
    case SHT_DYNSYM:
    case SHT_LOPROC:
    case SHT_HIPROC:
    case SHT_LOUSER:
    case SHT_HIUSER:
      break;
    default:
      err_msg("Invalid SH_TYPE");
    }
    next_str(stream, sizeof(sh_type));

    Elf64_Word sh_flags = 0;
    memcpy(&sh_flags, stream->data, sizeof(sh_flags));
    next_str(stream, sizeof(sh_flags));

    Elf64_Addr sh_addr = 0;
    memcpy(&sh_addr, stream->data, sizeof(sh_addr));
    next_str(stream, sizeof(sh_addr));

    Elf64_Off sh_offset = 0;
    memcpy(&sh_offset, stream->data, sizeof(sh_offset));
    next_str(stream, sizeof(sh_offset));

    Elf64_Word sh_size = 0;
    memcpy(&sh_size, stream->data, sizeof(sh_size));
    next_str(stream, sizeof(sh_size));

    Elf64_Word sh_link = 0;
    memcpy(&sh_link, stream->data, sizeof(sh_link));
    next_str(stream, sizeof(sh_link));

    Elf64_Word sh_info = 0;
    memcpy(&sh_info, stream->data, sizeof(sh_info));
    next_str(stream, sizeof(sh_info));

    Elf64_Word sh_addralign = 0;
    memcpy(&sh_addralign, stream->data, sizeof(sh_addralign));
    next_str(stream, sizeof(sh_addralign));

    Elf64_Word sh_entsize = 0;
    memcpy(&sh_entsize, stream->data, sizeof(sh_entsize));
    next_str(stream, sizeof(sh_entsize));
  }
}

void *parse_elf(stream *stream) {
  ElfHeader header = parse_elf_header(stream);
  assert(stream->curr == 0x40);

  if (header.e_shoff) {
    parse_sections(stream, &header);
  }

  __builtin_dump_struct(&header, &printf);

  return NULL;
}

int main(int argc, char *argv[]) {
  assert(sizeof(e_ident) == E_NIDENT);
  assert(sizeof(ElfHeader) == E_NHDR);

  if (argc < 2) {
    err_msg("Usage: <filename>");
  }

  stream *str = read_to_string(argv[1]);
  offset_str(str, 4);
  assert(memcmp(str->data, E_MAGIC, 4) != 0);
  offset_str(str, 0);
  assert(memcmp(str->data, E_MAGIC, 4) == 0);

  parse_elf(str);
  free(str);
}

#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <elf.h>

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
  u_short e_type;
  u_short e_machine;
  u_int e_version;
  void *e_entry;
  u_long e_phoff;
  u_long e_shoff;
  u_int e_flags;
  u_short e_ehsize;
  u_short e_phentsize;
  u_short e_phnum;
  u_short e_shentsize;
  u_short e_shnum;
  u_short e_shstrndx;
} e_header;

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
  size_t size;
  size_t curr;
} stream;

void advance_str(stream *str, size_t n) {
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
  advance_str(stream, E_NMAGIC);

  if (!(*stream->data == ELF32 || *stream->data == ELF64)) {
    err_msg("Invalid E_CLASS.");
  }

  ident.class = *stream->data;
  advance_str(stream, 1);

  if (!(*stream->data == LSB || *stream->data == MSB)) {
    err_msg("Invalid E_DATA.");
  }

  ident.data = *stream->data;
  advance_str(stream, 1);

  ident.version = 1;
  advance_str(stream, 1);

  // System V for now
  ident.os_abi = 0;
  advance_str(stream, 1);

  bzero(ident.pad, E_NPAD);
  advance_str(stream, E_NPAD);

  return ident;
}

e_header parse_header(stream *stream) {
  e_ident ident = parse_ident(stream);
  assert(stream->curr == E_NIDENT);

  e_header header = {};

  u_short e_type;
  memcpy(&e_type, stream->data, sizeof(e_type));

  switch (e_type) {
  case ET_NONE:
    header.e_type = ET_NONE;
    break;
  case ET_REL:
    header.e_type = ET_REL;
    break;
  case ET_EXEC:
    header.e_type = ET_EXEC;
    break;
  case ET_DYN:
    header.e_type = ET_DYN;
    break;
  case ET_CORE:
    header.e_type = ET_CORE;
    break;
  case ET_NUM:
    header.e_type = ET_NUM;
    break;
  case ET_LOOS:
    header.e_type = ET_LOOS;
    break;
  case ET_HIOS:
    header.e_type = ET_HIOS;
    break;
  case ET_LOPROC:
    header.e_type = ET_LOPROC;
    break;
  case ET_HIPROC:
    header.e_type = ET_HIPROC;
    break;
  default:
    err_msg("Invalid E_TYPE.");
  }
  advance_str(stream, sizeof(u_short));

  return header;
}

void *parse_elf(stream *stream) {
  e_header header = parse_header(stream);
  // e_ident ident = parse_ident(stream);

  return NULL;
}

int main(int argc, char *argv[]) {
  assert(sizeof(e_ident) == E_NIDENT);
  assert(sizeof(e_header) == E_NHDR);

  if (argc < 2) {
    err_msg("Usage: <filename>");
  }

  stream *str = read_to_string(argv[1]);
  parse_elf(str);
}

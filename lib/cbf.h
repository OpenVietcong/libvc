/* SPDX-License-Identifier: */
/*
 * A library for reading, creating, and modifying
 * CBF (CompressedBigFile) archives.
 *
 * Copyright (c) 2019 by Jan Havran
 */

#ifndef CBF_H
#define CBF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct cbf;
struct cbf_file;

struct cbf_stat {
	time_t mtime;
};

typedef struct cbf cbf_t;
typedef struct cbf_file cbf_file_t;
typedef struct cbf_stat cbf_stat_t;

cbf_t *cbf_open(const char *path);
void   cbf_close(cbf_t *cbf);

uint32_t    cbf_get_num_files(cbf_t *cbf);
const char *cbf_get_name(cbf_t *cbf, uint32_t index);
int         cbf_get_index(cbf_t *cbf, const char *name, uint32_t *index);

cbf_file_t *cbf_fopen(cbf_t *cbf, const char *name);
cbf_file_t *cbf_fopen_index(cbf_t *cbf, uint32_t index);
size_t      cbf_fread(void *ptr, size_t bytes, cbf_file_t *file);
int         cbf_fseek(cbf_file_t *file, uint32_t offset);
int         cbf_ftell(cbf_file_t *file, uint32_t *offset);
void        cbf_fclose(cbf_file_t *file);

#ifdef __cplusplus
}
#endif

#endif // CBF_H


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

typedef struct cbf cbf_t;
typedef struct cbf_file cbf_file_t;

cbf_t *cbf_open(const char *path);
void   cbf_close(cbf_t *cbf);

#ifdef __cplusplus
}
#endif

#endif // CBF_H


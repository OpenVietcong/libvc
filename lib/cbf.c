/* SPDX-License-Identifier: */
/*
 * A library for reading, creating, and modifying
 * CBF (CompressedBigFile) archives.
 *
 * Copyright (c) 2019 by Jan Havran
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cbf.h"

enum {
	CBF_ENC_ENCRYPTION  = 0,
	CBF_ENC_COMPRESSION = 1,
};

enum {
	CBF_MOD_CLASSIC  = 0,
	CBF_MOD_EXTENDED = 1,
};

const char cbf_sig[] = {
	0x42, 0x49, 0x47, 0x46,	/* BIGF  */
	0x01, 0x5A, 0x42, 0x4C, /* \1ZBL */
};

const uint8_t cbf_file_desc_lut[] = {
	0x32, 0xF3, 0x1E, 0x06,
	0x45, 0x70, 0x32, 0xAA,
	0x55, 0x3F, 0xF1, 0xDE,
	0xA3, 0x44, 0x21, 0xB4,
};

const uint8_t cbf_file_salt = 0xA6;

struct CBF_Header {
	char signature[sizeof(cbf_sig)];
	uint32_t archive_size;
	uint32_t res1;
	uint32_t file_count;
	uint32_t table_offset;
	uint32_t res2;
	uint32_t table_size;
	uint32_t res3;
	uint32_t header_size;
	uint32_t res4;
	uint32_t date_low;
	uint32_t date_high;
} __attribute__((packed));

struct CBF_File {
	uint32_t file_offset;
	uint32_t res1;
	uint32_t unk1;
	uint32_t date_low;
	uint32_t date_high;
	uint32_t file_size;
	uint32_t res2;
	uint32_t compressed_size;
	uint32_t encoding;
	uint32_t unk2;
	char name[];
} __attribute__((packed));

/* CBF file data */
struct cbf_file {
	cbf_t *cbf;		/* Parent CBF */
	uint32_t cur_ptr;	/* Cursor pointer */
	uint32_t offset;	/* Offset inside of cbf */
	uint32_t size;		/* Uncompressed file size */
	uint32_t comp_size;	/* Compressed file size */
	uint32_t encoding;
	char *name;		/* File name */
};

/* CBF archive data */
struct cbf {
	uint32_t mode;		/* CBF mode */
	uint32_t a_size;	/* Total archive size */
	uint32_t h_size;	/* Header size */
	uint32_t t_offset;	/* Table offset */
	uint32_t t_size;	/* Table size */
	uint32_t file_num;
	cbf_file_t *file_descs;
	FILE *f;
	char *comment;
};

static int cbf_parse_comment(cbf_t *cbf, uint32_t header_size)
{
	uint32_t comment_len;
	uint16_t label;

	/* Get comment label */
	if (fread(&label, sizeof(label), 1, cbf->f) != 1) {
		fprintf(stderr, "Unable to read comment label\n");
		return 1;
	}
	if (label != 1) {
		fprintf(stderr, "Invalid comment label\n");
		return 1;
	}

	/* Get comment length */
	if (fread(&comment_len, sizeof(comment_len), 1, cbf->f) != 1) {
		fprintf(stderr, "Unable to read comment size\n");;
		return 1;
	}
	if (header_size != 70u + (uint32_t) comment_len) {
		fprintf(stderr, "Comment does not fit the header\n");
		return 1;
	}

	/* Get comment itself */
	if ((cbf->comment = (char *) malloc(comment_len + 1)) == NULL) {
		fprintf(stderr, "Unable to malloc mem\n");
		return 1;
	}
	if (fread(cbf->comment, comment_len, 1, cbf->f) != 1) {
		fprintf(stderr, "Unable to read comment\n");
		free(cbf->comment);
		cbf->comment = NULL;
		return 1;
	}
	cbf->comment[comment_len] = '\0'; /* sic! */

	return 0;
}

static int cbf_parse_header(cbf_t *cbf)
{
	struct CBF_Header header;
	long file_size;
	uint32_t res[3];

	/* Read header */
	if (fseek(cbf->f, 0, SEEK_SET) == -1) {
		fprintf(stderr, "Unable to move file cursor\n");
		return 1;
	}
	if (fread(&header, sizeof(header), 1, cbf->f) != 1) {
		fprintf(stderr, "Unable to read CBF header\n");
		return 1;
	}
	if (memcmp(&header.signature, cbf_sig, sizeof(cbf_sig))) {
		fprintf(stderr, "Not a CBF file\n");
		return 1;
	}

	if (header.table_offset < sizeof(struct CBF_Header) ||
	    header.table_offset > (header.archive_size - header.table_size) ||
	    header.table_size >= header.archive_size) {
		fprintf(stderr, "Invalid CBF file table location\n");
		return 1;
	}

	if (header.res1 != 0u || header.res2 != 0u ||
	    header.res3 != 0u || header.res4 != 0u) {
		fprintf(stderr, "Found non-zero reserved fields in header\n");
	}

	if (header.header_size != 0u) {
		if (header.header_size < 64u) {
			fprintf(stderr, "Invalid size of CBF header: %u\n",
				header.header_size);
			return 1;
		}

		if (fread(res, sizeof(res), 1, cbf->f) != 1) {
			fprintf(stderr, "Unable to read reserved fields\n");
			return 1;
		}
		if (res[0] != 0u || res[1] != 0u || res[2] != 0u)
			fprintf(stderr, "Found non-zero reserved fields");

		if (header.header_size > 70u) {
			if (cbf_parse_comment(cbf, header.header_size))
				return 1;
		} else if (header.header_size > 64u) {
			fprintf(stderr, "Invalid header size: %u\n",
				header.header_size);
			return 1;
		}
	}

	/* Check for file size consistency */
	if (fseek(cbf->f, 0, SEEK_END) == -1)
		fprintf(stderr, "Unable to move file cursor\n");
	else if ((file_size = ftell(cbf->f)) == -1)
		fprintf(stderr, "Unable to read file cursor\n");
	else if (file_size != (long) header.archive_size)
		fprintf(stderr, "Incorrect archive size (%ld vs %u)\n",
			file_size, header.archive_size);

	cbf->mode     = (header.header_size) ? CBF_MOD_EXTENDED :
					       CBF_MOD_CLASSIC;
	cbf->a_size   = header.archive_size;
	cbf->h_size   = (header.header_size) ? header.header_size : 52u;
	cbf->file_num = header.file_count;
	cbf->t_offset = header.table_offset;
	cbf->t_size   = header.table_size;

	return 0;
}

static void cbf_decrypt_file_desc(uint8_t *ptr, size_t bytes, uint8_t key)
{
	uint8_t enc_byte;

	for (size_t pos = 0; pos < bytes; pos++) {
		enc_byte = ptr[pos];
		ptr[pos] = enc_byte ^ cbf_file_desc_lut[key & 0x0F];
		key = enc_byte;
	}
}

static int cbf_parse_file_desc(cbf_file_t *cbf_file, struct CBF_File *data,
			       size_t bytes)
{
	size_t name_len = bytes - sizeof(struct CBF_File);
	uint8_t key = bytes & 0xFF;

	cbf_decrypt_file_desc((uint8_t *) data, bytes, key);

	if (data->res1 != 0u || data->res2 != 0u) {
		fprintf(stderr, "Unexpected data in file descriptor\n");
	}

	if (data->encoding != CBF_ENC_ENCRYPTION &&
	    data->encoding != CBF_ENC_COMPRESSION) {
		fprintf(stderr, "Unknown encoding method\n");
		return -1;
	}

	if ((cbf_file->name = (char *) malloc(name_len)) == NULL) {
		fprintf(stderr, "Unable to malloc mem\n");
		return -1;
	}

	memcpy(cbf_file->name, data->name, name_len);

	cbf_file->offset    = data->file_offset;
	cbf_file->size      = data->file_size;
	cbf_file->comp_size = data->compressed_size;
	cbf_file->encoding  = data->encoding;

	return 0;
}

static int cbf_load_file_descs(cbf_t *cbf)
{
	struct CBF_File *data = NULL;
	size_t total_size = cbf->h_size;
	uint32_t read_size = 0;
	uint32_t file_cnt;
	uint16_t prev_desc_size = 0;
	uint16_t desc_size;

	if (fseek(cbf->f, cbf->t_offset, SEEK_SET) == -1) {
		fprintf(stderr, "Unable to move file cursor\n");
		return 1;
	}

	for (file_cnt = 0; file_cnt < cbf->file_num; file_cnt++) {
		cbf_file_t *cbf_file = &cbf->file_descs[file_cnt];

		if ((fread(&desc_size, sizeof(desc_size), 1, cbf->f)) != 1) {
			fprintf(stderr, "Unable to read file desc size\n");
			break;
		}
		read_size += sizeof(desc_size);

		if (desc_size <= sizeof(struct CBF_File)) {
			fprintf(stderr, "Invalid file desc size\n");
			break;
		}

		if (prev_desc_size < desc_size || data == NULL) {
			data = (struct CBF_File *) realloc(data, desc_size);
			if (data == NULL) {
				fprintf(stderr, "Unable to realloc memory\n");
				break;
			}
			prev_desc_size = desc_size;
		}

		if ((fread(data, desc_size, 1, cbf->f)) != 1) {
			fprintf(stderr, "Unable to read file desc\n");
			break;
		}
		read_size += desc_size;

		if (cbf_parse_file_desc(cbf_file, data, desc_size))
			break;

		if (cbf->mode == CBF_MOD_CLASSIC &&
		    (data->unk1 != 0 || data->date_low != 0 ||
		    data->date_high != 0)) {
			fprintf(stderr, "Found non-zero reserved fields\n");
		}

		total_size += (cbf_file->encoding) ? cbf_file->comp_size :
						     cbf_file->size;
		cbf_file->cbf = cbf;
	}
	total_size += read_size;

	if (file_cnt != cbf->file_num) {
		fprintf(stderr, "Found only %u/%u valid file descriptors\n",
			file_cnt, cbf->file_num);
		cbf->file_num = file_cnt;
	}
	else if (read_size != cbf->t_size) {
		fprintf(stderr, "Incorrect file descriptor table size\n");
	} else if (total_size != cbf->a_size) {
		fprintf(stderr, "Incorrect archive size\n");
	}

	if (data)
		free(data);

	return 0;
}

static void cbf_decrypt_file(uint8_t *ptr, size_t bytes, uint8_t key)
{
	for (size_t pos = 0; pos < bytes; pos++)
		ptr[pos] = (ptr[pos] + cbf_file_salt + key) ^ key;
}

cbf_t *cbf_open(const char *path)
{
	cbf_t *cbf;

	if ((cbf = (cbf_t *) calloc(sizeof(cbf_t), 1)) == NULL) {
		fprintf(stderr, "Unable to calloc memory\n");
		goto err_mem;
	}

	if ((cbf->f = fopen(path, "rb")) == NULL) {
		fprintf(stderr, "Unable to open file %s\n", path);
		goto err_fopen;
	}

	if (cbf_parse_header(cbf)) {
		fprintf(stderr, "Error while parsing CBF header\n");
		goto err_parse_header;
	}

	if ((cbf->file_descs = (cbf_file_t *) malloc(sizeof(cbf_file_t) *
	    cbf->file_num)) == NULL) {
		fprintf(stderr, "Unable to alloc file descs memory\n");
		goto err_mem_desc;
	}

	if (cbf_load_file_descs(cbf)) {
		fprintf(stderr, "Error while parsing CBF file descriptors\n");
		goto err_parse_descs;
	}

	return cbf;

err_parse_descs:
	free(cbf->file_descs);
err_mem_desc:
err_parse_header:
	fclose(cbf->f);
err_fopen:
	free(cbf);
err_mem:
	return NULL;
}

void cbf_close(cbf_t *cbf)
{
	uint32_t fid;

	if (cbf) {
		if (cbf->file_descs) {
			for (fid = 0; fid < cbf->file_num; fid++)
				if (cbf->file_descs[fid].name)
					free(cbf->file_descs[fid].name);
			free(cbf->file_descs);
		}

		if (cbf->comment)
			free(cbf->comment);
		if (cbf->f)
			fclose(cbf->f);

		free(cbf);
	}
}

uint32_t cbf_get_num_files(cbf_t *cbf)
{
	if (!cbf)
		return 0u;

	return cbf->file_num;
}

const char *cbf_get_name(cbf_t *cbf, uint32_t index)
{
	if (!cbf || index >= cbf->file_num)
		return NULL;

	return (const char *) cbf->file_descs[index].name;
}

int cbf_get_index(cbf_t *cbf, const char *name, uint32_t *index)
{
	uint32_t f_id;
	const char *f_name;

	if (!cbf || !name || !index)
		return 1;

	for (f_id = 0; f_id < cbf->file_num; f_id++) {
		f_name = cbf_get_name(cbf, f_id);
		if (strcmp(name, f_name) == 0) {
			*index = f_id;
			return 0;
		}
	}

	return 0;
}

cbf_file_t *cbf_fopen(cbf_t *cbf, const char *name)
{
	uint32_t index;

	if (cbf_get_index(cbf, name, &index))
		return NULL;

	return cbf_fopen_index(cbf, index);
}

cbf_file_t *cbf_fopen_index(cbf_t *cbf, uint32_t index)
{
	cbf_file_t *file;

	if (!cbf || index >= cbf->file_num)
		return NULL;

	file = &cbf->file_descs[index];
	file->cur_ptr = 0u;

	return (file->encoding == CBF_ENC_ENCRYPTION) ? file : NULL;
}

size_t cbf_fread(void *ptr, size_t bytes, cbf_file_t *file)
{
	cbf_t *cbf;
	size_t bytes_max;
	size_t ret;

	if (ptr == NULL || file == NULL ||
	    file->cbf == NULL || file->cbf->f == NULL)
		return 0;

	cbf = file->cbf;

	if (fseek(cbf->f, file->offset + file->cur_ptr, SEEK_SET) == -1)
		return 0;

	bytes_max = file->size - file->cur_ptr;
	ret = fread(ptr, 1, (bytes > bytes_max) ? bytes_max : bytes, cbf->f);
	file->cur_ptr += ret;

	if (file->encoding == CBF_ENC_ENCRYPTION)
		cbf_decrypt_file((uint8_t *) ptr, ret, file->size);

	return ret;
}

int cbf_fseek(cbf_file_t *file, uint32_t offset)
{
	if (!file || offset > file->size)
		return -1;

	file->cur_ptr = offset;

	return 0;
}

int cbf_ftell(cbf_file_t *file, uint32_t *offset)
{
	if (!file)
		return -1;

	*offset = file->cur_ptr;

	return 0;
}

void cbf_fclose(cbf_file_t *file)
{
	return;
}


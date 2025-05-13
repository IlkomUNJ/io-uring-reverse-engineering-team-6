// SPDX-License-Identifier: GPL-2.0

#include "alloc_cache.h"

/*
 * Fungsi ini membebaskan semua entri yang tersimpan dalam cache dengan
 * memanggil fungsi @free untuk setiap entri, kemudian membebaskan memori
 * yang dialokasikan untuk penyimpanan cache itu sendiri.
 */
void io_alloc_cache_free(struct io_alloc_cache *cache,
			 void (*free)(const void *))
{
	void *entry;

	if (!cache->entries)
		return;

	while ((entry = io_alloc_cache_get(cache)) != NULL)
		free(entry);

	kvfree(cache->entries);
	cache->entries = NULL;
}

/*
 * Fungsi ini mengalokasikan memori untuk menyimpan pointer ke entri cache
 * dan menginisialisasi parameter cache. Cache yang diinisialisasi akan kosong.
 *
 * Return: true jika gagal mengalokasikan memori, false jika berhasil
 */
bool io_alloc_cache_init(struct io_alloc_cache *cache,
			 unsigned max_nr, unsigned int size,
			 unsigned int init_bytes)
{
	cache->entries = kvmalloc_array(max_nr, sizeof(void *), GFP_KERNEL);
	if (!cache->entries)
		return true;

	cache->nr_cached = 0;
	cache->max_cached = max_nr;
	cache->elem_size = size;
	cache->init_clear = init_bytes;
	return false;
}

/*
 * Fungsi ini mengalokasikan elemen baru dengan ukuran yang ditentukan
 * dalam cache, dan menginisialisasi memori jika init_clear diatur.
 * Berbeda dengan alokasi dari cache, fungsi ini selalu membuat alokasi baru.
 *
 * Return: Pointer ke memori yang dialokasikan, atau NULL jika gagal
 */
void *io_cache_alloc_new(struct io_alloc_cache *cache, gfp_t gfp)
{
	void *obj;

	obj = kmalloc(cache->elem_size, gfp);
	if (obj && cache->init_clear)
		memset(obj, 0, cache->init_clear);
	return obj;
}
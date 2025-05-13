#ifndef IOU_ALLOC_CACHE_H
#define IOU_ALLOC_CACHE_H

#include <linux/io_uring_types.h>

/*
 * Don't allow the cache to grow beyond this size.
 */
#define IO_ALLOC_CACHE_MAX	128

void io_alloc_cache_free(struct io_alloc_cache *cache,
			 void (*free)(const void *));
			 /*membersihkan cache dengan membebaskan semua entri yang tersimpan di dalamnya menggunakan 
			 fungsi free yang diberikan, dan kemudian membebaskan memori yang dialokasikan untuk penyimpanan cache itu sendiri.*/
bool io_alloc_cache_init(struct io_alloc_cache *cache,
			 unsigned max_nr, unsigned int size,
			 unsigned int init_bytes);
			 /*mengalokasikan memori untuk menyimpan pointer ke entri-entri cache, menginisialisasi parameter-parameter cache, 
			 dan memastikan cache yang baru diinisialisasi berada dalam keadaan kosong.*/

void *io_cache_alloc_new(struct io_alloc_cache *cache, gfp_t gfp);
/*mengalokasikan memori untuk elemen baru dengan ukuran yang ditentukan, dan jika init_clear diatur, fungsi ini juga menginisialisasi
 memori tersebut; berbeda dengan alokasi dari cache, fungsi ini selalu membuat alokasi memori yang baru.*/

static inline bool io_alloc_cache_put(struct io_alloc_cache *cache,
				      void *entry)
{
	if (cache->nr_cached < cache->max_cached) {
		if (!kasan_mempool_poison_object(entry))
			return false;
		cache->entries[cache->nr_cached++] = entry;
		return true;
	}
	return false;
}
/*Fungsi ini menambahkan sebuah entri ke dalam cache jika masih terdapat ruang yang tersedia.
Jika penambahan berhasil, fungsi ini juga memperbarui jumlah entri yang saat ini disimpan dalam cache.*/
static inline void *io_alloc_cache_get(struct io_alloc_cache *cache)
{
	if (cache->nr_cached) {
		void *entry = cache->entries[--cache->nr_cached];

		/*
		 * If KASAN is enabled, always clear the initial bytes that
		 * must be zeroed post alloc, in case any of them overlap
		 * with KASAN storage.
		 */
#if defined(CONFIG_KASAN)
		kasan_mempool_unpoison_object(entry, cache->elem_size);
		if (cache->init_clear)
			memset(entry, 0, cache->init_clear);
#endif
		return entry;
	}

	return NULL;
}
/*Fungsi ini mengambil sebuah entri dari cache jika cache tersebut tidak kosong.
Setelah mengambil entri, fungsi ini memperbarui jumlah entri yang tersimpan dalam cache.*/

static inline void *io_cache_alloc(struct io_alloc_cache *cache, gfp_t gfp)
{
	void *obj;

	obj = io_alloc_cache_get(cache);
	if (obj)
		return obj;
	return io_cache_alloc_new(cache, gfp);
}
/*Fungsi ini mengalokasikan memori untuk sebuah elemen, dengan mencoba mengambilnya dari cache terlebih dahulu.
Jika pengambilan dari cache gagal, fungsi ini akan mengalokasikan memori baru untuk elemen tersebut.*/
static inline void io_cache_free(struct io_alloc_cache *cache, void *obj)
{
	if (!io_alloc_cache_put(cache, obj))
		kfree(obj);
}
/*Fungsi ini membebaskan memori yang dialokasikan untuk sebuah elemen, dengan mencoba mengembalikannya ke cache jika ada ruang.
Jika cache penuh, fungsi ini akan membebaskan memori elemen tersebut sepenuhnya.*/
#endif

#ifndef IO_URING_MEMMAP_H
#define IO_URING_MEMMAP_H

#define IORING_MAP_OFF_PARAM_REGION		0x20000000ULL
#define IORING_MAP_OFF_ZCRX_REGION		0x30000000ULL

//io_pin_pages digunakan untuk menyematkan(to pin) sejumlah halaman dari memori ruang pengguna(user-space)
struct page **io_pin_pages(unsigned long ubuf, unsigned long len, int *npages);

/*
 *io_uring_nommu_mmap_capabilities hanya akan dikompilasi jika konfigurasi MMU tidak diaktifkan
 *jika MMU tidak diaktifkan maka fungsi ini akan digunakan untuk mendapatkan kegunaan mmap khusus untuk io_uring.
*/
#ifndef CONFIG_MMU
unsigned int io_uring_nommu_mmap_capabilities(struct file *file);
#endif

//io_uring_get_unmapped_area berfungsi untuk menemukan area memori yang belum dipetakan untuk operasi mmap().
unsigned long io_uring_get_unmapped_area(struct file *file, unsigned long addr,
					 unsigned long len, unsigned long pgoff,
					 unsigned long flags);
//io_uring_mmap berfungsi untuk memetakan sebuah file ke dalam memori, berperan sebagai antarmuka mmap untuk io_uring.
int io_uring_mmap(struct file *file, struct vm_area_struct *vma);

//io_free_region berfungsi untuk membebaskan region (wilayah) yang telah dipetakan dan terasosiasi dengan io_uring.
void io_free_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr);

//io_create_region untuk membuat dan memetakan sebuah region memori dalam konteks io_uring.
int io_create_region(struct io_ring_ctx *ctx, struct io_mapped_region *mr,
		     struct io_uring_region_desc *reg,
		     unsigned long mmap_offset);

/*
 *io_create_region_mmap_safe adalah versi aman dari io_create_region yang menambahkan pengecekan  
 *atau mengunci (lock) untuk mencegah kondisi balapan (race condition) saat pemetaan memori.
*/
int io_create_region_mmap_safe(struct io_ring_ctx *ctx,
				struct io_mapped_region *mr,
				struct io_uring_region_desc *reg,
				unsigned long mmap_offset);
//fungsi inline io_region_get_ptr hanya digunakan untuk mendapatkan anggota ptr dari struktur io_mapped_region.
static inline void *io_region_get_ptr(struct io_mapped_region *mr)
{
	return mr->ptr;
}

//io_region_is_set digunakan untuk memeriksa apakah region yang dipetakan memiliki jumlah halaman yang bukan nol.
static inline bool io_region_is_set(struct io_mapped_region *mr)
{
	return !!mr->nr_pages;
}

#endif

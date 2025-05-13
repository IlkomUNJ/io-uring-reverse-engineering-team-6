// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_RSRC_H
#define IOU_RSRC_H

#include <linux/io_uring_types.h>
#include <linux/lockdep.h>

#define IO_VEC_CACHE_SOFT_CAP		256

enum {
	IORING_RSRC_FILE		= 0,
	IORING_RSRC_BUFFER		= 1,
};

//Representasi dari sebuah node sumber daya (resource) di dalam IO uring
struct io_rsrc_node {
	unsigned char			type; //Tipe dari sumber daya (file atau buffer).
	int				refs; // Jumlah referensi yang sedang digunakan (untuk reference counting).

	u64 tag; //Identifikasi unik untuk sumber daya.
	union {
		unsigned long file_ptr; //Pointer ke objek file jika tipe adalah file.
		struct io_mapped_ubuf *buf; //Pointer ke objek buffer jika tipe adalah buffer.
	};
};

enum {
	IO_IMU_DEST	= 1 << ITER_DEST,
	IO_IMU_SOURCE	= 1 << ITER_SOURCE,
};

//Representasi dari buffer yang dipetakan (mapped buffer) ke dalam memori kernel.
struct io_mapped_ubuf {
	u64		ubuf; // Alamat buffer di ruang pengguna
	unsigned int	len; //Panjang buffer
	unsigned int	nr_bvecs; //Jumlah vektor buffer
	unsigned int    folio_shift; //Pergeseran halaman (page shift) dalam buffer
	refcount_t	refs; //Referensi counter
	unsigned long	acct_pages; //Jumlah halaman yang di-account
	void		(*release)(void *); //Fungsi callback ketika buffer dilepas
	void		*priv; //Data privat pengguna
	bool		is_kbuf; //Menandai apakah buffer ini adalah buffer kernel
	u8		dir; //Arah operasi (directory)
	struct bio_vec	bvec[] __counted_by(nr_bvecs); //Array dari struktur bio_vec untuk akses fisik.
};

struct io_imu_folio_data {
	/* Head folio can be partially included in the fixed buf */
	unsigned int	nr_pages_head;
	/* For non-head/tail folios, has to be fully included */
	unsigned int	nr_pages_mid;
	unsigned int	folio_shift;
	unsigned int	nr_folios;
};

//Menginisialisasi cache sumber daya
bool io_rsrc_cache_init(struct io_ring_ctx *ctx);
//Membebaskan cache sumber daya
void io_rsrc_cache_free(struct io_ring_ctx *ctx);

//Mengalokasikan node sumber daya baru.
struct io_rsrc_node *io_rsrc_node_alloc(struct io_ring_ctx *ctx, int type);
//Membebaskan node sumber daya yang sudah tidak digunakan.
void io_free_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node);

//Fungsi ini digunakan untuk membebaskan memori yang terkait dengan io_rsrc_data
void io_rsrc_data_free(struct io_ring_ctx *ctx, struct io_rsrc_data *data);
//Fungsi ini digunakan untuk mengalokasikan memori untuk struktur io_rsrc_data
int io_rsrc_data_alloc(struct io_rsrc_data *data, unsigned nr);

//Mencari node buffer yang terkait dengan sebuah request (io_kiocb).
struct io_rsrc_node *io_find_buf_node(struct io_kiocb *req,
				      unsigned issue_flags);
//Mengimpor buffer yang terdaftar ke dalam iterasi IO
int io_import_reg_buf(struct io_kiocb *req, struct iov_iter *iter,
			u64 buf_addr, size_t len, int ddir,
			unsigned issue_flags);
//Mengimpor vektor IO yang terdaftar
int io_import_reg_vec(int ddir, struct iov_iter *iter,
			struct io_kiocb *req, struct iou_vec *vec,
			unsigned nr_iovs, unsigned issue_flags);
//Fungsi ini digunakan untuk mempersiapkan vektor I/O yang terdaftar sebelum digunakan dalam operasi I/O asinkron.
int io_prep_reg_iovec(struct io_kiocb *req, struct iou_vec *iv,
			const struct iovec __user *uvec, size_t uvec_segs);

//Fungsi ini digunakan untuk mendaftarkan buffer kloning di dalam konteks IO
int io_register_clone_buffers(struct io_ring_ctx *ctx, void __user *arg);
//Fungsi ini digunakan untuk membatalkan registrasi buffer yang sebelumnya didaftarkan di IO ring.
int io_sqe_buffers_unregister(struct io_ring_ctx *ctx);
//ungsi ini digunakan untuk mendaftarkan sekumpulan buffer ke dalam konteks IO ring
int io_sqe_buffers_register(struct io_ring_ctx *ctx, void __user *arg,
			    unsigned int nr_args, u64 __user *tags);
//Fungsi ini digunakan untuk membatalkan registrasi file descriptor yang sebelumnya didaftarkan
int io_sqe_files_unregister(struct io_ring_ctx *ctx);
//Fungsi ini digunakan untuk mendaftarkan sekumpulan file descriptor ke dalam ring IO
int io_sqe_files_register(struct io_ring_ctx *ctx, void __user *arg,
			  unsigned nr_args, u64 __user *tags);

//Fungsi ini digunakan untuk memperbarui daftar file descriptor yang sudah terdaftar di ring IO.
int io_register_files_update(struct io_ring_ctx *ctx, void __user *arg,
			     unsigned nr_args);
//Fungsi ini digunakan untuk memperbarui sumber daya (resource) di dalam konteks ring IO.
int io_register_rsrc_update(struct io_ring_ctx *ctx, void __user *arg,
			    unsigned size, unsigned type);
//Fungsi ini digunakan untuk mendaftarkan sumber daya baru ke dalam ring IO.
int io_register_rsrc(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int size, unsigned int type);
//Fungsi ini digunakan untuk memvalidasi buffer sebelum digunakan di dalam operasi IO.
int io_buffer_validate(struct iovec *iov);
//Fungsi ini bertugas untuk mengecek apakah beberapa buffer bisa digabungkan (coalesce) menjadi satu.
bool io_check_coalesce_buffer(struct page **page_array, int nr_pages,
			      struct io_imu_folio_data *data);

//Mencari node sumber daya berdasarkan indeks di dalam struktur data.
static inline struct io_rsrc_node *io_rsrc_node_lookup(struct io_rsrc_data *data,
						       int index)
{
	if (index < data->nr)
		return data->nodes[array_index_nospec(index, data->nr)];
	return NULL;
}

//Mengurangi referensi (refcount) dari node, dan membebaskan jika tidak ada referensi yang tersisa.
static inline void io_put_rsrc_node(struct io_ring_ctx *ctx, struct io_rsrc_node *node)
{
	lockdep_assert_held(&ctx->uring_lock);
	if (!--node->refs)
		io_free_rsrc_node(ctx, node);
}

//Mereset node sumber daya pada indeks tertentu.
static inline bool io_reset_rsrc_node(struct io_ring_ctx *ctx,
				      struct io_rsrc_data *data, int index)
{
	struct io_rsrc_node *node = data->nodes[index];

	if (!node)
		return false;
	io_put_rsrc_node(ctx, node);
	data->nodes[index] = NULL;
	return true;
}

//Fungsi ini bertugas untuk melepaskan referensi dari node sumber daya (resource node) yang terikat pada request IO 
static inline void io_req_put_rsrc_nodes(struct io_kiocb *req)
{
	if (req->file_node) {
		io_put_rsrc_node(req->ctx, req->file_node);
		req->file_node = NULL;
	}
	if (req->flags & REQ_F_BUF_NODE) {
		io_put_rsrc_node(req->ctx, req->buf_node);
		req->buf_node = NULL;
	}
}

//Fungsi ini bertugas untuk menghubungkan sebuah node sumber daya ke sebuah pointer tujuan
static inline void io_req_assign_rsrc_node(struct io_rsrc_node **dst_node,
					   struct io_rsrc_node *node)
{
	node->refs++;
	*dst_node = node;
}

//Fungsi ini adalah versi spesifik dari io_req_assign_rsrc_node yang digunakan untuk buffer node
static inline void io_req_assign_buf_node(struct io_kiocb *req,
					  struct io_rsrc_node *node)
{
	io_req_assign_rsrc_node(&req->buf_node, node);
	req->flags |= REQ_F_BUF_NODE;
}

//Melakukan persiapan untuk memperbarui file descriptors atau sumber daya terkait IO pada IO uring.
int io_files_update(struct io_kiocb *req, unsigned int issue_flags);
// Menjalankan proses pembaruan file descriptors secara aktual saat operasi IO berlangsung.
int io_files_update_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

//Meng-account alokasi memori di bawah kontrol pengguna
int __io_account_mem(struct user_struct *user, unsigned long nr_pages);

//Melepaskan (unaccount) alokasi memori yang sudah tidak digunakan.
static inline void __io_unaccount_mem(struct user_struct *user,
				      unsigned long nr_pages)
{
	atomic_long_sub(nr_pages, &user->locked_vm);
}

//Fungsi ini bertanggung jawab untuk membebaskan memori yang dialokasikan oleh struktur iou_vec
void io_vec_free(struct iou_vec *iv);
//Fungsi ini digunakan untuk mengubah ukuran alokasi memori dari iou_vec
int io_vec_realloc(struct iou_vec *iv, unsigned nr_entries);

//Fungsi ini bertujuan untuk menginisialisasi ulang struktur iou_vec
static inline void io_vec_reset_iovec(struct iou_vec *iv,
				      struct iovec *iovec, unsigned nr)
{
	io_vec_free(iv);
	iv->iovec = iovec;
	iv->nr = nr;
}

//Fungsi ini akan memeriksa apakah kasan diaktifkan dalam konfigurasi kernel.
static inline void io_alloc_cache_vec_kasan(struct iou_vec *iv)
{
	if (IS_ENABLED(CONFIG_KASAN))
		io_vec_free(iv);
}

#endif

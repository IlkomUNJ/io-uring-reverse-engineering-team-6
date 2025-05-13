// SPDX-License-Identifier: GPL-2.0

#include "cancel.h"

int io_futex_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/*ini menyiapkan permintaan operasi futex tunggal berdasarkan informasi dari submission queue entry (sqe).*/
int io_futexv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/*menyiapkan permintaan operasi futex dengan banyak alamat (vector) berdasarkan informasi dari submission queue entry (sqe).*/
int io_futex_wait(struct io_kiocb *req, unsigned int issue_flags);
/*memulai operasi menunggu pada futex tunggal secara asinkron.*/
int io_futexv_wait(struct io_kiocb *req, unsigned int issue_flags);
/*memulai operasi menunggu pada beberapa futex (vector) secara asinkron.*/
int io_futex_wake(struct io_kiocb *req, unsigned int issue_flags);
/*memulai operasi membangunkan satu atau lebih thread yang sedang menunggu pada futex secara asinkron.*/

#if defined(CONFIG_FUTEX)
int io_futex_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		    unsigned int issue_flags);
			/*digunakan untuk membatalkan operasi futex yang sedang berlangsung dalam konteks ring I/O (ctx) berdasarkan data pembatalan (cd) dan flag.*/
bool io_futex_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			 bool cancel_all);
			 /*digunakan untuk menghapus semua operasi futex yang terkait dengan sebuah task (tctx) dalam konteks ring I/O 
			 (ctx), dengan opsi untuk membatalkannya (cancel_all).*/
bool io_futex_cache_init(struct io_ring_ctx *ctx);
/*menginisialisasi cache yang digunakan untuk mengelola sumber daya atau informasi terkait operasi futex dalam konteks ring I/O (ctx).*/
void io_futex_cache_free(struct io_ring_ctx *ctx);
/*membersihkan dan membebaskan sumber daya yang dialokasikan oleh io_futex_cache_init dalam konteks ring I/O (ctx).*/
#else
static inline int io_futex_cancel(struct io_ring_ctx *ctx,
				  struct io_cancel_data *cd,
				  unsigned int issue_flags)
				  /*ketika CONFIG_FUTEX diaktifkan, selalu mengembalikan 0, yang mengindikasikan operasi 
				  pembatalan futex berhasil tanpa melakukan tindakan spesifik.*/
{
	return 0;
}
static inline bool io_futex_remove_all(struct io_ring_ctx *ctx,
				       struct io_uring_task *tctx, bool cancel_all)
{
	return false;
}
/* ketika CONFIG_FUTEX diaktifkan, selalu mengembalikan false, yang mengindikasikan tidak ada operasi futex yang dihapus atau dibatalkan.*/
static inline bool io_futex_cache_init(struct io_ring_ctx *ctx)
{
	return false;
}
/*ketika CONFIG_FUTEX diaktifkan, selalu mengembalikan false, yang mengindikasikan inisialisasi cache futex tidak diperlukan atau gagal.*/
static inline void io_futex_cache_free(struct io_ring_ctx *ctx)
{
}
/*ketika CONFIG_FUTEX diaktifkan, tidak melakukan tindakan apa pun, mengindikasikan tidak ada sumber daya cache futex yang perlu dibebaskan.*/
#endif

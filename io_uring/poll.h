// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring_types.h>

#define IO_POLL_ALLOC_CACHE_MAX 32

enum {
	IO_APOLL_OK,
	IO_APOLL_ABORTED,
	IO_APOLL_READY
};
//Struktur ini merepresentasikan informasi terkait operasi polling.
struct io_poll {
	struct file			*file; //Pointer ke objek file yang sedang dipolling.
	struct wait_queue_head		*head; //Antrian tunggu (wait queue) yang akan dipantau.
	__poll_t			events; //Event atau kejadian yang ditunggu (seperti POLLIN, POLLOUT).
	int				retries; //Jumlah percobaan polling yang dilakukan.
	struct wait_queue_entry		wait; //Entri dalam antrian tunggu.
};
//Struktur ini memperluas struktur io_poll untuk mendukung operasi polling ganda (double poll).
struct async_poll {
	struct io_poll		poll; //Struktur utama polling.
	struct io_poll		*double_poll; //Digunakan jika operasi membutuhkan dua polling secara bersamaan.
};

/*
 *Fungsi ini digunakan untuk meningkatkan (increment) nilai referensi polling (poll_refs) secara atomik.
 * Must only be called inside issue_flags & IO_URING_F_MULTISHOT, or
 * potentially other cases where we already "own" this poll request.
 */
static inline void io_poll_multishot_retry(struct io_kiocb *req)
{
	atomic_inc(&req->poll_refs);
}

//Menyiapkan permintaan polling (request) berdasarkan parameter dari SQE
int io_poll_add_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//Menjalankan polling pada objek file yang ditargetkan.
int io_poll_add(struct io_kiocb *req, unsigned int issue_flags);

//Menyiapkan proses penghapusan polling.
int io_poll_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//Mengeksekusi proses penghapusan polling dari daftar tunggu.
int io_poll_remove(struct io_kiocb *req, unsigned int issue_flags);

struct io_cancel_data;
//Membatalkan polling yang sedang berlangsung.
int io_poll_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		   unsigned issue_flags);
//Menangani eksekusi polling ketika event yang ditunggu telah terjadi.
int io_arm_poll_handler(struct io_kiocb *req, unsigned issue_flags);
//Menghapus semua entri polling yang terkait dengan konteks tugas (tctx).
bool io_poll_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			bool cancel_all);

//Fungsi ini dijalankan sebagai task untuk memproses polling di dalam kernel
void io_poll_task_func(struct io_kiocb *req, io_tw_token_t tw);

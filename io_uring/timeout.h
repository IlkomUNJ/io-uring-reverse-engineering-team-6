// SPDX-License-Identifier: GPL-2.0

/**
 * struct io_timeout_data - Struktur data untuk menangani timeout pada permintaan io_uring
 * @req: Permintaan I/O yang berkaitan
 * @timer: High-resolution timer untuk timeout
 * @ts: Nilai timeout dalam format timespec64
 * @mode: Mode dari hrtimer (relatif/absolut)
 * @flags: Flag tambahan untuk konfigurasi timeout
 */
 struct io_timeout_data {
	struct io_kiocb			*req;
	struct hrtimer			timer;
	struct timespec64		ts;
	enum hrtimer_mode		mode;
	u32				flags;
};

/**
 * __io_disarm_linked_timeout - Membatalkan timeout yang ditautkan ke permintaan lain
 * @req: Permintaan utama
 * @link: Permintaan timeout yang ditautkan
 *
 * Return: Pointer ke permintaan timeout yang dibatalkan jika ada, NULL jika tidak.
 */
struct io_kiocb *__io_disarm_linked_timeout(struct io_kiocb *req,
					    struct io_kiocb *link);

/**
 * io_disarm_linked_timeout - Membatalkan timeout yang ditautkan jika ada
 * @req: Permintaan utama
 *
 * Return: Pointer ke permintaan timeout jika ditemukan dan dibatalkan, NULL jika tidak ada.
 */
static inline struct io_kiocb *io_disarm_linked_timeout(struct io_kiocb *req)
{
	struct io_kiocb *link = req->link;

	if (link && link->opcode == IORING_OP_LINK_TIMEOUT)
		return __io_disarm_linked_timeout(req, link);

	return NULL;
}

/**
 * io_flush_timeouts - Menghapus semua permintaan timeout yang tertunda dalam konteks
 * @ctx: Konteks io_uring
 */
__cold void io_flush_timeouts(struct io_ring_ctx *ctx);

struct io_cancel_data;

/**
 * io_timeout_cancel - Membatalkan permintaan timeout berdasarkan data pembatalan
 * @ctx: Konteks io_uring
 * @cd: Data pembatalan (cancel data)
 *
 * Return: 0 jika berhasil, atau kode kesalahan jika gagal.
 */
int io_timeout_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd);

/**
 * io_kill_timeouts - Membatalkan semua timeout untuk task tertentu
 * @ctx: Konteks io_uring
 * @tctx: Konteks task pengguna io_uring
 * @cancel_all: True jika ingin membatalkan semua, false untuk selektif
 *
 * Return: True jika ada timeout yang dibatalkan, false jika tidak ada.
 */
__cold bool io_kill_timeouts(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			     bool cancel_all);

/**
 * io_queue_linked_timeout - Menjadwalkan permintaan timeout yang ditautkan
 * @req: Permintaan timeout
 */
void io_queue_linked_timeout(struct io_kiocb *req);

/**
 * io_disarm_next - Membatalkan permintaan berikutnya dalam urutan tautan jika ada
 * @req: Permintaan saat ini
 */
void io_disarm_next(struct io_kiocb *req);

/**
 * io_timeout_prep - Mempersiapkan permintaan timeout biasa
 * @req: Permintaan I/O
 * @sqe: Entry dari submission queue
 *
 * Return: 0 jika berhasil, atau kode kesalahan jika gagal.
 */
int io_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * io_link_timeout_prep - Mempersiapkan permintaan timeout yang ditautkan
 * @req: Permintaan I/O
 * @sqe: Entry dari submission queue
 *
 * Return: 0 jika berhasil, atau kode kesalahan jika gagal.
 */
int io_link_timeout_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * io_timeout - Menjalankan permintaan timeout (menunggu sampai timer berakhir)
 * @req: Permintaan I/O
 * @issue_flags: Flag pelaksanaan tambahan
 *
 * Return: 0 jika selesai, atau kode kesalahan jika terjadi error.
 */
int io_timeout(struct io_kiocb *req, unsigned int issue_flags);

/**
 * io_timeout_remove_prep - Mempersiapkan permintaan untuk menghapus timeout yang sedang aktif
 * @req: Permintaan I/O
 * @sqe: Entry dari submission queue
 *
 * Return: 0 jika berhasil, atau kode kesalahan.
 */
int io_timeout_remove_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * io_timeout_remove - Menjalankan penghapusan timeout
 * @req: Permintaan I/O
 * @issue_flags: Flag pelaksanaan tambahan
 *
 * Return: 0 jika berhasil, atau kode kesalahan.
 */
int io_timeout_remove(struct io_kiocb *req, unsigned int issue_flags);

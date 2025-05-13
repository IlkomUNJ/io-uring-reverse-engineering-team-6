// SPDX-License-Identifier: GPL-2.0

#include "../kernel/exit.h"

/**
 * struct io_waitid_async - Struktur untuk menyimpan informasi operasi waitid async
 * @req: Pointer ke permintaan io_uring (io_kiocb)
 * @wo: Struktur wait_opts untuk konfigurasi penantian
 */
struct io_waitid_async {
	struct io_kiocb *req;
	struct wait_opts wo;
};

/**
 * io_waitid_prep - Mempersiapkan operasi waitid
 * @req: Permintaan io_uring
 * @sqe: Submission Queue Entry dari userspace
 *
 * Return: 0 jika sukses, atau kode error negatif jika gagal.
 */
int io_waitid_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * io_waitid - Menjalankan operasi waitid
 * @req: Permintaan io_uring
 * @issue_flags: Flag eksekusi tambahan
 *
 * Return: Hasil dari operasi waitid atau kode error.
 */
int io_waitid(struct io_kiocb *req, unsigned int issue_flags);

/**
 * io_waitid_cancel - Membatalkan permintaan waitid
 * @ctx: Konteks io_uring
 * @cd: Data pembatalan
 * @issue_flags: Flag tambahan
 *
 * Return: 0 jika berhasil membatalkan, kode error jika gagal.
 */
int io_waitid_cancel(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags);

/**
 * io_waitid_remove_all - Menghapus semua permintaan waitid terkait task
 * @ctx: Konteks io_uring
 * @tctx: Task context
 * @cancel_all: Jika true, semua permintaan dibatalkan
 *
 * Return: true jika ada yang dihapus, false jika tidak.
 */
bool io_waitid_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  bool cancel_all);
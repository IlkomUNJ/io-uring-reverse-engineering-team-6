// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring/cmd.h>
#include <linux/io_uring_types.h>

/**
 * struct io_async_cmd - Struktur perintah async untuk io_uring
 * @data: Data perintah io_uring
 * @vec: Vektor buffer tetap (fixed buffer)
 * @sqes: Dua entri Submission Queue Entry (SQE)
 */
struct io_async_cmd {
	struct io_uring_cmd_data	data;
	struct iou_vec			vec;
	struct io_uring_sqe		sqes[2];
};

/**
 * io_uring_cmd - Eksekusi perintah io_uring
 * @req: Permintaan io_uring
 * @issue_flags: Flag tambahan saat eksekusi
 *
 * Return: 0 jika sukses, atau nilai negatif jika gagal.
 */
int io_uring_cmd(struct io_kiocb *req, unsigned int issue_flags);

/**
 * io_uring_cmd_prep - Mempersiapkan perintah io_uring
 * @req: Permintaan io_uring
 * @sqe: Submission Queue Entry dari userspace
 *
 * Return: 0 jika sukses, atau kode error jika gagal.
 */
int io_uring_cmd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * io_uring_cmd_cleanup - Membersihkan sumber daya perintah io_uring
 * @req: Permintaan io_uring
 */
void io_uring_cmd_cleanup(struct io_kiocb *req);

/**
 * io_uring_try_cancel_uring_cmd - Mencoba membatalkan perintah io_uring
 * @ctx: Konteks io_uring
 * @tctx: Task context yang bersangkutan
 * @cancel_all: Jika true, batalkan semua perintah terkait
 *
 * Return: true jika berhasil membatalkan, false jika tidak.
 */
bool io_uring_try_cancel_uring_cmd(struct io_ring_ctx *ctx,
				   struct io_uring_task *tctx, bool cancel_all);

/**
 * io_cmd_cache_free - Membebaskan entri cache perintah io_uring
 * @entry: Pointer ke entri yang akan dibebaskan
 */
void io_cmd_cache_free(const void *entry);

/**
 * io_uring_cmd_import_fixed_vec - Mengimpor vektor iovec tetap (fixed) dari userspace
 * @ioucmd: Struktur perintah io_uring
 * @uvec: Array iovec dari userspace
 * @uvec_segs: Jumlah segmen iovec
 * @ddir: Arah data transfer (misal read/write)
 * @iter: Iterator hasil yang akan diisi
 * @issue_flags: Flag tambahan saat eksekusi
 *
 * Return: 0 jika sukses, atau kode error jika gagal.
 */
int io_uring_cmd_import_fixed_vec(struct io_uring_cmd *ioucmd,
				  const struct iovec __user *uvec,
				  size_t uvec_segs,
				  int ddir, struct iov_iter *iter,
				  unsigned issue_flags);

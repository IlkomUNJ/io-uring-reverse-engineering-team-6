// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_CANCEL_H
#define IORING_CANCEL_H

#include <linux/io_uring_types.h>

struct io_cancel_data {
	struct io_ring_ctx *ctx;
	union {
		u64 data;
		struct file *file;
	};
	u8 opcode;
	u32 flags;
	int seq;
};
/*struktur data yang digunakan untuk menyimpan informasi yang diperlukan untuk membatalkan operasi I/O.*/

int io_async_cancel_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/*Fungsi ini menyiapkan operasi pembatalan asinkron berdasarkan entri queue submission (SQE).
Fungsi ini mungkin mengatur informasi spesifik pembatalan dalam struktur io_kiocb.*/
int io_async_cancel(struct io_kiocb *req, unsigned int issue_flags);
/*Fungsi ini melakukan pembatalan asinkron dari sebuah operasi I/O.
Fungsi ini menggunakan informasi yang disiapkan oleh io_async_cancel_prep dan flag terkait.*/

int io_try_cancel(struct io_uring_task *tctx, struct io_cancel_data *cd,
		  unsigned int issue_flags);
		  /*Fungsi ini mencoba membatalkan operasi I/O terkait dengan sebuah task (tctx) dengan data pembatalan tertentu.
Pembatalan mungkin tidak selalu berhasil dan bergantung pada status operasi.*/

int io_sync_cancel(struct io_ring_ctx *ctx, void __user *arg);
/*Fungsi ini melakukan pembatalan sinkron dari operasi I/O.
Fungsi ini mungkin digunakan untuk membatalkan operasi dari ruang pengguna.*/
bool io_cancel_req_match(struct io_kiocb *req, struct io_cancel_data *cd);
/*Fungsi ini memeriksa apakah sebuah permintaan I/O (io_kiocb) cocok dengan data pembatalan yang diberikan.
Fungsi ini digunakan untuk mengidentifikasi permintaan mana yang harus dibatalkan.*/

bool io_cancel_remove_all(struct io_ring_ctx *ctx, struct io_uring_task *tctx,
			  struct hlist_head *list, bool cancel_all,
			  bool (*cancel)(struct io_kiocb *));
/*Fungsi ini menghapus dan membatalkan semua permintaan I/O dari sebuah list.
Fungsi ini dapat membatalkan semua atau sebagian permintaan, menggunakan fungsi cancel yang diberikan.*/
int io_cancel_remove(struct io_ring_ctx *ctx, struct io_cancel_data *cd,
		     unsigned int issue_flags, struct hlist_head *list,
		     bool (*cancel)(struct io_kiocb *));
/*Fungsi ini menghapus dan membatalkan permintaan I/O tertentu dari sebuah list berdasarkan data pembatalan.
Fungsi ini menggunakan fungsi cancel yang diberikan untuk melakukan pembatalan.*/
static inline bool io_cancel_match_sequence(struct io_kiocb *req, int sequence)
{
	if (req->cancel_seq_set && sequence == req->work.cancel_seq)
		return true;

	req->cancel_seq_set = true;
	req->work.cancel_seq = sequence;
	return false;
}
/*Fungsi inline ini memeriksa apakah sebuah permintaan I/O cocok dengan nomor urut pembatalan tertentu.
Fungsi ini juga mengatur nomor urut pembatalan pada permintaan jika belum diatur.*/
#endif

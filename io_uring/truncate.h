// SPDX-License-Identifier: GPL-2.0

/**
 * io_ftruncate_prep - Mempersiapkan operasi ftruncate pada file descriptor
 * @req: Struktur permintaan I/O (io_kiocb)
 * @sqe: Submission Queue Entry (SQE) dari userspace
 */
 int io_ftruncate_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

 /**
  * io_ftruncate - Menjalankan operasi ftruncate untuk memotong file ke panjang tertentu
  * @req: Struktur permintaan I/O (io_kiocb)
  * @issue_flags: Flag tambahan yang digunakan saat eksekusi
  */
 int io_ftruncate(struct io_kiocb *req, unsigned int issue_flags);
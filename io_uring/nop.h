// SPDX-License-Identifier: GPL-2.0

//meyiapkan request nop (no operations)
int io_nop_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//mengeksekusi suatu request nop (no operation)
int io_nop(struct io_kiocb *req, unsigned int issue_flags);

// SPDX-License-Identifier: GPL-2.0

//digunakan secara internal untuk menutup deskriptor file tertentu yang terdaftar sebagai bagian dari fixed filetable.	.
int __io_close_fixed(struct io_ring_ctx *ctx, unsigned int issue_flags,
		     unsigned int offset);

//menyiapkan untuk syscall openat
int io_openat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//mengekseksi syscall openat 
int io_openat(struct io_kiocb *req, unsigned int issue_flags);

//membersihkan memori yang dialokasikan saat io_openat atau io_openat2 di eksekusi
void io_open_cleanup(struct io_kiocb *req);

//sama seperti openat, namun openat2 lebih fleksibel
int io_openat2_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_openat2(struct io_kiocb *req, unsigned int issue_flags);

//menyiapkan untuk syscall close untuk menutup suatu deskriptor file
int io_close_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//mengeksekusi syscall close
int io_close(struct io_kiocb *req, unsigned int issue_flags);

//menyiapkan untuk menginstall deskriptor file ke slot yang fixed
int io_install_fixed_fd_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//mengeksekusi penginstall deskriptor ke fixed slot
int io_install_fixed_fd(struct io_kiocb *req, unsigned int issue_flags);

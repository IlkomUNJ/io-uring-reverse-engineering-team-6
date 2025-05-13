// SPDX-License-Identifier: GPL-2.0
#ifndef IORING_REGISTER_H
#define IORING_REGISTER_H

//Menghapus pendaftaran eventfd dari konteks io_uring.
int io_eventfd_unregister(struct io_ring_ctx *ctx);

//Menghapus pendaftaran "personality" dalam io_uring.
//Personality adalah fitur yang memungkinkan pengguna untuk mengisolasi operasi IO tertentu dengan ID unik.
int io_unregister_personality(struct io_ring_ctx *ctx, unsigned id);

//berfungsi untuk mendapatkan objek file dari file descriptor (fd) yang terdaftar di io_uring.
struct file *io_uring_register_get_file(unsigned int fd, bool registered);

#endif

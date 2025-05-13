// SPDX-License-Identifier: GPL-2.0

//io_uring_sync_msg_ring berfungsi untuk mensikronisasikan message ring di dalam io_uring.
int io_uring_sync_msg_ring(struct io_uring_sqe *sqe);

//io_msg_ring_prep berfungsi untuk menyiapkan operasi message ring sebelum dijalankan.
int io_msg_ring_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

//io_msg_ring merupakan fungsi utama dalam eksekusi logika message ring.
//fungsi ini yang mengirim pesan menuju lokasi tujuan.
int io_msg_ring(struct io_kiocb *req, unsigned int issue_flags);

//io_msg_ring_cleanup befungsi untuk membersihkan yang ada di mmesssage ring setelah 
//operasi selesai atau dibatalkan.
void io_msg_ring_cleanup(struct io_kiocb *req);

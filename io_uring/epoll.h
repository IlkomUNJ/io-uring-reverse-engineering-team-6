// SPDX-License-Identifier: GPL-2.0

#if defined(CONFIG_EPOLL)
int io_epoll_ctl_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/*mempersiapkan operasi kontrol epoll (epoll_ctl) agar dapat dijalankan melalui io_uring. Informasi seperti file descriptor target, 
operasi yang akan dilakukan (menambah, memodifikasi, atau menghapus), dan event yang diinginkan diambil dari submission queue entry
 (sqe) dan disimpan dalam struktur I/O request (req).*/

int io_epoll_ctl(struct io_kiocb *req, unsigned int issue_flags);
/*mengirimkan permintaan kontrol epoll yang telah dipersiapkan (req) ke kernel melalui mekanisme io_uring. Flag issue_flags memberikan 
kontrol tambahan terkait bagaimana permintaan ini disubmit untuk dieksekusi.*/
int io_epoll_wait_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/*mempersiapkan operasi epoll_wait agar dapat dijalankan secara asinkron melalui io_uring. Informasi seperti file descriptor epoll dan 
jumlah maksimum event yang ingin diterima diambil dari sqe dan diatur dalam struktur I/O request (req).*/

int io_epoll_wait(struct io_kiocb *req, unsigned int issue_flags);
/*mengirimkan permintaan epoll_wait yang telah dipersiapkan (req) ke kernel melalui io_uring. Ketika ada event yang siap pada file descriptor
 yang dipantau oleh epoll, hasilnya akan dilaporkan kembali melalui mekanisme completion queue dari io_uring. Flag issue_flags mengatur bagaimana
 permintaan ini dikirim.*/
#endif

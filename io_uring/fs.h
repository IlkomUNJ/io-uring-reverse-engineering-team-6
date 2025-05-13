// SPDX-License-Identifier: GPL-2.0

int io_renameat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/* mempersiapkan operasi penggantian nama file atau direktori (renameat) untuk digunakan dengan io_uring. Informasi tentang direktori lama dan baru 
(beserta file descriptor jika relatif), nama lama dan baru, serta flag operasi diambil dari submission queue entry (sqe) dan disimpan dalam struktur 
I/O request (req).*/
int io_renameat(struct io_kiocb *req, unsigned int issue_flags);
/*mengirimkan permintaan penggantian nama (renameat) yang telah disiapkan (req) ke kernel melalui io_uring. Flag issue_flags mengontrol bagaimana 
permintaan ini disubmit untuk dieksekusi secara asinkron.*/
void io_renameat_cleanup(struct io_kiocb *req);
/*pembersihan setelah operasi renameat selesai (berhasil atau gagal). Ini mungkin melibatkan pelepasan sumber daya atau penanganan status penyelesaian 
setelah hasil diterima dari completion queue.*/

int io_unlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/*mempersiapkan operasi penghapusan file atau direktori (unlinkat) untuk io_uring. Informasi seperti direktori (file descriptor jika relatif), nama
 file atau direktori yang akan dihapus, dan flag (misalnya, untuk menghapus direktori) diambil dari sqe dan disimpan dalam req.*/
int io_unlinkat(struct io_kiocb *req, unsigned int issue_flags);
/*mengirimkan permintaan penghapusan (unlinkat) yang telah disiapkan (req) ke kernel melalui io_uring untuk dieksekusi secara asinkron. Flag issue_flags 
mengatur cara permintaan ini disubmit.*/
void io_unlinkat_cleanup(struct io_kiocb *req);
/*pembersihan setelah operasi unlinkat selesai. Ini mungkin melibatkan pelepasan sumber daya atau penanganan status penyelesaian setelah hasilnya 
diterima dari completion queue.*/

int io_mkdirat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/*mempersiapkan operasi pembuatan direktori (mkdirat) untuk io_uring. Informasi seperti direktori induk (file descriptor jika relatif), 
nama direktori yang akan dibuat, dan mode akses (permissions) diambil dari sqe dan disimpan dalam req.*/
int io_mkdirat(struct io_kiocb *req, unsigned int issue_flags);
/*mengirimkan permintaan pembuatan direktori (mkdirat) yang telah disiapkan (req) ke kernel melalui io_uring untuk dieksekusi secara asinkron.*/
void io_mkdirat_cleanup(struct io_kiocb *req);
/*pembersihan setelah operasi mkdirat selesai. Ini mungkin melibatkan pelepasan sumber daya atau penanganan status penyelesaian.*/

int io_symlinkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/*mempersiapkan operasi pembuatan symlink (symlinkat) untuk io_uring. Informasi tentang target symlink, direktori induk untuk symlink
 (file descriptor jika relatif), dan nama symlink diambil dari sqe dan disimpan dalam req.*/
int io_symlinkat(struct io_kiocb *req, unsigned int issue_flags);
/*mengirimkan permintaan pembuatan symlink (symlinkat) yang telah disiapkan (req) ke kernel melalui io_uring untuk dieksekusi secara asinkron.*/

int io_linkat_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/*mempersiapkan operasi pembuatan hard link (linkat) untuk io_uring. Informasi tentang file target (direktori dan nama, 
beserta file descriptor jika relatif), direktori induk untuk hard link (file descriptor jika relatif), dan nama hard 
link diambil dari sqe dan disimpan dalam req.*/
int io_linkat(struct io_kiocb *req, unsigned int issue_flags);
/*mengirimkan permintaan pembuatan hard link (linkat) yang telah disiapkan (req) ke kernel melalui io_uring untuk dieksekusi secara asinkron.*/
void io_link_cleanup(struct io_kiocb *req);
/*melakukan pembersihan setelah operasi linkat selesai.*/

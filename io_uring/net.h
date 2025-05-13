// SPDX-License-Identifier: GPL-2.0

#include <linux/net.h>
#include <linux/uio.h>
#include <linux/io_uring_types.h>

//struktur ini mengelola header dari asynchronous message dalam komunikasi dalam jaringan
struct io_async_msghdr {
#if defined(CONFIG_NET)
//jika CONFIG_NET diaktifkan maka yang dibawah ini akan juga digunakan 
	struct iou_vec				vec; //vektor untukk operasi I/O

	struct_group(clear,
		int				namelen; //panjang dari nama address
		struct iovec			fast_iov; //vektor I/o untuk jalur cepat
		__kernel_size_t			controllen; //panjang dari data control
		__kernel_size_t			payloadlen; //panjang dari data payload
		struct sockaddr __user		*uaddr; //address pengguna sebagai lokasi message
		struct msghdr			msg; //Header sebenarya dari message
		struct sockaddr_storage		addr; //tempat penyimpanan untuk socket address
	);
#else
	struct_group(clear);
	//jika CONFIG_NET tidak aktif maka hanya struct_group(clear) yang didefiniskan, ini hanya group kosong.
#endif
};

#if defined(CONFIG_NET)
//fungsi berikut juga hannya digunakan jika CONFIG_NET aktif

//io_shutdown_prep menyiapkan operasi shutdown
int io_shutdown_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//io_shutdown mengeksekusi operasi shutdown
int io_shutdown(struct io_kiocb *req, unsigned int issue_flags);

//io_sendmsg_recvmsg_cleanup untuk membersihkan sumber daya setelah selesai mengirim atau menerima message
void io_sendmsg_recvmsg_cleanup(struct io_kiocb *req);
//io_sendmsg_prep menyiapkan operasi mengirim message (sendmsg)
int io_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//io_sendmsg mengeksekusi operasi mengirim message(sendmsg)
int io_sendmsg(struct io_kiocb *req, unsigned int issue_flags);

//io_send, versi yang lebih sederhana dari io_sendmsg
int io_send(struct io_kiocb *req, unsigned int issue_flags);

//io_recvmsg_prep menyiapkan operasi menerima message (recvmsg)
int io_recvmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//io_recvmsg mengeksekusi operasi menerima message (recvmsg)
int io_recvmsg(struct io_kiocb *req, unsigned int issue_flags);
//io_recv, versi yang lebih sederhana dari io_recvmsg
int io_recv(struct io_kiocb *req, unsigned int issue_flags);
//menangani saat operasi mengirim atau menerima message gagal
void io_sendrecv_fail(struct io_kiocb *req);

//io_accept_prep menyiapkan operasi menerima konceksi
int io_accept_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//io_accept untuk menerima koneksi
int io_accept(struct io_kiocb *req, unsigned int issue_flags);

//io_socket_prep menyiapkan untuk operasi membuat socket 
int io_socket_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//io_socket untuk menerima socket
int io_socket(struct io_kiocb *req, unsigned int issue_flags);

//io_connect_prep menyiapkan untuk operasi menghubungkan socket
int io_connect_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//io_connect untuk menghubungkan socket
int io_connect(struct io_kiocb *req, unsigned int issue_flags);

/*
 *Fungsi-fungsi ini untuk pengimplementasian pengiriman zero-copy (zc)
 *io_send_zc_prep untuk menyiapkan pengiriman zero-copy
 *io_send_zc dan io_sendmsg_zc untuk mengirim zero-copy
 *io_send_zc_cleanup untuk membersihkan sumber daya setelah operasi selesai
*/
int io_send_zc(struct io_kiocb *req, unsigned int issue_flags);
int io_sendmsg_zc(struct io_kiocb *req, unsigned int issue_flags);
int io_send_zc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
void io_send_zc_cleanup(struct io_kiocb *req);

//io_bind_prep untuk menyiapkan operasi pengikatan socket
int io_bind_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//io_bind untuk melakukan operasi pengikatan socket
int io_bind(struct io_kiocb *req, unsigned int issue_flags);

//io_listen_prep menyiapkan untuk operasi penandaan socket
int io_listen_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
//io_listen melakukan operasi penandaan listening socket untul koneksi yang akan datang
int io_listen(struct io_kiocb *req, unsigned int issue_flags);

//io_netmsg_cache_free untuk membersihkan cache yang dialokasikan untuk header netmsg
void io_netmsg_cache_free(const void *entry);
#else
//jika CONFIG_NET tidak aktif maka hanya stub berikut yang digunakan,yang tidak melakukan apa-apa
static inline void io_netmsg_cache_free(const void *entry)
{
}
#endif

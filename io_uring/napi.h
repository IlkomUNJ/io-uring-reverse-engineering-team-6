/* SPDX-License-Identifier: GPL-2.0 */

#ifndef IOU_NAPI_H
#define IOU_NAPI_H

#include <linux/kernel.h>
#include <linux/io_uring.h>
#include <net/busy_poll.h>

#ifdef CONFIG_NET_RX_BUSY_POLL
//fungsi-fungsi berikut hanya akan dikompilasi jika CONFIG_NET_RX_BUSY_POLL diaktifkan

//io_napi_init berfungsi untuk menginisialisasi pelacakan napi untuk io_uring
void io_napi_init(struct io_ring_ctx *ctx);

//io_napi_free berfungsi untuk membersihkan daya yang digunakan selama inisialisasi napi
void io_napi_free(struct io_ring_ctx *ctx);

//io_register_napi meregistrasikan napi dalam konteks io_uring
int io_register_napi(struct io_ring_ctx *ctx, void __user *arg);

//io_unregister_napi untuk membatalkan pendaftaran napi dalam konteks io_uring
int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg);

//__io_napi_add_id menambahkan ID napi kedalam konteks io_uring
int __io_napi_add_id(struct io_ring_ctx *ctx, unsigned int napi_id);

//__io_napi_busy_loop digunakan untuk mengeksekusi looping dari buys poll pada napi
void __io_napi_busy_loop(struct io_ring_ctx *ctx, struct io_wait_queue *iowq);

//io_napi_sqpoll_busy_poll melakukan busy poll saat io_uring dalam mode SQPOLL
int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx);

//fungsi ini mengecek apakah napi_list di dalam io_ring_ctx memiliki isi
static inline bool io_napi(struct io_ring_ctx *ctx)
{
	return !list_empty(&ctx->napi_list);
}

//ini adalah wrapper untuk __io_napi_busy_loop, fungsi ini memeriksa apakah napi aktif 
//sebelum mencoba melakukan busy loop
static inline void io_napi_busy_loop(struct io_ring_ctx *ctx,
				     struct io_wait_queue *iowq)
{
	if (!io_napi(ctx))
		return;
	__io_napi_busy_loop(ctx, iowq);
}

/*
 * io_napi_add() - Menambahkan napi id ke daftar busy poll
 * @req: pointer to io_kiocb request
 *
 * menambahkan napi id milik socket ke dalam  napi busy poll dan hash table.
 */
static inline void io_napi_add(struct io_kiocb *req)
{
	struct io_ring_ctx *ctx = req->ctx;
	struct socket *sock;

	if (READ_ONCE(ctx->napi_track_mode) != IO_URING_NAPI_TRACKING_DYNAMIC)
		return;

	sock = sock_from_file(req->file);
	if (sock && sock->sk)
		__io_napi_add_id(ctx, READ_ONCE(sock->sk->sk_napi_id));
}

#else
//Fungsi-fungsi dibawah ini hanya akan dikompilasi jika CONFIG_NET_RX_BUSY_POLL tidak diaktifkan
static inline void io_napi_init(struct io_ring_ctx *ctx)
{
}
static inline void io_napi_free(struct io_ring_ctx *ctx)
{
}
static inline int io_register_napi(struct io_ring_ctx *ctx, void __user *arg)
{
	return -EOPNOTSUPP;
}
static inline int io_unregister_napi(struct io_ring_ctx *ctx, void __user *arg)
{
	return -EOPNOTSUPP;
}
static inline bool io_napi(struct io_ring_ctx *ctx)
{
	return false;
}
static inline void io_napi_add(struct io_kiocb *req)
{
}
static inline void io_napi_busy_loop(struct io_ring_ctx *ctx,
				     struct io_wait_queue *iowq)
{
}
static inline int io_napi_sqpoll_busy_poll(struct io_ring_ctx *ctx)
{
	return 0;
}
#endif /* CONFIG_NET_RX_BUSY_POLL */

#endif

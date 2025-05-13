// SPDX-License-Identifier: GPL-2.0

#include <linux/net.h>
#include <linux/uio.h>
#include <net/sock.h>
#include <linux/nospec.h>

#include "rsrc.h"

#define IO_NOTIF_UBUF_FLAGS	(SKBFL_ZEROCOPY_FRAG | SKBFL_DONT_ORPHAN)
#define IO_NOTIF_SPLICE_BATCH	32

//struktur ini merepresentasikan data notifikasi untuk operasi I/O
struct io_notif_data {
	struct file		*file; //objek file yang berkaitan dengan notifikasinya
	struct ubuf_info	uarg; //argumen yang digunakan untuk operasi zero-copy

	struct io_notif_data	*next; //pointer untuk penelusuran linked list
	struct io_notif_data	*head; //pointer untuk penelusuran linked list

	unsigned		account_pages; //melacak berapa banyak halama yang digunakan
	bool			zc_report; //penginndikasian apabila suatu zero-copy harus dilaporkan
	bool			zc_used; //pengindikasian apabila suatu zero-copy digunakan
	bool			zc_copied; //pengindikasian apabila copy fallback digunakan dan bukan zero-copy
};

//io_alloc_notif mengalokasikan objek notifikasi dari konteks ring IO
struct io_kiocb *io_alloc_notif(struct io_ring_ctx *ctx);
//io_tx_ubuf_complete akan dipanggil saat suatu transfer buffer sudah selesai 
void io_tx_ubuf_complete(struct sk_buff *skb, struct ubuf_info *uarg,
			 bool success);

//io_notif_to_data mengubah pointer io_kiocb menjadi struktur io_notif_data 
static inline struct io_notif_data *io_notif_to_data(struct io_kiocb *notif)
{
	return io_kiocb_to_cmd(notif, struct io_notif_data);
}

//io_notif_flush melakukan operasi flush untuk request io_kiocb yang spesifik
static inline void io_notif_flush(struct io_kiocb *notif)
	__must_hold(&notif->ctx->uring_lock)
{
	struct io_notif_data *nd = io_notif_to_data(notif);

	io_tx_ubuf_complete(NULL, &nd->uarg, true);
}

//io_notif_account_mem melakukan operasi account atas memori dalam konteks ring IO
//jika konteksnya berkaitan dengan pengguna, maka akan menggunakan __io_account_mem
static inline int io_notif_account_mem(struct io_kiocb *notif, unsigned len)
{
	struct io_ring_ctx *ctx = notif->ctx;
	struct io_notif_data *nd = io_notif_to_data(notif);
	unsigned nr_pages = (len >> PAGE_SHIFT) + 2;
	int ret;

	if (ctx->user) {
		ret = __io_account_mem(ctx->user, nr_pages);
		if (ret)
			return ret;
		nd->account_pages += nr_pages;
	}
	return 0;
}

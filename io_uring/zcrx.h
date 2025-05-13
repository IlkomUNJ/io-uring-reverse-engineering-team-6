// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_ZC_RX_H
#define IOU_ZC_RX_H

#include <linux/io_uring_types.h>
#include <linux/socket.h>
#include <net/page_pool/types.h>
#include <net/net_trackers.h>

struct io_zcrx_area {
	struct net_iov_area	nia;
	struct io_zcrx_ifq	*ifq;
	atomic_t		*user_refs;

	bool			is_mapped;
	u16			area_id;
	struct page		**pages;

	/* freelist */
	spinlock_t		freelist_lock ____cacheline_aligned_in_smp;
	u32			free_count;
	u32			*freelist;
};

struct io_zcrx_ifq {
	struct io_ring_ctx		*ctx;
	struct io_zcrx_area		*area;

	struct io_uring			*rq_ring;
	struct io_uring_zcrx_rqe	*rqes;
	u32				rq_entries;
	u32				cached_rq_head;
	spinlock_t			rq_lock;

	u32				if_rxq;
	struct device			*dev;
	struct net_device		*netdev;
	netdevice_tracker		netdev_tracker;
	spinlock_t			lock;
};

#if defined(CONFIG_IO_URING_ZCRX)

/**
 * io_register_zcrx_ifq - Mendaftarkan interface queue (IFQ) zero-copy receive untuk io_uring
 * @ctx: Konteks io_uring
 * @arg: Pointer ke struktur register interface queue dari user space
 *
 * Fungsi ini digunakan untuk mendaftarkan IFQ yang mendukung zero-copy receive
 * pada socket melalui io_uring.
 *
 * Return: 0 jika sukses, negatif jika gagal.
 */
int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
			 struct io_uring_zcrx_ifq_reg __user *arg);

/**
 * io_unregister_zcrx_ifqs - Membatalkan pendaftaran semua IFQ ZC-RX pada konteks io_uring
 * @ctx: Konteks io_uring
 *
 * Fungsi ini membatalkan semua pendaftaran interface queue untuk zero-copy receive.
 */
void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx);

/**
 * io_shutdown_zcrx_ifqs - Menghentikan (shutdown) interface queue zero-copy receive
 * @ctx: Konteks io_uring
 *
 * Menghentikan semua IFQ aktif yang terdaftar untuk ZC-RX (zero-copy receive).
 */
void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx);

/**
 * io_zcrx_recv - Melakukan receive data dengan metode zero-copy
 * @req: Struktur permintaan io_uring
 * @ifq: Interface queue yang digunakan untuk receive
 * @sock: Socket yang digunakan
 * @flags: Flag untuk operasi receive
 * @issue_flags: Flag tambahan dari io_uring untuk pengeluaran perintah
 * @len: Panjang data yang diterima (output)
 *
 * Menerima data melalui socket dengan menggunakan mekanisme zero-copy dari IFQ.
 *
 * Return: Jumlah byte yang diterima, atau nilai error negatif.
 */
int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
		 struct socket *sock, unsigned int flags,
		 unsigned issue_flags, unsigned int *len);

#else

static inline int io_register_zcrx_ifq(struct io_ring_ctx *ctx,
					struct io_uring_zcrx_ifq_reg __user *arg)
{
	return -EOPNOTSUPP;
}
static inline void io_unregister_zcrx_ifqs(struct io_ring_ctx *ctx)
{
}
static inline void io_shutdown_zcrx_ifqs(struct io_ring_ctx *ctx)
{
}
static inline int io_zcrx_recv(struct io_kiocb *req, struct io_zcrx_ifq *ifq,
			       struct socket *sock, unsigned int flags,
			       unsigned issue_flags, unsigned int *len)
{
	return -EOPNOTSUPP;
}

#endif

/**
 * io_recvzc - Melakukan receive data dengan mekanisme zero-copy (tanpa salin buffer)
 * @req: Struktur permintaan io_uring
 * @issue_flags: Flag tambahan untuk pengeluaran perintah
 *
 * Fungsi utama yang menangani operasi receive dengan zero-copy.
 *
 * Return: 0 jika sukses, atau nilai error negatif.
 */
int io_recvzc(struct io_kiocb *req, unsigned int issue_flags);

/**
 * io_recvzc_prep - Mempersiapkan permintaan receive zero-copy sebelum eksekusi
 * @req: Struktur permintaan io_uring
 * @sqe: Submission Queue Entry dari io_uring
 *
 * Menginisialisasi struktur request untuk operasi zero-copy receive.
 *
 * Return: 0 jika sukses, atau nilai error negatif.
 */
int io_recvzc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

#endif

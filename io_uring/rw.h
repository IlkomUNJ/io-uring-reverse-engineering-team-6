// SPDX-License-Identifier: GPL-2.0

#include <linux/io_uring_types.h>
#include <linux/pagemap.h>

// Struktur untuk menyimpan status metadata I/O
struct io_meta_state {
	u32			seed; // Nilai acak (seed) untuk operasi I/O
	struct iov_iter_state	iter_meta; // Status iterasi I/O
};

// Struktur untuk operasi baca/tulis asinkron (async)
struct io_async_rw {
	struct iou_vec			vec; // Vektor I/O
	size_t				bytes_done; // Jumlah byte yang sudah diproses

	// Struktur untuk membersihkan operasi I/O
	struct_group(clear,
		struct iov_iter			iter; // Iterator untuk I/O
		struct iov_iter_state		iter_state; // Status iterator
		struct iovec			fast_iov; // Buffer cepat untuk I/O

		/*
		 * wpq digunakan untuk buffered I/O, sementara field meta digunakan
		 * untuk direct I/O.
		 */
		union {
			struct wait_page_queue		wpq; // Antrian halaman untuk buffered I/O
			struct {
				struct uio_meta			meta; // Metadata untuk I/O
				struct io_meta_state		meta_state; // Status metadata I/O
			};
		};
	);
};

// Fungsi untuk mempersiapkan operasi baca tetap (fixed read)
int io_prep_read_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi tulis tetap (fixed write)
int io_prep_write_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi baca vektor tetap (fixed readv)
int io_prep_readv_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi tulis vektor tetap (fixed writev)
int io_prep_writev_fixed(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi baca vektor (readv)
int io_prep_readv(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi tulis vektor (writev)
int io_prep_writev(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi baca (read)
int io_prep_read(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk mempersiapkan operasi tulis (write)
int io_prep_write(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melaksanakan operasi baca
int io_read(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk melaksanakan operasi tulis
int io_write(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk melaksanakan operasi baca tetap (fixed read)
int io_read_fixed(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk melaksanakan operasi tulis tetap (fixed write)
int io_write_fixed(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk membersihkan operasi baca/tulis vektor (readv/writev)
void io_readv_writev_cleanup(struct io_kiocb *req);

// Fungsi untuk menangani kegagalan operasi baca/tulis
void io_rw_fail(struct io_kiocb *req);

// Fungsi untuk menyelesaikan operasi baca/tulis dan memberikan token untuk I/O
void io_req_rw_complete(struct io_kiocb *req, io_tw_token_t tw);

// Fungsi untuk mempersiapkan operasi baca snapshot (mshot)
int io_read_mshot_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

// Fungsi untuk melaksanakan operasi baca snapshot (mshot)
int io_read_mshot(struct io_kiocb *req, unsigned int issue_flags);

// Fungsi untuk membebaskan cache untuk entri I/O
void io_rw_cache_free(const void *entry);

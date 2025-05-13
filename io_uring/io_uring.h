#ifndef IOU_CORE_H
#define IOU_CORE_H

#include <linux/errno.h>
#include <linux/lockdep.h>
#include <linux/resume_user_mode.h>
#include <linux/kasan.h>
#include <linux/poll.h>
#include <linux/io_uring_types.h>
#include <uapi/linux/eventpoll.h>
#include "alloc_cache.h"
#include "io-wq.h"
#include "slist.h"
#include "filetable.h"
#include "opdef.h"

#ifndef CREATE_TRACE_POINTS
#include <trace/events/io_uring.h>
#endif

enum {
	IOU_OK			= 0, /* deprecated, use IOU_COMPLETE */
	IOU_COMPLETE		= 0,

	IOU_ISSUE_SKIP_COMPLETE	= -EIOCBQUEUED,

	/*
	 * The request has more work to do and should be retried. io_uring will
	 * attempt to wait on the file for eligible opcodes, but otherwise
	 * it'll be handed to iowq for blocking execution. It works for normal
	 * requests as well as for the multi shot mode.
	 */
	IOU_RETRY		= -EAGAIN,

	/*
	 * Requeue the task_work to restart operations on this request. The
	 * actual value isn't important, should just be not an otherwise
	 * valid error code, yet less than -MAX_ERRNO and valid internally.
	 */
	IOU_REQUEUE		= -3072,
};

struct io_wait_queue {
	struct wait_queue_entry wq;
	struct io_ring_ctx *ctx;
	unsigned cq_tail;
	unsigned cq_min_tail;
	unsigned nr_timeouts;
	int hit_timeout;
	ktime_t min_timeout;
	ktime_t timeout;
	struct hrtimer t;
	/*digunakan untuk mengelola proses menunggu operasi I/O dalam io_uring. Ia menyimpan informasi tentang:
	Antrian tunggu kernel (wq)
	Konteks io_uring (ctx)
	Posisi completion queue (cq_tail, cq_min_tail)
	Informasi timeout (nr_timeouts, hit_timeout, min_timeout, timeout)
	Timer resolusi tinggi (t)*/

#ifdef CONFIG_NET_RX_BUSY_POLL
	ktime_t napi_busy_poll_dt;
	bool napi_prefer_busy_poll;
#endif
};
/*menambahkan dua anggota ke dalam struktur io_wait_queue yang secara spesifik terkait dengan optimasi penerimaan jaringan menggunakan NAPI busy-polling:

napi_busy_poll_dt: Menyimpan durasi waktu untuk melakukan busy-polling.
napi_prefer_busy_poll: Menunjukkan preferensi untuk menggunakan busy-polling.*/

static inline bool io_should_wake(struct io_wait_queue *iowq)
{
	struct io_ring_ctx *ctx = iowq->ctx;
	int dist = READ_ONCE(ctx->rings->cq.tail) - (int) iowq->cq_tail;

	/*
	 * Wake up if we have enough events, or if a timeout occurred since we
	 * started waiting. For timeouts, we always want to return to userspace,
	 * regardless of event count.
	 */
	return dist >= 0 || atomic_read(&ctx->cq_timeouts) != iowq->nr_timeouts;
}

#define IORING_MAX_ENTRIES	32768
#define IORING_MAX_CQ_ENTRIES	(2 * IORING_MAX_ENTRIES)

unsigned long rings_size(unsigned int flags, unsigned int sq_entries,
			 unsigned int cq_entries, size_t *sq_offset);
int io_uring_fill_params(unsigned entries, struct io_uring_params *p);
/*Fungsi ini digunakan untuk mengisi struktur io_uring_params dengan parameter yang diperlukan untuk membuat instance io_uring.*/
bool io_cqe_cache_refill(struct io_ring_ctx *ctx, bool overflow);
/*Fungsi ini mengisi ulang cache Completion Queue Entry (CQE) dalam konteks io_uring (ctx).*/
int io_run_task_work_sig(struct io_ring_ctx *ctx);
/*Fungsi ini menjalankan pekerjaan yang terkait dengan task dalam konteks io_uring (ctx).*/
void io_req_defer_failed(struct io_kiocb *req, s32 res);
/*Fungsi ini menangani kasus ketika permintaan I/O (io_kiocb) gagal dan penanganannya ditunda.*/
bool io_post_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags);
/*Fungsi ini menambahkan entri CQE tambahan (auxiliary) ke completion queue io_uring.*/
void io_add_aux_cqe(struct io_ring_ctx *ctx, u64 user_data, s32 res, u32 cflags);
/*menambahkan entri CQE tambahan ke completion queue.*/
bool io_req_post_cqe(struct io_kiocb *req, s32 res, u32 cflags);
/* menambahkan entri CQE yang terkait dengan permintaan I/O (io_kiocb) ke completion queue.*/
void __io_commit_cqring_flush(struct io_ring_ctx *ctx);
/*memastikan bahwa semua entri CQE yang telah ditambahkan benar-benar terlihat oleh konsumen completion queue (misalnya, aplikasi pengguna).*/

struct file *io_file_get_normal(struct io_kiocb *req, int fd);
struct file *io_file_get_fixed(struct io_kiocb *req, int fd,
			       unsigned issue_flags);
				   /* kedua fungsi ini mendapatkan pointer ke objek file, tetapi io_file_get_normal menggunakan deskriptor file biasa,
				    sedangkan io_file_get_fixed menggunakan indeks ke file yang telah didaftarkan dalam io_uring.*/

void __io_req_task_work_add(struct io_kiocb *req, unsigned flags);
void io_req_task_work_add_remote(struct io_kiocb *req, unsigned flags);
void io_req_task_queue(struct io_kiocb *req);
void io_req_task_complete(struct io_kiocb *req, io_tw_token_t tw);
void io_req_task_queue_fail(struct io_kiocb *req, int ret);
void io_req_task_submit(struct io_kiocb *req, io_tw_token_t tw);
/* fungsi-fungsi ini menyediakan mekanisme untuk mengelola dan menjadwalkan pekerjaan yang terkait dengan permintaan I/O dalam konteks task,
 termasuk penambahan, penempatan antrian, penyelesaian, penanganan kegagalan, dan pengiriman pekerjaan.*/
struct llist_node *io_handle_tw_list(struct llist_node *node, unsigned int *count, unsigned int max_entries);
/*melakukan iterasi melalui list, memproses setiap pekerjaan, dan mengembalikan pointer ke node berikutnya yang perlu diproses. Fungsi ini digunakan 
untuk menangani daftar pekerjaan terkait task yang perlu diproses, membatasi jumlah pekerjaan yang diproses dalam satu panggilan.*/
struct llist_node *tctx_task_work_run(struct io_uring_task *tctx, unsigned int max_entries, unsigned int *count);
/*mengambil pekerjaan dari antrian task, mengeksekusinya, dan memperbarui jumlah pekerjaan yang telah diproses. Fungsi ini digunakan untuk menjalankan
 pekerjaan terkait task dalam konteks io_uring, membatasi jumlah pekerjaan yang dijalankan dalam satu panggilan.*/
void tctx_task_work(struct callback_head *cb);
/*Fungsi ini kemungkinan melakukan pembersihan atau tugas lain yang perlu dilakukan dalam konteks task setelah operasi io_uring.*/
__cold void io_uring_cancel_generic(bool cancel_all, struct io_sq_data *sqd);
/* implementasi generik untuk membatalkan operasi io_uring, yang ditandai dengan __cold untuk mengindikasikan bahwa fungsi ini jarang dipanggil, 
dan menerima parameter untuk menentukan apakah semua operasi harus dibatalkan dan struktur data antrian pengajuan io_uring.*/
int io_uring_alloc_task_context(struct task_struct *task,
				struct io_ring_ctx *ctx);
				/*mengalokasikan konteks io_uring yang diperlukan untuk sebuah task, di mana ia menerima struktur task dan konteks 
				io_uring sebagai input untuk menyiapkan data yang memungkinkan task tersebut berinteraksi dengan io_uring*/

int io_ring_add_registered_file(struct io_uring_task *tctx, struct file *file,
				     int start, int end);
					 /*menambahkan file yang terdaftar ke dalam rentang file yang terdaftar pada konteks io_uring task,
					  memungkinkan penggunaan file yang efisien dalam operasi io_uring dengan merujuknya melalui indeks.*/
void io_req_queue_iowq(struct io_kiocb *req);
/*menempatkan permintaan I/O ke dalam antrian antrian kerja I/O, untuk diproses oleh worker thread io_uring.*/

int io_poll_issue(struct io_kiocb *req, io_tw_token_t tw);
/*Memulai operasi polling I/O dengan token untuk melacaknya.*/
int io_submit_sqes(struct io_ring_ctx *ctx, unsigned int nr);
/*Mengirimkan sejumlah SQEs ke ring io_uring.*/
int io_do_iopoll(struct io_ring_ctx *ctx, bool force_nonspin);
/*Melakukan polling I/O dengan opsi untuk menghindari penggunaan CPU berlebihan.*/
void __io_submit_flush_completions(struct io_ring_ctx *ctx);
/*memastikan bahwa penyelesaian (completions) yang telah diproses oleh io_uring 
menjadi terlihat oleh pemanggil, yang mungkin melibatkan operasi flush atau sinkronisasi memori.*/

struct io_wq_work *io_wq_free_work(struct io_wq_work *work);
/*Fungsi ini membebaskan sumber daya yang terkait dengan sebuah item pekerjaan (io_wq_work).*/
void io_wq_submit_work(struct io_wq_work *work);
/*Fungsi ini mengirimkan (submit) sebuah item pekerjaan (io_wq_work) untuk dieksekusi.*/

void io_free_req(struct io_kiocb *req);
/*membebaskan sumber daya yang dialokasikan untuk sebuah permintaan I/O (io_kiocb).*/
void io_queue_next(struct io_kiocb *req);
/*menempatkan permintaan I/O (io_kiocb) ke antrian untuk diproses selanjutnya.*/

void io_task_refs_refill(struct io_uring_task *tctx);
/*mengisi ulang referensi task io_uring (io_uring_task).*/
bool __io_alloc_req_refill(struct io_ring_ctx *ctx);
/*mengisi ulang alokasi permintaan I/O (io_kiocb)*/
bool io_match_task_safe(struct io_kiocb *head, struct io_uring_task *tctx,
			bool cancel_all);
/*memeriksa apakah permintaan I/O (atau serangkaian permintaan I/O) yang terkait dengan io_kiocb
 *head cocok dengan konteks task io_uring tertentu (io_uring_task *tctx).*/
void io_activate_pollwq(struct io_ring_ctx *ctx);
/*mengaktifkan atau membangunkan antrian tunggu polling (poll waitqueue) yang terkait dengan konteks io_uring (io_ring_ctx *ctx).*/
static inline void io_lockdep_assert_cq_locked(struct io_ring_ctx *ctx)
{
#if defined(CONFIG_PROVE_LOCKING)
	lockdep_assert(in_task());

	if (ctx->flags & IORING_SETUP_DEFER_TASKRUN)
		lockdep_assert_held(&ctx->uring_lock);

	if (ctx->flags & IORING_SETUP_IOPOLL) {
		lockdep_assert_held(&ctx->uring_lock);
	} else if (!ctx->task_complete) {
		lockdep_assert_held(&ctx->completion_lock);
	} else if (ctx->submitter_task) {
		/*
		 * ->submitter_task may be NULL and we can still post a CQE,
		 * if the ring has been setup with IORING_SETUP_R_DISABLED.
		 * Not from an SQE, as those cannot be submitted, but via
		 * updating tagged resources.
		 */
		if (!percpu_ref_is_dying(&ctx->refs))
			lockdep_assert(current == ctx->submitter_task);
	}
#endif
}

static inline bool io_is_compat(struct io_ring_ctx *ctx)
{
	return IS_ENABLED(CONFIG_COMPAT) && unlikely(ctx->compat);
}
/*memeriksa apakah konteks io_uring (io_ring_ctx *ctx) sedang berjalan dalam mode kompatibilitas 32-bit pada sistem 64-bit.*/

static inline void io_req_task_work_add(struct io_kiocb *req)
{
	__io_req_task_work_add(req, 0);
}
/*menambahkan pekerjaan yang terkait dengan permintaan I/O (req) ke antrian pekerjaan task (task workqueue) dengan flag nol.*/
static inline void io_submit_flush_completions(struct io_ring_ctx *ctx)
{
	if (!wq_list_empty(&ctx->submit_state.compl_reqs) ||
	    ctx->submit_state.cq_flush)
		__io_submit_flush_completions(ctx);
}
/*memeriksa apakah ada permintaan penyelesaian yang tertunda dalam daftar (ctx->submit_state.compl_reqs) atau apakah flag flush completion queue (ctx->submit_state.cq_flush) diatur.*/
#define io_for_each_link(pos, head) \
	for (pos = (head); pos; pos = pos->link)
/*menyediakan sintaks yang mudah dibaca untuk melakukan perulangan melalui semua elemen dalam sebuah linked list.*/
static inline bool io_get_cqe_overflow(struct io_ring_ctx *ctx,
					struct io_uring_cqe **ret,
					bool overflow)
					/*mencoba mendapatkan entri Completion Queue Entry (CQE) dari area overflow ring io_uring dalam konteks (ctx).*/
{
	io_lockdep_assert_cq_locked(ctx);

	if (unlikely(ctx->cqe_cached >= ctx->cqe_sentinel)) {
		if (unlikely(!io_cqe_cache_refill(ctx, overflow)))
			return false;
	}
	*ret = ctx->cqe_cached;
	ctx->cached_cq_tail++;
	ctx->cqe_cached++;
	if (ctx->flags & IORING_SETUP_CQE32)
		ctx->cqe_cached++;
	return true;
}
/*mendapatkan entri Completion Queue Entry (CQE), yang menandakan selesainya operasi I/O. */

static inline bool io_get_cqe(struct io_ring_ctx *ctx, struct io_uring_cqe **ret)
{
	return io_get_cqe_overflow(ctx, ret, false);
}
/*memanggil io_get_cqe_overflow dengan parameter overflow diatur ke false. Ini berarti fungsi ini pertama-tama akan mencoba 
mendapatkan CQE dari area reguler completion queue dan hanya akan mempertimbangkan area overflow jika mekanisme pengisian 
ulang cache secara internal memutuskan untuk melihat ke sana. */
static inline bool io_defer_get_uncommited_cqe(struct io_ring_ctx *ctx,
					       struct io_uring_cqe **cqe_ret)
						   /*mendapatkan entri Completion Queue Entry (CQE) yang belum di-commit (uncommitted) dari konteks io_uring (ctx).*/
{
	io_lockdep_assert_cq_locked(ctx);

	ctx->cq_extra++;
	ctx->submit_state.cq_flush = true;
	return io_get_cqe(ctx, cqe_ret);
}
/*mendapatkan CQE sambil juga menandai bahwa ada CQE tambahan yang sedang diproses dan bahwa completion queue perlu di-flush pada submit berikutnya.*/
static __always_inline bool io_fill_cqe_req(struct io_ring_ctx *ctx,
					    struct io_kiocb *req)
{
	struct io_uring_cqe *cqe;

	/*
	 * If we can't get a cq entry, userspace overflowed the
	 * submission (by quite a lot). Increment the overflow count in
	 * the ring.
	 */
	if (unlikely(!io_get_cqe(ctx, &cqe)))
		return false;


	memcpy(cqe, &req->cqe, sizeof(*cqe));
	if (ctx->flags & IORING_SETUP_CQE32) {
		memcpy(cqe->big_cqe, &req->big_cqe, sizeof(*cqe));
		memset(&req->big_cqe, 0, sizeof(req->big_cqe));
	}

	if (trace_io_uring_complete_enabled())
		trace_io_uring_complete(req->ctx, req, cqe);
	return true;
}

static inline void req_set_fail(struct io_kiocb *req)
{
	req->flags |= REQ_F_FAIL;
	if (req->flags & REQ_F_CQE_SKIP) {
		req->flags &= ~REQ_F_CQE_SKIP;
		req->flags |= REQ_F_SKIP_LINK_CQES;
	}
}
/* menangani kasus di mana permintaan tersebut awalnya ditandai untuk melewatkan pengiriman Completion Queue Entry (CQE).
 Jika permintaan gagal dan flag REQ_F_CQE_SKIP diatur, fungsi ini akan menghapus flag REQ_F_CQE_SKIP dan mengatur flag REQ_F_SKIP_LINK_CQES.*/

static inline void io_req_set_res(struct io_kiocb *req, s32 res, u32 cflags)
{
	req->cqe.res = res;
	req->cqe.flags = cflags;
}
/*mengisi informasi status penyelesaian operasi I/O sebelum CQE tersebut dikirimkan ke aplikasi pengguna. req->cqe.res menyimpan hasil operasi 
(misalnya, jumlah byte yang dibaca atau ditulis, atau kode kesalahan), dan req->cqe.flags menyimpan flag tambahan yang terkait dengan penyelesaian.*/

static inline void *io_uring_alloc_async_data(struct io_alloc_cache *cache,
					      struct io_kiocb *req)
						  /*mengalokasikan memori untuk data asinkron yang terkait dengan sebuah permintaan I/O (io_kiocb *req) dari sebuah cache alokasi (struct io_alloc_cache *cache).*/
{
	if (cache) {
		req->async_data = io_cache_alloc(cache, GFP_KERNEL);
	} else {
		const struct io_issue_def *def = &io_issue_defs[req->opcode];

		WARN_ON_ONCE(!def->async_size);
		req->async_data = kmalloc(def->async_size, GFP_KERNEL);
	}
	if (req->async_data)
		req->flags |= REQ_F_ASYNC_DATA;
	return req->async_data;
}
/*mengalokasikan memori untuk data asinkron yang dibutuhkan oleh permintaan I/O. Ia lebih memilih menggunakan cache 
alokasi yang disediakan untuk efisiensi. Jika tidak ada cache, ia akan menggunakan kmalloc dengan ukuran yang ditentukan oleh jenis operasi I/O.*/

static inline bool req_has_async_data(struct io_kiocb *req)
{
	return req->flags & REQ_F_ASYNC_DATA;
}
/*memeriksa apakah sebuah permintaan I/O (struct io_kiocb *req) memiliki data asinkron yang terkait dengannya.*/
static inline void io_put_file(struct io_kiocb *req)
{
	if (!(req->flags & REQ_F_FIXED_FILE) && req->file)
		fput(req->file);
}
/*melepaskan referensi ke file yang terkait dengan permintaan I/O jika file tersebut bukan merupakan file tetap 
(terdaftar) dan pointer file-nya valid. Ini adalah bagian penting dari manajemen sumber daya untuk menghindari kebocoran file.*/
static inline void io_ring_submit_unlock(struct io_ring_ctx *ctx,
					 unsigned issue_flags)
{
	lockdep_assert_held(&ctx->uring_lock);
	if (unlikely(issue_flags & IO_URING_F_UNLOCKED))
		mutex_unlock(&ctx->uring_lock);
}
/*memastikan bahwa kunci io_uring dipegang pada awal fungsi dan kemudian secara kondisional dilepaskan 
jika operasi yang sedang diproses ditandai untuk penanganan tanpa kunci selama fase utamanya.*/
static inline void io_ring_submit_lock(struct io_ring_ctx *ctx,
				       unsigned issue_flags)
{
	/*
	 * "Normal" inline submissions always hold the uring_lock, since we
	 * grab it from the system call. Same is true for the SQPOLL offload.
	 * The only exception is when we've detached the request and issue it
	 * from an async worker thread, grab the lock for that case.
	 */
	if (unlikely(issue_flags & IO_URING_F_UNLOCKED))
		mutex_lock(&ctx->uring_lock);
	lockdep_assert_held(&ctx->uring_lock);
}

static inline void io_commit_cqring(struct io_ring_ctx *ctx)
{
	/* order cqe stores with ring update */
	smp_store_release(&ctx->rings->cq.tail, ctx->cached_cq_tail);
}
/*membuat entri Completion Queue (CQE) yang telah di-cache terlihat oleh konsumen (biasanya aplikasi pengguna).*/

static inline void io_poll_wq_wake(struct io_ring_ctx *ctx)
{
	if (wq_has_sleeper(&ctx->poll_wq))
		__wake_up(&ctx->poll_wq, TASK_NORMAL, 0,
				poll_to_key(EPOLL_URING_WAKE | EPOLLIN));
}
/*membangunkan task yang sedang tidur (menunggu) pada antrian tunggu polling (ctx->poll_wq) yang terkait dengan konteks 
io_uring (ctx). Pembangkitan ini hanya terjadi jika ada task yang sedang tidur di antrian tunggu (wq_has_sleeper). */

static inline void io_cqring_wake(struct io_ring_ctx *ctx)
{
	/*
	 * Trigger waitqueue handler on all waiters on our waitqueue. This
	 * won't necessarily wake up all the tasks, io_should_wake() will make
	 * that decision.
	 *
	 * Pass in EPOLLIN|EPOLL_URING_WAKE as the poll wakeup key. The latter
	 * set in the mask so that if we recurse back into our own poll
	 * waitqueue handlers, we know we have a dependency between eventfd or
	 * epoll and should terminate multishot poll at that point.
	 */
	if (wq_has_sleeper(&ctx->cq_wait))
		__wake_up(&ctx->cq_wait, TASK_NORMAL, 0,
				poll_to_key(EPOLL_URING_WAKE | EPOLLIN));
}

static inline bool io_sqring_full(struct io_ring_ctx *ctx)
{
	struct io_rings *r = ctx->rings;

	/*
	 * SQPOLL must use the actual sqring head, as using the cached_sq_head
	 * is race prone if the SQPOLL thread has grabbed entries but not yet
	 * committed them to the ring. For !SQPOLL, this doesn't matter, but
	 * since this helper is just used for SQPOLL sqring waits (or POLLOUT),
	 * just read the actual sqring head unconditionally.
	 */
	return READ_ONCE(r->sq.tail) - READ_ONCE(r->sq.head) == ctx->sq_entries;
}

static inline unsigned int io_sqring_entries(struct io_ring_ctx *ctx)
{
	struct io_rings *rings = ctx->rings;
	unsigned int entries;

	/* make sure SQ entry isn't read before tail */
	entries = smp_load_acquire(&rings->sq.tail) - ctx->cached_sq_head;
	return min(entries, ctx->sq_entries);
}

static inline int io_run_task_work(void)
{
	bool ret = false;

	/*
	 * Always check-and-clear the task_work notification signal. With how
	 * signaling works for task_work, we can find it set with nothing to
	 * run. We need to clear it for that case, like get_signal() does.
	 */
	if (test_thread_flag(TIF_NOTIFY_SIGNAL))
		clear_notify_signal();
	/*
	 * PF_IO_WORKER never returns to userspace, so check here if we have
	 * notify work that needs processing.
	 */
	if (current->flags & PF_IO_WORKER) {
		if (test_thread_flag(TIF_NOTIFY_RESUME)) {
			__set_current_state(TASK_RUNNING);
			resume_user_mode_work(NULL);
		}
		if (current->io_uring) {
			unsigned int count = 0;

			__set_current_state(TASK_RUNNING);
			tctx_task_work_run(current->io_uring, UINT_MAX, &count);
			if (count)
				ret = true;
		}
	}
	if (task_work_pending(current)) {
		__set_current_state(TASK_RUNNING);
		task_work_run();
		ret = true;
	}

	return ret;
}

static inline bool io_local_work_pending(struct io_ring_ctx *ctx)
{
	return !llist_empty(&ctx->work_llist) || !llist_empty(&ctx->retry_llist);
}
/*memeriksa apakah ada pekerjaan lokal yang tertunda untuk konteks io_uring (ctx). Pekerjaan lokal yang tertunda ditunjukkan
 jika salah satu dari dua linked list (ctx->work_llist atau ctx->retry_llist) tidak kosong.*/

static inline bool io_task_work_pending(struct io_ring_ctx *ctx)
{
	return task_work_pending(current) || io_local_work_pending(ctx);
}
/*memeriksa apakah ada pekerjaan task yang tertunda untuk task saat ini (current) atau pekerjaan lokal yang tertunda untuk konteks io_uring (ctx).*/

static inline void io_tw_lock(struct io_ring_ctx *ctx, io_tw_token_t tw)
{
	lockdep_assert_held(&ctx->uring_lock);
}

/*
 * Don't complete immediately but use deferred completion infrastructure.
 * Protected by ->uring_lock and can only be used either with
 * IO_URING_F_COMPLETE_DEFER or inside a tw handler holding the mutex.
 */
static inline void io_req_complete_defer(struct io_kiocb *req)
	__must_hold(&req->ctx->uring_lock)
{
	struct io_submit_state *state = &req->ctx->submit_state;

	lockdep_assert_held(&req->ctx->uring_lock);

	wq_list_add_tail(&req->comp_list, &state->compl_reqs);
}

static inline void io_commit_cqring_flush(struct io_ring_ctx *ctx)
{
	if (unlikely(ctx->off_timeout_used || ctx->drain_active ||
		     ctx->has_evfd || ctx->poll_activated))
		__io_commit_cqring_flush(ctx);
}
/*melakukan flush completion queue hanya ketika ada kondisi tertentu yang mungkin memerlukan sinkronisasi 
segera untuk memastikan pemrosesan peristiwa atau manajemen sumber daya yang tepat.*/

static inline void io_get_task_refs(int nr)
{
	struct io_uring_task *tctx = current->io_uring;

	tctx->cached_refs -= nr;
	if (unlikely(tctx->cached_refs < 0))
		io_task_refs_refill(tctx);
}
/*mengurangi jumlah referensi yang di-cache (cached_refs) dalam struktur io_uring_task (tctx) dari task saat ini (current) sebanyak nr. */
static inline bool io_req_cache_empty(struct io_ring_ctx *ctx)
{
	return !ctx->submit_state.free_list.next;
}
/*memeriksa apakah cache permintaan I/O (request cache) dalam konteks io_uring (ctx) kosong.
*/
extern struct kmem_cache *req_cachep;

static inline struct io_kiocb *io_extract_req(struct io_ring_ctx *ctx)
{
	struct io_kiocb *req;

	req = container_of(ctx->submit_state.free_list.next, struct io_kiocb, comp_list);
	wq_stack_extract(&ctx->submit_state.free_list);
	return req;
}
/*mengambil (mengekstrak) sebuah permintaan I/O (struct io_kiocb) dari free list cache dalam konteks io_uring (ctx).*/

static inline bool io_alloc_req(struct io_ring_ctx *ctx, struct io_kiocb **req)
{
	if (unlikely(io_req_cache_empty(ctx))) {
		if (!__io_alloc_req_refill(ctx))
			return false;
	}
	*req = io_extract_req(ctx);
	return true;
}/*mencoba mendapatkan permintaan I/O dari cache io_uring, mengisi ulang cache jika kosong, dan mengembalikan permintaan yang berhasil dialokasikan.*/

static inline bool io_allowed_defer_tw_run(struct io_ring_ctx *ctx)
{
	return likely(ctx->submitter_task == current);
}
/*memeriksa apakah task saat ini (current) adalah task yang sama dengan task yang melakukan pengiriman (submitter task) untuk konteks io_uring (ctx->submitter_task).*/

static inline bool io_allowed_run_tw(struct io_ring_ctx *ctx)
{
	return likely(!(ctx->flags & IORING_SETUP_DEFER_TASKRUN) ||
		      ctx->submitter_task == current);
}
/*pekerjaan task work diizinkan untuk dijalankan segera kecuali jika penundaan secara eksplisit diminta dan task saat ini bukan task yang melakukan pengiriman.*/

/*
 * Terminate the request if either of these conditions are true:
 *
 * 1) It's being executed by the original task, but that task is marked
 *    with PF_EXITING as it's exiting.
 * 2) PF_KTHREAD is set, in which case the invoker of the task_work is
 *    our fallback task_work.
 */
static inline bool io_should_terminate_tw(void)
{
	return current->flags & (PF_KTHREAD | PF_EXITING);
}

static inline void io_req_queue_tw_complete(struct io_kiocb *req, s32 res)
{
	io_req_set_res(req, res, 0);
	req->io_task_work.func = io_req_task_complete;
	io_req_task_work_add(req);
}/*fungsi ini mencatat hasil operasi, menentukan fungsi penyelesaian yang akan 
dijalankan dalam konteks task, dan kemudian mengantrikan pekerjaan tersebut untuk dieksekusi. */

/*
 * IORING_SETUP_SQE128 contexts allocate twice the normal SQE size for each
 * slot.
 */
static inline size_t uring_sqe_size(struct io_ring_ctx *ctx)
{
	if (ctx->flags & IORING_SETUP_SQE128)
		return 2 * sizeof(struct io_uring_sqe);
	return sizeof(struct io_uring_sqe);
}
/*mengembalikan ukuran SQE yang sesuai berdasarkan konfigurasi io_uring,
 yang bisa menjadi ukuran standar atau dua kali ukuran standar jika flag IORING_SETUP_SQE128 diaktifkan.*/

static inline bool io_file_can_poll(struct io_kiocb *req)
{
	if (req->flags & REQ_F_CAN_POLL)
		return true;
	if (req->file && file_can_poll(req->file)) {
		req->flags |= REQ_F_CAN_POLL;
		return true;
	}
	return false;
}
/*memeriksa apakah file yang terkait dengan permintaan I/O mendukung polling, menggunakan flag cache untuk menghindari pemeriksaan berulang.*/

static inline ktime_t io_get_time(struct io_ring_ctx *ctx)
{
	if (ctx->clockid == CLOCK_MONOTONIC)
		return ktime_get();

	return ktime_get_with_offset(ctx->clock_offset);
}
/*mendapatkan waktu saat ini berdasarkan clock ID yang dikonfigurasi dalam konteks io_uring (ctx).*/

enum {
	IO_CHECK_CQ_OVERFLOW_BIT,
	IO_CHECK_CQ_DROPPED_BIT,
};

static inline bool io_has_work(struct io_ring_ctx *ctx)
{
	return test_bit(IO_CHECK_CQ_OVERFLOW_BIT, &ctx->check_cq) ||
	       io_local_work_pending(ctx);
}
#endif

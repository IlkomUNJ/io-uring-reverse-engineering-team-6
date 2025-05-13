#ifndef INTERNAL_IO_WQ_H
#define INTERNAL_IO_WQ_H

#include <linux/refcount.h>
#include <linux/io_uring_types.h>

struct io_wq;

enum {
	IO_WQ_WORK_CANCEL	= 1,
	IO_WQ_WORK_HASHED	= 2,
	IO_WQ_WORK_UNBOUND	= 4,
	IO_WQ_WORK_CONCURRENT	= 16,

	IO_WQ_HASH_SHIFT	= 24,	/* upper 8 bits are used for hash key */
};
/*mendefinisikan flag dan konstanta yang digunakan untuk mengontrol dan menjelaskan properti dari "work item" di 
dalam sistem antrian kerja I/O, khususnya terkait dengan pembatalan, pengindeksan hash, penjadwalan CPU, dan konkurensi.*/

enum io_wq_cancel {
	IO_WQ_CANCEL_OK,	/* cancelled before started */
	IO_WQ_CANCEL_RUNNING,	/* found, running, and attempted cancelled */
	IO_WQ_CANCEL_NOTFOUND,	/* work not found */
};
/*menyediakan informasi status yang jelas tentang hasil dari operasi pembatalan "work item" dalam antrian kerja I/O. 
Informasi ini penting untuk penanganan kesalahan, pelaporan status, dan memastikan perilaku sistem yang benar dalam mengelola pembatalan operasi I/O.*/
typedef struct io_wq_work *(free_work_fn)(struct io_wq_work *);
/*membebaskan atau membersihkan sumber daya yang terkait dengan sebuah "work item" (io_wq_work). Fungsi ini menerima pointer ke "work item" yang akan 
dibebaskan dan mengembalikan pointer (mungkin pointer yang sama, mungkin pointer lain, atau NULL).*/
typedef void (io_wq_work_fn)(struct io_wq_work *);
/*bertugas untuk melakukan pekerjaan yang terkait dengan sebuah "work item". Fungsi ini menerima pointer ke
 "work item" sebagai input dan melakukan operasinya tanpa mengembalikan nilai apa pun.*/
struct io_wq_hash {
	refcount_t refs;
	unsigned long map;
	struct wait_queue_head wait;
};
/*mengelola bagian dari tabel hash yang dipakai oleh antrian kerja I/O, dengan memanfaatkan reference count (refs) untuk manajemen memori, 
bitmask (map) untuk melacak status dalam tabel hash, dan wait queue (wait) untuk sinkronisasi.*/

static inline void io_wq_put_hash(struct io_wq_hash *hash)
{
	if (refcount_dec_and_test(&hash->refs))
		kfree(hash);
}
/*menerapkan mekanisme reference counting untuk memastikan bahwa memori yang dialokasikan untuk io_wq_hash tidak dibebaskan terlalu 
cepat (ketika masih ada yang menggunakannya) atau terlalu lambat (menyebabkan kebocoran memori).*/

struct io_wq_data {
	struct io_wq_hash *hash;
	struct task_struct *task;
	io_wq_work_fn *do_work;
	free_work_fn *free_work;
};
/*menyimpan informasi penting terkait pekerjaan I/O dalam antrian kerja, meliputi pointer ke tabel hash (hash) untuk pengelolaan, 
pointer ke task (task) yang terkait, fungsi untuk melakukan pekerjaan (do_work), dan fungsi untuk membersihkan sumber daya (free_work).*/
struct io_wq *io_wq_create(unsigned bounded, struct io_wq_data *data);
/*membuat dan menginisialisasi sebuah antrian kerja I/O (io_wq), dengan opsi untuk membuat antrian tersebut terbatas (bounded) 
atau tidak, dan menggunakan data pekerjaan yang diberikan (data).*/
void io_wq_exit_start(struct io_wq *wq);
/*memulai proses penghentian untuk sebuah antrian kerja I/O (io_wq). Ini mungkin melibatkan penolakan pekerjaan baru dan menunggu pekerjaan yang ada selesai.*/
void io_wq_put_and_exit(struct io_wq *wq);
/*mengurangi reference count antrian kerja I/O (io_wq) dan memulai proses penghentian jika reference count mencapai nol.
 Ini adalah cara untuk melepaskan antrian kerja dan memastikan penghentian yang bersih.*/

void io_wq_enqueue(struct io_wq *wq, struct io_wq_work *work);
/*menambahkan sebuah pekerjaan (io_wq_work) ke dalam antrian kerja I/O (io_wq) untuk dieksekusi.*/
void io_wq_hash_work(struct io_wq_work *work, void *val);
/*mengaitkan sebuah pekerjaan (io_wq_work) dengan sebuah nilai (val) untuk keperluan pengindeksan atau pencarian menggunakan hash table.*/

int io_wq_cpu_affinity(struct io_uring_task *tctx, cpumask_var_t mask);
/* mengatur afinitas CPU untuk task (tctx) yang terkait dengan antrian kerja I/O, memungkinkan untuk membatasi 
eksekusi task tersebut ke CPU tertentu yang ditentukan oleh mask.*/
int io_wq_max_workers(struct io_wq *wq, int *new_count);
/*mengatur atau mengambil jumlah maksimum worker threads yang dapat digunakan oleh antrian kerja I/O (wq), 
dengan new_count sebagai pointer untuk nilai baru atau menerima nilai saat ini.*/
bool io_wq_worker_stopped(void);
/* memeriksa apakah worker thread saat ini telah dihentikan atau sedang dalam proses penghentian.*/

static inline bool __io_wq_is_hashed(unsigned int work_flags)
{
	return work_flags & IO_WQ_WORK_HASHED;
}

static inline bool io_wq_is_hashed(struct io_wq_work *work)
{
	return __io_wq_is_hashed(atomic_read(&work->flags));
}

typedef bool (work_cancel_fn)(struct io_wq_work *, void *);

enum io_wq_cancel io_wq_cancel_cb(struct io_wq *wq, work_cancel_fn *cancel,
					void *data, bool cancel_all);

#if defined(CONFIG_IO_WQ)
extern void io_wq_worker_sleeping(struct task_struct *);
extern void io_wq_worker_running(struct task_struct *);
#else
static inline void io_wq_worker_sleeping(struct task_struct *tsk)
{
}
static inline void io_wq_worker_running(struct task_struct *tsk)
{
}
#endif

static inline bool io_wq_current_is_worker(void)
{
	return in_task() && (current->flags & PF_IO_WORKER) &&
		current->worker_private;
}
#endif

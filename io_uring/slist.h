#ifndef INTERNAL_IO_SLIST_H
#define INTERNAL_IO_SLIST_H

#include <linux/io_uring_types.h>

// Makro untuk iterasi daftar work queue (wq) dengan cara biasa
#define __wq_list_for_each(pos, head)				\
	for (pos = (head)->first; pos; pos = (pos)->next)

// Makro untuk iterasi daftar work queue dengan pointer previous (prv)
#define wq_list_for_each(pos, prv, head)			\
	for (pos = (head)->first, prv = NULL; pos; prv = pos, pos = (pos)->next)

// Makro untuk melanjutkan iterasi daftar work queue setelah posisi tertentu
#define wq_list_for_each_resume(pos, prv)			\
	for (; pos; prv = pos, pos = (pos)->next)

// Makro untuk mengecek apakah daftar work queue kosong
#define wq_list_empty(list)	(READ_ONCE((list)->first) == NULL)

// Inisialisasi daftar work queue menjadi kosong
#define INIT_WQ_LIST(list)	do {				\
	(list)->first = NULL;					\
} while (0)

/**
 * wq_list_add_after:
 * Menambahkan node ke dalam daftar work queue setelah node tertentu.
 * 
 * @node: Node yang akan ditambahkan ke dalam daftar.
 * @pos: Node setelahnya, tempat node baru akan dimasukkan.
 * @list: Daftar tempat node akan ditambahkan.
 */
static inline void wq_list_add_after(struct io_wq_work_node *node,
				     struct io_wq_work_node *pos,
				     struct io_wq_work_list *list)
{
	struct io_wq_work_node *next = pos->next;

	pos->next = node;
	node->next = next;
	if (!next)
		list->last = node;
}

/**
 * wq_list_add_tail:
 * Menambahkan node ke bagian akhir daftar work queue.
 * 
 * @node: Node yang akan ditambahkan ke dalam daftar.
 * @list: Daftar tempat node akan ditambahkan.
 */
static inline void wq_list_add_tail(struct io_wq_work_node *node,
				    struct io_wq_work_list *list)
{
	node->next = NULL;
	if (!list->first) {
		list->last = node;
		WRITE_ONCE(list->first, node);
	} else {
		list->last->next = node;
		list->last = node;
	}
}

/**
 * wq_list_add_head:
 * Menambahkan node ke bagian awal daftar work queue.
 * 
 * @node: Node yang akan ditambahkan ke dalam daftar.
 * @list: Daftar tempat node akan ditambahkan.
 */
static inline void wq_list_add_head(struct io_wq_work_node *node,
				    struct io_wq_work_list *list)
{
	node->next = list->first;
	if (!node->next)
		list->last = node;
	WRITE_ONCE(list->first, node);
}

/**
 * wq_list_cut:
 * Memotong node dari daftar dan mengubah pointer terkait.
 * 
 * @list: Daftar tempat node akan dipotong.
 * @last: Node yang akan dipotong.
 * @prev: Node sebelumnya untuk mengubah pointer next.
 */
static inline void wq_list_cut(struct io_wq_work_list *list,
			       struct io_wq_work_node *last,
			       struct io_wq_work_node *prev)
{
	/* pertama dalam daftar, jika prev==NULL */
	if (!prev)
		WRITE_ONCE(list->first, last->next);
	else
		prev->next = last->next;

	if (last == list->last)
		list->last = prev;
	last->next = NULL;
}

/**
 * __wq_list_splice:
 * Menggabungkan dua daftar work queue, menempatkan daftar pertama ke dalam daftar kedua.
 * 
 * @list: Daftar yang akan digabungkan.
 * @to: Node tujuan tempat daftar pertama akan digabungkan.
 */
static inline void __wq_list_splice(struct io_wq_work_list *list,
				    struct io_wq_work_node *to)
{
	list->last->next = to->next;
	to->next = list->first;
	INIT_WQ_LIST(list);
}

/**
 * wq_list_splice:
 * Menggabungkan dua daftar work queue jika daftar pertama tidak kosong.
 * 
 * @list: Daftar yang akan digabungkan.
 * @to: Node tujuan tempat daftar pertama akan digabungkan.
 * 
 * Mengembalikan true jika daftar pertama tidak kosong dan berhasil digabungkan.
 * Mengembalikan false jika daftar pertama kosong.
 */
static inline bool wq_list_splice(struct io_wq_work_list *list,
				  struct io_wq_work_node *to)
{
	if (!wq_list_empty(list)) {
		__wq_list_splice(list, to);
		return true;
	}
	return false;
}

/**
 * wq_stack_add_head:
 * Menambahkan node ke bagian atas tumpukan (stack).
 * 
 * @node: Node yang akan ditambahkan ke dalam stack.
 * @stack: Stack tempat node akan ditambahkan.
 */
static inline void wq_stack_add_head(struct io_wq_work_node *node,
				     struct io_wq_work_node *stack)
{
	node->next = stack->next;
	stack->next = node;
}

/**
 * wq_list_del:
 * Menghapus node dari daftar work queue.
 * 
 * @list: Daftar tempat node akan dihapus.
 * @node: Node yang akan dihapus.
 * @prev: Node sebelumnya untuk mengubah pointer next.
 */
static inline void wq_list_del(struct io_wq_work_list *list,
			       struct io_wq_work_node *node,
			       struct io_wq_work_node *prev)
{
	wq_list_cut(list, node, prev);
}

/**
 * wq_stack_extract:
 * Mengekstrak node dari stack, menghapusnya dan mengembalikan pointer ke node tersebut.
 * 
 * @stack: Stack tempat node akan diekstrak.
 * 
 * Mengembalikan node yang diekstrak dari stack.
 */
static inline
struct io_wq_work_node *wq_stack_extract(struct io_wq_work_node *stack)
{
	struct io_wq_work_node *node = stack->next;

	stack->next = node->next;
	return node;
}

/**
 * wq_next_work:
 * Mendapatkan pekerjaan berikutnya dalam daftar work queue.
 * 
 * @work: Pekerjaan saat ini.
 * 
 * Mengembalikan pekerjaan berikutnya dalam daftar, atau NULL jika tidak ada pekerjaan lagi.
 */
static inline struct io_wq_work *wq_next_work(struct io_wq_work *work)
{
	if (!work->list.next)
		return NULL;

	return container_of(work->list.next, struct io_wq_work, list);
}

#endif // INTERNAL_IO_SLIST_H

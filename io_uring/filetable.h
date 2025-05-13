// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_FILE_TABLE_H
#define IOU_FILE_TABLE_H

#include <linux/file.h>
#include <linux/io_uring_types.h>
#include "rsrc.h"

bool io_alloc_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table, unsigned nr_files);
/*mengalokasikan memori untuk menyimpan tabel deskriptor file yang digunakan oleh io_uring, dengan ctx sebagai konteks io_uring, table sebagai struktur untuk menyimpan informasi tabel, 
dan nr_files sebagai jumlah deskriptor file yang akan dialokasikan. Fungsi ini mengembalikan nilai boolean yang menunjukkan keberhasilan atau kegagalan alokasi.*/
void io_free_file_tables(struct io_ring_ctx *ctx, struct io_file_table *table);
/*membebaskan memori yang sebelumnya dialokasikan untuk tabel deskriptor file, dengan ctx sebagai konteks io_uring dan table sebagai struktur yang menyimpan informasi tabel yang akan dibebaskan.*/

int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
			struct file *file, unsigned int file_slot);
			/*  menginstal deskriptor file tertentu (file) ke dalam slot file tetap (file_slot) untuk digunakan dengan io_uring, terkait dengan permintaan 
			I/O (req) dan dengan flag penerbitan tertentu (issue_flags).*/
int __io_fixed_fd_install(struct io_ring_ctx *ctx, struct file *file,
				unsigned int file_slot);
				/*versi internal dari io_fixed_fd_install yang melakukan instalasi deskriptor file (file) ke dalam slot
				 file tetap (file_slot) dalam konteks io_uring tertentu (ctx).*/
int io_fixed_fd_remove(struct io_ring_ctx *ctx, unsigned int offset); /*menghapus deskriptor file dari slot file tetap pada offset tertentu dalam konteks io_uring (ctx).*/

int io_register_file_alloc_range(struct io_ring_ctx *ctx,
				 struct io_uring_file_index_range __user *arg);
				 /*mendaftarkan rentang alokasi file untuk io_uring, yang memungkinkan alokasi dinamis dari deskriptor file dalam rentang yang ditentukan oleh argumen
				  ruang pengguna (arg) dalam konteks io_uring (ctx).*/

io_req_flags_t io_file_get_flags(struct file *file);
/*mengambil flag permintaan I/O (io_req_flags_t) yang terkait dengan sebuah objek file (file). 
Dengan kata lain, fungsi ini membaca properti atau atribut tertentu dari file yang relevan untuk operasi I/O.*/

static inline void io_file_bitmap_clear(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(!test_bit(bit, table->bitmap));
	__clear_bit(bit, table->bitmap);
	table->alloc_hint = bit;
}
/*membersihkan bit tertentu (bit) dalam bitmap (table->bitmap) dari tabel file (table).*/

static inline void io_file_bitmap_set(struct io_file_table *table, int bit)
{
	WARN_ON_ONCE(test_bit(bit, table->bitmap));
	__set_bit(bit, table->bitmap);
	table->alloc_hint = bit + 1;
}
/*mengatur bit tertentu (bit) dalam bitmap (table->bitmap) dari tabel file (table). Ini menandakan bahwa slot file yang diwakili oleh bit tersebut sedang digunakan.*/

#define FFS_NOWAIT		0x1UL
#define FFS_ISREG		0x2UL
#define FFS_MASK		~(FFS_NOWAIT|FFS_ISREG)

static inline unsigned int io_slot_flags(struct io_rsrc_node *node)
{

	return (node->file_ptr & ~FFS_MASK) << REQ_F_SUPPORT_NOWAIT_BIT;
}
/*menghitung dan mengembalikan flag untuk sebuah slot I/O, yang diperoleh dari pointer file (node->file_ptr). Fungsi ini melakukan masking (& ~FFS_MASK) untuk 
menghilangkan bagian tertentu dari pointer dan kemudian menggeser hasilnya ke kiri (<< REQ_F_SUPPORT_NOWAIT_BIT) untuk mengatur bit flag yang sesuai.*/

static inline struct file *io_slot_file(struct io_rsrc_node *node)
{
	return (struct file *)(node->file_ptr & FFS_MASK);
}
/*mengekstrak dan mengembalikan pointer ke objek file dari dalam struktur io_rsrc_node (node).*/

static inline void io_fixed_file_set(struct io_rsrc_node *node,
				     struct file *file)
					 /* mengatur (menyimpan) pointer ke objek file dalam struktur io_rsrc_node (node). Fungsi ini kemungkinan juga 
					 melakukan beberapa manipulasi bitwise pada pointer file sebelum menyimpannya di node->file_ptr*/
{
	node->file_ptr = (unsigned long)file |
		(io_file_get_flags(file) >> REQ_F_SUPPORT_NOWAIT_BIT);
}
/* memungkinkan penyimpanan informasi tambahan (flag) bersama dengan pointer file dalam satu variabel
, yang mungkin digunakan untuk optimasi ruang atau kinerja.*/

static inline void io_file_table_set_alloc_range(struct io_ring_ctx *ctx,
						 unsigned off, unsigned len)
{
	ctx->file_alloc_start = off;
	ctx->file_alloc_end = off + len;
	ctx->file_table.alloc_hint = ctx->file_alloc_start;
}
/*mendefinisikan di mana dan seberapa besar rentang slot file yang dapat dialokasikan.*/

#endif

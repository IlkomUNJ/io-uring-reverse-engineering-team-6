// SPDX-License-Identifier: GPL-2.0
#ifndef IOU_OP_DEF_H
#define IOU_OP_DEF_H

//struktur ini men-"define" kemampuan dan penangan untuk setiap operasi io_uring
struct io_issue_def {
	/* needs req->file assigned */
	unsigned		needs_file : 1;
	/* should block plug */
	unsigned		plug : 1;
	/* supports ioprio */
	unsigned		ioprio : 1;
	/* supports iopoll */
	unsigned		iopoll : 1;
	/* op supports buffer selection */
	unsigned		buffer_select : 1;
	/* hash wq insertion if file is a regular file */
	unsigned		hash_reg_file : 1;
	/* unbound wq insertion if file is a non-regular file */
	unsigned		unbound_nonreg_file : 1;
	/* set if opcode supports polled "wait" */
	unsigned		pollin : 1;
	unsigned		pollout : 1;
	unsigned		poll_exclusive : 1;
	/* skip auditing */
	unsigned		audit_skip : 1;
	/* have to be put into the iopoll list */
	unsigned		iopoll_queue : 1;
	/* vectored opcode, set if 1) vectored, and 2) handler needs to know */
	unsigned		vectored : 1;

	/* size of async data needed, if any */
	unsigned short		async_size;

	int (*issue)(struct io_kiocb *, unsigned int);
	int (*prep)(struct io_kiocb *, const struct io_uring_sqe *);
};

//struktur ini untuk mendefinisikan penangan pembersih dan penangan gagal untuk operasi IO
struct io_cold_def {
	/*nama dari operasi*/
	const char		*name;

	/*pointer fungsi untuk menangani pembersihan setelah operasi IO*/
	void (*cleanup)(struct io_kiocb *);
	/*pointer fungsi untuk menangani skenario terjadinya kegagalan dalam operasi IO*/
	void (*fail)(struct io_kiocb *);
};

//array external yang berisi semua definisi io_issue_def
extern const struct io_issue_def io_issue_defs[];
//array eksternal yang berisi semua definisi io_cold_def
extern const struct io_cold_def io_cold_defs[];

//mengecek apakah opcode yang ada terdukung oleh konfigurasi kernel yang ada
bool io_uring_op_supported(u8 opcode);

//menginisialisasi tabel operasi untuk io_uring
void io_uring_optable_init(void);
#endif

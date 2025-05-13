// SPDX-License-Identifier: GPL-2.0

/**
 * io_xattr_cleanup - Membersihkan sumber daya setelah operasi xattr selesai
 * @req: Struktur permintaan io_uring
 *
 * Digunakan untuk membersihkan state internal atau buffer
 * setelah operasi extended attribute selesai dijalankan.
 */
 void io_xattr_cleanup(struct io_kiocb *req);

 /**
  * io_fsetxattr_prep - Mempersiapkan operasi fsetxattr
  * @req: Struktur permintaan io_uring
  * @sqe: Submission Queue Entry dari io_uring
  *
  * Mempersiapkan operasi untuk menyetel extended attribute pada file descriptor.
  *
  * Return: 0 jika sukses, atau error code negatif.
  */
 int io_fsetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
 
 /**
  * io_fsetxattr - Menyetel extended attribute ke file descriptor
  * @req: Struktur permintaan io_uring
  * @issue_flags: Flag tambahan untuk eksekusi perintah
  *
  * Menjalankan operasi fsetxattr pada file descriptor secara asynchronous.
  *
  * Return: 0 jika sukses, atau error code negatif.
  */
 int io_fsetxattr(struct io_kiocb *req, unsigned int issue_flags);
 
 /**
  * io_setxattr_prep - Mempersiapkan operasi setxattr pada path file
  * @req: Struktur permintaan io_uring
  * @sqe: Submission Queue Entry dari io_uring
  *
  * Return: 0 jika sukses, atau error code negatif.
  */
 int io_setxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
 
 /**
  * io_setxattr - Menyetel extended attribute pada file berdasarkan path
  * @req: Struktur permintaan io_uring
  * @issue_flags: Flag tambahan untuk eksekusi perintah
  *
  * Return: 0 jika sukses, atau error code negatif.
  */
 int io_setxattr(struct io_kiocb *req, unsigned int issue_flags);
 
 /**
  * io_fgetxattr_prep - Mempersiapkan operasi fgetxattr
  * @req: Struktur permintaan io_uring
  * @sqe: Submission Queue Entry dari io_uring
  *
  * Return: 0 jika sukses, atau error code negatif.
  */
 int io_fgetxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
 
 /**
  * io_fgetxattr - Mendapatkan nilai extended attribute dari file descriptor
  * @req: Struktur permintaan io_uring
  * @issue_flags: Flag tambahan untuk eksekusi perintah
  *
  * Return: Panjang data xattr jika sukses, atau error code negatif.
  */
 int io_fgetxattr(struct io_kiocb *req, unsigned int issue_flags);
 
 /**
  * io_getxattr_prep - Mempersiapkan operasi getxattr berdasarkan path
  * @req: Struktur permintaan io_uring
  * @sqe: Submission Queue Entry dari io_uring
  *
  * Return: 0 jika sukses, atau error code negatif.
  */
 int io_getxattr_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
 
 /**
  * io_getxattr - Mendapatkan nilai extended attribute dari file path
  * @req: Struktur permintaan io_uring
  * @issue_flags: Flag tambahan untuk eksekusi perintah
  *
  * Return: Panjang data xattr jika sukses, atau error code negatif.
  */
 int io_getxattr(struct io_kiocb *req, unsigned int issue_flags);
 
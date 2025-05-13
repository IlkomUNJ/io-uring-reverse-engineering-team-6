// SPDX-License-Identifier: GPL-2.0

/**
 * io_tee_prep:
 * Mempersiapkan permintaan I/O untuk operasi tee, yang menyalin data antara dua deskriptor file secara langsung
 * di kernel, tanpa melalui ruang pengguna. Fungsi ini memvalidasi entry antrian pengajuan (SQE) dan
 * menyiapkan struktur yang diperlukan untuk operasi tersebut.
 * 
 * @req: Blok kontrol permintaan I/O untuk operasi ini.
 * @sqe: Entry antrian pengajuan yang berisi parameter operasi.
 * 
 * Mengembalikan 0 jika berhasil, atau kode kesalahan jika parameter tidak valid.
 */
 int io_tee_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

 /**
  * io_tee:
  * Melakukan operasi tee yang sebenarnya, menyalin data antara dua deskriptor file. Kernel menangani
  * transfer data secara langsung, menghindari keterlibatan ruang pengguna, sehingga meningkatkan performa.
  * 
  * @req: Blok kontrol permintaan I/O untuk operasi ini.
  * @issue_flags: Flag yang menunjukkan apakah operasi harus non-blocking atau dieksekusi dengan pengaturan khusus lainnya.
  * 
  * Mengembalikan 0 jika berhasil, atau kode kesalahan jika terjadi masalah.
  */
 int io_tee(struct io_kiocb *req, unsigned int issue_flags);
 
 /**
  * io_splice_cleanup:
  * Membersihkan sumber daya yang terkait dengan operasi splice. Operasi splice memindahkan data antara
  * deskriptor file di kernel, menghindari ruang pengguna, dan fungsi ini dipanggil untuk memastikan pembersihan
  * yang benar setelah operasi selesai.
  * 
  * @req: Blok kontrol permintaan I/O untuk operasi splice.
  */
 void io_splice_cleanup(struct io_kiocb *req);
 
 /**
  * io_splice_prep:
  * Mempersiapkan permintaan I/O untuk operasi splice. Fungsi ini memvalidasi entry antrian pengajuan (SQE) dan
  * menyiapkan struktur internal yang diperlukan. Operasi splice mentransfer data antara deskriptor file di kernel
  * tanpa melibatkan ruang pengguna.
  * 
  * @req: Blok kontrol permintaan I/O.
  * @sqe: Entry antrian pengajuan yang berisi parameter operasi.
  * 
  * Mengembalikan 0 jika persiapan berhasil, atau kode kesalahan jika parameter tidak valid.
  */
 int io_splice_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
 
 /**
  * io_splice:
  * Menjalankan operasi splice yang sebenarnya. Operasi ini mentransfer data antara dua deskriptor file secara langsung di kernel,
  * tanpa menyalin data ke ruang pengguna, yang menghasilkan efisiensi yang lebih tinggi.
  * 
  * @req: Blok kontrol permintaan I/O untuk operasi ini.
  * @issue_flags: Flag untuk mengontrol bagaimana operasi harus dijalankan (misalnya, non-blocking).
  * 
  * Mengembalikan 0 jika operasi berhasil, atau kode kesalahan jika terjadi masalah.
  */
 int io_splice(struct io_kiocb *req, unsigned int issue_flags);
 
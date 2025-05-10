# Task 1: Information about io_uring source
List in this section source and headers of io_uring. For each of the C source/header, you must put description what's the prime responsibily of the source. Take notes, description of the source should be slightly technical like the example given. 

## Source
### advice.c
Store io_madvice & io_fadvice structures, both have the same exact attributes. Which make them basically the same thing. Except function body treat them as separate. Codes which make use of io_madvice are guarded by compilation macro, which make its relevant functions only active if the build flag is set. But functions that make use of io_fadvice are active all the time. The exact difference between io_madvice & io_fadvice will only known after exploring do_madvise function for io_madvice & vfs_fadvise function for io_fadvice. 

### alloc_cache.h
mengelola cache memori dengan tiga fungsi utama: io_alloc_cache_free untuk membebaskan entri cache, io_alloc_cache_init untuk menginisialisasi cache, dan io_cache_alloc_new untuk mengalokasikan memori baru dalam cache. Semua fungsi ini memastikan pengelolaan memori yang efisien dan aman.

### cancel.c
File ini menangani logika untuk membatalkan submission queue entry (SQE) yang sebelumnya sudah dikirim tetapi belum selesai diproses. Ini mencakup pencarian dan identifikasi request yang cocok berdasarkan user data atau opcode, serta memastikan bahwa resource yang terkait dibersihkan dengan aman dan konsisten. Pembatalan ini penting dalam kasus di mana aplikasi pengguna tidak lagi membutuhkan hasil dari operasi I/O tertentu, atau dalam kondisi error di mana proses harus menghentikan operasi I/O yang sedang berjalan.

### epoll.c
mengintegrasikan mekanisme epoll dengan io_uring, memungkinkan event polling berbasis epoll dijalankan melalui interface io_uring. Fungsinya mencakup pendaftaran event, pemantauan file descriptor menggunakan epoll, serta penanganan notifikasi ketika kondisi I/O (seperti readable atau writable) terjadi. Ini memungkinkan aplikasi untuk menggunakan io_uring tidak hanya untuk operasi I/O langsung, tetapi juga untuk event-driven programming berbasis epoll, sehingga meningkatkan efisiensi dan skalabilitas pada aplikasi dengan banyak koneksi seperti server jaringan.

### eventfd.c
menyediakan dukungan untuk operasi I/O terhadap eventfd melalui interface io_uring. Eventfd sendiri adalah mekanisme sinkronisasi ringan yang digunakan antar thread atau antar proses untuk memberi sinyal (event notification). Dalam file ini, io_uring memungkinkan operasi read dan write terhadap eventfd dilakukan secara asynchronous. Implementasi ini memetakan request dari submission queue ke operasi eventfd di kernel, serta menangani penyelesaian (completion) yang sesuai. Ini memungkinkan penggunaan eventfd sebagai sarana signaling yang efisien dalam aplikasi asynchronous yang dibangun di atas io_uring.

### fdinfo.c
menyediakan informasi terkait file descriptor yang terhubung dengan instance io_uring, biasanya melalui antarmuka /proc. Fungsi utamanya adalah menampilkan data statistik dan status internal io_uring, seperti jumlah request yang masuk, request yang selesai, dan informasi antrean. 

### filetable.c
manajemen tabel file (file table) yang menyimpan struktur file descriptor untuk setiap proses. Dalam kaitannya dengan io_uring, file ini berperan dalam memastikan bahwa setiap operasi I/O yang menggunakan file descriptor dilakukan secara aman dan konsisten, terutama dalam hal referensi, validasi, dan sinkronisasi terhadap struktur file. 

### fs.c
menangani interaksi antara io_uring dan subsistem filesystem di kernel Linux. Fungsinya meliputi pengelolaan akses terhadap objek-objek filesystem seperti path, file, dan direktori yang digunakan dalam operasi I/O berbasis io_uring. Ini termasuk resolving pathnames, menjaga referensi ke struktur file dan mount, serta mengelola akses yang aman dan efisien terhadap entitas filesystem saat melakukan operasi seperti open, statx, atau remove.

### futex.c
menyediakan dukungan untuk operasi futex (fast userspace mutex) melalui mekanisme io_uring. Futex adalah primitif sinkronisasi yang memungkinkan thread melakukan wait dan wake terhadap nilai di memory userspace, dengan efisiensi tinggi karena sebagian besar operasinya tidak perlu masuk ke kernel (kecuali saat kontensi terjadi). Melalui file ini, io_uring memungkinkan operasi futex dilakukan secara asynchronous—memperluas fungsionalitas futex ke model I/O non-blocking.

#### io_uring.c
inti dari implementasi io_uring di kernel Linux. File ini bertanggung jawab atas pembentukan, pengelolaan, dan eksekusi utama seluruh lifecycle dari instance io_uring. Di dalamnya terdapat logika untuk mengatur submission queue (SQ) dan completion queue (CQ), inisialisasi dan teardown context, pemrosesan request I/O (baik langsung maupun melalui worker thread), serta manajemen sumber daya dan sinkronisasi. Selain itu, file ini menangani komunikasi antara userspace dan kernel, termasuk pengambilan request, penjadwalan eksekusi, dan penyelesaian hasil. 

#### io-wq.c
mengimplementasikan mekanisme thread pool yang digunakan oleh io_uring untuk menjalankan tugas I/O secara asinkron. Setiap instance io_wq (work queue) dapat memiliki beberapa worker thread, yang dibagi menjadi dua jenis: bound (terikat pada CPU tertentu) dan unbound (bisa berjalan di sembarang CPU). Thread-thread ini menunggu tugas masuk melalui antrian kerja (work_list), lalu memprosesnya secara efisien dengan memperhatikan pengaturan afinitas CPU dan batasan jumlah maksimum worker. Jika tidak ada worker yang tersedia, sistem akan membuat yang baru selama belum mencapai batas maksimal. Ketika tidak ada pekerjaan, worker akan tidur atau bahkan keluar jika sudah terlalu lama tidak aktif.

### kbuf.c
emungkinkan aplikasi pengguna untuk mendaftarkan buffer yang akan digunakan untuk operasi I/O seperti read atau write tanpa perlu menyalin data berulang-ulang. Fungsi-fungsi seperti io_provide_buffers(), io_register_pbuf_ring(), dan io_unregister_pbuf_ring() digunakan untuk mengelola daftar buffer tersebut. Ada dua mode utama: buffer yang dikelola secara sederhana dalam list (IOBL_BUF_RING), dan buffer yang di-mmap sebagai struktur ring untuk akses lebih cepat. Selain itu, terdapat juga fungsi untuk memilih buffer saat I/O dimulai (io_provided_buffer_select()), serta mekanisme untuk menghapus atau mengganti buffer yang telah terpakai.

### memmap.c
engatur mekanisme buffer management dalam io_uring, yaitu cara aplikasi pengguna dapat menyediakan buffer sendiri untuk digunakan oleh operasi I/O seperti read atau write. Fungsi utama seperti io_add_buffers(), io_remove_buffers(), io_register_pbuf_ring(), dan io_unregister_pbuf_ring() digunakan untuk menambahkan, menghapus, dan mengelola buffer tersebut. Buffer bisa dikelola sebagai daftar sederhana atau sebagai struktur ring buffer yang di-map menggunakan mmap. 

### msg_ring.c
menangani operasi IORING_OP_MSG_RING, yaitu fitur di io_uring yang memungkinkan komunikasi antar dua instance io_uring. Dengan operasi ini, aplikasi bisa mengirimkan data (IORING_MSG_DATA ) atau bahkan file descriptor (IORING_MSG_SEND_FD ) ke instance io_uring lain. Data dikirim sebagai completion queue event (CQE ) ke instance tujuan. Kode ini mencakup fungsi-fungsi seperti io_msg_ring_data() untuk mengirimkan data dan io_msg_send_fd() untuk mengirimkan file descriptor secara aman. Jika instance tujuan sedang tidak aktif atau perlu diproses oleh thread worker, maka pengiriman didelegasikan melalui mekanisme task work . 

### napi.c
menambahkan dukungan untuk mekanisme NAPI ke dalam io_uring, yaitu fitur yang digunakan oleh driver jaringan untuk mencegah terlalu banyak interupsi saat menerima banyak paket (high packet rate ). Dengan io_uring, aplikasi bisa menggunakan busy-loop polling untuk menunggu event jaringan tanpa perlu beralih ke mode interupsi, sehingga mengurangi latensi. Fungsi seperti io_register_napi() dan io_unregister_napi() digunakan untuk mengatur cara polling dilakukan, termasuk mode statis atau dinamis, durasi polling, dan ID NAPI tertentu. Selama polling, fungsi io_napi_do_busy_loop() akan memeriksa apakah ada pekerjaan baru atau apakah sudah waktunya berhenti polling berdasarkan timeout atau sinyal dari aplikasi.

### net.c
mengimplementasikan operasi sistem bind() menggunakan antarmuka io_uring, memungkinkan aplikasi pengguna mengikat socket ke alamat tertentu secara asinkron. Fungsi io_bind_prep() membaca parameter dari struktur sqe (Submission Queue Entry), memvalidasi input, dan menyalin alamat dari ruang pengguna ke ruang kernel. Selanjutnya, io_bind() melakukan pemanggilan sistem bind() sebenarnya pada socket yang sesuai. File ini juga mencakup bagian dari operasi sendmsg() dengan dukungan zero-copy (io_sendmsg_zc) yang memungkinkan pengiriman data tanpa penyalinan memori tambahan, meningkatkan efisiensi. Ada juga fungsi penanganan error umum seperti io_sendrecv_fail() untuk membersihkan status I/O jika terjadi kegagalan atau interupsi.

### nop.c
mendefinisikan dua fungsi utama: io_nop_prep() dan io_nop(). Fungsi io_nop_prep() membaca parameter dari struktur SQE (Submission Queue Entry ) seperti flag, hasil yang akan diinjeksi, file descriptor, atau buffer index, serta memvalidasi bahwa flag yang digunakan diperbolehkan. Flag-flag tersebut dapat menentukan apakah NOP harus mengembalikan nilai tertentu, menggunakan file tetap (fixed file ), atau menggunakan buffer tetap (fixed buffer ). Selanjutnya, io_nop() memproses operasi NOP dengan mempertimbangkan opsi-opsi yang telah disiapkan. Jika ada file atau buffer yang terlibat, maka operasi akan mencoba mendapatkan akses ke sumber daya tersebut sesuai dengan jenisnya. Jika berhasil, operasi NOP mengembalikan nilai yang ditentukan; jika gagal, seperti file descriptor tidak valid atau buffer tidak tersedia, maka akan dilaporkan error ke aplikasi pengguna melalui CQE (Completion Queue Event )

### notif.c
mengimplementasikan fungsi-fungsi penting untuk mendukung pengiriman data jaringan tanpa penyalinan memori (zero-copy ), yaitu dengan menggunakan struktur io_notif_data dan ubuf_info. Fungsi utama seperti io_alloc_notif() digunakan untuk mengalokasikan objek notifikasi (io_kiocb) yang akan digunakan untuk melacak status pengiriman zero-copy. Dua fungsi kunci, io_tx_ubuf_complete() dan io_link_skb(), menentukan apa yang terjadi ketika pengiriman selesai dan bagaimana skb (socket buffer ) dikaitkan dengan buffer notifikasi. Jika semua referensi ke buffer telah selesai, maka callback io_notif_tw_complete() dipanggil untuk membersihkan dan melaporkan hasil akhir ke aplikasi pengguna melalui CQE (Completion Queue Event ). 

### opdef.c
mendefinisikan tabel penanganan opcode untuk io_uring, di mana setiap operasi (IORING_OP_XXX) dipetakan ke fungsi persiapan (prep) dan penerbitan (issue) yang sesuai, serta flag-flag khusus (misalnya needs_file, pollin/pollout, atau async_size) yang mengatur cara kerjanya. Tabel io_issue_defs mengonfigurasi perilaku runtime (buffer, polling, prioritas I/O, dan sebagainya), sedangkan io_cold_defs menyediakan metadata seperti nama operasi dan fungsi pembersihan (cleanup) atau penanganan kegagalan (fail). Ini memastikan bahwa setiap permintaan I/O—mulai dari baca/tulis file, operasi socket, hingga timeout dan cancel—dikenali, dipersiapkan, dan dieksekusi dengan tepat oleh io_uring.

### openclose.c
mengimplementasikan tiga operasi utama: io_openat() untuk membuka file secara asinkron seperti openat(), io_close() untuk menutup file descriptor, dan io_install_fixed_fd() untuk menginstal file descriptor tetap. Fungsi io_openat_prep() dan io_openat2_prep() digunakan untuk memvalidasi parameter dari aplikasi pengguna sebelum operasi dimulai, sedangkan io_openat() dan io_close() menjalankan operasi sesungguhnya menggunakan fungsi kernel standar seperti do_filp_open() dan filp_close(). Jika operasi tidak bisa dilakukan secara langsung (misal karena flag O_CREAT atau O_TRUNC), maka akan dipaksa sebagai operasi async agar tidak memblokir thread. 

### poll.c
mengatur mekanisme polling untuk io_uring, mulai dari pendaftaran wait-queue pada file descriptor, cek dan penanganan event lewat vfs_poll(), hingga wake-up dan penjadwalan ulang atau pembatalan request. Modul ini juga mengelola referensi dan kepemilikan (poll_refs), duplikasi entri (double_poll), hash table untuk cancel, serta integrasi dengan task-work (io_poll_task_func) untuk memastikan event I/O di-arm, dijalankan, atau dibatalkan secara aman dan efisien.

### register.c
mengimplementasikan syscall io_uring_register(), yang menangani pendaftaran berbagai sumber daya dan konfigurasi untuk sebuah io_uring (buffer, file, eventfd, probe, personality, batasan, affinitas I/O-wq, ukuran worker, mmap region, dll.). Berdasarkan opcode yang dikirim user, ia menyalin data dari user space, memvalidasi parameter, dan memanggil fungsi khusus seperti io_sqe_buffers_register(), io_eventfd_register(), io_register_restrictions(), io_register_resize_rings(), dan seterusnya—semuanya di dalam proteksi uring_lock untuk memastikan konsistensi dan keamanan.

### rsrc.c
menangani manajemen fixed file descriptors (FD) dalam io_uring, yang memungkinkan proses untuk register (mendaftarkan) dan unregister (menghapus) file descriptor agar bisa diakses lebih cepat tanpa lookup berulang. Di dalamnya terdapat fungsi seperti io_register_files dan io_unregister_files yang bertugas mengatur daftar FD tetap pada konteks io_ring_ctx. File ini juga menyediakan logika untuk mengganti (io_register_files_update) dan memetakan file descriptor ke entri internal io_uring, serta memastikan sinkronisasi dan keamanan memori melalui locking saat FD digunakan atau diubah.

### rw.c
menangani operasi baca (read) dan tulis (write) pada io_uring. Ia mencakup I/O sinkron maupun asynchronous untuk file biasa, pipes, dan soket, serta mendukung fitur lanjutan seperti I/O langsung (Direct I/O), short read/write, vectored I/O (readv, writev), dan zero-copy menggunakan io_uring yang efisien. Fungsi io_read, io_write, dan variannya memproses permintaan dengan menjaga efisiensi kernel.

### splice.c
Mengimplementasikan operasi splice, tee, dan vmsplice yang memungkinkan pemindahan data antar file descriptor tanpa menyalin ke ruang pengguna. Ini penting untuk performa tinggi, seperti streaming atau relay data. io_splice, io_tee, dan io_vmsplice menangani alur parsing parameter SQE, eksekusi dengan do_splice, dan pembersihan setelah operasi.

### sqpoll.c
mengelola mekanisme polling pada submission queue (SQ). Mengelola thread yang menangani polling untuk memindahkan entri dari userspace ke kernel secara efisien tanpa melibatkan interaksi langsung dengan aplikasi. Fungsinya mencakup pembuatan dan pengelolaan thread polling, pengaturan idle time, penanganan sinyal dan pembatalan tugas, serta pengolahan event dengan memanfaatkan task work atau worker queues.

### statx.c
mengimplementasikan operasi statx pada io_uring, yang memungkinkan pengguna untuk mengambil status file secara efisien. Fungsi io_statx_prep menyiapkan data yang diperlukan, seperti file descriptor, flag, dan path file, serta memvalidasi parameter yang diterima. Fungsi io_statx kemudian mengeksekusi panggilan sistem do_statx untuk mendapatkan status file sesuai dengan mask dan flag yang diberikan, sementara io_statx_cleanup membersihkan sumber daya yang digunakan (seperti nama file) setelah operasi selesai. Semua operasi ini dilakukan secara asinkron menggunakan io_uring.

### sync.c
mengimplementasikan beberapa operasi sinkronisasi file dalam konteks io_uring, termasuk sync_file_range, fsync, dan fallocate. Setiap fungsi mempersiapkan dan menjalankan operasi tersebut dengan memeriksa parameter, memastikan operasi berjalan secara sinkron, dan menangani pengalokasian ruang atau penyimpanan data ke disk. Menggunakan struktur io_sync untuk menyimpan informasi terkait offset, panjang, dan flag yang diperlukan oleh operasi yang dilakukan, serta memastikan eksekusi tidak dilakukan dalam mode non-blocking.

### tctx.c
mengelola konteks tugas untuk operasi io_uring di kernel Linux. Fungsi io_uring_alloc_task_context mengalokasikan dan menginisialisasi konteks tugas untuk setiap thread atau task, mencakup pembuatan antrian kerja (workqueue) untuk pemrosesan asinkron dan pengaturan berbagai atribut seperti task list dan task work. Fungsi io_ringfd_register dan io_ringfd_unregister digunakan untuk mendaftarkan dan membatalkan pendaftaran file descriptor ring buffer, yang memungkinkan penggunaan berulang tanpa perlu memanggil fdget atau fdput setiap kali. Selain itu, fungsi __io_uring_add_tctx_node menambahkan node konteks tugas ke dalam xarray untuk melacak task yang terkait dengan ring.

### timeout.c
mengimplementasikan fitur timeout untuk io_uring, sebuah mekanisme I/O asinkron yang efisien. menangani pembuatan, pembatalan, dan eksekusi timeout, baik untuk operasi tunggal maupun yang terhubung (linked). Fungsi utamanya termasuk mengatur timer berbasis hrtimer, memproses timeout yang telah berjalan, membatalkan timeout sesuai permintaan, serta mengelola timeout multishot (berulang). Kode juga menangani kasus khusus seperti linked timeout yang terkait dengan operasi I/O lain, memastikan operasi dibatalkan jika timeout terjadi.

### trumcate.c
mengimplementasikan operasi ftruncate untuk io_uring, yang memungkinkan pemotongan (truncate) file secara asinkron. Fungsi io_ftruncate_prep memvalidasi dan mempersiapkan permintaan truncate, sedangkan io_ftruncate menjalankan operasi truncate sebenarnya dengan memanggil do_ftruncate. Operasi ini dipaksa berjalan secara asinkron (REQ_F_FORCE_ASYNC) dan tidak mendukung mode non-blocking. Hasil operasi disetel dalam struktur permintaan untuk diproses lebih lanjut oleh io_uring.

### uring_cmd.c
menangani eksekusi, pembatalan, dan penyelesaian perintah khusus (uring_cmd) dari userspace ke kernel. File ini mengelola alokasi dan pembebasan memori async, penandaan dan penghapusan status cancelable, serta eksekusi perintah secara sinkron maupun asinkron melalui task work atau worker queue. Fungsi utamanya juga mengatur pemrosesan data dari sqe, integrasi dengan driver melalui f_op->uring_cmd, dan mendukung operasi socket tertentu jika dikompilasi dengan dukungan jaringan (CONFIG_NET).

### waitlid.c
mengimplementasikan dukungan untuk operasi waitid secara asynchronous dalam io_uring, dengan menangani proses persiapan (io_waitid_prep), eksekusi (io_waitid), penyalinan hasil ke ruang pengguna, penanganan pembatalan (io_waitid_cancel), dan penyelesaian permintaan. Membuat dan mengelola struktur io_waitid dan io_waitid_async yang berisi informasi proses yang ditunggu, mengatur antrean penungguan (wait_queue), serta menggunakan mekanisme task work untuk menunda eksekusi penyelesaian hingga proses anak selesai atau dibatalkan. Jika proses selesai, informasi status seperti PID, UID, dan kode keluar disalin ke user space; jika terjadi pembatalan, permintaan ditandai dan dibersihkan dengan aman.

### xattr.c
menangani operasi extended attributes (xattr) secara asynchronous di io_uring, termasuk membaca (getxattr, fgetxattr) dan menulis (setxattr, fsetxattr) metadata tambahan pada file. Ia menggunakan struktur io_xattr untuk menyimpan informasi seperti nama dan nilai atribut, serta menyediakan fungsi prep untuk inisialisasi permintaan dan finish untuk pembersihan setelah eksekusi.

### zcrx.c
Mengimplementasikan penerimaan data (recv) zero-copy pada soket. Dengan zcrx, data diterima langsung ke memory-mapped buffer tanpa salinan ke ruang pengguna, yang menghemat waktu dan CPU. Ia mengatur alokasi buffer, integrasi dengan socket recvmsg, dan pemrosesan efisien untuk jaringan.


## another source

## Headers
### advice.h
Just declare the function specification. 

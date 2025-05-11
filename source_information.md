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
### advise.h
mendefinisikan fungsi untuk mengoptimalkan manajemen memori dan file secara asinkron melalui io_uring. Fungsi io_madvise_prep() dan io_madvise() bertanggung jawab untuk operasi terkait memori, seperti memberi tahu kernel tentang pola akses memori (misal: MADV_SEQUENTIAL untuk akses berurutan) atau membersihkan cache yang tidak perlu (MADV_DONTNEED). Sementara itu, io_fadvise_prep() dan io_fadvise() fokus pada file, memungkinkan aplikasi memberikan saran seperti POSIX_FADV_WILLNEED (prefetch data) atau POSIX_FADV_DONTNEED (bersihkan cache file). Kedua pasangan fungsi ini bekerja dua tahap: prep (validasi input) dan execute (eksekusi asinkron), dengan hasil yang dilaporkan via Completion Queue Event (CQE) 

### alloc_cache.h
mendefinisikan mekanisme cache alokasi memori untuk io_uring yang bertujuan mengurangi overhead alokasi/delokasi dinamis dengan memanfaatkan objek yang sudah pernah dialokasikan. Fungsi utama seperti io_alloc_cache_init() menginisialisasi cache dengan batas maksimal (IO_ALLOC_CACHE_MAX), sementara io_alloc_cache_free() membersihkan cache dan mengembalikan memori ke sistem. Fungsi io_cache_alloc_new() digunakan untuk alokasi baru jika cache kosong, sedangkan io_alloc_cache_put() dan io_alloc_cache_get() mengelola penyimpanan/pengambilan objek dari cache secara efisien. Ada juga penanganan khusus untuk KASAN (Kernel Address Sanitizer) untuk memastikan keamanan memori.

### cancel.h
mendefinisikan mekanisme pembatalan operasi asinkron dalam io_uring, memungkinkan aplikasi membatalkan permintaan I/O yang sedang berjalan atau tertunda. Fungsi inti seperti io_async_cancel_prep() dan io_async_cancel() menangani pembatalan berbasis SQE (Submission Queue Entry), sementara io_try_cancel() dan io_sync_cancel() memproses pembatalan secara sinkron atau asinkron berdasarkan parameter seperti file descriptor atau opcode. Struktur io_cancel_data menyimpan konteks pembatalan, termasuk target operasi (file atau data) dan flags. Fungsi io_cancel_req_match() digunakan untuk mencocokkan permintaan yang akan dibatalkan dengan kriteria tertentu.

### epoll.h
mendefinisikan fungsi-fungsi untuk mengintegrasikan sistem epoll dengan io_uring, memungkinkan manajemen event I/O yang efisien secara asinkron. Fungsi io_epoll_ctl_prep() dan io_epoll_ctl() menangani operasi kontrol epoll seperti menambah, menghapus, atau memodifikasi file descriptor yang dipantau, sementara io_epoll_wait_prep() dan io_epoll_wait() mengimplementasikan fungsi wait epoll untuk menerima notifikasi event secara non-blocking. Semua fungsi ini hanya tersedia jika kernel dikompilasi dengan dukungan epoll (CONFIG_EPOLL).

### eventfd.h
mendefinisikan antarmuka untuk mengintegrasikan eventfd dengan io_uring, menyediakan mekanisme notifikasi antar-proses yang efisien. Fungsi io_eventfd_register() dan io_eventfd_unregister() bertanggung jawab untuk menghubungkan dan melepaskan eventfd dari konteks io_uring (io_ring_ctx), memungkinkan aplikasi menerima notifikasi asinkron tentang penyelesaian operasi I/O. Fungsi io_eventfd_signal() digunakan untuk memicu notifikasi eventfd secara manual, sementara io_eventfd_flush_signal() memastikan semua sinyal yang tertunda diproses sebelum eventfd diunregister.

### fdinfo.h
mendeklarasikan fungsi io_uring_show_fdinfo() yang bertujuan untuk menampilkan informasi debug terkait io_uring melalui sistem file /proc. Fungsi ini mengambil parameter berupa pointer ke seq_file (untuk output berurutan) dan pointer ke file (representasi file descriptor), lalu memformat berbagai informasi penting seperti status submission/completion queue, jumlah operasi I/O aktif, serta konfigurasi io_uring termasuk flags dan ukuran buffer. Informasi ini sangat berharga untuk keperluan debugging dan pemantauan performa sistem secara real-time.

### filetable.h
mendefinisikan mekanisme manajemen tabel file untuk io_uring yang memungkinkan alokasi dan pengelolaan file descriptor secara efisien. Fungsi utama seperti io_alloc_file_tables dan io_free_file_tables bertanggung jawab untuk mengalokasikan dan membebaskan struktur data yang menyimpan informasi file, sementara io_fixed_fd_install dan io_fixed_fd_remove menangani instalasi dan penghapusan file descriptor tetap (fixed file descriptors) yang merupakan fitur kunci io_uring untuk menghindari overhead pengelolaan file descriptor tradisional. File ini juga menyediakan fungsi pendukung seperti io_file_get_flags untuk mendapatkan flags file dan berbagai macro serta fungsi inline untuk manipulasi bitmap yang mengelola slot file, seperti io_file_bitmap_set dan io_file_bitmap_clear yang memastikan manajemen slot file yang efisien dan aman.

### fs.h
mendefinisikan serangkaian fungsi untuk operasi filesystem asinkron melalui io_uring, menyediakan antarmuka performa tinggi untuk manipulasi file dan direktori. Setiap operasi filesystem (seperti rename, unlink, mkdir, symlink, dan link) diimplementasikan dalam tiga tahap: fungsi *_prep untuk memvalidasi parameter dan menyiapkan request, fungsi *_execute untuk menjalankan operasi secara asinkron, dan fungsi *_cleanup untuk membebaskan resource setelah operasi selesai. Pendekatan modular ini memungkinkan io_uring menangani operasi filesystem yang kompleks dengan efisien sambil menjaga konsistensi sistem.

### futex.h
mendefinisikan mekanisme operasi futex (fast userspace mutex) asinkron melalui io_uring, yang memungkinkan sinkronisasi antar-thread/userspace dengan performa tinggi. Fungsi utama seperti io_futex_wait dan io_futex_wake menyediakan operasi dasar futex untuk menunggu dan membangunkan thread, sementara io_futexv_wait mendukung operasi pada array futex (futex vector). File ini juga mencakup fungsi persiapan (io_futex_prep, io_futexv_prep) untuk memvalidasi parameter request, serta fungsi manajemen seperti io_futex_cancel untuk membatalkan operasi yang sedang berjalan. Implementasi ini hanya aktif ketika kernel dikompilasi dengan dukungan futex (CONFIG_FUTEC), dengan fallback ke fungsi dummy ketika fitur tidak tersedia.

### io_uring.h
merupakan header inti yang mendefinisikan struktur dasar dan mekanisme operasional io_uring untuk I/O asinkron berkinerja tinggi. File ini berisi deklarasi fungsi-fungsi kunci seperti io_uring_fill_params untuk inisialisasi konteks io_uring, io_run_task_work untuk mengeksekusi task work terkait I/O, serta berbagai utility function seperti io_get_cqe untuk mengakses Completion Queue Entries (CQE). File ini juga mendefinisikan struktur penting seperti io_wait_queue untuk manajemen wait queue dan berbagai macro untuk operasi atomik pada ring buffer. Implementasi ini dirancang untuk mendukung operasi I/O non-blocking dengan overhead minimal.

### io-wq.h
mendefinisikan antarmuka untuk I/O Work Queue (io_wq), sebuah komponen kritis dalam io_uring yang menangani eksekusi asynchronous I/O operations di kernel space. Header ini mendeklarasikan struktur utama seperti io_wq sebagai representasi work queue, io_wq_work untuk unit pekerjaan, dan io_wq_data yang berisi konfigurasi seperti fungsi callback (do_work dan free_work). Fungsi inti seperti io_wq_create() untuk inisialisasi work queue, io_wq_enqueue() untuk menjadwalkan pekerjaan, serta io_wq_cancel_cb() untuk membatalkan pekerjaan, menunjukkan arsitektur berbasis task yang fleksibel. Dukungan fitur seperti work hashing (melalui IO_WQ_WORK_HASHED) dan konfigurasi affinity CPU (io_wq_cpu_affinity) memungkinkan optimasi performa untuk workload spesifik.

### kbuf.h
mendefinisikan mekanisme manajemen buffer untuk io_uring, menyediakan dua pendekatan utama: provided buffers (buffer yang dikelola pengguna) dan buffer rings (ring buffer terpetik). Fungsi inti seperti io_provide_buffers() dan io_remove_buffers() menangani registrasi dan pelepasan buffer, sementara io_buffer_select() dan io_buffers_peek() memungkinkan seleksi buffer dinamis selama operasi I/O. File ini juga mendukung fitur canggih seperti buffer recycling melalui io_kbuf_recycle() untuk mengurangi alokasi memori berulang, serta manajemen buffer ring berbasis halaman memori (io_register_pbuf_ring). Struktur data kunci seperti io_buffer_list dan io_buffer mengorganisir buffer dalam grup (bgid) untuk efisiensi.

### memmap.h
mendefinisikan fungsi-fungsi untuk manajemen memory mapping dalam io_uring, khususnya terkait alokasi dan pemetaan memori antara user space dan kernel space. Fungsi utama seperti io_pin_pages bertanggung jawab untuk meminjam (pin) halaman memori pengguna agar tetap tersedia selama operasi I/O berlangsung, sementara io_uring_mmap dan io_uring_get_unmapped_area menangani pembuatan memory mapping untuk ring buffers dan struktur data io_uring lainnya. File ini juga menyediakan fungsi seperti io_create_region dan io_free_region untuk mengelola wilayah memori terpetik (mapped regions) yang digunakan oleh io_uring, termasuk penanganan khusus untuk sistem tanpa MMU (Memory Management Unit) melalui io_uring_nommu_mmap_capabilities.

### msg_ring.h
mendefinisikan mekanisme message passing antar-proses melalui io_uring, yang memungkinkan komunikasi dan koordinasi yang efisien antara berbagai komponen sistem. Fungsi utama seperti io_msg_ring_prep bertanggung jawab untuk mempersiapkan permintaan pengiriman pesan dengan memvalidasi parameter dari Submission Queue Entry (SQE), sementara io_msg_ring mengeksekusi pengiriman pesan secara asinkron. File ini juga menyertakan io_uring_sync_msg_ring untuk operasi sinkron dan io_msg_ring_cleanup untuk membersihkan resource setelah operasi selesai, memastikan tidak ada memory leak atau kondisi race.

### napi.h
mendefinisikan mekanisme busy polling untuk io_uring yang memungkinkan operasi I/O jaringan berlatensi rendah dengan memanfaatkan NAPI (New API) dari subsistem jaringan Linux. Fungsi inti seperti io_napi_init dan io_napi_free mengelola inisialisasi dan pembersihan struktur NAPI, sementara io_register_napi dan io_unregister_napi menyediakan antarmuka untuk registrasi dinamis. Implementasi busy polling dilakukan melalui __io_napi_busy_loop dan io_napi_sqpoll_busy_poll, yang secara aktif memeriksa ketersediaan data jaringan tanpa perlu interrupt, mengurangi latency secara signifikan. Fungsi utilitas seperti io_napi_add secara otomatis menambahkan socket ke dalam sistem tracking NAPI berdasarkan ID-nya, memungkinkan optimasi yang dinamis dan terarah.

### net.h
mendefinisikan antarmuka untuk operasi jaringan asinkron melalui io_uring, menyediakan implementasi high-performance untuk berbagai syscall jaringan tradisional. File ini mencakup fungsi-fungsi dasar seperti io_send dan io_recv untuk pengiriman/penerimaan data, serta operasi socket management seperti io_socket, io_bind, dan io_listen. Fungsi-fungsi tersebut mengikuti pola io_uring yang khas dengan fase _prep untuk validasi parameter, fase eksekusi asinkron, dan _cleanup untuk manajemen resource. Struktur io_async_msghdr yang kompleks digunakan untuk menangani operasi messaging seperti io_sendmsg dan io_recvmsg, termasuk dukungan untuk scatter-gather I/O dan alamat socket.

### nop.h
mendefinisikan operasi no-operation (NOP) dalam io_uring, yang berfungsi sebagai operasi dummy atau placeholder untuk keperluan testing dan benchmarking. Fungsi io_nop_prep bertugas mempersiapkan request NOP dengan memvalidasi Submission Queue Entry (SQE), meskipun tidak ada parameter khusus yang perlu diproses untuk operasi ini. Sementara itu, io_nop mengeksekusi operasi NOP secara asinkron, yang pada dasarnya tidak melakukan tindakan apa pun tetapi tetap menghasilkan Completion Queue Event (CQE) untuk menandai penyelesaian request.

### notif.h
mendefinisikan mekanisme notifikasi zero-copy dalam io_uring, yang memungkinkan pengiriman data jaringan tanpa penyalinan memori (zero-copy) antara user space dan kernel space. Fungsi utama seperti io_alloc_notif bertanggung jawab untuk mengalokasikan struktur notifikasi (io_notif_data) yang melacak status pengiriman data, termasuk informasi buffer dan akun memori. Fungsi io_tx_ubuf_complete menangani callback yang dipanggil ketika pengiriman data selesai, baik berhasil maupun gagal, dan membersihkan resource yang terkait. Struktur io_notif_data menyimpan metadata penting seperti file target, halaman memori yang digunakan, dan status zero-copy (zc_report, zc_used, zc_copied).

### opdef.h
mendefinisikan struktur kunci yang menjadi blueprint operasi io_uring, mengatur karakteristik dan perilaku semua opcode yang didukung. File ini mendeklarasikan dua struktur utama: io_issue_def yang berisi metadata operasi seperti flag kebutuhan file (needs_file), dukungan iopoll (iopoll), atau kemampuan buffer selection (buffer_select), serta pointer fungsi untuk issue dan prep; dan io_cold_def yang menangani operasi "dingin" seperti cleanup dan fail handling melalui callback khusus. Array global io_issue_defs[] dan io_cold_defs[] berisi definisi semua operasi yang didukung, sementara fungsi io_uring_op_supported() memungkinkan pengecekan ketersediaan opcode.

### openclose.h
mendefinisikan fungsi-fungsi untuk operasi pembukaan dan penutupan file secara asinkron melalui io_uring, menyediakan antarmuka performa tinggi untuk manajemen file descriptor. Fungsi utama seperti io_openat, io_openat2, dan io_close menangani operasi dasar pembukaan dan penutupan file, sementara io_openat_prep dan io_close_prep bertanggung jawab untuk memvalidasi dan mempersiapkan parameter operasi dari Submission Queue Entry (SQE). File ini juga mencakup fungsi khusus seperti __io_close_fixed untuk menutup fixed file descriptor dan io_install_fixed_fd untuk mengaitkan file descriptor dengan slot fixed file yang telah dialokasikan sebelumnya.

### poll.h
mendefinisikan mekanisme I/O polling asinkron dalam io_uring, yang memungkinkan aplikasi memantau ketersediaan event pada file descriptor tanpa blocking. Fungsi inti seperti io_poll_add dan io_poll_remove menangani pendaftaran dan penghapusan operasi polling, dengan fase preparasi (io_poll_add_prep, io_poll_remove_prep) untuk validasi parameter dari SQE. Struktur data seperti io_poll menyimpan konteks polling (file, event mask, wait queue), sementara async_poll mendukung operasi double-poll untuk skenario kompleks. File ini juga menyediakan fungsi cancel (io_poll_cancel) dan manajemen multishot polling melalui io_poll_multishot_retry.

### refs.h
mendefinisikan mekanisme reference counting yang aman dan efisien untuk request I/O (io_kiocb) dalam io_uring, memastikan manajemen siklus hidup request yang tepat. Fungsi-fungsi seperti req_ref_get dan req_ref_put menangani increment/decrement reference count secara atomik, dilengkapi dengan pemeriksaan keamanan melalui makro req_ref_zero_or_close_to_overflow yang mendeteksi potential overflow. File ini juga menyediakan fungsi khusus seperti req_ref_put_and_test yang menggabungkan operasi decrement dengan pengecekan apakah reference count mencapai nol, serta io_req_set_refcount untuk inisialisasi reference count pada request baru.

### register.h
mendefinisikan fungsi-fungsi untuk manajemen registrasi dan deregistrasi resource dalam io_uring, yang memungkinkan aplikasi mengaitkan atau melepaskan resource tertentu dengan ring io_uring. Fungsi io_eventfd_unregister bertanggung jawab untuk melepaskan eventfd yang sebelumnya terdaftar, memutuskan mekanisme notifikasi antara io_uring dan file descriptor eventfd. Sementara itu, io_unregister_personality menangani penghapusan personality (konfigurasi spesifik thread) yang terdaftar dengan ID tertentu, berguna dalam skenario multi-thread di mana setiap thread mungkin memerlukan konfigurasi unik.

### rsrc.h
mendefinisikan mekanisme manajemen resource terdaftar (registered resources) dalam io_uring, yang memungkinkan aplikasi mendaftarkan dan mengelola buffer serta file descriptor secara efisien untuk operasi I/O berkinerja tinggi. Fungsi utama seperti io_sqe_buffers_register dan io_sqe_files_register menangani pendaftaran resource (buffer memori dan file descriptor) ke dalam io_uring, sementara io_import_reg_buf dan io_import_reg_vec bertanggung jawab untuk mengakses resource yang telah terdaftar selama operasi I/O. File ini juga menyediakan struktur data kompleks seperti io_mapped_ubuf untuk memetakan buffer pengguna (user buffers) dan io_rsrc_node untuk melacak referensi resource dengan sistem reference counting (refs).

### rw.h
mendefinisikan fungsi-fungsi inti untuk operasi baca/tulis (read/write) asinkron dalam io_uring, menyediakan implementasi performa tinggi untuk berbagai skenario I/O. File ini mencakup fungsi preparasi seperti io_prep_read dan io_prep_write yang memvalidasi parameter dari Submission Queue Entry (SQE), serta fungsi eksekusi seperti io_read dan io_write yang menangani operasi aktual secara asinkron. Struktur io_async_rw menyimpan konteks operasi I/O yang kompleks, termasuk state iterasi (iov_iter), buffer vektor (iou_vec), dan metadata untuk I/O langsung (direct) maupun buffered, memungkinkan penanganan yang efisien untuk berbagai jenis operasi baca/tulis.

### slist.h
mendefinisikan implementasi single-linked list yang dioptimalkan untuk kebutuhan io_uring, menyediakan operasi dasar manajemen linked list dengan performa tinggi dan thread-safety. File ini berisi macro dan fungsi utilitas seperti wq_list_add_head dan wq_list_add_tail untuk penambahan node, wq_list_del untuk penghapusan node, serta wq_list_splice untuk penggabungan list. Struktur utamanya menggunakan io_wq_work_node sebagai elemen list dan io_wq_work_list sebagai penanda head-tail list, dengan dukungan operasi atomik melalui READ_ONCE/WRITE_ONCE untuk menghindari race condition.

### splice.h
mendefinisikan fungsi-fungsi untuk operasi splice dan tee asinkron dalam io_uring, yang memungkinkan transfer data efisien antara file descriptor tanpa menyalin data ke user space. Fungsi io_splice_prep dan io_splice menangani operasi splice untuk memindahkan data langsung antara dua file descriptor (misalnya dari pipe ke file), sementara io_tee_prep dan io_tee mengimplementasikan operasi tee yang menduplikasi aliran data dari satu pipe ke pipe lainnya tanpa mengonsumsi data asli. Kedua operasi ini menggunakan mekanisme preparasi (_prep) untuk validasi parameter dari SQE dan eksekusi asinkron (io_splice/io_tee) yang dioptimalkan untuk performa tinggi.

### sqpoll.h
mendefinisikan mekanisme kernel-based submission queue polling (SQPOLL) untuk io_uring, yang memungkinkan proses pengiriman I/O dilakukan sepenuhnya di kernel space tanpa memerlukan system call dari aplikasi. Fungsi inti seperti io_sq_offload_create menginisialisasi thread SQPOLL yang berjalan di kernel untuk memproses submission queue secara asinkron, sementara io_sq_thread_stop dan io_sq_thread_park mengatur lifecycle thread tersebut. Struktur io_sq_data menyimpan seluruh konteks operasi SQPOLL termasuk referensi thread, status eksekusi, dan daftar konteks io_uring yang terasosiasi.

### statx.h
mendefinisikan operasi statx asinkron dalam io_uring, yang memungkinkan aplikasi mengambil metadata file secara efisien tanpa blocking. Fungsi io_statx_prep bertugas memvalidasi dan mempersiapkan parameter dari Submission Queue Entry (SQE), termasuk path file dan mask flag yang menentukan informasi metadata yang diminta, sedangkan io_statx mengeksekusi operasi statx secara asinkron dan menghasilkan completion event. Fungsi io_statx_cleanup memastikan resource seperti alokasi memori untuk path file dibersihkan setelah operasi selesai, mencegah memory leak.

### sync.h
mendefinisikan operasi sinkronisasi dan alokasi file asinkron dalam io_uring, yang memungkinkan aplikasi mengontrol persistensi data dan manajemen ruang penyimpanan secara efisien. Fungsi seperti io_sync_file_range dan io_fsync menyediakan mekanisme untuk memastikan data tertulis ke storage device, dengan io_sfr_prep dan io_fsync_prep sebagai fungsi preparasi yang memvalidasi parameter dari SQE. Sementara itu, io_fallocate dan io_fallocate_prep menangani operasi preallocation ruang disk untuk file, yang berguna untuk mengoptimalkan penulisan data sekaligus menghindari fragmentasi.

### tctx.h
mendefinisikan mekanisme manajemen konteks tugas (task context) dalam io_uring, yang menghubungkan struktur task (proses/thread) dengan ring io_uring yang digunakan. Fungsi inti seperti io_uring_alloc_task_context mengalokasikan struktur io_uring_task untuk tugas tertentu, sementara __io_uring_add_tctx_node dan io_uring_add_tctx_node menambahkan asosiasi antara task dan konteks io_uring (io_ring_ctx). Struktur io_tctx_node menyimpan hubungan ini dalam bentuk linked list, memungkinkan satu task berinteraksi dengan multiple io_uring instances.

### timeout.h
mendefinisikan mekanisme manajemen timeout asinkron dalam io_uring, yang memungkinkan aplikasi mengatur batas waktu eksekusi untuk operasi I/O. Fungsi inti seperti io_timeout dan io_link_timeout_prep mengimplementasikan timeout biasa dan linked timeout (timeout yang terhubung dengan operasi tertentu), menggunakan struktur io_timeout_data untuk menyimpan konfigurasi timer seperti durasi (timespec64) dan mode (hrtimer_mode). File ini juga menyediakan fungsi seperti io_disarm_linked_timeout dan io_disarm_next untuk menonaktifkan timeout yang terkait dengan operasi yang telah selesai sebelum waktunya, mencegah trigger yang tidak perlu.

### truncate.h
mendefinisikan operasi pemotongan file (truncate) asinkron dalam io_uring, yang memungkinkan aplikasi mengubah ukuran file secara efisien tanpa blocking. Fungsi io_ftruncate_prep bertanggung jawab untuk memvalidasi parameter dari Submission Queue Entry (SQE), termasuk file descriptor dan ukuran baru yang diinginkan, sementara io_ftruncate mengeksekusi operasi pemotongan file secara asinkron. Kedua fungsi ini bekerja sama untuk memastikan operasi ftruncate yang tradisional dapat diintegrasikan ke dalam model pemrograman asinkron io_uring.

### uring_cmd.h
mendefinisikan operasi waitid asinkron dalam io_uring, yang memungkinkan aplikasi memantau status perubahan proses child secara efisien tanpa blocking. Fungsi io_waitid_prep memvalidasi parameter dari Submission Queue Entry (SQE) seperti process ID dan options, sementara io_waitid mengeksekusi operasi pemantauan secara asinkron menggunakan struktur io_waitid_async yang menyimpan konteks permintaan dan opsi wait (wait_opts). File ini juga menyediakan mekanisme pembatalan melalui io_waitid_cancel dan io_waitid_remove_all untuk membersihkan permintaan yang tertunda.

### waitid.h
mendefinisikan mekanisme asynchronous process waiting dalam io_uring, yang memungkinkan pemantauan status proses child secara non-blocking. Fungsi utama io_waitid_prep dan io_waitid bekerja bersama untuk mengimplementasikan operasi waitid secara asinkron, di mana io_waitid_prep memvalidasi parameter dari SQE (seperti PID dan options) dan io_waitid mengeksekusi operasi aktual menggunakan struktur io_waitid_async yang menyimpan konteks permintaan beserta opsi wait (wait_opts dari kernel).

### xattr.h
mendefinisikan operasi extended attributes (xattr) asinkron dalam io_uring, yang memungkinkan manipulasi metadata file secara efisien tanpa blocking. File ini mencakup dua pasang fungsi utama untuk operasi set dan get: io_fsetxattr/io_setxattr untuk menulis atribut (melalui file descriptor atau path), dan io_fgetxattr/io_getxattr untuk membaca atribut, masing-masing dengan fungsi _prep terkait untuk validasi parameter dari SQE. Fungsi io_xattr_cleanup bertanggung jawab untuk membersihkan resource setelah operasi selesai, seperti memori yang dialokasikan untuk nama atau nilai atribut.

### zcrx.h
mendefinisikan mekanisme zero-copy receive (ZC RX) dalam io_uring, yang mengoptimalkan penerimaan data jaringan dengan menghindari penyalinan data antara kernel dan user space. File ini memperkenalkan dua struktur utama: io_zcrx_area untuk mengelola area memori shared yang digunakan untuk penerimaan data, dan io_zcrx_ifq yang merepresentasikan antarmuka network queue (NIC queue) yang terdaftar. Fungsi inti seperti io_register_zcrx_ifq dan io_unregister_zcrx_ifqs menangani pendaftaran dan deregistrasi antarmuka jaringan, sementara io_zcrx_recv melakukan operasi penerimaan data zero-copy yang sebenarnya.

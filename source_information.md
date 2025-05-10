# Task 1: Information about io_uring source
List in this section source and headers of io_uring. For each of the C source/header, you must put description what's the prime responsibily of the source. Take notes, description of the source should be slightly technical like the example given. 

## Source
### advice.c
Store io_madvice & io_fadvice structures, both have the same exact attributes. Which make them basically the same thing. Except function body treat them as separate. Codes which make use of io_madvice are guarded by compilation macro, which make its relevant functions only active if the build flag is set. But functions that make use of io_fadvice are active all the time. The exact difference between io_madvice & io_fadvice will only known after exploring do_madvise function for io_madvice & vfs_fadvise function for io_fadvice. 

###alloc_cache.c

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
enangani operasi IORING_OP_MSG_RING, yaitu fitur di io_uring yang memungkinkan komunikasi antar dua instance io_uring. Dengan operasi ini, aplikasi bisa mengirimkan data (IORING_MSG_DATA ) atau bahkan file descriptor (IORING_MSG_SEND_FD ) ke instance io_uring lain. Data dikirim sebagai completion queue event (CQE ) ke instance tujuan. Kode ini mencakup fungsi-fungsi seperti io_msg_ring_data() untuk mengirimkan data dan io_msg_send_fd() untuk mengirimkan file descriptor secara aman. Jika instance tujuan sedang tidak aktif atau perlu diproses oleh thread worker, maka pengiriman didelegasikan melalui mekanisme task work . 

### napi.c
menambahkan dukungan untuk mekanisme NAPI ke dalam io_uring, yaitu fitur yang digunakan oleh driver jaringan untuk mencegah terlalu banyak interupsi saat menerima banyak paket (high packet rate ). Dengan io_uring, aplikasi bisa menggunakan busy-loop polling untuk menunggu event jaringan tanpa perlu beralih ke mode interupsi, sehingga mengurangi latensi. Fungsi seperti io_register_napi() dan io_unregister_napi() digunakan untuk mengatur cara polling dilakukan, termasuk mode statis atau dinamis, durasi polling, dan ID NAPI tertentu. Selama polling, fungsi io_napi_do_busy_loop() akan memeriksa apakah ada pekerjaan baru atau apakah sudah waktunya berhenti polling berdasarkan timeout atau sinyal dari aplikasi.

### net.c
mengimplementasikan operasi sistem bind() menggunakan antarmuka io_uring, memungkinkan aplikasi pengguna mengikat socket ke alamat tertentu secara asinkron. Fungsi io_bind_prep() membaca parameter dari struktur sqe (Submission Queue Entry), memvalidasi input, dan menyalin alamat dari ruang pengguna ke ruang kernel. Selanjutnya, io_bind() melakukan pemanggilan sistem bind() sebenarnya pada socket yang sesuai. File ini juga mencakup bagian dari operasi sendmsg() dengan dukungan zero-copy (io_sendmsg_zc) yang memungkinkan pengiriman data tanpa penyalinan memori tambahan, meningkatkan efisiensi. Ada juga fungsi penanganan error umum seperti io_sendrecv_fail() untuk membersihkan status I/O jika terjadi kegagalan atau interupsi.

### nop.c
mendefinisikan dua fungsi utama: io_nop_prep() dan io_nop(). Fungsi io_nop_prep() membaca parameter dari struktur SQE (Submission Queue Entry ) seperti flag, hasil yang akan diinjeksi, file descriptor, atau buffer index, serta memvalidasi bahwa flag yang digunakan diperbolehkan. Flag-flag tersebut dapat menentukan apakah NOP harus mengembalikan nilai tertentu, menggunakan file tetap (fixed file ), atau menggunakan buffer tetap (fixed buffer ). Selanjutnya, io_nop() memproses operasi NOP dengan mempertimbangkan opsi-opsi yang telah disiapkan. Jika ada file atau buffer yang terlibat, maka operasi akan mencoba mendapatkan akses ke sumber daya tersebut sesuai dengan jenisnya. Jika berhasil, operasi NOP mengembalikan nilai yang ditentukan; jika gagal, seperti file descriptor tidak valid atau buffer tidak tersedia, maka akan dilaporkan error ke aplikasi pengguna melalui CQE (Completion Queue Event )

### notif.c
mengimplementasikan fungsi-fungsi penting untuk mendukung pengiriman data jaringan tanpa penyalinan memori (zero-copy ), yaitu dengan menggunakan struktur io_notif_data dan ubuf_info. Fungsi utama seperti io_alloc_notif() digunakan untuk mengalokasikan objek notifikasi (io_kiocb) yang akan digunakan untuk melacak status pengiriman zero-copy. Dua fungsi kunci, io_tx_ubuf_complete() dan io_link_skb(), menentukan apa yang terjadi ketika pengiriman selesai dan bagaimana skb (socket buffer ) dikaitkan dengan buffer notifikasi. Jika semua referensi ke buffer telah selesai, maka callback io_notif_tw_complete() dipanggil untuk membersihkan dan melaporkan hasil akhir ke aplikasi pengguna melalui CQE (Completion Queue Event ). 

### opdef.c

### openclose.c
mengimplementasikan tiga operasi utama: io_openat() untuk membuka file secara asinkron seperti openat(), io_close() untuk menutup file descriptor, dan io_install_fixed_fd() untuk menginstal file descriptor tetap. Fungsi io_openat_prep() dan io_openat2_prep() digunakan untuk memvalidasi parameter dari aplikasi pengguna sebelum operasi dimulai, sedangkan io_openat() dan io_close() menjalankan operasi sesungguhnya menggunakan fungsi kernel standar seperti do_filp_open() dan filp_close(). Jika operasi tidak bisa dilakukan secara langsung (misal karena flag O_CREAT atau O_TRUNC), maka akan dipaksa sebagai operasi async agar tidak memblokir thread. 
## another source

## Headers
### advice.h
Just declare the function specification. 

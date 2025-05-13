// SPDX-License-Identifier: GPL-2.0

int io_madvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/*menyiapkan permintaan madvise (saran penggunaan memori) untuk io_uring. 
Informasi tentang area memori dan sarannya diambil dari sqe lalu disimpan di req.*/
int io_madvise(struct io_kiocb *req, unsigned int issue_flags);
/*mengirimkan permintaan madvise yang sudah disiapkan (req) ke kernel melalui io_uring untuk diproses. 
Flag issue_flags mengatur bagaimana permintaan ini dikirim.*/

int io_fadvise_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
/*menyiapkan permintaan fadvise (saran penggunaan berkas) untuk io_uring. 
Detail berkas, rentang data, dan sarannya diambil dari sqe dan disimpan di req.*/
int io_fadvise(struct io_kiocb *req, unsigned int issue_flags);
/*mengirimkan permintaan fadvise yang sudah disiapkan (req) ke kernel melalui io_uring agar saran penggunaan berkas dapat dipertimbangkan. 
Flag issue_flags memengaruhi cara permintaan ini dikirim.*/
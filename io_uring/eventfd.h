
struct io_ring_ctx;
int io_eventfd_register(struct io_ring_ctx *ctx, void __user *arg,
			unsigned int eventfd_async);
			/* mendaftarkan sebuah eventfd dengan io_uring instance yang diwakili oleh ctx.*/
int io_eventfd_unregister(struct io_ring_ctx *ctx);
/*membatalkan pendaftaran eventfd yang sebelumnya telah didaftarkan dengan io_uring instance ctx.*/

void io_eventfd_flush_signal(struct io_ring_ctx *ctx);
/*memastikan bahwa sinyal yang tertunda pada eventfd yang terdaftar untuk konteks ctx telah diproses atau "dibersihkan".*/
void io_eventfd_signal(struct io_ring_ctx *ctx);
/*kemungkinan digunakan untuk secara manual memberi sinyal pada eventfd yang terdaftar untuk konteks ctx. */
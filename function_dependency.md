# Task 2: Dependency Injection
For this assigment, we want a little clarity regarding what kind of functions being imported and used on each source. Do note, we record all function actually being used by the source including function defined by itself if actually used inside the file. For the sake of completion, it's better if you straight disregard include list on the source. Instead, trace each function being used to the declared source.

Source | Libary | Function utilized | Time Used
-------|--------|--------------| ------------------
advise.c | advise.c | io_madvise_prep | 1
| | advise.c | io_madvise | 1
| | mm/madvise.c | do_madvise | 1
| | io_uring.h | io_req_set_res | 2
| | advise.c | io_fadvise_force_async | 3
| | advise.c | io_fadvise_prep | 1
| | advise.c | io_fadvise | 1
| | mm/fadvise.c | vfs_fadvise | 1
| | io_uring/io_uring.h | req_set_fail | 1 
advise.h | advise.c | io_madvise_prep | 1
| | advise.c | io_madvise | 1
| | advise.c | io_fadvise_prep | 1
| | advise.c | io_fadvise | 1
alloc_cache.c | alloc_cache.c | io_alloc_cache_free | 1
| | alloc_cache.h | io_alloc_cache_get | 1
| | lib/inflate.c | free | 1
| | mm/slub.c | kvfree | 1
| | alloc_cache.c | io_alloc_cache_init | 1
| | WHERE YOU AT DAAWGGG GADAM | kvmalloc_array | 1
| | alloc_cache.c | io_cache_alloc_new | 1
| | tools/lib/slab.c | kmalloc | 1
| | lib/string.c | memset | 1
alloc_cache.h | alloc_cache.c | io_alloc_cache_free | 1
| | alloc_cache.c | io_alloc_cache_init | 1
| | alloc_cache.h | io_cache_alloc_new | 2
| | alloc_cache.h | io_alloc_cache_put | 2
| | include/linux/kasan.h | kasan_mempool_poison_object | 1
| | alloc_cache.h | io_alloc_cache_get | 2
| | include/linux/kasan.h | kasan_mempool_unpoison_object | 1
| | lib/string.c | memset | 1
| | alloc_cache.h | io_cache_alloc | 1
| | alloc_cache.h | io_cache_free | 1
| | mm/slub.c | kfree | 1

cancel.c | cancel.c | io_cancel_req_match | 
| | cancel.h | io_cancel_match_sequence |
| | cancel.c | io_cancel_cb |
| | cancel.c | io_async_cancel_one |
| | io-wq.c | io_wq_cancel_cb |
| | cancel.c | io_try_cancel |
| | io-wq.h | io_wq_current_is_worker | 
| | poll.c | io_poll_cancel |
| | waitid.c | io_waitid_cancel |
| | futex.c | io_futex_cancel |
| | include/linux/spinlock.h | spin_lock |
| | timeout.c | io_timeout_cancel | 
| | include/linux/spinlock.h | spin_unlock |
| | cancel.c | io_async_cancel_prep |
| | cancel.c | __io_async_cancel |
| | io_uring.h | io_ring_submit_lock |
| | io_uring.h | io_ring_submit_unlock |
| | cancel.c | io_async_cancel |
| | include/linux/atomic/atomic-instrumented.h | atomic_inc_return |
| | io_uring.c | io_file_get_fixed |
| | io_uring.c | io_file_get_normal | 
| | rsrc.h | io_rsrc_node_lookup |
| | filetable.h | io_slot_file |
| | cancel.c | io_sync_cancel |
-------------------

Continue with the list untill all functions used in each source are listed.

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
kbuf.c | kbuf.c | io_buffer_get_list | 10
| | linux/compiler.h | READ_ONCE | 8
| | linux/lockdep.h | lockdep_assert_held | 6
| | linux/slab.h | kfree | 6
| | kbuf.c | io_ring_head_to_buf | 5
| | kbuf.c | io_ring_submit_lock | 5
| | kbuf.c | io_ring_submit_unlock | 5
| | kbuf.c | io_kbuf_commit | 4
| | linux/list.h | list_empty | 4
| | linux/uaccess.h | u64_to_user_ptr | 4
| | kbuf.c | io_put_bl | 4
| | kbuf.c | io_kiocb_to_cmd | 4
| | linux/kernel.h | min_t | 3
| | kbuf.c | io_buffer_add_list | 3
| | kbuf.c | io_provided_buffer_select | 3
| | kbuf.c | io_provided_buffers_select | 3
| | kbuf.c | io_ring_buffers_peek | 3
| | kbuf.c | __io_remove_buffers | 3
| | tools/include/scoped.h | scoped_guard | 3
| | linux/xarray.h | xa_erase | 3
| | linux/uaccess.h | copy_from_user | 3
| | kbuf.c | io_kbuf_inc_commit | 2
| | linux/xarray.h | xa_load | 2
| | kbuf.c | io_kbuf_drop_legacy | 2
| | linux/bug.h | WARN_ON_ONCE | 2
| | linux/list.h | list_first_entry | 2
| | linux/list.h | list_del | 2
| | kbuf.c | io_ring_buffer_select | 2
| | asm/barrier.h | smp_load_acquire | 2
| | kbuf.c | __io_put_kbuf_ring | 2
kbuf.h | kbuf.h | __io_put_kbufs | 3
| | kbuf.h | io_kbuf_recycle_legacy | 2
| | kbuf.h | io_kbuf_recycle_ring | 2
| | kbuf.h | io_buffer_select | 1
| | kbuf.h | io_buffers_select | 1
| | kbuf.h | io_buffers_peek | 1
| | kbuf.h | io_destroy_buffers | 1
| | kbuf.h | io_remove_buffers_prep | 1
| | kbuf.h | io_remove_buffers | 1
| | kbuf.h | io_provide_buffers_prep | 1
| | kbuf.h | io_provide_buffers | 1
| | kbuf.h | io_register_pbuf_ring | 1
| | kbuf.h | io_unregister_pbuf_ring | 1
| | kbuf.h | io_register_pbuf_status | 1
| | kbuf.h | io_kbuf_drop_legacy | 1
| | kbuf.h | io_kbuf_commit | 1
| | kbuf.h | io_pbuf_get_region | 1
| | kbuf.h | io_do_buffer_select | 1
| | kbuf.h | io_kbuf_recycle | 1
| | kbuf.h | io_put_kbuf | 1
| | kbuf.h | io_put_kbufs | 1
memmap.c | linux/err.h | ERR_PTR | 11
| | linux/err.h | IS_ERR | 5
| | linux/bug.h | WARN_ON_ONCE | 4
| | tools/include/scoped.h | guard | 4
| | memmap.c | io_uring_validate_mmap_request | 4
| | linux/overflow.h | check_add_overflow | 3
| | linux/slab.h | kvfree | 3
| | linux/err.h | PTR_ERR | 3
| | memmap.c | io_mmap_get_region | 3
| | memmap.c | io_mem_alloc_compound | 2
| | linux/mm.h | page_address | 2
| | memmap.c | io_pin_pages | 2
| | linux/slab.h | kvmalloc_array | 2
| | linux/mm.h | unpin_user_pages | 2
| | memmap.c | io_free_region | 2
| | linux/mm.h | release_pages | 2
| | memmap.c | io_region_init_ptr | 2
| | memmap.c | io_region_pin_pages | 2
| | memmap.c | io_region_allocate_pages | 2
| | memmap.c | io_create_region | 2
| | string.h | memcpy | 2
| | memmap.c | io_region_validate_mmap | 2
| | memmap.c | io_region_mmap | 2
| | memmap.c | io_uring_mmap | 2
| | memmap.c | io_uring_get_unmapped_area | 2
| | linux/mm.h | get_order | 1
| | linux/gfp.h | alloc_pages | 1
| | linux/mm.h | pin_user_pages_fast | 1
| | linux/vmalloc.h | vunmap | 1
| | memmap.c | __io_unaccount_mem | 1
memmap.h | memmap.h | io_pin_pages | 1
| | memmap.h | io_uring_nommu_mmap_capabilities | 1
| | memmap.h | io_uring_get_unmapped_area | 1
| | memmap.h | io_uring_mmap | 1
| | memmap.h | io_free_region | 1
| | memmap.h | io_create_region | 1
| | memmap.h | io_create_region_mmap_safe | 1
| | memmap.h | io_region_get_ptr | 1
| | memmap.h | io_region_is_set | 1
msg_ring.c | msg_ring.c | io_double_unlock_ctx | 1
| | msg_ring.c | io_lock_external_ctx | 1
| | msg_ring.c | io_msg_ring_cleanup | 1
| | msg_ring.c | io_msg_need_remote | 1
| | msg_ring.c | io_msg_tw_complete | 1
| | msg_ring.c | io_msg_remote_post | 1
| | msg_ring.c | io_msg_get_kiocb | 1
| | msg_ring.c | io_msg_data_remote | 1
| | msg_ring.c | __io_msg_ring_data | 1
| | msg_ring.c | io_msg_ring_data | 1
| | msg_ring.c | io_msg_grab_file | 1
| | msg_ring.c | io_msg_install_complete | 1
| | msg_ring.c | io_msg_tw_fd_complete | 1
| | msg_ring.c | io_msg_fd_remote | 1
| | msg_ring.c | io_msg_send_fd | 1
| | msg_ring.c | io_msg_ring_prep | 1
| | msg_ring.c | io_msg_ring | 1
| | msg_ring.c | io_uring_sync_msg_ring | 1
| | file.c | get_file | 1
| | file.c | fput | 1
| | file.c | get_file_rcu | 1
| | file.c | io_file_get | 1
| | file.c | io_file_put | 1
| | io_uring.h | io_cqring_add_event | 1
| | io_uring.h | io_req_complete_post | 1
| | io_uring.h | io_req_set_rsrc_node | 1
msg_ring.h | msg_ring.c | io_msg_ring_cleanup | 1
| | msg_ring.c | io_msg_ring | 1
| | msg_ring.c | io_msg_ring_prep | 1
| | msg_ring.c | io_uring_sync_msg_ring | 1
napi.c | io_uring.h | io_should_wake | 1
| | io_uring.h | io_has_work | 1
| | io_uring.h | io_get_time | 1
| | io_uring.h | io_register_napi | 1
| | io_uring.h | io_unregister_napi | 1
| | io_uring.h | __io_napi_busy_loop | 1
| | io_uring.h | io_napi_sqpoll_busy_poll | 1
| | napi.h | napi_id_valid | 2
| | linux/jiffies.h | jiffies | 5
| | linux/spinlock.h | spin_lock, spin_unlock | 3
| | linux/rcupdate.h | kfree_rcu | 3
| | linux/rculist.h | list_add_tail_rcu | 1
| | linux/rculist.h | list_del_rcu | 2
| | linux/hashtable.h | hash_min, HASH_BITS | 2
| | linux/list.h | INIT_LIST_HEAD | 1
| | linux/slab.h | kmalloc, kfree | 2
| | linux/types.h | ktime_t | >5
| | linux/ktime.h | ktime_add, ktime_sub | 2
| | linux/ktime.h | ktime_to_us | 2
| | linux/ktime.h | ktime_after | 2
| | linux/time.h | ns_to_ktime | 2
| | linux/time.h | time_after | 2
| | linux/uaccess.h | copy_from_user, copy_to_user | 2
| | linux/sched/signal.h | signal_pending | 1
| | net/busy_poll.h | busy_loop_current_time | 3
| | internal (defined itself) | io_napi_hash_find | 2
| | internal (defined itself) | __io_napi_add_id | 1
| | internal (defined itself) | __io_napi_del_id | 1
| | internal (defined itself) | __io_napi_remove_stale | 1
| | internal (defined itself) | io_napi_remove_stale | 2
| | internal (defined itself) | io_napi_busy_loop_timeout | 1
| | internal (defined itself) | io_napi_busy_loop_should_end | 1
| | internal (defined itself) | static_tracking_do_busy_loop | 1
| | internal (defined itself) | dynamic_tracking_do_busy_loop | 1
| | internal (defined itself) | __io_napi_do_busy_loop | 1
| | internal (defined itself) | io_napi_blocking_busy_loop | 2
| | internal (defined itself) | io_napi_init | 1
| | internal (defined itself) | io_napi_free | 1
| | internal (defined itself) | io_napi_register_napi | 1
| | internal (defined itself) | io_register_napi | 1
| | internal (defined itself) | io_napi_unregister | 1
| | internal (defined itself) | __io_napi_busy_loop | 1
| | internal (defined itself) | io_napi_sqpoll_busy_poll | 1
napi.h | linux/kernel.h |  | 1
| | linux/io_uring.h | io_ring_ctx | 1
| | net/busy_poll.h | sock->sk->sk_napi_id | 1
| | internal (self-declared) | io_napi_init | 1
| | internal (self-declared) | io_napi_free | 1
| | internal (self-declared) | io_register_napi | 1
| | internal (self-declared) | io_unregister_napi | 1
| | internal (self-declared) | __io_napi_add_id | 1
| | internal (self-declared) | __io_napi_busy_loop | 1
| | internal (self-declared) | io_napi_sqpoll_busy_poll | 1
| | internal (self-declared) | io_napi | 1
| | internal (self-declared) | io_napi_busy_loop | 1
| | internal (self-declared) | io_napi_add | 1


----------------------

Continue with the list untill all functions used in each source are listed.

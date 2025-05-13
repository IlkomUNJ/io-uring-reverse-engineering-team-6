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
| | io_uring.h | req_set_fail | 1 
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
cancel.c | cancel.c | io_cancel_req_match | 3
| | cancel.h | io_cancel_match_sequence | 1
| | cancel.c | io_cancel_cb | 1
| | cancel.c | io_async_cancel_one | 3
| | io-wq.c | io_wq_cancel_cb | 1
| | cancel.c | io_try_cancel | 2
| | io-wq.h | io_wq_current_is_worker | 1
| | poll.c | io_poll_cancel | 1
| | waitid.c | io_waitid_cancel | 1
| | futex.c | io_futex_cancel | 1
| | include/linux/spinlock.h | spin_lock | 1
| | timeout.c | io_timeout_cancel | 1
| | include/linux/spinlock.h | spin_unlock | 1
| | cancel.c | io_async_cancel_prep | 1
| | cancel.c | __io_async_cancel | 3
| | io_uring.h | io_ring_submit_lock | 2
| | io_uring.h | io_ring_submit_unlock | 2
| | cancel.c | io_async_cancel | 1
| | include/linux/atomic/atomic-instrumented.h | atomic_inc_return | 3
| | io_uring.c | io_file_get_fixed | 1
| | io_uring.c | io_file_get_normal | 1
| | io_uring.h | req_set_fail | 1
| | io_uring.h | io_req_set_res | 1 
| | cancel.c | __io_sync_cancel | 3
| | rsrc.h | io_rsrc_node_lookup | 1
| | filetable.h | io_slot_file | 1
| | cancel.c | io_sync_cancel | 1
| | include/linux/ktime.h | ktime_add_ns | 1
| | include/linux/ktime.h | timespec64_to_ktime | 1
| | include/linux/timekeeping.h | ktime_get_ns | 1
| | kernel/sched/wait.c | prepare_to_wait | 1
| | include/linux/mutex.h | mutex_unlock | 1
| | io_uring.c | io_run_task_work_sig | 1 
| | kernel/time/sleep_timeout.c | schedule_hrtimeout | 1
| | include/linux/mutex.h | mutex_lock | 2
| | kernel/sched/wait.c | finish_wait | 1
| | tools/testing/vma/vma_internal.h | fput | 1
| | cancel.c | io_cancel_remove_all | 1
| | tools/include/linux/list.h | hlist_for_each_entry_safe | 2
| | io_uring.c | io_match_task_safe | 1
| | tools/include/linux/list.h | hlist_del_init | 1
| | cancel.c | io_cancel_remove | 1
cancel.h | cancel.c | io_async_cancel_prep | 1
| | cancel.c | io_async_cancel | 1
| | cancel.c | io_try_cancel | 1
| | cancel.c | io_sync_cancel | 1
| | cancel.c | io_cancel_req_match | 1
| | cancel.c | io_cancel_remove_all | 1
| | cancel.c | io_cancel_remove | 1
| | cancel.h | io_cancel_match_sequence | 1
epoll.c | epoll.c | io_epoll_ctl_prep | 1
| | include/linux/eventpoll.h | ep_op_has_event | 1
| | include/linux/uaccess.h | copy_from_user | 1
| | epoll.c | io_epoll_ctl | 1
| | include/linux/eventpoll.h | do_epoll_ctl | 1
| | io_uring.h | req_set_fail | 2
| | io_uring.h | io_req_set_res | 2 
| | epoll.c | io_epoll_wait_prep | 1
| | epoll.c | io_epoll_wait | 1
| | include/linux/eventpoll.h | epoll_sendevents | 1
epoll.h | epoll.c | io_epoll_ctl_prep | 1
| | epoll.c | io_epoll_ctl | 1
| | epoll.c | io_epoll_wait_prep | 1
| | epoll.c | io_epoll_wait | 1
eventfd.c | eventfd.c | io_eventfd_free | 2
| | fs/eventfd.c | eventfd_ctx_put | 1
| | mm/slub.c | kfree | 2
| | eventfd.c | io_eventfd_put | 4
| | include/linux/refcount.h | refcount_dec_and_test | 1
| | kernel/rcu/tiny.c | call_rcu | 1
| | eventfd.c | io_eventfd_do_signal | 2
| | fs/eventfd.c | eventfd_signal_mask | 2 
| | eventfd.c | io_eventfd_release | 3
| | include/linux/rcupdate.h | rcu_read_unlock | 2
| | eventfd.c | __io_eventfd_signal | 3
| | include/linux/eventfd.h | eventfd_signal_allowed | 1
| | include/linux/atomic/atomic-instrumented.h | atomic_fetch_or | 1
| | include/linux/rcupdate.h | call_rcu_hurry | 1
| | eventfd.c | io_eventfd_trigger | 2
| | io-wq.h | io_wq_current_is_worker | 1
| | eventfd.c | io_eventfd_grab | 3
| | include/linux/refcount.h | refcount_inc_not_zero | 1
| | eventfd.c | io_eventfd_signal | 1 
| | eventfd.c | io_eventfd_flush_signal | 1
| | include/linux/spinlock.h | spin_lock | 2
| | include/linux/spinlock.h | spin_unlock | 2
| | eventfd.c | io_eventfd_register | 1
| | include/linux/uaccess.h | copy_from_user | 1
| | tools/lib/slab.c | kmalloc | 1
| | fs/eventfd.c | eventfd_ctx_fdget | 1
| | include/linux/refcount.h | refcount_set | 1
| | eventfd.c | io_eventfd_unregister | 1
eventfd.h | eventfd.c | io_eventfd_register | 1
| | eventfd.c | io_eventfd_unregister | 1
| | eventfd.c | io_eventfd_flush_signal | 1
| | eventfd.c | io_eventfd_signal | 1
fdinfo.c | finfo.c | io_uring_show_cred | 
| | | seq_user_ns | 
| | | seq_printf | 
| | | seq_put_decimal_ull | 
| | | from_kuid_munged | 
| | | from_kgid_munged | 
| | | seq_puts | 
| | | seq_put_hex_ll | 
| | | seq_putc | 
| | | common_tracking_show_fdinfo |
| | | napi_show_fdinfo | 
| | | io_uring_show_fdinfo | 
| | | io_uring_get_opcode | 
| | | mutex_trylock | 
| | | getrusage | 
| | | io_slot_file | 
| | | seq_file_path | 
| | | xa_empty | 
| | | xa_for_each | 
| | | task_work_pending | 
| | | mutex_unlock | 
| | | spin_lock | 
| | | spin_unlock | 
fdinfo.h | fdinfo.c | io_uring_show_fdinfo | 1 
filetable.c | filetable.c | io_file_bitmap_get | 2
| | | find_next_zero_bit | 
| | | io_alloc_file_tables |
| | | io_rsrc_data_alloc | 
| | | bitmap_zalloc | 
| | | io_rsrc_data_free | 
| | | io_free_file_tables | 
| | | bitmap_free | 
| | | io_install_fixed_file | 
| | | __must_hold | 
| | | io_is_uring_fops | 
| | | io_rsrc_node_alloc | 
| | | io_reset_rsrc_node | 
| | | io_file_bitmap_set | 
| | | io_fixed_file_set | 
| | | __io_fixed_fd_install | 
| | | io_fixed_fd_install | 
| | | io_ring_submit_lock | 
| | | io_ring_submit_unlock | 
| | | fput | 
| | | io_fixed_fd_remove | 
| | | io_rsrc_node_lookup | 
| | | io_file_bitmap_clear | 
| | | io_register_file_alloc_range | 
| | | copy_from_user | 
| | | check_add_overflow | 
| | | io_file_table_set_alloc_range | 
filetable.h | filetable.c | io_alloc_file_tables | 1
| | | io_free_file_tables |
| | | io_fixed_fd_install | 
| | | __io_fixed_fd_install | 
| | | io_fixed_fd_remove | 
| | | io_register_file_alloc_range | 
| | | io_file_get_flags | 2  
| | | io_file_bitmap_clear | 
| | | io_file_bitmap_set | 
| | | io_slot_flags | 
| | | io_slot_file | 
| | | io_fixed_file_set | 
| | | io_file_table_set_alloc_range | 
fs.c | fs.c | io_renameat_prep | 
| | | getname | 
| | | putname | 
| | | io_renameat |
| | | do_renameat2 | 
| | | io_req_set_res | 
| | | io_renameat_cleanup | 
| | | io_unlinkat_prep | 
| | | io_unlinkat | 
| | | do_rmdir | 
| | | do_unlinkat | 
| | | io_unlinkat_cleanup | 
| | | io_mkdirat_prep | 
| | | io_mkdirat | 
| | | do_mkdirat | 
| | | io_mkdirat_cleanup | 
| | | io_symlinkat_prep | 
| | | io_symlinkat | 
| | | io_linkat_prep | 
| | | getname_uflags | 
| | | io_linkat | 
| | | do_linkat | 
| | | io_link_cleanup | 
fs.h | fs.c | io_renameat_prep | 1
| | | io_renameat | 
| | | io_renameat_cleanup | 
| | | io_unlinkat_prep | 
| | | io_unlinkat | 
| | | io_unlinkat_cleanup | 
| | | io_mkdirat_prep | 
| | | io_mkdirat | 
| | | io_mkdirat_cleanup | 
| | | io_symlinkat_prep | 
| | | io_symlinkat | 
| | | io_linkat_prep | 
| | | io_linkat | 
| | | io_link_cleanup | 
futex.c | futex.c | io_futex_cache_init | 
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
net.c | linux/socket.h | sock_from_file | 9 
| | net/socket.c | __sys_shutdown_sock | 1 
| | net/socket.c | __sys_sendmsg_sock | 2 
| | net/socket.c | __sys_recvmsg_sock | 1 
| | net/socket.c | __sys_connect_file | 1 
| | net/socket.c | __sys_socket_file | 1 
| | linux/uio.c | iov_iter_count | 7 
| | linux/uio.c | iov_iter_ubuf | 1 
| | linux/uio.c | iov_iter_init | 2 
| | linux/uio.c | io_import_reg_buf | 1 
| | linux/uio.c | io_import_reg_vec | 1 
| | linux/uio.c | import_ubuf | 6 
| | linux/uio.c | __import_iovec | 1 
| | linux/uio.c | __copy_msghdr | 1 
| | linux/uio.c | io_vec_reset_iovec | 1 
| | linux/uio.c | io_vec_free | 2 
| | linux/uio.c | io_prep_reg_iovec | 1 
| | linux/uaccess.h | copy_from_user | 4 
| | linux/uaccess.h | copy_to_user | 1 
| | linux/uaccess.h | user_access_begin | 1 
| | linux/uaccess.h | user_access_end | 1 
| | linux/limits.h | rlimit | 2 
| | linux/file.c | __get_unused_fd_flags | 2 
| | linux/file.c | fd_install | 2 
| | linux/file.c | put_unused_fd | 2 
| | linux/net/socket.c | do_accept | 1 
| | linux/net/socket.c | sock_error | 1 
| | net/core/skbuff.c | sock_sendmsg | 2 
| | net/core/skbuff.c | sock_recvmsg | 3 
| | linux/errno.h | PTR_ERR | 3 
| | linux/errno.h | IS_ERR | 3 
| | internal (self-declared) | io_shutdown_prep | 1 
| | internal (self-declared) | io_shutdown | 1 
| | internal (self-declared) | io_net_retry | 2 
| | internal (self-declared) | io_netmsg_iovec_free | 2 
| | internal (self-declared) | io_netmsg_recycle | 1 
| | internal (self-declared) | io_msg_alloc_async | 3 
| | internal (self-declared) | io_mshot_prep_retry | 2 
| | internal (self-declared) | io_net_import_vec | 2 
| | internal (self-declared) | io_compat_msg_copy_hdr | 1 
| | internal (self-declared) | io_copy_msghdr_from_user | 1 
| | internal (self-declared) | io_msg_copy_hdr | 1 
| | internal (self-declared) | io_sendmsg_recvmsg_cleanup | 1 
| | internal (self-declared) | io_send_setup | 1 
| | internal (self-declared) | io_sendmsg_setup | 1 
| | internal (self-declared) | io_sendmsg_prep | 1 
| | internal (self-declared) | io_send_finish | 1 
| | internal (self-declared) | io_sendmsg | 1 
| | internal (self-declared) | io_send_select_buffer | 1 
| | internal (self-declared) | io_send | 1 
| | internal (self-declared) | io_recvmsg_mshot_prep | 1 
| | internal (self-declared) | io_recvmsg_copy_hdr | 1 
| | internal (self-declared) | io_recvmsg_prep_setup | 1 
| | internal (self-declared) | io_recvmsg_prep | 1 
| | internal (self-declared) | io_recv_finish | 1 
| | internal (self-declared) | io_recvmsg_multishot | 1 
| | internal (self-declared) | io_recvmsg | 1 
| | internal (self-declared) | io_recv_buf_select | 1 
| | internal (self-declared) | io_recv | 1 
| | internal (self-declared) | io_recvzc_prep | 1 
| | internal (self-declared) | io_recvzc | 1 
| | internal (self-declared) | io_send_zc_cleanup | 1 
| | internal (self-declared) | io_send_zc_prep | 1 
| | internal (self-declared) | io_send_zc | 1 
| | internal (self-declared) | io_sendmsg_zc | 1 
| | internal (self-declared) | io_sendrecv_fail | 1 
| | internal (self-declared) | io_accept_prep | 1 
| | internal (self-declared) | io_accept | 1 
| | internal (self-declared) | io_socket_prep | 1 
| | internal (self-declared) | io_socket | 1 
| | internal (self-declared) | io_connect_prep | 1 
| | internal (self-declared) | io_connect | 1 
net.h | linux/net.h | struct socket, struct sockaddr | 1 
| | linux/uio.h | struct iovec, struct msghdr | 1 
| | linux/io_uring_types.h | struct io_kiocb, struct io_uring_sqe | 1 
| | internal (self-declared) | io_shutdown_prep | 1 
| | internal (self-declared) | io_shutdown | 1 
| | internal (self-declared) | io_sendmsg_recvmsg_cleanup | 1 
| | internal (self-declared) | io_sendmsg_prep | 1 
| | internal (self-declared) | io_sendmsg | 1 
| | internal (self-declared) | io_send | 1 
| | internal (self-declared) | io_recvmsg_prep | 1 
| | internal (self-declared) | io_recvmsg | 1 
| | internal (self-declared) | io_recv | 1 
| | internal (self-declared) | io_sendrecv_fail | 1 
| | internal (self-declared) | io_accept_prep | 1 
| | internal (self-declared) | io_accept | 1 
| | internal (self-declared) | io_socket_prep | 1 
| | internal (self-declared) | io_socket | 1 
| | internal (self-declared) | io_connect_prep | 1 
| | internal (self-declared) | io_connect | 1 
| | internal (self-declared) | io_send_zc | 1 
| | internal (self-declared) | io_sendmsg_zc | 1 
| | internal (self-declared) | io_send_zc_prep | 1 
| | internal (self-declared) | io_send_zc_cleanup | 1 
| | internal (self-declared) | io_bind_prep | 1 
| | internal (self-declared) | io_bind | 1 
| | internal (self-declared) | io_listen_prep | 1 
| | internal (self-declared) | io_listen | 1 
| | internal (self-declared) | io_netmsg_cache_free | 1
nop.c | linux/kernel.h | READ_ONCE | 4 
| | linux/errno.h | -EINVAL, -EBADF, -EFAULT | 3 
| | linux/io_uring.h | IORING_NOP_* flags | 4 
| | internal (self-declared) | io_nop_prep | 1 
| | internal (self-declared) | io_nop | 1 
| | internal (self-declared) | io_kiocb_to_cmd | 2 
| | internal (self-declared) | io_file_get_fixed | 1 
| | internal (self-declared) | io_file_get_normal | 1 
| | internal (self-declared) | io_find_buf_node | 1 
| | internal (self-declared) | req_set_fail | 1 
| | internal (self-declared) | io_req_set_res | 1
nop.h | internal (self-declared) | io_nop_prep | 1 
| | internal (self-declared) | io_nop | 1 
| | linux/io_uring_types.h | struct io_kiocb | 1 
| | linux/io_uring.h | struct io_uring_sqe | 1
notif.c | linux/kernel.h | WRITE_ONCE, unlikely | 3 
| | linux/errno.h | -EEXIST | 3 
| | linux/file.h | struct file | 1 
| | linux/slab.h | NULL, kmalloc/kfree-related macro | 1 
| | linux/net.h | struct sk_buff | 1 
| | linux/io_uring.h | IORING_OP_NOP | 1 
| | internal (self-declared) | io_notif_tw_complete | 1 
| | internal (self-declared) | io_tx_ubuf_complete | 1 
| | internal (self-declared) | io_link_skb | 1 
| | internal (self-declared) | io_alloc_notif | 1 
| | internal (self-declared) | io_notif_to_data | 3 
| | internal (self-declared) | cmd_to_io_kiocb | 4 
| | internal (self-declared) | io_req_task_complete | 1 
| | internal (self-declared) | __io_unaccount_mem | 1 
| | internal (self-declared) | refcount_read | 1 
| | internal (self-declared) | refcount_dec_and_test | 1 
| | internal (self-declared) | __io_req_task_work_add | 1 
| | internal (self-declared) | skb_zcopy | 1 
| | internal (self-declared) | skb_zcopy_init | 1 
| | internal (self-declared) | net_zcopy_get | 2 
| | internal (self-declared) | io_alloc_req | 1 
| | internal (self-declared) | io_get_task_refs | 1 
| | internal (self-declared) | refcount_set | 1
notif.h | linux/net.h | struct sock | 1 
| | linux/uio.h | struct ubuf_info | 1 
| | net/sock.h |  | 0 
| | linux/nospec.h | __must_hold | 1 
| | linux/io_uring.h | struct io_kiocb, io_ring_ctx | 3 
| | mm/user_mem.c | __io_account_mem | 1 
| | io_uring/io_uring.c | io_kiocb_to_cmd | 1 
| | internal (self-declared) | io_alloc_notif | 1 
| | internal (self-declared) | io_tx_ubuf_complete | 2 
| | internal (self-declared) | io_notif_to_data | 2 
| | internal (self-declared) | io_notif_flush | 1 
| | internal (self-declared) | io_notif_account_mem | 1
opdef.c | nop.h | io_nop_prep | 1 
| | nop.h | io_nop | 1 
| | rw.h | io_prep_readv | 1 
| | rw.h | io_read | 4 
| | rw.h | io_prep_writev | 1 
| | rw.h | io_write | 4 
| | fs.h | io_fsync_prep | 1 
| | fs.h | io_fsync | 1 
| | rw.h | io_prep_read_fixed | 1 
| | rw.h | io_read_fixed | 1 
| | rw.h | io_prep_write_fixed | 1 
| | rw.h | io_write_fixed | 1 
| | poll.h | io_poll_add_prep | 1 
| | poll.h | io_poll_add | 1 
| | poll.h | io_poll_remove_prep | 1 
| | poll.h | io_poll_remove | 1 
| | fs.h | io_sfr_prep | 1 
| | fs.h | io_sync_file_range | 1 
| | net.h | io_sendmsg_prep | 1 
| | net.h | io_sendmsg | 1 
| | net.h | io_recvmsg_prep | 1 
| | net.h | io_recvmsg | 1 
| | timeout.h | io_timeout_prep | 1 
| | timeout.h | io_timeout | 1 
| | timeout.h | io_timeout_remove_prep | 1 
| | timeout.h | io_timeout_remove | 1 
| | net.h | io_accept_prep | 1 
| | net.h | io_accept | 1 
| | cancel.h | io_async_cancel_prep | 1 
| | cancel.h | io_async_cancel | 1 
| | timeout.h | io_link_timeout_prep | 1 
| | internal (self-declared) | io_no_issue | 1 
| | net.h | io_connect_prep | 1 
| | net.h | io_connect | 1 
| | fs.h | io_fallocate_prep | 1 
| | fs.h | io_fallocate | 1 
| | openclose.h | io_openat_prep | 1 
| | openclose.h | io_openat | 1 
| | openclose.h | io_close_prep | 1 
| | openclose.h | io_close | 1 
| | rsrc.h | io_files_update_prep | 1 
| | rsrc.h | io_files_update | 1 
| | statx.h | io_statx_prep | 1 
| | statx.h | io_statx | 1 
| | rw.h | io_prep_read | 1 
| | rw.h | io_prep_write | 1 
| | advise.h | io_fadvise_prep | 1 
| | advise.h | io_fadvise | 1 
| | advise.h | io_madvise_prep | 1 
| | advise.h | io_madvise | 1 
| | openclose.h | io_openat2_prep | 1 
| | openclose.h | io_openat2 | 1 
| | epoll.h | io_epoll_ctl_prep | 1 
| | epoll.h | io_epoll_ctl | 1 
| | splice.h | io_splice_prep | 1 
| | splice.h | io_splice | 1 
| | kbuf.h | io_provide_buffers_prep | 1 
| | kbuf.h | io_provide_buffers | 1 
| | kbuf.h | io_remove_buffers_prep | 1 
| | kbuf.h | io_remove_buffers | 1 
| | splice.h | io_tee_prep | 1 
| | splice.h | io_tee | 1 
| | net.h | io_shutdown_prep | 1 
| | net.h | io_shutdown | 1 
| | fs.h | io_renameat_prep | 1 
| | fs.h | io_renameat | 1 
| | fs.h | io_unlinkat_prep | 1 
| | fs.h | io_unlinkat | 1 
| | fs.h | io_mkdirat_prep | 1 
| | fs.h | io_mkdirat | 1 
| | fs.h | io_symlinkat_prep | 1 
| | fs.h | io_symlinkat | 1 
| | fs.h | io_linkat_prep | 1 
| | fs.h | io_linkat | 1 
| | msg_ring.h | io_msg_ring_prep | 1 
| | msg_ring.h | io_msg_ring | 1 
| | xattr.h | io_fsetxattr_prep | 1 
| | xattr.h | io_fsetxattr | 1 
| | xattr.h | io_setxattr_prep | 1 
| | xattr.h | io_setxattr | 1 
| | xattr.h | io_fgetxattr_prep | 1 
| | xattr.h | io_fgetxattr | 1 
| | xattr.h | io_getxattr_prep | 1 
| | xattr.h | io_getxattr | 1 
| | uring_cmd.h | io_uring_cmd_prep | 1 
| | uring_cmd.h | io_uring_cmd | 1 
| | zcrx.h | io_send_zc_prep | 1 
| | zcrx.h | io_send_zc | 1 
| | zcrx.h | io_sendmsg_zc_prep | 1 
| | zcrx.h | io_sendmsg_zc | 1 
| | rw.h | io_read_mshot_prep | 1 
| | rw.h | io_read_mshot | 1
| | waitid.h | io_waitid_prep | 1 
| | waitid.h | io_waitid | 1 
| | futex.h | io_futex_prep | 2 
| | futex.h | io_futex_wait | 1 
| | futex.h | io_futex_wake | 1 
| | futex.h | io_futexv_prep | 1 
| | futex.h | io_futexv_wait | 1 
| | truncate.h | io_install_fixed_fd_prep | 1 
| | truncate.h | io_install_fixed_fd | 1 
opdef.h | linux/types.h | u8 | 1 
| | internal (self-declared) | struct io_issue_def | 1 
| | internal (self-declared) | struct io_cold_def | 1 
| | internal (self-declared) | io_issue_defs | 1 
| | internal (self-declared) | io_cold_defs | 1 
| | internal (self-declared) | io_uring_op_supported | 1 
| | internal (self-declared) | io_uring_optable_init | 1 
openclose.c | linux/kernel.h | WARN_ON_ONCE | 1 
| | linux/errno.h | EINVAL, EBADF, EPERM | 3 
| | linux/fs.h | struct file, filp_close | 2 
| | linux/file.h | f_op, flush | 1 
| | linux/fdtable.h | __get_unused_fd_flags, put_unused_fd, fd_install | 3 
| | linux/fsnotify.h |  | 0 
| | linux/namei.h | do_filp_open, build_open_flags, files_lookup_fd_locked, file_close_fd_locked | 4 
| | linux/io_uring.h | struct io_uring_sqe | 1 
| | uapi/linux/io_uring.h | struct open_how, IORING_FIXED_FD_NO_CLOEXEC | 2 
| | io_uring.h | io_kiocb_to_cmd, io_req_set_res, req_set_fail, IOU_OK, REQ_F_FORCE_ASYNC, REQ_F_NEED_CLEANUP, REQ_F_FIXED_FILE, REQ_F_CREDS | 9 
| | rsrc.h | io_fixed_fd_install, io_fixed_fd_remove | 2 
| | openclose.h | io_openat_prep, io_openat2_prep, io_openat2, io_openat, io_close_prep, io_close, io_open_cleanup, io_install_fixed_fd_prep, io_install_fixed_fd | 9 
| | fs/internal.h | build_open_how, copy_struct_from_user, force_o_largefile | 3 
| | internal (self-declared) | struct io_open, struct io_close, struct io_fixed_install | 3 
| | internal (self-declared) | io_openat_force_async | 1 
| | internal (self-declared) | __io_openat_prep | 1 
| | internal (self-declared) | __io_close_fixed | 1 
| | current macro | current->files | 1 
| | linux/rlimit.h (implisit) | rlimit, RLIMIT_NOFILE | 1
openclose.h | openclose.h | __io_close_fixed | 1 
| | io_openat_prep | 1 
| | io_openat | 1 
| | io_open_cleanup | 1 
| | io_openat2_prep | 1 
| | io_openat2 | 1 
| | io_close_prep | 1 
| | io_close | 1 
| | io_install_fixed_fd_prep | 1 
| | io_install_fixed_fd | 1
| poll.c | io_uring/cancel.c | lockdep_assert_held | 2 |
| | io_uring/alloc_cache.h | kfree | 2 |
| | io_uring/poll.c | add_wait_queue_exclusive | 1 |
| | io_uring/poll.c | io_poll_add | 1 |
| | io_uring/alloc_cache.c | kmalloc | 2 |
| | io_uring/poll.c | io_req_task_submit | 2 |
| | io_uring/cancel.c | container_of | 3 |
| | io_uring/io_uring.c | io_should_terminate_tw | 1 |
| | io_uring/advise.c | req_set_fail | 4 |
| | io_uring/poll.c | io_poll_add_hash | 2 |
| | io_uring/cancel.c | hlist_for_each_entry_safe | 1 |
| | io_uring/poll.c | io_pollfree_wake | 1 |
| | io_uring/advise.c | io_kiocb_to_cmd | 8 |
| | io_uring/poll.c | swahw32 | 1 |
| | io_uring/poll.c | vfs_poll | 2 |
| | io_uring/poll.c | INIT_HLIST_NODE | 1 |
| | io_uring/io_uring.c | atomic_andnot | 1 |
| | io_uring/advise.c | io_req_set_res | 6 |
| | io_uring/cancel.c | io_match_task_safe | 1 |
| | io_uring/poll.c | io_poll_check_events | 1 |
| | io_uring/poll.c | io_poll_execute | 2 |
| | io_uring/poll.c | io_poll_get_single | 2 |
| | io_uring/poll.c | trace_io_uring_poll_arm | 1 |
| | io_uring/poll.c | __io_queue_proc | 2 |
| | io_uring/poll.c | io_poll_file_find | 1 |
| | io_uring/poll.c | hash_del | 2 |
| | io_uring/poll.c | add_wait_queue | 1 |
| | io_uring/poll.c | io_poll_issue | 1 |
| | io_uring/poll.c | io_poll_remove_entries | 4 |
| | io_uring/poll.c | io_poll_get_ownership | 4 |
| | io_uring/poll.c | io_poll_get_double | 1 |
| | io_uring/eventfd.c | rcu_read_lock | 2 |
| | io_uring/fdinfo.c | hlist_for_each_entry | 2 |
| | io_uring/poll.c | io_poll_can_finish_inline | 3 |
| | io_uring/futex.c | hlist_add_head | 1 |
| | io_uring/advise.c | READ_ONCE | 5 |
| | io_uring/eventfd.c | rcu_read_unlock | 2 |
| | io_uring/poll.c | atomic_fetch_inc | 2 |
| | io_uring/poll.c | io_poll_get_ownership_slowpath | 1 |
| | io_uring/io_uring.c | smp_store_release | 1 |
| | io_uring/poll.c | io_init_poll_iocb | 2 |
| | io_uring/advise.c | WARN_ON_ONCE | 2 |
| | io_uring/futex.c | io_cache_alloc | 1 |
| | io_uring/poll.c | io_poll_parse_events | 2 |
| | io_uring/poll.c | GENMASK | 1 |
| | io_uring/poll.c | key_to_poll | 1 |
| | io_uring/futex.c | io_tw_lock | 1 |
| | io_uring/poll.c | io_napi_add | 2 |
| | io_uring/poll.c | io_poll_find | 2 |
| | io_uring/poll.c | io_poll_mark_cancelled | 3 |
| | io_uring/cancel.c | io_cancel_match_sequence | 1 |
| | io_uring/io-wq.c | INIT_LIST_HEAD | 1 |
| | io_uring/poll.c | io_req_alloc_apoll | 1 |
| | io_uring/eventfd.c | atomic_fetch_or | 1 |
| | io_uring/io-wq.c | spin_unlock_irq | 2 |
| | io_uring/poll.c | __io_poll_cancel | 1 |
| | io_uring/poll.c | wqe_to_req | 1 |
| | io_uring/eventfd.c | BIT | 2 |
| | io_uring/io_uring.c | io_file_can_poll | 1 |
| | io_uring/cancel.c | unlikely | 9 |
| | io_uring/io_uring.c | __io_req_task_work_add | 1 |
| | io_uring/io-wq.c | spin_lock_irq | 2 |
| | io_uring/poll.c | io_poll_req_insert | 1 |
| | io_uring/io-wq.c | atomic_or | 1 |
| | io_uring/futex.c | io_req_task_work_add | 1 |
| | io_uring/poll.c | io_poll_disarm | 1 |
| | io_uring/io_uring.h | smp_load_acquire | 2 |
| | io_uring/poll.c | wqe_is_double | 1 |
| | io_uring/poll.c | atomic_cmpxchg | 1 |
| | io_uring/cancel.c | io_cancel_req_match | 1 |
| | io_uring/cancel.c | io_ring_submit_lock | 3 |
| | io_uring/poll.c | __io_arm_poll_handler | 2 |
| | io_uring/io_uring.c | io_req_defer_failed | 1 |
| | io_uring/cancel.c | io_ring_submit_unlock | 3 |
| | io_uring/futex.c | io_req_task_complete | 2 |
| | io_uring/poll.c | io_poll_double_prepare | 1 |
| | io_uring/poll.c | io_poll_cancel_req | 2 |
| | io_uring/poll.c | __io_poll_execute | 5 |
| | io_uring/io_uring.c | io_kbuf_recycle | 3 |
| | io_uring/cancel.c | hlist_del_init | 1 |
| | io_uring/poll.c | mangle_poll | 2 |
| | io_uring/io_uring.c | init_waitqueue_func_entry | 1 |
| | io_uring/io-wq.c | atomic_read | 2 |
| | io_uring/poll.c | trace_io_uring_task_add | 1 |
| | io_uring/net.c | io_req_post_cqe | 1 |
| | io_uring/poll.c | atomic_sub_return | 1 |
| | io_uring/poll.c | demangle_poll | 1 |
| | io_uring/eventfd.c | atomic_set | 1 |
| | io_uring/poll.c | hash_long | 2 |
| | io_uring/poll.c | io_poll_remove_entry | 2 |
| | io_uring/io-wq.c | list_del_init | 3 |
| poll.h | io_uring/io-wq.c | atomic_inc | 1 |
| refs.h | io_uring/io_uring.c | __io_req_set_refcount | 1 |
| | io_uring/refs.h | atomic_inc_not_zero | 1 |
| | io_uring/refs.h | data_race | 1 |
| | io_uring/eventfd.c | atomic_set | 1 |
| | io_uring/refs.h | req_ref_zero_or_close_to_overflow | 4 |
| | io_uring/io-wq.c | atomic_dec | 1 |
| | io_uring/io-wq.c | atomic_read | 1 |
| | io_uring/advise.c | WARN_ON_ONCE | 8 |
| | io_uring/io-wq.c | likely | 1 |
| | io_uring/io-wq.c | atomic_inc | 1 |
| | io_uring/io-wq.c | atomic_dec_and_test | 2 |
| register.c | io_uring/io_uring.c | io_uring_fill_params | 1 |
| | io_uring/cancel.c | __must_hold | 1 |
| | io_uring/eventfd.c | atomic_set | 1 |
| | io_uring/register.c | trace_io_uring_register | 1 |
| | io_uring/filetable.c | io_is_uring_fops | 1 |
| | io_uring/cancel.c | ARRAY_SIZE | 3 |
| | io_uring/register.c | io_put_sq_data | 2 |
| | io_uring/advise.c | READ_ONCE | 7 |
| | io_uring/io_uring.c | get_current_cred | 1 |
| | io_uring/io-wq.c | __acquires | 1 |
| | io_uring/register.c | io_ringfd_unregister | 1 |
| | io_uring/register.c | io_register_zcrx_ifq | 1 |
| | io_uring/register.c | io_register_napi | 1 |
| | io_uring/epoll.c | u64_to_user_ptr | 1 |
| | io_uring/register.c | io_uring_register_get_file | 1 |
| | io_uring/io_uring.c | io_sqe_files_unregister | 1 |
| | io_uring/register.c | io_sqpoll_wq_cpu_affinity | 1 |
| | io_uring/cancel.c | spin_unlock | 1 |
| | io_uring/io-wq.c | atomic_read | 1 |
| | io_uring/register.c | io_register_resize_rings | 1 |
| | io_uring/register.c | io_sqe_files_register | 1 |
| | io_uring/filetable.h | __set_bit | 2 |
| | io_uring/io_uring.c | io_eventfd_unregister | 1 |
| | io_uring/memmap.c | memchr_inv | 3 |
| | io_uring/io_uring.c | io_sq_thread_unpark | 1 |
| | io_uring/cancel.c | fput | 2 |
| | io_uring/register.c | io_register_pbuf_ring | 1 |
| | io_uring/io_uring.c | io_sqe_buffers_unregister | 1 |
| | io_uring/io-wq.c | get_task_struct | 1 |
| | io_uring/register.c | cpumask_clear | 1 |
| | io_uring/register.c | io_parse_restrictions | 1 |
| | io_uring/register.c | io_uring_sync_msg_ring | 1 |
| | io_uring/io-wq.c | free_cpumask_var | 2 |
| | io_uring/register.c | io_register_pbuf_status | 1 |
| | io_uring/memmap.c | io_region_is_set | 1 |
| | io_uring/cancel.c | unlikely | 3 |
| | io_uring/register.c | io_uring_op_supported | 1 |
| | io_uring/register.c | io_unregister_iowq_aff | 1 |
| | io_uring/filetable.h | test_bit | 1 |
| | io_uring/register.c | io_unregister_pbuf_ring | 1 |
| | io_uring/io_uring.c | io_activate_pollwq | 1 |
| | io_uring/io_uring.c | struct_size | 1 |
| | io_uring/io-wq.c | refcount_inc | 1 |
| | io_uring/io-wq.c | wq_has_sleeper | 2 |
| | io_uring/cancel.c | mutex_unlock | 9 |
| | io_uring/kbuf.c | xa_erase | 1 |
| | io_uring/io_uring.c | io_free_region | 3 |
| | io_uring/io_uring.c | io_sq_thread_park | 1 |
| | io_uring/io_uring.c | put_cred | 2 |
| | io_uring/register.c | io_register_mem_region | 1 |
| | io_uring/register.c | __io_register_iowq_aff | 2 |
| | io_uring/io-wq.c | ERR_PTR | 3 |
| | io_uring/kbuf.c | io_create_region_mmap_safe | 3 |
| | io_uring/register.c | swap_old | 2 |
| | io_uring/register.c | io_register_free_rings | 5 |
| | io_uring/register.c | cpumask_size | 2 |
| | io_uring/io_uring.c | rings_size | 1 |
| | io_uring/register.c | io_wq_cpu_affinity | 1 |
| | io_uring/register.c | io_register_file_alloc_range | 1 |
| | io_uring/eventfd.c | IS_ERR | 2 |
| | io_uring/alloc_cache.h | kfree | 2 |
| | io_uring/register.c | xa_alloc_cyclic | 1 |
| | io_uring/io-wq.c | __releases | 1 |
| | io_uring/advise.c | WARN_ON_ONCE | 2 |
| | io_uring/register.c | io_register_iowq_max_workers | 1 |
| | io_uring/alloc_cache.c | memset | 4 |
| | io_uring/register.c | io_sync_cancel | 1 |
| | io_uring/register.c | __io_uring_register | 1 |
| | io_uring/io-wq.c | kzalloc | 1 |
| | io_uring/register.c | io_eventfd_register | 2 |
| | io_uring/register.c | compat_get_bitmap | 1 |
| | io_uring/register.c | io_probe | 1 |
| | io_uring/io-wq.c | BUILD_BUG_ON | 1 |
| | io_uring/cancel.c | copy_from_user | 8 |
| | io_uring/register.c | io_uring_register_blind | 1 |
| | io_uring/register.c | cpumask_bits | 1 |
| | io_uring/io_uring.h | percpu_ref_is_dying | 1 |
| | io_uring/cancel.c | spin_lock | 1 |
| | io_uring/cancel.c | fget | 1 |
| | io_uring/register.c | io_ringfd_register | 1 |
| | io_uring/io_uring.c | PAGE_ALIGN | 2 |
| | io_uring/io_uring.c | copy_to_user | 5 |
| | io_uring/cancel.c | mutex_lock | 8 |
| | io_uring/register.c | io_sqe_buffers_register | 1 |
| | io_uring/io_uring.c | io_region_get_ptr | 3 |
| | io_uring/register.c | io_register_rsrc | 2 |
| | io_uring/io_uring.c | WRITE_ONCE | 12 |
| | io_uring/register.c | io_unregister_napi | 1 |
| | io_uring/io_uring.c | array_size | 3 |
| | io_uring/io_uring.c | io_unregister_personality | 1 |
| | io_uring/io_uring.c | array_index_nospec | 2 |
| | io_uring/register.c | io_register_rsrc_update | 2 |
| | io_uring/register.c | io_register_iowq_aff | 1 |
| | io_uring/register.c | io_register_personality | 1 |
| | io_uring/io_uring.c | in_compat_syscall | 1 |
| | io_uring/eventfd.c | PTR_ERR | 2 |
| | io_uring/register.c | io_register_enable_rings | 1 |
| | io_uring/register.c | XA_LIMIT | 1 |
| | io_uring/register.c | io_register_restrictions | 1 |
| | io_uring/register.c | io_register_clock | 1 |
| | io_uring/cancel.c | list_for_each_entry | 1 |
| | io_uring/msg_ring.c | get_file | 1 |
| | io_uring/io-wq.c | wake_up | 1 |
| | io_uring/register.c | memdup_user | 1 |
| | io_uring/register.c | io_wq_max_workers | 2 |
| | io_uring/register.c | io_register_files_update | 1 |
| | io_uring/register.c | io_register_clone_buffers | 1 |
| | io_uring/io-wq.c | alloc_cpumask_var | 1 |
| rsrc.c | io_uring/memmap.c | __io_account_mem | 1 |
| | io_uring/rsrc.c | lock_two_rings | 1 |
| | io_uring/rsrc.c | io_unaccount_mem | 1 |
| | io_uring/rsrc.c | iovec_from_user | 3 |
| | io_uring/filetable.c | io_is_uring_fops | 2 |
| | io_uring/rsrc.c | io_buffer_validate | 2 |
| | io_uring/io-wq.c | ERR_PTR | 2 |
| | io_uring/net.c | rlimit | 2 |
| | io_uring/cancel.c | io_rsrc_node_lookup | 2 |
| | io_uring/filetable.c | io_rsrc_data_alloc | 2 |
| | io_uring/cancel.c | mutex_lock | 1 |
| | io_uring/filetable.c | check_add_overflow | 7 |
| | io_uring/futex.c | io_cache_free | 3 |
| | io_uring/rsrc.c | for_each_mp_bvec | 1 |
| | io_uring/rsrc.c | unpin_user_page | 1 |
| | io_uring/rsrc.c | page_size | 1 |
| | io_uring/filetable.c | io_rsrc_node_alloc | 5 |
| | io_uring/msg_ring.c | cmd_to_io_kiocb | 2 |
| | io_uring/rsrc.c | io_sqe_buffer_register | 2 |
| | io_uring/rsrc.c | io_alloc_file_tables | 1 |
| | io_uring/rsrc.c | io_buffer_account_pin | 1 |
| | io_uring/rsrc.c | page_folio | 3 |
| | io_uring/memmap.c | io_pin_pages | 1 |
| | io_uring/rsrc.c | folio_nr_pages | 1 |
| | io_uring/memmap.c | io_check_coalesce_buffer | 1 |
| | io_uring/kbuf.c | kmalloc_array | 1 |
| | io_uring/rsrc.c | io_kern_bvec_size | 1 |
| | io_uring/rsrc.c | io_req_assign_buf_node | 1 |
| | io_uring/alloc_cache.c | kvfree | 4 |
| | io_uring/cancel.c | io_ring_submit_unlock | 4 |
| | io_uring/net.c | io_fixed_fd_install | 1 |
| | io_uring/rsrc.c | blk_rq_bytes | 1 |
| | io_uring/rsrc.c | io_import_fixed | 1 |
| | io_uring/filetable.c | io_fixed_file_set | 2 |
| | io_uring/cancel.c | copy_from_user | 11 |
| | io_uring/rsrc.c | io_vec_realloc | 2 |
| | io_uring/rsrc.c | io_free_imu | 2 |
| | io_uring/eventfd.c | refcount_set | 2 |
| | io_uring/rsrc.c | __io_sqe_buffers_update | 1 |
| | io_uring/futex.c | io_alloc_cache_free | 2 |
| | io_uring/rsrc.c | io_clone_buffers | 1 |
| | io_uring/rsrc.c | io_account_mem | 1 |
| | io_uring/nop.c | io_find_buf_node | 2 |
| | io_uring/net.c | io_is_compat | 1 |
| | io_uring/fdinfo.c | min | 1 |
| | io_uring/memmap.c | __io_unaccount_mem | 1 |
| | io_uring/rsrc.c | atomic_long_try_cmpxchg | 1 |
| | io_uring/futex.c | io_cache_alloc | 2 |
| | io_uring/msg_ring.c | io_post_aux_cqe | 1 |
| | io_uring/rsrc.c | struct_size_t | 2 |
| | io_uring/advise.c | WARN_ON_ONCE | 3 |
| | io_uring/rsrc.c | io_estimate_bvec_size | 1 |
| | io_uring/io_uring.c | copy_to_user | 1 |
| | io_uring/rsrc.c | atomic_long_read | 1 |
| | io_uring/io_uring.c | array_index_nospec | 3 |
| | io_uring/rsrc.c | mutex_lock_nested | 1 |
| | io_uring/rsrc.c | io_buffer_unmap | 1 |
| | io_uring/openclose.c | __io_close_fixed | 1 |
| | io_uring/rsrc.c | validate_fixed_range | 3 |
| | io_uring/eventfd.c | refcount_dec_and_test | 1 |
| | io_uring/filetable.c | io_file_bitmap_clear | 1 |
| | io_uring/cancel.c | mutex_unlock | 2 |
| | io_uring/rsrc.c | __io_register_rsrc_update | 3 |
| | io_uring/rsrc.c | io_put_rsrc_node | 2 |
| | io_uring/register.c | io_sqe_files_register | 1 |
| | io_uring/advise.c | req_set_fail | 1 |
| | io_uring/io_uring.c | io_sqe_files_unregister | 1 |
| | io_uring/rsrc.c | folio_size | 1 |
| | io_uring/cancel.c | io_slot_file | 1 |
| | io_uring/alloc_cache.c | kvmalloc_array | 2 |
| | io_uring/rsrc.c | rq_data_dir | 1 |
| | io_uring/cancel.c | fget | 3 |
| | io_uring/memmap.c | memchr_inv | 1 |
| | io_uring/epoll.c | u64_to_user_ptr | 9 |
| | io_uring/rsrc.c | headpage_already_acct | 1 |
| | io_uring/rsrc.c | __io_sqe_files_update | 1 |
| | io_uring/rsrc.c | blk_rq_nr_phys_segments | 1 |
| | io_uring/rsrc.c | release | 1 |
| | io_uring/rsrc.c | rq_for_each_bvec | 1 |
| | io_uring/rsrc.c | io_coalesce_buffer | 1 |
| | io_uring/rsrc.c | io_vec_fill_kern_bvec | 1 |
| | io_uring/io_uring.c | min_t | 3 |
| | io_uring/rsrc.c | io_alloc_imu | 2 |
| | io_uring/alloc_cache.h | io_alloc_cache_init | 2 |
| | io_uring/rsrc.c | swap | 1 |
| | io_uring/eventfd.c | IS_ERR | 7 |
| | io_uring/io_uring.c | max | 1 |
| | io_uring/filetable.c | io_rsrc_data_free | 3 |
| | io_uring/advise.c | io_kiocb_to_cmd | 3 |
| | io_uring/rsrc.c | kvmalloc | 1 |
| | io_uring/advise.c | io_req_set_res | 1 |
| | io_uring/rsrc.c | atomic64_add | 1 |
| | io_uring/cancel.c | fput | 6 |
| | io_uring/rsrc.c | compound_head | 4 |
| | io_uring/rsrc.c | iov_iter_bvec | 3 |
| | io_uring/rsrc.c | iov_iter_advance | 1 |
| | io_uring/cancel.c | io_ring_submit_lock | 4 |
| | io_uring/cancel.c | lockdep_assert_held | 3 |
| | io_uring/register.c | io_uring_register_get_file | 1 |
| | io_uring/rsrc.c | iov_kern_bvec_size | 1 |
| | io_uring/eventfd.c | PTR_ERR | 7 |
| | io_uring/rsrc.c | io_files_update_with_index_alloc | 1 |
| | io_uring/io_uring.c | io_sqe_buffers_unregister | 1 |
| | io_uring/rsrc.c | io_free_file_tables | 1 |
| | io_uring/rsrc.c | bvec_iter_advance | 1 |
| | io_uring/net.c | io_vec_free | 2 |
| | io_uring/cancel.c | unlikely | 14 |
| | io_uring/rsrc.c | folio_shift | 1 |
| | io_uring/rsrc.c | atomic64_sub | 1 |
| | io_uring/rsrc.c | io_vec_fill_bvec | 1 |
| | io_uring/filetable.c | io_file_bitmap_set | 2 |
| | io_uring/register.c | io_sqe_buffers_register | 1 |
| | io_uring/rsrc.c | bvec_set_page | 2 |
| | io_uring/alloc_cache.c | memset | 3 |
| | io_uring/filetable.c | io_file_table_set_alloc_range | 2 |
| | io_uring/filetable.c | io_reset_rsrc_node | 2 |
| | io_uring/io_uring.c | memcpy | 1 |
| | io_uring/rsrc.c | PageCompound | 3 |
| | io_uring/alloc_cache.h | kfree | 2 |
| | io_uring/memmap.c | unpin_user_pages | 3 |
| | io_uring/io-wq.c | BUILD_BUG_ON | 1 |
| | io_uring/io-wq.c | refcount_inc | 1 |
| | io_uring/advise.c | READ_ONCE | 3 |
| | io_uring/rsrc.c | folio_page_idx | 2 |
| rsrc.h | io_uring/rsrc.h | io_free_rsrc_node | 1 |
| | io_uring/cancel.c | lockdep_assert_held | 1 |
| | io_uring/io_uring.c | io_req_assign_rsrc_node | 1 |
| | io_uring/rsrc.h | atomic_long_sub | 1 |
| | io_uring/net.c | io_vec_free | 2 |
| | io_uring/io_uring.c | array_index_nospec | 1 |
| | io_uring/rsrc.c | io_put_rsrc_node | 3 |
| | io_uring/io_uring.h | IS_ENABLED | 1 |
| rw.c | io_uring/rw.c | rq_list_empty | 2 |
| | io_uring/rw.c | io_write | 1 |
| | io_uring/alloc_cache.h | kfree | 1 |
| | io_uring/cancel.c | io_wq_current_is_worker | 1 |
| | io_uring/poll.c | vfs_poll | 1 |
| | io_uring/io_uring.c | __io_req_task_work_add | 1 |
| | io_uring/io_uring.c | smp_store_release | 1 |
| | io_uring/rw.c | rw_verify_area | 2 |
| | io_uring/rw.c | ioprio_check_cap | 1 |
| | io_uring/cancel.c | unlikely | 28 |
| | io_uring/rsrc.c | iov_iter_advance | 2 |
| | io_uring/net.c | io_import_reg_buf | 1 |
| | io_uring/rw.c | io_hybrid_iopoll_delay | 1 |
| | io_uring/rw.c | kiocb_start_write | 1 |
| | io_uring/advise.c | io_kiocb_to_cmd | 22 |
| | io_uring/io-wq.c | likely | 2 |
| | io_uring/io_uring.c | file_inode | 3 |
| | io_uring/rw.c | io_kiocb_ppos | 1 |
| | io_uring/io_uring.h | smp_load_acquire | 1 |
| | io_uring/rw.c | io_rw_should_reissue | 2 |
| | io_uring/rw.c | iopoll | 1 |
| | io_uring/rw.c | __io_prep_rw | 6 |
| | io_uring/rw.c | io_rw_prep_reg_vec | 2 |
| | io_uring/net.c | io_vec_reset_iovec | 1 |
| | io_uring/rw.c | hrtimer_sleeper_start_expires | 1 |
| | io_uring/rw.c | sb_start_write_trylock | 1 |
| | io_uring/filetable.h | io_file_get_flags | 1 |
| | io_uring/rw.c | io_prep_rw | 3 |
| | io_uring/advise.c | req_set_fail | 2 |
| | io_uring/rw.c | io_rw_init_file | 2 |
| | io_uring/advise.c | io_req_set_res | 5 |
| | io_uring/rw.c | wq_list_for_each_resume | 1 |
| | io_uring/net.c | io_prep_reg_iovec | 1 |
| | io_uring/net.c | io_do_buffer_select | 3 |
| | io_uring/io_uring.c | io_put_kbuf | 5 |
| | io_uring/rw.c | trace_io_uring_short_write | 1 |
| | io_uring/rw.c | __io_read | 2 |
| | io_uring/io-wq.c | wq_list_cut | 1 |
| | io_uring/cancel.c | lockdep_assert_held | 1 |
| | io_uring/rw.c | io_rw_alloc_async | 1 |
| | io_uring/epoll.c | u64_to_user_ptr | 7 |
| | io_uring/net.c | io_is_compat | 2 |
| | io_uring/io_uring.c | S_ISREG | 1 |
| | io_uring/rw.c | io_read | 1 |
| | io_uring/rw.c | iter_iov_len | 1 |
| | io_uring/rw.c | io_rw_recycle | 2 |
| | io_uring/msg_ring.c | cmd_to_io_kiocb | 3 |
| | io_uring/net.c | __import_iovec | 1 |
| | io_uring/io_uring.h | __io_submit_flush_completions | 1 |
| | io_uring/rw.c | io_uring_hybrid_poll | 1 |
| | io_uring/io-wq.c | wq_list_for_each | 1 |
| | io_uring/io_uring.c | io_file_can_poll | 4 |
| | io_uring/rw.c | __sb_writers_release | 1 |
| | io_uring/rw.c | io_meta_restore | 3 |
| | io_uring/rw.c | iov_iter_restore | 5 |
| | io_uring/net.c | iter_is_ubuf | 1 |
| | io_uring/cancel.c | container_of | 5 |
| | io_uring/rw.c | io_import_vec | 1 |
| | io_uring/rw.c | wake_page_match | 1 |
| | io_uring/rw.c | io_uring_classic_poll | 2 |
| | io_uring/rw.c | read | 1 |
| | io_uring/futex.c | __set_current_state | 1 |
| | io_uring/cancel.c | ktime_get_ns | 2 |
| | io_uring/rw.c | hrtimer_setup_sleeper_on_stack | 1 |
| | io_uring/rw.c | io_file_supports_nowait | 2 |
| | io_uring/net.c | iov_iter_count | 6 |
| | io_uring/rw.c | io_rw_import_reg_vec | 2 |
| | io_uring/rw.c | write | 1 |
| | io_uring/rw.c | io_req_io_end | 2 |
| | io_uring/rw.c | ktime_set | 1 |
| | io_uring/rw.c | kiocb_end_write | 1 |
| | io_uring/rw.c | iov_iter_save_state | 6 |
| | io_uring/rw.c | uring_cmd_iopoll | 1 |
| | io_uring/rw.c | io_init_rw_fixed | 2 |
| | io_uring/net.c | io_uring_alloc_async_data | 1 |
| | io_uring/rw.c | io_req_rw_cleanup | 4 |
| | io_uring/rw.c | io_rw_done | 1 |
| | io_uring/io_uring.c | destroy_hrtimer_on_stack | 1 |
| | io_uring/rw.c | io_complete_rw | 1 |
| | io_uring/rw.c | io_iov_compat_buffer_select_prep | 1 |
| | io_uring/io_uring.h | percpu_ref_is_dying | 1 |
| | io_uring/rw.c | write_iter | 1 |
| | io_uring/io-wq.c | complete | 1 |
| | io_uring/rw.c | kiocb_set_rw_flags | 1 |
| | io_uring/rw.c | io_iter_do_read | 2 |
| | io_uring/net.c | req_has_async_data | 1 |
| | io_uring/advise.c | WARN_ON_ONCE | 1 |
| | io_uring/rw.c | io_rw_should_retry | 1 |
| | io_uring/rw.c | io_schedule | 1 |
| | io_uring/io-wq.c | INIT_LIST_HEAD | 1 |
| | io_uring/rw.c | iter_iov_addr | 1 |
| | io_uring/rw.c | io_prep_rwv | 2 |
| | io_uring/io_uring.c | S_ISBLK | 2 |
| | io_uring/rw.c | iov_iter_is_bvec | 2 |
| | io_uring/net.c | io_alloc_cache_vec_kasan | 1 |
| | io_uring/rw.c | DEFINE_IO_COMP_BATCH | 1 |
| | io_uring/rw.c | io_kiocb_start_write | 1 |
| | io_uring/io_uring.c | io_kbuf_recycle | 2 |
| | io_uring/rw.c | io_poll_multishot_retry | 1 |
| | io_uring/rw.c | __io_import_rw_buffer | 1 |
| | io_uring/rw.c | fsnotify_access | 1 |
| | io_uring/rw.c | loop_rw_iter | 2 |
| | io_uring/net.c | io_req_post_cqe | 1 |
| | io_uring/io-wq.c | wq_list_empty | 1 |
| | io_uring/futex.c | io_req_task_complete | 1 |
| | io_uring/io-wq.c | list_del_init | 1 |
| | io_uring/advise.c | READ_ONCE | 10 |
| | io_uring/rw.c | io_iov_buffer_select_prep | 1 |
| | io_uring/rw.c | fsnotify_modify | 1 |
| | io_uring/io_uring.c | hrtimer_cancel | 1 |
| | io_uring/rw.c | io_req_end_write | 4 |
| | io_uring/rw.c | read_iter | 1 |
| | io_uring/rw.c | kiocb_done | 2 |
| | io_uring/rw.c | io_meta_save_state | 1 |
| | io_uring/rw.c | io_prep_rw_pi | 1 |
| | io_uring/rw.c | __io_complete_rw_common | 2 |
| | io_uring/net.c | io_buffer_select | 1 |
| | io_uring/rw.c | io_fixup_rw_res | 4 |
| | io_uring/rw.c | need_complete_io | 2 |
| | io_uring/io_uring.c | io_req_task_queue | 1 |
| | io_uring/io_uring.c | hrtimer_set_expires | 1 |
| | io_uring/rw.c | io_rw_do_import | 1 |
| | io_uring/alloc_cache.h | io_alloc_cache_put | 1 |
| | io_uring/net.c | import_ubuf | 2 |
| | io_uring/rw.c | dio_complete | 1 |
| | io_uring/rw.c | io_import_rw_buffer | 2 |
| | io_uring/rw.c | get_current_ioprio | 1 |
| | io_uring/cancel.c | copy_from_user | 3 |
| | io_uring/io-wq.c | set_current_state | 1 |
| | io_uring/net.c | io_vec_free | 2 |
| | io_uring/rw.c | io_kiocb_update_pos | 2 |
| | io_uring/rw.c | io_complete_rw_iopoll | 1 |
| | io_uring/net.c | io_import_reg_vec | 1 |
| slist.h | io_uring/io-wq.c | INIT_WQ_LIST | 1 |
| | io_uring/advise.c | READ_ONCE | 1 |
| | io_uring/io-wq.c | wq_list_cut | 1 |
| | io_uring/io-wq.c | wq_list_empty | 1 |
| | io_uring/cancel.c | container_of | 1 |
| | io_uring/slist.h | __wq_list_splice | 1 |
| | io_uring/io_uring.c | WRITE_ONCE | 3 |
| splice.c | io_uring/cancel.c | io_ring_submit_unlock | 1 |
| | io_uring/cancel.c | io_file_get_normal | 1 |
| | io_uring/cancel.c | fput | 2 |
| | io_uring/advise.c | READ_ONCE | 6 |
| | io_uring/cancel.c | io_slot_file | 1 |
| | io_uring/cancel.c | io_ring_submit_lock | 1 |
| | io_uring/advise.c | req_set_fail | 2 |
| | io_uring/rsrc.c | io_put_rsrc_node | 1 |
| | io_uring/splice.c | __io_splice_prep | 2 |
| | io_uring/splice.c | io_splice_get_file | 2 |
| | io_uring/cancel.c | unlikely | 1 |
| | io_uring/advise.c | io_req_set_res | 2 |
| | io_uring/advise.c | io_kiocb_to_cmd | 6 |
| | io_uring/splice.c | do_tee | 1 |
| | io_uring/cancel.c | io_rsrc_node_lookup | 1 |
| | io_uring/advise.c | WARN_ON_ONCE | 2 |
| | io_uring/splice.c | do_splice | 1 |
| sqpoll.c | io_uring/io_uring.c | atomic_andnot | 1 |
| | io_uring/eventfd.c | refcount_dec_and_test | 1 |
| | io_uring/io_uring.c | io_sq_thread_park | 3 |
| | io_uring/sqpoll.c | io_attach_sq_data | 1 |
| | io_uring/sqpoll.c | cpumask_of | 1 |
| | io_uring/filetable.c | io_is_uring_fops | 2 |
| | io_uring/io-wq.c | likely | 1 |
| | io_uring/eventfd.c | atomic_set | 1 |
| | io_uring/sqpoll.c | io_get_sq_data | 1 |
| | io_uring/eventfd.c | IS_ERR | 3 |
| | io_uring/io-wq.c | wait_for_completion | 1 |
| | io_uring/io-wq.c | wq_has_sleeper | 1 |
| | io_uring/cancel.c | unlikely | 1 |
| | io_uring/sqpoll.c | atomic_dec_return | 1 |
| | io_uring/io-wq.c | set_bit | 3 |
| | io_uring/io-wq.c | cpumask_test_cpu | 1 |
| | io_uring/io-wq.c | clear_bit | 1 |
| | io_uring/io-wq.c | __releases | 1 |
| | io_uring/io_uring.h | percpu_ref_is_dying | 1 |
| | io_uring/io-wq.c | free_cpumask_var | 2 |
| | io_uring/advise.c | READ_ONCE | 1 |
| | io_uring/sqpoll.c | io_sq_tw | 2 |
| | io_uring/io_uring.c | init_waitqueue_head | 1 |
| | io_uring/sqpoll.c | io_sqd_handle_event | 1 |
| | io_uring/io-wq.c | atomic_read | 2 |
| | io_uring/cancel.c | DEFINE_WAIT | 2 |
| | io_uring/io-wq.c | set_cpus_allowed_ptr | 2 |
| | io_uring/io-wq.c | atomic_inc | 1 |
| | io_uring/io_uring.c | tctx_task_work_run | 1 |
| | io_uring/io-wq.c | refcount_inc | 1 |
| | io_uring/io_uring.c | io_handle_tw_list | 1 |
| | io_uring/cancel.c | finish_wait | 2 |
| | io_uring/io_uring.c | revert_creds | 1 |
| | io_uring/io-wq.c | INIT_LIST_HEAD | 1 |
| | io_uring/sqpoll.c | wait_event | 1 |
| | io_uring/io_uring.c | io_sq_thread_finish | 1 |
| | io_uring/io_uring.c | mutex_init | 1 |
| | io_uring/io-wq.c | __acquires | 1 |
| | io_uring/sqpoll.c | io_sqd_update_thread_idle | 2 |
| | io_uring/io_uring.c | io_sqring_entries | 2 |
| | io_uring/io_uring.c | audit_uring_exit | 1 |
| | io_uring/io_uring.c | need_resched | 1 |
| | io_uring/io-wq.c | get_signal | 1 |
| | io_uring/cancel.c | list_for_each_entry | 6 |
| | io_uring/io-wq.c | msecs_to_jiffies | 1 |
| | io_uring/kbuf.c | list_add | 1 |
| | io_uring/sqpoll.c | io_napi_sqpoll_busy_poll | 1 |
| | io_uring/io_uring.c | io_uring_cancel_generic | 1 |
| | io_uring/io_uring.c | io_submit_sqes | 1 |
| | io_uring/io-wq.c | ERR_PTR | 5 |
| | io_uring/io-wq.c | atomic_or | 2 |
| | io_uring/io-wq.c | wake_up_process | 2 |
| | io_uring/eventfd.c | PTR_ERR | 3 |
| | io_uring/refs.h | data_race | 1 |
| | io_uring/cancel.c | mutex_unlock | 8 |
| | io_uring/io-wq.c | alloc_cpumask_var | 1 |
| | io_uring/io_uring.c | schedule | 2 |
| | io_uring/advise.c | WARN_ON_ONCE | 5 |
| | io_uring/io-wq.c | cpuset_cpus_allowed | 1 |
| | io_uring/io-wq.c | cond_resched | 1 |
| | io_uring/fdinfo.c | getrusage | 2 |
| | io_uring/io-wq.c | wq_list_empty | 4 |
| | io_uring/io_uring.c | time_after | 1 |
| | io_uring/sqpoll.c | cpu_online | 1 |
| | io_uring/io-wq.c | io_run_task_work | 1 |
| | io_uring/sqpoll.c | io_uring_alloc_task_context | 1 |
| | io_uring/msg_ring.c | fd_empty | 2 |
| | io_uring/io_uring.c | io_sq_thread_unpark | 3 |
| | io_uring/sqpoll.c | io_sq_thread_stop | 1 |
| | io_uring/msg_ring.c | fd_file | 3 |
| | io_uring/sqpoll.c | smp_mb__after_atomic | 1 |
| | io_uring/io_uring.c | audit_uring_entry | 1 |
| | io_uring/register.c | io_wq_cpu_affinity | 1 |
| | io_uring/io-wq.c | wake_up_new_task | 1 |
| | io_uring/io-wq.c | set_task_comm | 1 |
| | io_uring/cancel.c | mutex_lock | 8 |
| | io_uring/sqpoll.c | io_sq_update_worktime | 1 |
| | io_uring/io_uring.c | io_do_iopoll | 1 |
| | io_uring/io-wq.c | get_task_struct | 1 |
| | io_uring/fdinfo.c | task_work_pending | 1 |
| | io_uring/filetable.h | test_bit | 3 |
| | io_uring/io-wq.c | list_del_init | 1 |
| | io_uring/napi.c | list_is_singular | 1 |
| | io_uring/io-wq.c | raw_smp_processor_id | 4 |
| | io_uring/sqpoll.c | io_sq_tw_pending | 1 |
| | io_uring/msg_ring.c | CLASS | 2 |
| | io_uring/napi.h | io_napi | 1 |
| | io_uring/io_uring.c | io_sqring_full | 2 |
| | io_uring/io-wq.c | snprintf | 1 |
| | io_uring/io-wq.c | put_task_struct | 2 |
| | io_uring/io_uring.c | get_current_cred | 1 |
| | io_uring/io_uring.c | llist_empty | 1 |
| | io_uring/sqpoll.c | io_sqd_events_pending | 2 |
| | io_uring/alloc_cache.h | kfree | 1 |
| | io_uring/sqpoll.c | security_uring_sqpoll | 1 |
| | io_uring/io-wq.c | wake_up | 2 |
| | io_uring/io-wq.c | init_completion | 1 |
| | io_uring/sqpoll.c | __io_sq_thread | 1 |
| | io_uring/io-wq.c | kzalloc | 1 |
| | io_uring/io_uring.c | override_creds | 1 |
| | io_uring/io-wq.c | do_exit | 1 |
| | io_uring/io_uring.c | max | 1 |
| | io_uring/io-wq.c | create_io_thread | 1 |
| | io_uring/eventfd.c | refcount_set | 1 |
| | io_uring/cancel.c | prepare_to_wait | 2 |
| | io_uring/io-wq.c | complete | 2 |
| | io_uring/io_uring.h | task_work_run | 1 |
| | io_uring/io_uring.c | current_cred | 1 |
| | io_uring/register.c | io_put_sq_data | 1 |
| | io_uring/io-wq.c | signal_pending | 4 |
| statx.c | io_uring/fs.c | getname_uflags | 1 |
| | io_uring/eventfd.c | IS_ERR | 1 |
| | io_uring/statx.c | do_statx | 1 |
| | io_uring/fs.c | putname | 1 |
| | io_uring/eventfd.c | PTR_ERR | 1 |
| | io_uring/advise.c | io_kiocb_to_cmd | 3 |
| | io_uring/epoll.c | u64_to_user_ptr | 2 |
| | io_uring/advise.c | io_req_set_res | 1 |
| | io_uring/advise.c | WARN_ON_ONCE | 1 |
| | io_uring/advise.c | READ_ONCE | 5 |
| sync.c | io_uring/cancel.c | unlikely | 3 |
| | io_uring/advise.c | io_req_set_res | 3 |
| | io_uring/sync.c | vfs_fallocate | 1 |
| | io_uring/sync.c | vfs_fsync_range | 1 |
| | io_uring/advise.c | WARN_ON_ONCE | 3 |
| | io_uring/sync.c | sync_file_range | 1 |
| | io_uring/advise.c | READ_ONCE | 9 |
| | io_uring/rw.c | fsnotify_modify | 1 |
| | io_uring/advise.c | io_kiocb_to_cmd | 6 |
| tctx.c | io_uring/io_uring.c | xa_init | 1 |
| | io_uring/eventfd.c | IS_ERR | 1 |
| | io_uring/sqpoll.c | io_uring_alloc_task_context | 1 |
| | io_uring/tctx.c | percpu_counter_destroy | 2 |
| | io_uring/eventfd.c | PTR_ERR | 1 |
| | io_uring/eventfd.c | refcount_set | 1 |
| | io_uring/kbuf.c | list_add | 1 |
| | io_uring/fdinfo.c | xa_for_each | 2 |
| | io_uring/fdinfo.c | min | 1 |
| | io_uring/advise.c | WARN_ON_ONCE | 5 |
| | io_uring/cancel.c | copy_from_user | 2 |
| | io_uring/io_uring.c | init_waitqueue_head | 2 |
| | io_uring/io-wq.c | cond_resched | 1 |
| | io_uring/io_uring.c | list_del | 1 |
| | io_uring/io_uring.c | io_uring_del_tctx_node | 1 |
| | io_uring/io-wq.c | kzalloc | 2 |
| | io_uring/tctx.c | io_ring_add_registered_fd | 1 |
| | io_uring/cancel.c | fput | 5 |
| | io_uring/io_uring.c | io_ring_add_registered_file | 1 |
| | io_uring/eventfd.c | atomic_set | 2 |
| | io_uring/alloc_cache.c | kmalloc | 1 |
| | io_uring/cancel.c | mutex_unlock | 5 |
| | io_uring/tctx.c | io_wq_create | 1 |
| | io_uring/io_uring.c | array_index_nospec | 2 |
| | io_uring/io-wq.c | list_empty | 1 |
| | io_uring/io_uring.c | copy_to_user | 1 |
| | io_uring/tctx.c | num_online_cpus | 1 |
| | io_uring/tctx.c | percpu_counter_init | 1 |
| | io_uring/cancel.c | unlikely | 4 |
| | io_uring/register.c | io_wq_max_workers | 1 |
| | io_uring/alloc_cache.h | kfree | 5 |
| | io_uring/io_uring.c | init_llist_head | 1 |
| | io_uring/kbuf.c | xa_err | 1 |
| | io_uring/cancel.c | fget | 1 |
| | io_uring/cancel.c | mutex_lock | 4 |
| | io_uring/io-wq.c | ERR_PTR | 1 |
| | io_uring/kbuf.c | xa_store | 1 |
| | io_uring/io-wq.c | init_task_work | 1 |
| | io_uring/io_uring.c | xa_load | 1 |
| | io_uring/tctx.c | io_wq_put_and_exit | 1 |
| | io_uring/filetable.c | io_is_uring_fops | 1 |
| | io_uring/kbuf.c | xa_erase | 1 |
| | io_uring/io_uring.c | __io_uring_add_tctx_node | 2 |
| | io_uring/tctx.c | io_init_wq_offload | 1 |
| tctx.h | io_uring/tctx.h | __io_uring_add_tctx_node_from_submit | 1 |
| | io_uring/io-wq.c | likely | 1 |
| timeout.c | io_uring/timeout.c | io_timeout_update | 1 |
| | io_uring/io-wq.c | INIT_LIST_HEAD | 1 |
| | io_uring/timeout.c | io_flush_killed_timeouts | 2 |
| | io_uring/timeout.c | raw_spin_unlock_irqrestore | 2 |
| | io_uring/futex.c | io_req_task_complete | 4 |
| | io_uring/timeout.c | io_kill_timeout | 2 |
| | io_uring/io_uring.c | list_first_entry | 1 |
| | io_uring/futex.c | io_tw_lock | 1 |
| | io_uring/timeout.c | io_linked_timeout_update | 1 |
| | io_uring/advise.c | io_kiocb_to_cmd | 14 |
| | io_uring/io_uring.c | raw_spin_unlock_irq | 8 |
| | io_uring/msg_ring.c | io_req_queue_tw_complete | 3 |
| | io_uring/timeout.c | hweight32 | 2 |
| | io_uring/io_uring.c | io_req_task_queue_fail | 1 |
| | io_uring/cancel.c | __must_hold | 10 |
| | io_uring/timeout.c | __io_timeout_prep | 2 |
| | io_uring/net.c | io_uring_alloc_async_data | 1 |
| | io_uring/timeout.c | list_entry | 1 |
| | io_uring/eventfd.c | IS_ERR | 2 |
| | io_uring/advise.c | READ_ONCE | 4 |
| | io_uring/cancel.c | timespec64_to_ktime | 5 |
| | io_uring/cancel.c | spin_lock | 2 |
| | io_uring/cancel.c | list_for_each_entry | 2 |
| | io_uring/io_uring.c | io_for_each_link | 1 |
| | io_uring/io_uring.c | LIST_HEAD | 2 |
| | io_uring/cancel.c | container_of | 2 |
| | io_uring/timeout.c | io_disarm_linked_timeout | 1 |
| | io_uring/advise.c | req_set_fail | 3 |
| | io_uring/io_uring.c | io_queue_next | 1 |
| | io_uring/timeout.c | hrtimer_try_to_cancel | 4 |
| | io_uring/timeout.c | io_fail_links | 1 |
| | io_uring/cancel.c | io_try_cancel | 1 |
| | io_uring/timeout.c | io_remove_next_linked | 3 |
| | io_uring/cancel.c | io_cancel_req_match | 1 |
| | io_uring/cancel.c | io_timeout_cancel | 1 |
| | io_uring/timeout.c | io_is_timeout_noseq | 3 |
| | io_uring/timeout.c | req_ref_inc_not_zero | 1 |
| | io_uring/refs.h | data_race | 1 |
| | io_uring/io-wq.c | list_empty | 2 |
| | io_uring/io_uring.c | io_free_req | 1 |
| | io_uring/io-wq.c | list_del_init | 3 |
| | io_uring/timeout.c | list_for_each_prev | 1 |
| | io_uring/net.c | io_req_post_cqe | 1 |
| | io_uring/timeout.c | io_put_req | 2 |
| | io_uring/eventfd.c | PTR_ERR | 2 |
| | io_uring/epoll.c | u64_to_user_ptr | 2 |
| | io_uring/cancel.c | spin_unlock | 2 |
| | io_uring/io-wq.c | atomic_read | 4 |
| | io_uring/cancel.c | unlikely | 3 |
| | io_uring/io_uring.c | raw_spin_lock_irq | 8 |
| | io_uring/eventfd.c | atomic_set | 2 |
| | io_uring/futex.c | io_req_task_work_add | 3 |
| | io_uring/timeout.c | io_timeout_extract | 2 |
| | io_uring/advise.c | WARN_ON_ONCE | 2 |
| | io_uring/io-wq.c | ERR_PTR | 2 |
| | io_uring/io_uring.c | req_ref_put_and_test | 1 |
| | io_uring/io_uring.c | list_add_tail | 2 |
| | io_uring/timeout.c | io_timeout_finish | 1 |
| | io_uring/timeout.c | trace_io_uring_fail_link | 1 |
| | io_uring/timeout.c | hrtimer_start | 5 |
| | io_uring/timeout.c | list_for_each_entry_safe | 2 |
| | io_uring/timeout.c | hrtimer_setup | 4 |
| | io_uring/timeout.c | raw_spin_lock_irqsave | 2 |
| | io_uring/io_uring.c | io_should_terminate_tw | 1 |
| | io_uring/timeout.c | io_timeout_get_clock | 4 |
| | io_uring/timeout.c | io_translate_timeout_mode | 2 |
| | io_uring/timeout.c | io_match_task | 1 |
| | io_uring/io_uring.c | list_del | 2 |
| | io_uring/msg_ring.c | cmd_to_io_kiocb | 6 |
| | io_uring/kbuf.c | list_add | 2 |
| | io_uring/net.c | req_has_async_data | 1 |
| | io_uring/advise.c | io_req_set_res | 5 |
| | io_uring/timeout.c | list_move_tail | 1 |
| | io_uring/io_uring.c | get_timespec64 | 2 |
| timeout.h | io_uring/timeout.h | __io_disarm_linked_timeout | 1 |
| truncate.c | io_uring/truncate.c | do_ftruncate | 1 |
| | io_uring/advise.c | READ_ONCE | 1 |
| | io_uring/advise.c | io_req_set_res | 1 |
| | io_uring/advise.c | WARN_ON_ONCE | 1 |
| | io_uring/advise.c | io_kiocb_to_cmd | 2 |
| uring_cmd.c | io_uring/net.c | io_alloc_cache_vec_kasan | 1 |
| | io_uring/net.c | io_is_compat | 1 |
| | io_uring/io_uring.c | memcpy | 1 |
| | io_uring/uring_cmd.c | io_uring_cmd_setsockopt | 1 |
| | io_uring/uring_cmd.c | USER_SOCKPTR | 2 |
| | io_uring/advise.c | io_req_set_res | 2 |
| | io_uring/uring_cmd.c | task_work_cb | 1 |
| | io_uring/cancel.c | hlist_for_each_entry_safe | 1 |
| | io_uring/uring_cmd.c | KERNEL_SOCKPTR | 1 |
| | io_uring/net.c | io_prep_reg_iovec | 1 |
| | io_uring/io_uring.c | __io_req_task_work_add | 1 |
| | io_uring/io_uring.c | smp_store_release | 1 |
| | io_uring/io-wq.c | BUILD_BUG_ON | 1 |
| | io_uring/uring_cmd.c | security_uring_cmd | 1 |
| | io_uring/cancel.c | lockdep_assert_held | 1 |
| | io_uring/msg_ring.c | cmd_to_io_kiocb | 7 |
| | io_uring/io_uring.c | io_submit_flush_completions | 1 |
| | io_uring/io_uring.c | offsetof | 1 |
| | io_uring/uring_cmd.c | io_uring_cmd_getsockopt | 1 |
| | io_uring/alloc_cache.h | io_alloc_cache_put | 1 |
| | io_uring/net.c | io_vec_free | 2 |
| | io_uring/net.c | io_import_reg_buf | 1 |
| | io_uring/uring_cmd.c | ioctl | 2 |
| | io_uring/io_uring.c | io_should_terminate_tw | 1 |
| | io_uring/futex.c | hlist_add_head | 1 |
| | io_uring/advise.c | req_set_fail | 2 |
| | io_uring/futex.c | io_req_task_work_add | 1 |
| | io_uring/alloc_cache.h | kfree | 2 |
| | io_uring/uring_cmd.c | uring_cmd | 2 |
| | io_uring/uring_cmd.c | io_uring_cmd_prep_setup | 1 |
| | io_uring/uring_cmd.c | do_sock_getsockopt | 1 |
| | io_uring/advise.c | io_kiocb_to_cmd | 6 |
| | io_uring/epoll.c | u64_to_user_ptr | 2 |
| | io_uring/uring_cmd.c | io_req_queue_iowq | 1 |
| | io_uring/uring_cmd.c | do_sock_setsockopt | 1 |
| | io_uring/advise.c | WARN_ON_ONCE | 1 |
| | io_uring/net.c | io_uring_alloc_async_data | 1 |
| | io_uring/advise.c | READ_ONCE | 12 |
| | io_uring/uring_cmd.c | uring_sqe_size | 1 |
| | io_uring/uring_cmd.c | hlist_del | 1 |
| | io_uring/net.c | io_import_reg_vec | 1 |
| | io_uring/cancel.c | io_ring_submit_lock | 2 |
| | io_uring/io_uring.c | io_req_complete_defer | 1 |
| | io_uring/uring_cmd.c | io_req_set_cqe32_extra | 1 |
| | io_uring/uring_cmd.c | io_req_uring_cleanup | 3 |
| | io_uring/cancel.c | io_ring_submit_unlock | 2 |
| | io_uring/uring_cmd.c | io_uring_cmd_del_cancelable | 1 |
| waitid.c | io_uring/futex.c | io_tw_lock | 1 |
| | io_uring/net.c | io_is_compat | 1 |
| | io_uring/waitid.c | io_waitid_finish | 2 |
| | io_uring/cancel.c | io_ring_submit_unlock | 3 |
| | io_uring/poll.c | atomic_sub_return | 1 |
| | io_uring/advise.c | io_kiocb_to_cmd | 8 |
| | io_uring/futex.c | io_req_task_work_add | 2 |
| | io_uring/msg_ring.c | io_req_queue_tw_complete | 1 |
| | io_uring/waitid.c | io_waitid_complete | 2 |
| | io_uring/cancel.c | unlikely | 2 |
| | io_uring/futex.c | io_cancel_remove_all | 1 |
| | io_uring/advise.c | WARN_ON_ONCE | 1 |
| | io_uring/futex.c | io_req_task_complete | 1 |
| | io_uring/io-wq.c | spin_unlock_irq | 1 |
| | io_uring/waitid.c | io_waitid_compat_copy_si | 1 |
| | io_uring/io-wq.c | atomic_or | 1 |
| | io_uring/futex.c | hlist_add_head | 1 |
| | io_uring/poll.c | atomic_fetch_inc | 2 |
| | io_uring/waitid.c | kernel_waitid_prepare | 1 |
| | io_uring/advise.c | req_set_fail | 2 |
| | io_uring/waitid.c | unsafe_put_user | 12 |
| | io_uring/net.c | io_uring_alloc_async_data | 1 |
| | io_uring/epoll.c | u64_to_user_ptr | 1 |
| | io_uring/waitid.c | io_waitid_copy_si | 1 |
| | io_uring/io-wq.c | list_del_init | 2 |
| | io_uring/waitid.c | __do_wait | 3 |
| | io_uring/cancel.h | io_cancel_remove | 1 |
| | io_uring/waitid.c | io_waitid_drop_issue_ref | 2 |
| | io_uring/waitid.c | pid_child_should_wake | 1 |
| | io_uring/io-wq.c | spin_lock_irq | 1 |
| | io_uring/waitid.c | io_waitid_free | 1 |
| | io_uring/io_uring.c | init_waitqueue_func_entry | 1 |
| | io_uring/advise.c | io_req_set_res | 2 |
| | io_uring/poll.c | add_wait_queue | 2 |
| | io_uring/eventfd.c | atomic_set | 1 |
| | io_uring/advise.c | READ_ONCE | 4 |
| | io_uring/waitid.c | user_write_access_begin | 2 |
| | io_uring/waitid.c | put_pid | 1 |
| | io_uring/io-wq.c | atomic_read | 2 |
| | io_uring/cancel.c | lockdep_assert_held | 1 |
| | io_uring/cancel.c | container_of | 2 |
| | io_uring/eventfd.c | BIT | 1 |
| | io_uring/waitid.c | remove_wait_queue | 3 |
| | io_uring/cancel.c | hlist_del_init | 2 |
| | io_uring/cancel.c | io_ring_submit_lock | 1 |
| | io_uring/alloc_cache.h | kfree | 1 |
| | io_uring/waitid.c | user_write_access_end | 2 |
| | io_uring/poll.c | GENMASK | 1 |
| xattr.c | io_uring/alloc_cache.c | kmalloc | 2 |
| | io_uring/cancel.c | unlikely | 2 |
| | io_uring/epoll.c | u64_to_user_ptr | 6 |
| | io_uring/xattr.c | setxattr_copy | 1 |
| | io_uring/advise.c | io_kiocb_to_cmd | 9 |
| | io_uring/fs.c | getname | 2 |
| | io_uring/xattr.c | io_xattr_finish | 4 |
| | io_uring/xattr.c | import_xattr_name | 1 |
| | io_uring/xattr.c | file_setxattr | 1 |
| | io_uring/xattr.c | file_getxattr | 1 |
| | io_uring/xattr.c | __io_getxattr_prep | 2 |
| | io_uring/xattr.c | __io_setxattr_prep | 2 |
| | io_uring/advise.c | io_req_set_res | 1 |
| | io_uring/alloc_cache.h | kfree | 3 |
| | io_uring/eventfd.c | PTR_ERR | 2 |
| | io_uring/xattr.c | io_xattr_cleanup | 1 |
| | io_uring/advise.c | WARN_ON_ONCE | 4 |
| | io_uring/xattr.c | filename_setxattr | 1 |
| | io_uring/eventfd.c | IS_ERR | 2 |
| | io_uring/fs.c | putname | 1 |
| | io_uring/advise.c | READ_ONCE | 10 |
| | io_uring/xattr.c | filename_getxattr | 1 |
| | io_uring/alloc_cache.c | kvfree | 1 |
| zcrx.c | io_uring/memmap.c | memchr_inv | 1 |
| | io_uring/zcrx.c | io_zcrx_ifq_free | 2 |
| | io_uring/zcrx.c | io_zcrx_ring_refill | 1 |
| | io_uring/zcrx.c | io_zcrx_return_niov | 3 |
| | io_uring/zcrx.c | skb_frag_foreach_page | 1 |
| | io_uring/kbuf.c | io_create_region_mmap_safe | 1 |
| | io_uring/net.c | sock_error | 1 |
| | io_uring/zcrx.c | io_zcrx_get_rqe | 1 |
| | io_uring/zcrx.c | kmap_local_page | 2 |
| | io_uring/zcrx.c | put_device | 1 |
| | io_uring/zcrx.c | io_allocate_rbuf_ring | 1 |
| | io_uring/zcrx.c | net_iov_idx | 4 |
| | io_uring/zcrx.c | io_zcrx_queue_cqe | 2 |
| | io_uring/zcrx.c | net_iov_owner | 1 |
| | io_uring/zcrx.c | page_pool_unref_netmem | 2 |
| | io_uring/zcrx.c | io_zcrx_recv_skb | 1 |
| | io_uring/zcrx.c | net_mp_open_rxq | 1 |
| | io_uring/zcrx.c | spin_unlock_bh | 5 |
| | io_uring/zcrx.c | io_zcrx_refill_slow | 1 |
| | io_uring/cancel.c | spin_unlock | 2 |
| | io_uring/zcrx.c | io_zcrx_free_area | 2 |
| | io_uring/advise.c | WARN_ON_ONCE | 5 |
| | io_uring/io_uring.c | offsetof | 2 |
| | io_uring/zcrx.c | netmem_to_net_iov | 2 |
| | io_uring/zcrx.c | io_close_queue | 2 |
| | io_uring/eventfd.c | atomic_set | 1 |
| | io_uring/zcrx.c | WARN_ON | 2 |
| | io_uring/zcrx.c | __io_zcrx_get_free_niov | 2 |
| | io_uring/zcrx.c | page_pool_ref_netmem | 1 |
| | io_uring/zcrx.c | net_mp_niov_set_page_pool | 1 |
| | io_uring/io_uring.c | array_index_nospec | 1 |
| | io_uring/io_uring.c | smp_store_release | 1 |
| | io_uring/zcrx.c | net_mp_netmem_place_in_cache | 2 |
| | io_uring/zcrx.c | nla_nest_start | 1 |
| | io_uring/io_uring.c | io_region_get_ptr | 1 |
| | io_uring/zcrx.c | release_sock | 1 |
| | io_uring/zcrx.c | io_zcrx_ifq_alloc | 1 |
| | io_uring/alloc_cache.h | kfree | 2 |
| | io_uring/zcrx.c | dma_unmap_page_attrs | 2 |
| | io_uring/zcrx.c | io_zcrx_alloc_fallback | 1 |
| | io_uring/zcrx.c | io_zcrx_sync_for_device | 2 |
| | io_uring/zcrx.c | atomic_xchg | 1 |
| | io_uring/zcrx.c | spin_lock_bh | 4 |
| | io_uring/zcrx.c | io_zcrx_scrub | 1 |
| | io_uring/io-wq.c | atomic_dec | 1 |
| | io_uring/eventfd.c | PTR_ERR | 1 |
| | io_uring/zcrx.c | skb_walk_frags | 1 |
| | io_uring/zcrx.c | page_pool_fragment_netmem | 1 |
| | io_uring/zcrx.c | page_pool_get_dma_addr_netmem | 2 |
| | io_uring/zcrx.c | io_zcrx_return_niov_freelist | 2 |
| | io_uring/io-wq.c | atomic_read | 2 |
| | io_uring/io_uring.c | memcpy | 1 |
| | io_uring/zcrx.c | io_zcrx_create_area | 1 |
| | io_uring/zcrx.c | __dma_sync_single_for_device | 1 |
| | io_uring/zcrx.c | page_pool_put_unrefed_netmem | 1 |
| | io_uring/zcrx.c | io_zcrx_rqring_entries | 1 |
| | io_uring/zcrx.c | __io_zcrx_unmap_area | 2 |
| | io_uring/cancel.c | lockdep_assert_held | 3 |
| | io_uring/cancel.c | spin_lock | 2 |
| | io_uring/cancel.c | copy_from_user | 3 |
| | io_uring/zcrx.c | net_mp_niov_clear_page_pool | 1 |
| | io_uring/zcrx.c | io_zcrx_map_area | 1 |
| | io_uring/zcrx.c | netmem_is_net_iov | 1 |
| | io_uring/epoll.c | u64_to_user_ptr | 5 |
| | io_uring/zcrx.c | dma_map_page_attrs | 1 |
| | io_uring/eventfd.c | IS_ERR | 1 |
| | io_uring/io_uring.c | percpu_ref_put | 1 |
| | io_uring/zcrx.c | dma_mapping_error | 1 |
| | io_uring/zcrx.c | netdev_get_by_index | 1 |
| | io_uring/io_uring.c | spin_lock_init | 3 |
| | io_uring/zcrx.c | net_iov_to_netmem | 8 |
| | io_uring/io_uring.c | capable | 1 |
| | io_uring/zcrx.c | nla_nest_end | 1 |
| | io_uring/io-wq.c | likely | 1 |
| | io_uring/zcrx.c | skb_frag_page | 1 |
| | io_uring/zcrx.c | io_get_user_counter | 4 |
| | io_uring/zcrx.c | io_free_rbuf_ring | 1 |
| | io_uring/zcrx.c | io_zcrx_put_niov_uref | 1 |
| | io_uring/zcrx.c | netdev_put | 2 |
| | io_uring/cancel.c | container_of | 1 |
| | io_uring/zcrx.c | skb_headlen | 4 |
| | io_uring/zcrx.c | io_zcrx_recv_frag | 1 |
| | io_uring/zcrx.c | io_zcrx_iov_page | 1 |
| | io_uring/zcrx.c | tcp_read_sock | 1 |
| | io_uring/zcrx.c | sock_flag | 2 |
| | io_uring/zcrx.c | dma_dev_need_sync | 1 |
| | io_uring/io_uring.c | io_free_region | 1 |
| | io_uring/zcrx.c | io_zcrx_unmap_area | 1 |
| | io_uring/zcrx.c | net_mp_niov_set_dma_addr | 2 |
| | io_uring/zcrx.c | io_zcrx_get_niov_uref | 2 |
| | io_uring/zcrx.c | get_device | 1 |
| | io_uring/zcrx.c | lock_sock | 1 |
| | io_uring/zcrx.c | io_zcrx_copy_frag | 1 |
| | io_uring/zcrx.c | sock_rps_record_flow | 1 |
| | io_uring/alloc_cache.c | kvmalloc_array | 3 |
| | io_uring/rsrc.c | io_buffer_validate | 1 |
| | io_uring/zcrx.c | io_zcrx_copy_chunk | 2 |
| | io_uring/io_uring.c | copy_to_user | 3 |
| | io_uring/zcrx.c | io_zcrx_drop_netdev | 2 |
| | io_uring/memmap.c | unpin_user_pages | 1 |
| | io_uring/io-wq.c | kzalloc | 2 |
| | io_uring/zcrx.c | io_zcrx_tcp_recvmsg | 1 |
| | io_uring/io-wq.c | atomic_inc | 1 |
| | io_uring/memmap.c | io_pin_pages | 1 |
| | io_uring/alloc_cache.c | kvfree | 4 |
| | io_uring/zcrx.c | skb_frag_off | 2 |
| | io_uring/zcrx.c | io_zcrx_iov_to_area | 4 |
| | io_uring/io_uring.h | smp_load_acquire | 1 |
| | io_uring/advise.c | READ_ONCE | 1 |
| | io_uring/zcrx.c | skb_frag_is_net_iov | 1 |
| | io_uring/zcrx.c | io_defer_get_uncommited_cqe | 1 |
| | io_uring/io_uring.c | min_t | 4 |
| | io_uring/net.c | skb_shinfo | 2 |
| | io_uring/io_uring.c | percpu_ref_get | 1 |
| | io_uring/zcrx.c | net_mp_close_rxq | 1 |
| | io_uring/zcrx.c | skb_frag_size | 1 |
| | io_uring/fdinfo.c | min | 1 |
| | io_uring/zcrx.c | kunmap_local | 2 |
| | io_uring/cancel.c | unlikely | 10 |
| | io_uring/io_uring.c | roundup_pow_of_two | 1 |

----------------------

Continue with the list untill all functions used in each source are listed.

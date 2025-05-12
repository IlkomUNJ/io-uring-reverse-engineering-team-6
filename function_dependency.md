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
| poll.c | io_uring/cancel.c | lockdep_assert_held | 2 |


----------------------

Continue with the list untill all functions used in each source are listed.

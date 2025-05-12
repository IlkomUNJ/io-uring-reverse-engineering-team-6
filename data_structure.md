# Task 3: Data Structure Investigation
The objective of this task is to document all internal data structures defined in io_uring. 

Structure name | Defined in | Attributes | Caller Functions Source | source caller | usage
---------------|------------|------------|-------------------------|---------------|-------------------
io_ev_fd       | io_uring/eventfd.c | eventfd_ctx, uint, uint, refcount_t, atomic_t, rcu_head | io_eventfd_free | io_uring/eventfd.c | local variable
| | | | io_eventfd_put | io_uring/eventfd.c | function parameter
| | | | io_eventfd_do_signal | io_uring/eventfd.c | local variable, function parameter
| | | | __io_eventfd_signal | io_uring/eventfd.c | function parameter
| | | | io_eventfd_grab | io_uring/eventfd.c | return value, local variable
| | | | io_eventfd_signal | io_uring/eventfd.c | local variable 
| | | | io_eventfd_flush_signal | io_uring/eventfd.c | local variable
| | | | io_eventfd_register | io_uring/eventfd.c | local variable
| | | | io_eventfd_unregister | io_uring/eventfd.c | function parameter
| io_fadvise | io_uring/advise.c | struct file			*file, u64				offset, u64				len, u32				advice | io_fadvise_force_async | io_uring/advise.c | function parameter |
| io_fadvise | io_uring/advise.c | struct file			*file, u64				offset, u64				len, u32				advice | io_fadvise_prep | io_uring/advise.c | local variable |
| io_fadvise | io_uring/advise.c | struct file			*file, u64				offset, u64				len, u32				advice | io_fadvise | io_uring/advise.c | return value |
| io_madvise | io_uring/advise.c | struct file			*file, u64				addr, u64				len, u32				advice | io_madvise_prep | io_uring/advise.c | local variable |
| io_madvise | io_uring/advise.c | struct file			*file, u64				addr, u64				len, u32				advice | io_madvise | io_uring/advise.c | return value |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_cancel_req_match | io_uring/cancel.c | function parameter |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_cancel_cb | io_uring/cancel.c | local variable |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_cancel_req_match | io_uring/cancel.c | unknown |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_cancel_req_match | io_uring/cancel.c | unknown |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_async_cancel_prep | io_uring/cancel.c | local variable |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | if | io_uring/cancel.c | unknown |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_async_cancel | io_uring/cancel.c | local variable |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_async_cancel | io_uring/cancel.c | local variable |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | req_set_fail | io_uring/cancel.c | unknown |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_sync_cancel | io_uring/cancel.c | local variable |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | if | io_uring/cancel.c | unknown |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | if | io_uring/futex.c | unknown |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_poll_cancel_req | io_uring/poll.c | unknown |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | if | io_uring/poll.c | unknown |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | __io_poll_cancel | io_uring/poll.c | function parameter |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_poll_cancel_req | io_uring/poll.c | unknown |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_poll_remove | io_uring/poll.c | local variable |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | req_set_fail | io_uring/timeout.c | unknown |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_timeout_cancel | io_uring/timeout.c | function parameter |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | if | io_uring/timeout.c | local variable |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | if | io_uring/timeout.c | local variable |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | io_timeout_remove | io_uring/timeout.c | local variable |
| io_cancel | io_uring/cancel.c | struct file			*file, u64				addr, u32				flags, s32				fd, u8				opcode | __io_waitid_cancel | io_uring/waitid.c | unknown |

If the following row value in a column is missing, assume the value is the same with the previous row in the same column. 
Continue until all data structures documented properly.

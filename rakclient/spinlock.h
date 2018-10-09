#ifndef _UDT_SPINLOCK_H_
#define _UDT_SPINLOCK_H_

#define PAUSE() asm("pause\n")
#define ATOMIC_LOAD(x) __atomic_load_n((x), __ATOMIC_SEQ_CST)

struct HALSpinLock{
	char atomic_;
};
inline void init_sp_lock(struct HALSpinLock* spl)
{
	spl->atomic_ = 0;
}

inline int sp_try_lock(struct HALSpinLock* spl)
{
	return __sync_lock_test_and_set(&spl->atomic_,1) == 0;
}

inline void sp_lock(struct HALSpinLock* spl)
{
	while (__sync_lock_test_and_set(&spl->atomic_,1)) {PAUSE();}
}

inline void sp_unlock(struct HALSpinLock* spl)
{
	__sync_lock_release(&spl->atomic_);
}

#endif
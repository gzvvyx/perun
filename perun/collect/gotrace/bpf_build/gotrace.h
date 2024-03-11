#ifndef __UPROBE_H__
#define __UPROBE_H__

struct basic_info {
    int func;
    bool type; // 0 entry, 1 leave
	int pid;
	int tgid;
    int64_t goid;
    uint64_t ts;
};

struct stack {
    uint64_t lo;
    uint64_t hi;
};

struct gobuf {
    uint64_t sp;
    uint64_t pc;
    uint64_t g;
    uint64_t ctxt;
    uint64_t ret;
    uint64_t lr;
    uint64_t bp;
};

struct g {
    struct stack stack;
    uint64_t stackguard0;
    uint64_t stackguard1;

    uint64_t _panic;
    uint64_t _defer;
    uint64_t m;
    struct gobuf sched;
    uint64_t syscallsp;
    uint64_t syscallpc;
    uint64_t stktopsp;
    uint64_t param;
    uint32_t atomicstatus;
    uint32_t stackLock;
    int64_t goid;
};


#endif // __UPROBE_H__
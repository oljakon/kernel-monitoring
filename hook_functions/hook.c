#define pr_fmt(fmt) "hook: " fmt

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

MODULE_DESCRIPTION("Coursework module");
MODULE_AUTHOR("Kondrashova Olga");
MODULE_LICENSE("GPL");

#define USE_FENTRY_OFFSET 0

/* struct ftrace_hook описывает перехватываемую функцию
name - имя перехватываемой функции
function - адрес функции-обертки, вызываемой вместо перехваченной функции
original - указатель на мест, куда будет записан адрес перехватываемой функции
address - адрес перехватываемой функции
*/
struct ftrace_hook {
	const char *name;
	void *function;
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

/* адрес перехватываемой функции */
static int resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = kallsyms_lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

#if USE_FENTRY_OFFSET
	*((unsigned long*) hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	*((unsigned long*) hook->original) = hook->address;
#endif

	return 0;
}

/* выполнение перехвата функций */
static void notrace ftrace_thunk(unsigned long ip, unsigned long parent_ip,
		struct ftrace_ops *ops, struct pt_regs *regs)
{
    /* получаем адрес struct ftrace_hook по адресу внедренной в неё struct ftrace_ops */
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

#if USE_FENTRY_OFFSET
	regs->ip = (unsigned long) hook->function;
#else
    /* пропускаем вызовы функции из текущего модуля */
	if (!within_module(parent_ip, THIS_MODULE))
		regs->ip = (unsigned long) hook->function;
#endif
}

/* инициализация структуры ftrace_ops */
int install_hook(struct ftrace_hook *hook)
{
	int err;

	err = resolve_hook_address(hook);
	if (err)
		return err;

	hook->ops.func = ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	                | FTRACE_OPS_FL_RECURSION_SAFE
	                | FTRACE_OPS_FL_IPMODIFY;

    /* включить ftrace для функции */
	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

    /* разрешить ftrace вызывать коллбек */
	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
		return err;
	}

	return 0;
}

/* выключить перехват */
void remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_debug("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
	}
}

/**
 * install_hooks() - register and enable multiple hooks
 * @hooks: array of hooks to install
 * @count: number of hooks to install
 *
 * If some hooks fail to install then all hooks will be removed.
 *
 * Returns: zero on success, negative error code otherwise.
 */
int install_hooks(struct ftrace_hook *hooks, size_t count)
{
	int err;
	size_t i;

	for (i = 0; i < count; i++) {
		err = install_hook(&hooks[i]);
		if (err)
			goto error;
	}

	return 0;

error:
	while (i != 0) {
		remove_hook(&hooks[--i]);
	}

	return err;
}

/**
 * remove_hooks() - disable and unregister multiple hooks
 * @hooks: array of hooks to remove
 * @count: number of hooks to remove
 */
void remove_hooks(struct ftrace_hook *hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		remove_hook(&hooks[i]);
}

#ifndef CONFIG_X86_64
#error Currently only x86_64 architecture is supported
#endif

#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/*
 * Tail call optimization can interfere with recursion detection based on
 * return address on the stack. Disable it to avoid machine hangups.
 */
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_clone)(struct pt_regs *regs);

static asmlinkage long fh_sys_clone(struct pt_regs *regs)
{
	long ret;

	pr_info("clone() before\n");

	ret = real_sys_clone(regs);

	pr_info("clone() after: %ld\n", ret);

	return ret;
}
#else
static asmlinkage long (*real_sys_clone)(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls);

static asmlinkage long fh_sys_clone(unsigned long clone_flags,
		unsigned long newsp, int __user *parent_tidptr,
		int __user *child_tidptr, unsigned long tls)
{
	long ret;

	pr_info("clone() before\n");

	ret = real_sys_clone(clone_flags, newsp, parent_tidptr,
		child_tidptr, tls);

	pr_info("clone() after: %ld\n", ret);

	return ret;
}
#endif

static char *duplicate_filename(const char __user *filename)
{
	char *kernel_filename;

	kernel_filename = kmalloc(4096, GFP_KERNEL);
	if (!kernel_filename)
		return NULL;

	if (strncpy_from_user(kernel_filename, filename, 4096) < 0) {
		kfree(kernel_filename);
		return NULL;
	}

	return kernel_filename;
}

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*real_sys_execve)(struct pt_regs *regs);

static asmlinkage long fh_sys_execve(struct pt_regs *regs)
{
	long ret;
	char *kernel_filename;

	kernel_filename = duplicate_filename((void*) regs->di);

	pr_info("execve() before: %s\n", kernel_filename);

	kfree(kernel_filename);

	ret = real_sys_execve(regs);

	pr_info("execve() after: %ld\n", ret);

	return ret;
}
#else
/* Указатель на оригинальный обработчки системного вызова execve
Можно вызывать из обертки
*/
static asmlinkage long (*real_sys_execve)(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

/* Функция, которая будет вызываться вместо перехваченной
 Возвращаемое значение будет передано вызывающей функции
*/
static asmlinkage long fh_sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp)
{
	long ret;
	char *kernel_filename;

	kernel_filename = duplicate_filename(filename);

	pr_info("execve() before: %s\n", kernel_filename);

	kfree(kernel_filename);

	ret = real_sys_execve(filename, argv, envp);

	pr_info("execve() after: %ld\n", ret);

	return ret;
}
#endif

/*
 * x86_64 kernels have a special naming convention for syscall entry points in newer kernels.
 * That's what you end up with if an architecture has 3 (three) ABIs for system calls.
 */
#ifdef PTREGS_SYSCALL_STUBS
#define SYSCALL_NAME(name) ("__x64_" name)
#else
#define SYSCALL_NAME(name) (name)
#endif

#define HOOK(_name, _function, _original)    \
    {                    \
        .name = SYSCALL_NAME(_name),    \
        .function = (_function),    \
        .original = (_original),    \
    }

/* массив перехватываемых функций */
static struct ftrace_hook demo_hooks[] = {
    HOOK("sys_clone",  fh_sys_clone,  &real_sys_clone),
    HOOK("sys_execve", fh_sys_execve, &real_sys_execve),
};


static int hook_module_init(void)
{
	int err;

	err = install_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	if (err)
		return err;

	pr_info("module loaded\n");

	return 0;
}

static void hook_module_exit(void)
{
	remove_hooks(demo_hooks, ARRAY_SIZE(demo_hooks));
	pr_info("module unloaded\n");
}

module_init(hook_module_init);
module_exit(hook_module_exit);

#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x56e230cf, __VMLINUX_SYMBOL_STR(module_layout) },
	{ 0x6c2e3320, __VMLINUX_SYMBOL_STR(strncmp) },
	{ 0xd0d8621b, __VMLINUX_SYMBOL_STR(strlen) },
	{ 0xdb7305a1, __VMLINUX_SYMBOL_STR(__stack_chk_fail) },
	{ 0xa9b7604f, __VMLINUX_SYMBOL_STR(filp_close) },
	{ 0xaf2aff69, __VMLINUX_SYMBOL_STR(vfs_read) },
	{ 0xe0ace46a, __VMLINUX_SYMBOL_STR(filp_open) },
	{ 0x6b7fd372, __VMLINUX_SYMBOL_STR(call_usermodehelper_exec) },
	{ 0x125c36e8, __VMLINUX_SYMBOL_STR(call_usermodehelper_setup) },
	{ 0x50eedeb8, __VMLINUX_SYMBOL_STR(printk) },
	{ 0xa2157926, __VMLINUX_SYMBOL_STR(current_task) },
	{ 0x8ff4079b, __VMLINUX_SYMBOL_STR(pv_irq_ops) },
	{ 0xb4390f9a, __VMLINUX_SYMBOL_STR(mcount) },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "25268B5C1A471F34B6CF9D7");

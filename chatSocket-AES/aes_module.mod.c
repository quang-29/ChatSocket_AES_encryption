#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/export-internal.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

#ifdef CONFIG_UNWINDER_ORC
#include <asm/orc_header.h>
ORC_HEADER;
#endif

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif



static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xb88db70c, "kmalloc_caches" },
	{ 0x4454730e, "kmalloc_trace" },
	{ 0xe3ec2f2b, "alloc_chrdev_region" },
	{ 0x1399bb1, "class_create" },
	{ 0xd3044a78, "device_create" },
	{ 0x3df63fc3, "cdev_alloc" },
	{ 0xa6f7a612, "cdev_init" },
	{ 0xf4407d6b, "cdev_add" },
	{ 0x37a0cba, "kfree" },
	{ 0x92ce99, "class_destroy" },
	{ 0x6091b333, "unregister_chrdev_region" },
	{ 0x88db9f48, "__check_object_size" },
	{ 0x13c49cc2, "_copy_from_user" },
	{ 0xbcab6ee6, "sscanf" },
	{ 0x8c8569cb, "kstrtoint" },
	{ 0xf7be671b, "device_destroy" },
	{ 0x8f44466e, "cdev_del" },
	{ 0x754d539c, "strlen" },
	{ 0xfb578fc5, "memset" },
	{ 0x3c3ff9fd, "sprintf" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x7420ff38, "crypto_alloc_base" },
	{ 0x39dff2fe, "crypto_cipher_setkey" },
	{ 0x45800008, "crypto_cipher_encrypt_one" },
	{ 0x7e880505, "crypto_destroy_tfm" },
	{ 0x39764e9f, "crypto_cipher_decrypt_one" },
	{ 0xa916b694, "strnlen" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0x656e4a6e, "snprintf" },
	{ 0xe914e41e, "strcpy" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x8f9724a5, "crypto_alloc_shash" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x7eca907c, "crypto_shash_digest" },
	{ 0x6b10bee1, "_copy_to_user" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x122c3a7e, "_printk" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x2fa5cadd, "module_layout" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "37B22985B9557B8EA6675EB");

#include <linux/module.h>  /* kernel module */
#include <linux/kernel.h>  /* (KERN_WARNING, KERN_EMERG, KERN_INFO,...) */
#include <linux/init.h>    /*  __init va __exit. */
#include <linux/unistd.h>  /* sys_call_table __NR_ */
#include <linux/fs.h>      /* filp_open */
#include <linux/slab.h>    /* kmalloc */

#include <asm/paravirt.h> /* write_cr0 */
#include <asm/uaccess.h>  /* get_fs, set_fs */

#include "hook-write.h"

#define PROC_V    "/proc/version" /*vi tri thong tin file kernel dang chay */
#define BOOT_PATH "/boot/System.map-" /* dia chi system call table*/
#define MAX_VERSION_LEN   256 

unsigned long *syscall_table = NULL;
asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);

static int find_sys_call_table (char *kern_ver) {
    char system_map_entry[MAX_VERSION_LEN];
    int i = 0;
    char *filename;
    size_t filename_length = strlen(kern_ver) + strlen(BOOT_PATH) + 1;
    struct file *f = NULL;
 
    mm_segment_t oldfs;
 
    oldfs = get_fs();
    set_fs (KERNEL_DS);

    printk(KERN_EMERG "Kernel version: %s\n", kern_ver);
     
    filename = kmalloc(filename_length, GFP_KERNEL);
    if (filename == NULL) {
        printk(KERN_EMERG "kmalloc failed on System.map-<version> filename allocation");
        return -1;
    }
    memset(filename, 0, filename_length);
    strncpy(filename, BOOT_PATH, strlen(BOOT_PATH));
    strncat(filename, kern_ver, strlen(kern_ver));
    f = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(f) || (f == NULL)) {
        printk(KERN_EMERG "Error opening System.map-<version> file: %s\n", filename);
        return -1;
    }
 
    memset(system_map_entry, 0, MAX_VERSION_LEN);
    while (vfs_read(f, system_map_entry + i, 1, &f->f_pos) == 1) {
        if ( system_map_entry[i] == '\n' || i == MAX_VERSION_LEN ) {
            i = 0;
             
            if (strstr(system_map_entry, "sys_call_table") != NULL) {
                char *sys_string;
                char *system_map_entry_ptr = system_map_entry;
                 
                sys_string = kmalloc(MAX_VERSION_LEN, GFP_KERNEL);  
                if (sys_string == NULL) { 
                    filp_close(f, 0);
                    set_fs(oldfs);

                    kfree(filename);
     
                    return -1;
                }
 
                memset(sys_string, 0, MAX_VERSION_LEN);

                strncpy(sys_string, strsep(&system_map_entry_ptr, " "), MAX_VERSION_LEN);
                kstrtoul(sys_string, 16, &syscall_table);
                printk(KERN_EMERG "syscall_table retrieved\n");
                 
                kfree(sys_string);
                 
                break;
            }
             
            memset(system_map_entry, 0, MAX_VERSION_LEN);
            continue;
        }
         
        i++;
    }
 
    filp_close(f, 0);
    set_fs(oldfs);
     
    kfree(filename);
 
    return 0;
}

/* doc so version tu PROC_V va lay ra chuoi so do <=> $(uname -r)*/ 
char *acquire_kernel_version (char *buf) {
    struct file *proc_version;
    char *kernel_version;
    mm_segment_t oldfs;
    oldfs = get_fs();
    set_fs (KERNEL_DS);
    proc_version = filp_open(PROC_V, O_RDONLY, 0);
    if (IS_ERR(proc_version) || (proc_version == NULL)) {
        return NULL;
    }
    memset(buf, 0, MAX_VERSION_LEN);
    vfs_read(proc_version, buf, MAX_VERSION_LEN, &(proc_version->f_pos));
    kernel_version = strsep(&buf, " ");
    kernel_version = strsep(&buf, " ");
    kernel_version = strsep(&buf, " ");
  
    filp_close(proc_version, 0);

    set_fs(oldfs);
    return kernel_version;
}

ssize_t new_write (unsigned int x, const char __user *y, size_t size) {
   
  //printk(KERN_INFO "Ten Tien Trinh:%s\n",current->comm);
  //char tenFile[255];
  //fd_to_pathname(x,tenFile);
 // printk(KERN_INFO "ten file ghi:%s\n",tenFile);
  int written_bytes= original_write(x,y,size);
   printk(KERN_INFO "so byte co the ghi:%d\n",written_bytes);
    return original_write(x,y,size);
}

static int __init input(void) {
    char *kernel_version = kmalloc(MAX_VERSION_LEN, GFP_KERNEL);
     
    find_sys_call_table(acquire_kernel_version(kernel_version));
  
 
    if (syscall_table != NULL) {
        write_cr0 (read_cr0 () & (~ 0x10000));
        original_write = (void *)syscall_table[__NR_write];
        syscall_table[__NR_write] = &new_write;
        write_cr0 (read_cr0 () | 0x10000);
       
    } else {
        printk(KERN_EMERG "[-] input: syscall_table is NULL\n");
    }
  
    kfree(kernel_version);
  
    return 0;
}

static void __exit output(void) {
    if (syscall_table != NULL) {
        write_cr0 (read_cr0 () & (~ 0x10000));
        syscall_table[__NR_write] = original_write;
        write_cr0 (read_cr0 () | 0x10000);
    } else {
        printk(KERN_EMERG "[-] output: syscall_table is NULL\n");
    }
}

module_init(input);
module_exit(output);


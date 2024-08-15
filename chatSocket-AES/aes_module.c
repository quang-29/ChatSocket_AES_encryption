#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/ctype.h>
#include <crypto/internal/cipher.h>
#include <crypto/algapi.h>
#include <crypto/internal/skcipher.h>
#include <crypto/hash.h>
#include <linux/mm.h>
#include <linux/string.h>

#define DRIVER_AUTHOR "minhquang"
#define MEM_SIZE 1024
#define AES_BLOCK_SIZE 16
#define MD5_LEN 16
#define SHA1_LEN 20
#define SHA2_LEN 32

char key[16] = "12345678";
char opt[1], value[128];
int mode;
dev_t dev_number = 0;
static struct class *device_class;
static struct cdev *cdev;
uint8_t *kernel_buffer;
char modeHash[4], modeCipher[4];

static int driver_open(struct inode *inode, struct file *flip);
static int driver_release(struct inode *inode, struct file *filp);
static ssize_t driver_read(struct file *filp, char __user *user_buf, size_t len, loff_t *off);
static ssize_t driver_write(struct file *filp, const char __user *user_buf, size_t len, loff_t *off);

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .read = driver_read,
    .write = driver_write,
    .open = driver_open,
    .release = driver_release,
};

static int driver_open(struct inode *inode, struct file *flip) {
    printk("Open\n");
    return 0;
}

static int driver_release(struct inode *inode, struct file *filp) {
    printk("Release\n");
    return 0;
}

void toHexString(char input[MEM_SIZE], int len, char output[MEM_SIZE]) {
    int i;
    memset(output, 0, strlen(output));
    for (i = 0; i < len; i++) 
    {
        sprintf(output, "%s%02hhx", output, input[i]);
    }
}

int hexToUnicode(char *in, int len, char *out) {
    int i;
    int converter[105];
    converter['0'] = 0;
    converter['1'] = 1;
    converter['2'] = 2;
    converter['3'] = 3;
    converter['4'] = 4;
    converter['5'] = 5;
    converter['6'] = 6;
    converter['7'] = 7;
    converter['8'] = 8;
    converter['9'] = 9;
    converter['a'] = 10;
    converter['b'] = 11;
    converter['c'] = 12;
    converter['d'] = 13;
    converter['e'] = 14;
    converter['f'] = 15;

    for (i = 0; i < len; i = i + 2) {
        char byte = converter[(int)in[i]] << 4 | converter[(int)in[i + 1]];
        out[i / 2] = byte;
    }

    return 0;
}

void doAESCipherEN(char inpuData[MEM_SIZE], char outputData[MEM_SIZE]) 
{
    struct crypto_cipher *tfm;
    int numOfCipher, lenOutput, i, j = 0;
    int lenData = strlen(inpuData);
    char temp[MEM_SIZE];
    numOfCipher = lenData / 16;
    numOfCipher += (lenData % 16 == 0) ? 0 : 1;

    tfm = crypto_alloc_cipher("aes", 0, 0);
    crypto_cipher_setkey(tfm, key, 16);

    for (i = 0; i < numOfCipher; i++) {
        crypto_cipher_encrypt_one(tfm, &temp[j], &inpuData[j]);
        j += 16;
    }
    lenOutput = (lenData % 16 == 0) ? lenData : (lenData + (16 - (lenData % 16)));
    temp[lenOutput] = '\0';
    toHexString(temp, lenOutput, outputData);
    crypto_free_cipher(tfm);
}

void doAESCipherDE(char inpuData[MEM_SIZE], char outputData[MEM_SIZE]) {
    struct crypto_cipher *tfm;
    int numOfCipher, i, j = 0;
    int lenData = strlen(inpuData);
    char temp[MEM_SIZE];
    numOfCipher = (lenData / 16 < 1) ? 1 : (lenData / 16);

    tfm = crypto_alloc_cipher("aes", 0, 0);
    crypto_cipher_setkey(tfm, key, 16);

    for (i = 0; i < numOfCipher; i++) {
        crypto_cipher_decrypt_one(tfm, &temp[j], &inpuData[j]);
        j += 16;
    }

    strcpy(outputData, temp);
    crypto_free_cipher(tfm);
}

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg) {
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
                     const unsigned char *data, unsigned int datalen,
                     unsigned char *digest) {
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("Can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

static int doHash(char *mode, const unsigned char *data, unsigned int datalen,
                  unsigned char *digest) {
    struct crypto_shash *alg;
    const char *hash_alg_name = mode;
    int ret;

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if (IS_ERR(alg)) {
        pr_info("Can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    ret = calc_hash(alg, data, datalen, digest);
    crypto_free_shash(alg);
    return ret;
}

void reAssignValue(int size, unsigned char *hashdata, char outData[MEM_SIZE]) {
    size_t i;
    memset(outData, 0, strlen(outData));
    for (i = 0; i < size; ++i) {
        snprintf(outData + strlen(outData), 3, "%02x", hashdata[i]);
    }
}

void hashPassword(char password[64], char outputData[MEM_SIZE]) {
    u8 md5[MD5_LEN];
    u8 sha1[SHA1_LEN];
    u8 sha2[SHA2_LEN];
    unsigned char *data;
    data = kmalloc(256, GFP_KERNEL);
    sprintf(data, "%s", password);
    if (strcmp(modeHash, "MD5") == 0) {
        doHash("md5", data, strlen(data), md5);
        reAssignValue(MD5_LEN, md5, outputData);
    }
}

void doCipherEncrypt(char message[MEM_SIZE], char outputData[MEM_SIZE]) {
    if (strcmp(modeCipher, "AES") == 0) {
        doAESCipherEN(message, outputData);
    }
}

void doCipherDecrypt(char message[MEM_SIZE], char outputData[MEM_SIZE]) {
    char temp[MEM_SIZE];
    if (strcmp(modeCipher, "AES") == 0) {
        doAESCipherDE(message, outputData);
    }
}

static ssize_t driver_read(struct file *filp, char __user *user_buf, size_t len, loff_t *off) {
    char buffer[MEM_SIZE];
    char username[64];
    char password[64];
    char message[MEM_SIZE];

    switch (mode) {
        case 0:
            memcpy(modeHash, &value[0], 3);
            memcpy(modeCipher, &value[3], 3);
            sprintf(buffer, "%s", "# Setup was successful");
            break;
        case 1:
            sscanf(value, "%s %s", username, password);
            hashPassword(password, buffer);
            break;
        case 2:
            doCipherEncrypt(value, buffer);
            break;
        case 3:
            hexToUnicode(value, strlen(value), message);
            doCipherDecrypt(message, buffer);
            break;
        default:
            break;
    }

    copy_to_user(user_buf, buffer, MEM_SIZE);
    printk("Driver Read Function\n");
    return 0;
}

static ssize_t driver_write(struct file *filp, const char __user *user_buf, size_t len, loff_t *off) {
    copy_from_user(kernel_buffer, user_buf, len);
    memset(opt,0,sizeof(opt));
    memset(value,0,sizeof(value));
    sscanf(kernel_buffer, "opt:%s\nvalue:%200[^\n]", opt, value);
    kstrtoint(opt,0,&mode);
    printk("%s", value);
    return 0;
}

int simple_driver_init(void) {
    int result = 0;
    int ret = 0;
    dev_number = 0;
    int major = 0;
    kernel_buffer = kmalloc(MEM_SIZE, GFP_KERNEL);

    if (alloc_chrdev_region(&dev_number, 0, 1, "simple_driver") < 0) {
        printk("Can't allocate device number\n");
        return -1;
    }
    printk("Alloc success\n");
    major = MAJOR(dev_number);
    device_class = class_create("simple_driver_class");

    if (device_class == NULL) {
        printk("Can't create class\n");
        goto ClassError;
    }
    if (device_create(device_class, NULL, dev_number, NULL, "simple_driver") == NULL) {
        printk("Can't create device file\n");
        goto FileError;
    }
    printk("Create success\n");
    cdev = cdev_alloc();
    if (cdev == NULL) {
        printk("Cdev alloc failed\n");
        goto FileError;
    }
    cdev_init(cdev, &fops);
    ret = cdev_add(cdev, dev_number, 1);
    if (ret < 0) {
        printk("Cdev add fail\n");
        goto AddError;
    }

    printk("Init success with major: %d\n", major);
    return result;

AddError:
    kfree(cdev);
FileError:
    class_destroy(device_class);
ClassError:
    unregister_chrdev_region(dev_number, 1);
    return -1;
}

void simple_driver_exit(void) {
    device_destroy(device_class, dev_number);
    class_destroy(device_class);
    unregister_chrdev_region(dev_number, 1);
    cdev_del(cdev);
    kfree(kernel_buffer);
    printk("Exit success\n");
}

module_init(simple_driver_init);
module_exit(simple_driver_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION("AES Encryption and Decryption");
MODULE_IMPORT_NS(CRYPTO_INTERNAL);


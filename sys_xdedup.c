#include <linux/linkage.h>
#include <linux/moduleloader.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <asm/page.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include "xdedup.h"


asmlinkage extern long (*sysptr)(void *arg);

/**
 * @brief Printk if flag is set
 * 
 * @param filename File where the print is being done
 * @param line Line on which print is called
 * @param message message to print
 * @param flag
 */
static void debug_print(char * filename, int line, char * message, bool flag){
	if(flag){
		printk("In file %s: on line %d: %s\n", filename, line, message);
	}
}

/**
 * @brief decide whether we need to compare file content or not
 * @details Checks all the parameters to determine whether the files may be identical or not 
 * 			Checks for equal file size, permission and same owner
 * 
 * @param inode1 Inode of input file 1
 * @param inode2 Inode of input file 2
 * 
 * @return bool value
 */
static int fileParamEqual(struct inode* inode1, struct inode* inode2, int flag){
	if(!(flag & P_FLAG_RETRIEVE) && !(flag & N_FLAG_RETRIEVE) && !uid_eq(inode1->i_uid, inode2->i_uid)){
		return -EPERM;
	}

	if(!(flag & P_FLAG_RETRIEVE) && inode1->i_size != inode2->i_size){
		return -EINVAL;
	}

	if(!(flag & P_FLAG_RETRIEVE) && !(flag & N_FLAG_RETRIEVE) && inode1->i_mode != inode2->i_mode){
		return -EPERM;		
	}

	return 0;
}


static bool sameFileCheck(struct file* file1, struct file* file2){
	struct inode* inode1 = file1->f_path.dentry->d_inode;
	struct inode* inode2 = file2->f_path.dentry->d_inode;
	if(inode1->i_ino == inode2->i_ino && inode1->i_sb->s_uuid == inode2->i_sb->s_uuid){
		return true;
	}
	return false;
}

/**
 * @brief Validate the existence of correct arguments sent to kernel for the syscall
 * 			Do not check for invalid file paths, just checks the existence.
 * 
 * @param syscall_args Argument with which syscall was called.
 * @return error on failure or 0 on success
 */

static int checkValidArgs(struct syscall_args * xdedup_args){
	//char * flag_error = "give flag is invalid";
	char * output_file_not_required = "output file is not required";
	char * output_file_Required = "output file is required";
	char * input_file_null = "Input files are not given";
	bool debug = false;

	if(xdedup_args->flag >=8 || xdedup_args->flag < 0){
		//debug_print(__FILE__, __LINE__, flag_error, true);
		return -EINVAL;
	}

	debug =  ((xdedup_args->flag & D_FLAG_RETRIEVE) == 4);

	if( (xdedup_args->flag & P_FLAG_RETRIEVE) == 2 ){
		if((xdedup_args->flag & N_FLAG_RETRIEVE) == 1 && xdedup_args->output_file){
			debug_print(__FILE__, __LINE__, output_file_not_required, debug);
			return -EINVAL;			
		}

		if((xdedup_args->flag & N_FLAG_RETRIEVE) == 0 && !xdedup_args->output_file){
			debug_print(__FILE__, __LINE__, output_file_Required, debug);
			return -EINVAL;
		}
	}

	

	if( (xdedup_args->flag & P_FLAG_RETRIEVE) == 0 && xdedup_args->output_file){
		debug_print(__FILE__, __LINE__, output_file_not_required, debug);
		return -EINVAL;
	}

	if(!xdedup_args->input_file_1 || !xdedup_args->input_file_2){
		debug_print(__FILE__, __LINE__, input_file_null, debug);
		return -EINVAL;
	}

	return 0;
}

static struct file * open_file_check(char * file_path, int flag, size_t *err, umode_t mode){


	mm_segment_t oldfs;
	struct file * result_file_pointer = NULL;


	oldfs = get_fs();
    set_fs(get_ds());
	result_file_pointer = filp_open(file_path, flag, mode);
	set_fs(oldfs);
	*err = 0;
	if (!result_file_pointer || IS_ERR(result_file_pointer)) {
        *err = PTR_ERR(result_file_pointer);
    }

	return result_file_pointer;
}


static int read_from_file(struct file * input_file, char *buffer, unsigned int size, unsigned long long * offset) 
{
	int dedupSize;
    mm_segment_t oldfs;
    oldfs = get_fs();
    set_fs(get_ds());

    dedupSize = vfs_read(input_file, buffer, size, offset);

    set_fs(oldfs);
	return dedupSize;
}

static int write_to_file(struct file *output_file, unsigned char *data, unsigned int size, unsigned long long *offset) 
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(output_file, data, size, offset);

    set_fs(oldfs);
    return ret;
}

/**
 * @brief Compare 2 files and write to the ouput file
 * @details read data from both the input files. Compare data byte by byte.
 * 			write into ouput file if given. return the number of matching bytes.
 * 
 * @param file input file1_pointer
 * @param file input_file2_pointer
 * @param file output_file_pointer
 * @param flag flags
 * @return error or number of matching bytes
 */
static size_t read_compare_write(struct file * input_file1_pointer, struct file * input_file2_pointer, struct file *output_file_pointer, bool flag){

	int num_bits_file1, num_bits_file2, i, smmaller_size;

	unsigned long long offset_1, offset_2, output_offset;

	char * input1_buff, * input2_buff;
	bool same_file_flag = false;
	size_t written_bytes = 0;
	int error = 0;

	input1_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!input1_buff) {
		debug_print(__FILE__, __LINE__, "Couldn't allocate memory for reading file1", flag);
		error = -ENOMEM;
		goto ERR;
	}

	input2_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!input2_buff) {
		debug_print(__FILE__, __LINE__, "Couldn't allocate memory for reading file2", flag);
		error = -ENOMEM;
		goto ERR_BUFF2;
	}

	offset_2 = offset_1 = 0;
	output_offset = 0;

	same_file_flag = sameFileCheck(input_file1_pointer, input_file2_pointer);

	while(1){

		num_bits_file1 = read_from_file(input_file1_pointer, input1_buff, PAGE_SIZE, &offset_1);
		if(num_bits_file1 < 0){
			debug_print(__FILE__, __LINE__, "error in read for input file1", true);
			error = num_bits_file1;
			goto ERR_WRITE;
		}

		smmaller_size = num_bits_file1;

		if(!same_file_flag){
			num_bits_file2 = read_from_file(input_file2_pointer, input2_buff, PAGE_SIZE, &offset_2);
			if(num_bits_file2 < 0){
				debug_print(__FILE__, __LINE__, "error in read for input file2", true);
				error = num_bits_file2;
				goto ERR_WRITE;
			}

			if(num_bits_file1 == 0 || num_bits_file2 == 0){
				kfree(input1_buff);
				kfree(input2_buff);
				return written_bytes;	
			}

			smmaller_size = num_bits_file1 >= num_bits_file2 ? num_bits_file2 : num_bits_file1;
			
			for(i=0; i<smmaller_size; i++){
				if(input1_buff[i] != input2_buff[i]){
					debug_print(__FILE__, __LINE__, "input file content is not identical", flag);
					break;
				}
			}

			num_bits_file1 = i;

		}
		

		if(!output_file_pointer){

			written_bytes += num_bits_file1;

		}else{

			error = write_to_file(output_file_pointer, input1_buff, num_bits_file1, &output_offset);
			if(error<0){
				debug_print(__FILE__, __LINE__, "error in witing to the file", flag);
				goto ERR_WRITE;
			}
			written_bytes += error;

		}

		if(num_bits_file1 < smmaller_size || num_bits_file1 < PAGE_SIZE){
			kfree(input1_buff);
			kfree(input2_buff);
			debug_print(__FILE__, __LINE__, "everything in read and write went well", flag);
			return written_bytes;
		}
	}

	ERR_WRITE:
		kfree(input2_buff);
	ERR_BUFF2:
		kfree(input1_buff);
	ERR:
		debug_print(__FILE__, __LINE__, "error in reading or writing ", flag);
		return error;

}


static int unlink(struct inode * input_file2_dir_inode, struct dentry * input_file2_dentry){
	
	int unlink_err = 0;

	inode_lock_nested(input_file2_dir_inode, I_MUTEX_PARENT);
	unlink_err = vfs_unlink(input_file2_dir_inode, input_file2_dentry, NULL);
	inode_unlock(input_file2_dir_inode);

	return unlink_err;

}

static int link(struct file* input_file1_pointer, struct dentry* input_file1_dentry, char * newname){
	struct dentry *new_dentry;
	struct path new_path, old_path;
	int newdfd  = AT_FDCWD;
	int how = 0;
	//int error = 0;
	int retval = 0;
	mm_segment_t old_fs;

	old_path = input_file1_pointer->f_path;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	
	new_dentry =  user_path_create(newdfd, newname, &new_path, (how & LOOKUP_REVAL));

	retval = PTR_ERR(new_dentry);
	if (IS_ERR(new_dentry))
		goto out;

	if (old_path.mnt != new_path.mnt){
		goto out_dput;		
	}
		
	if(!inode_owner_or_capable(input_file1_dentry->d_inode)){
		retval = -EPERM;
		goto out_dput;
	}

	retval = vfs_link(input_file1_dentry, new_path.dentry->d_inode, new_dentry, NULL);
	
	out_dput:

		done_path_create(&new_path, new_dentry);
		set_fs(old_fs);
	
	out:
		path_put(&input_file1_pointer->f_path);

		return retval;

}

/**
 * @brief : Rename one file to another at kernel level
 * @details Takes dentry of temp_file and rename it to output file.
 * 			Locks the parent directories before locking.
 * 
 * @param temp_dentry Dentry of file to be renamed.
 * @param output_file_dentry Dentry of new output file
 * 
 * @return return error number on error or 0 on success.
 */

static int xdedup_rename(struct dentry* temp_dentry, struct dentry* output_file_dentry){
	struct dentry *trap = NULL;
	struct dentry * output_pardir_dentry = NULL;
	struct dentry * temp_pardir_dentry = NULL;

	int error = 0;
	int unlink_err = 0;

	temp_pardir_dentry = dget_parent(temp_dentry);
	output_pardir_dentry = dget_parent(output_file_dentry);

	trap = lock_rename(temp_pardir_dentry, output_pardir_dentry);
	if(trap == temp_dentry){
		error = -EINVAL;
		goto OUT;
	}

	if(trap == output_file_dentry){
		error = -EINVAL;
		goto OUT;
	}


	error = vfs_rename(d_inode(temp_pardir_dentry), temp_dentry,
						d_inode(output_pardir_dentry), output_file_dentry, NULL, 0);

	if(error){
		unlink_err = unlink(temp_pardir_dentry->d_inode, temp_dentry);
		if(unlink_err){
			error = unlink_err;
		}
	}

	OUT:
		unlock_rename(temp_pardir_dentry, output_pardir_dentry);
		return error;
}

static struct kstat stat_file(char * filename, int *err){

	struct kstat stats;
	
	mm_segment_t old_fs;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	*err = vfs_stat(filename, &stats);
	set_fs(old_fs);

	return stats;
}

static int stat_check(char * filename, bool flag){

	int stat_err;
	struct kstat stats;
	stats = stat_file(filename, &stat_err);
	if(stat_err){
		debug_print(__FILE__, __LINE__, "error in stat call", flag);
		goto STAT_ERR;
	}
	if(!S_ISREG(stats.mode)){
		stat_err = -EINVAL;
		debug_print(__FILE__, __LINE__, "file is not a regular file", flag);
	}

	STAT_ERR:
		return stat_err;
}



asmlinkage long xdedup(void *arg)
{
	char * temp_file_name;
	char * absoulte_file2_path, *temp_buff;

	struct syscall_args *xdedup_args;
	struct file * output_file_pointer = NULL;
	struct file * input_file1_pointer = NULL;
	struct file * input_file2_pointer = NULL;
	struct file * temp_output_file_pointer = NULL;
	struct inode * input_file1_inode = NULL;
	struct inode * input_file2_inode = NULL;
	struct inode * input_file1_dir_inode = NULL;
	struct inode * input_file2_dir_inode = NULL;


	struct dentry * input_file1_dentry = NULL;
	struct dentry * input_file2_dentry = NULL;
	struct dentry * temp_dentry  = NULL;
	struct dentry * output_file_dentry = NULL;
	//struct dentry * temp_hard_link_dentry = NULL;

	bool partial_dedup_flag = false;
	bool debug_flag = false;
	bool n_flag = false;

	int temp_rename_err, unlink_err;
	int vfs_unlink_ret, vfs_link_ret;

	bool outfile_created = false;

	size_t retVal;

	retVal = 0; 

	vfs_unlink_ret = vfs_link_ret = temp_rename_err = 0;

	if (arg == NULL){
		retVal = -EINVAL;
		goto NO_FILE_OPEN;
	}

	xdedup_args = kmalloc(sizeof(struct syscall_args), GFP_KERNEL);
	if(!xdedup_args){
		retVal = -ENOMEM;
		goto NO_FILE_OPEN;
	}

	retVal = copy_from_user(xdedup_args, arg, sizeof(struct syscall_args));
	if(retVal){
		retVal = -EFAULT;
		goto FREE_ARGS;
	}

	retVal = checkValidArgs(xdedup_args);
	if(retVal != 0){
		goto FREE_ARGS;
	}

	partial_dedup_flag = ((xdedup_args->flag & P_FLAG_RETRIEVE) == 2);
	debug_flag = ((xdedup_args->flag & D_FLAG_RETRIEVE) == 4);
	n_flag = ((xdedup_args->flag & N_FLAG_RETRIEVE) == 1);

	debug_print(__FILE__, __LINE__, "arguments are valid", debug_flag);


	retVal = stat_check(xdedup_args->input_file_1, debug_flag);
	if(retVal){
		debug_print(__FILE__, __LINE__, "file 1 not valid", debug_flag);
		goto FREE_ARGS;
	}

	retVal = stat_check(xdedup_args->input_file_2, debug_flag);
	if(retVal){
		debug_print(__FILE__, __LINE__, "file 2 not valid", debug_flag);
		goto FREE_ARGS;
	}
	
	input_file1_pointer = open_file_check(xdedup_args->input_file_1, O_RDONLY|AT_SYMLINK_FOLLOW, &retVal, 0);
	if(retVal != 0){
		debug_print(__FILE__, __LINE__, "error in opening input file 1", debug_flag);
	 	goto FREE_ARGS;
	}

	input_file2_pointer = open_file_check(xdedup_args->input_file_2, O_RDONLY|AT_SYMLINK_FOLLOW, &retVal, 0);
	if(retVal != 0){
		debug_print(__FILE__, __LINE__, "error in opening input file 2", debug_flag);
	 	goto INFILE1_CLOSE;
	}

	temp_buff = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if(!temp_buff){
		retVal = -ENOMEM;
		goto INFILE2_CLOSE;
	}

	absoulte_file2_path = d_path(&input_file2_pointer->f_path, temp_buff, PAGE_SIZE);

	input_file1_inode = input_file1_pointer->f_path.dentry->d_inode;
	input_file2_inode = input_file2_pointer->f_path.dentry->d_inode;

	retVal = fileParamEqual(input_file1_inode, input_file2_inode, xdedup_args->flag);

	if(retVal){
		debug_print(__FILE__, __LINE__, "both files have different parameters so can't be identical", debug_flag);
		goto INFILE2_CLOSE;
	}

	debug_print(__FILE__, __LINE__, "files are ok and set for deduplicartion", debug_flag);

	if(xdedup_args->output_file){

		output_file_pointer = open_file_check(xdedup_args->output_file , O_WRONLY|AT_SYMLINK_FOLLOW, &retVal, 0);
		/* If output file do not exists create the output file.
		*/
		if(retVal == -ENOENT){
			output_file_pointer = open_file_check(xdedup_args->output_file , O_WRONLY|O_CREAT|AT_SYMLINK_FOLLOW, &retVal, input_file1_inode->i_mode & 0777);
			outfile_created = true;
		}
		if(retVal != 0){
			debug_print(__FILE__, __LINE__, "error opening output_file", debug_flag);
			goto INFILE2_CLOSE;
		}

		if(sameFileCheck(output_file_pointer, input_file1_pointer) || sameFileCheck(output_file_pointer, input_file2_pointer)){
			debug_print(__FILE__, __LINE__, "same input files and output_file", debug_flag);
			retVal = -EINVAL;
			goto INFILE2_CLOSE;
		}
	}


	debug_print(__FILE__, __LINE__, "No error with files, ready for deduplication", debug_flag);


	if(partial_dedup_flag){

		if(n_flag){

			/**
			 * if n and p flag both are there just check the identical bytes and do not write to any output file
			 */
			retVal = read_compare_write(input_file1_pointer, input_file2_pointer, NULL, debug_flag);
			if(retVal<0){
				debug_print(__FILE__,__LINE__, "error in read and compare", debug_flag);
			}
			goto OUTPUT_FILE_CLOSE;

		}else{
			/* Creating temp file in same directory as of output file. Adding Date and Time to make 
					the temp file name unique
			*/
			temp_file_name = (char * ) kmalloc(PAGE_SIZE, GFP_KERNEL);
			if(!temp_file_name){
				retVal = -ENOMEM;
				goto OUTPUT_FILE_CLOSE;
			}

			strcpy(temp_file_name, xdedup_args->output_file);
			strcat(temp_file_name, __DATE__);
			strcat(temp_file_name, __TIME__);

			temp_output_file_pointer = open_file_check(temp_file_name, O_WRONLY|O_CREAT|O_TRUNC, &retVal, output_file_pointer->f_path.dentry->d_inode->i_mode & 0777);

			if(retVal != 0){
				debug_print(__FILE__, __LINE__, "error in creating temp file", debug_flag);
				goto OUTPUT_FILE_CLOSE;
			}

			temp_dentry = temp_output_file_pointer->f_path.dentry;
			output_file_dentry = output_file_pointer->f_path.dentry;

			retVal = read_compare_write(input_file1_pointer, input_file2_pointer, temp_output_file_pointer, debug_flag);

			if(retVal<0){
				debug_print(__FILE__,__LINE__, "error in read and compare", debug_flag);
				temp_rename_err = unlink(d_inode(dget_parent(temp_dentry)), temp_dentry);
				if(temp_rename_err){
					retVal = temp_rename_err;
				}
				
				if(outfile_created){
					temp_rename_err = unlink(d_inode(dget_parent(output_file_dentry)) ,output_file_dentry);
					if(temp_rename_err){
						retVal = temp_rename_err;
					}
				}
				
				goto TEMP_CLOSE;
			}


			temp_rename_err = xdedup_rename(temp_dentry, output_file_dentry);

			if(temp_rename_err){
				debug_print(__FILE__, __LINE__, "error in renaming file", debug_flag);
				retVal = temp_rename_err;

				if(outfile_created){
					temp_rename_err = unlink(d_inode(dget_parent(output_file_dentry)) ,output_file_dentry);
					if(temp_rename_err){
						retVal = temp_rename_err;
					}
				}

				goto TEMP_CLOSE;
			}

			debug_print(__FILE__, __LINE__, "partial deduped temp file replaced output file successfully", debug_flag);

			TEMP_CLOSE:
				if(temp_output_file_pointer){
					filp_close(temp_output_file_pointer, NULL);
				}
				kfree(temp_file_name);

				goto OUTPUT_FILE_CLOSE;
		}

	}else{

		retVal = read_compare_write(input_file1_pointer, input_file2_pointer, NULL, debug_flag);
		if(retVal< 0){
			debug_print(__FILE__, __LINE__, "read, compare and write failed", debug_flag);
			goto INFILE2_CLOSE;
		}

		debug_print(__FILE__, __LINE__, "read and compared in case of not d flag", debug_flag);

		if(retVal != input_file1_inode->i_size){

			debug_print(__FILE__, __LINE__, "content of both files is not identical", debug_flag);
			retVal = -EINVAL;
			goto INFILE2_CLOSE;

		}else{

			debug_print(__FILE__, __LINE__, "file content is identical", debug_flag);

			if(n_flag){

				debug_print(__FILE__, __LINE__, "only n and d flag is on so will match and return matching bytes", debug_flag);

				retVal = input_file1_inode->i_size;
				goto INFILE2_CLOSE;

			}else{

				debug_print(__FILE__, __LINE__, "starting process of actual deduplication", debug_flag);

				/** check for same files, if both the input files are poingitng to same file do not dedup
					return invalid args
				 */
				if(sameFileCheck(input_file1_pointer, input_file2_pointer)){
					debug_print(__FILE__, __LINE__, "both the input files are same", debug_flag);
					retVal = -EINVAL;
					goto INFILE2_CLOSE;
				}

				input_file1_dentry = input_file1_pointer->f_path.dentry;
				input_file2_dentry = input_file2_pointer->f_path.dentry;
				input_file1_dir_inode = input_file1_dentry->d_parent->d_inode;
				input_file2_dir_inode = input_file2_dentry->d_parent->d_inode;

				debug_print(__FILE__, __LINE__, "unlinking of second input starting", debug_flag);

				unlink_err = unlink(input_file2_dir_inode, input_file2_dentry);
				if(unlink_err){
					debug_print(__FILE__, __LINE__, "error in unlinking second input file", debug_flag);
					retVal = unlink_err;
					goto INFILE2_CLOSE;
				}

				debug_print(__FILE__, __LINE__, "unlinking of second input file was success", debug_flag);
				//printk("%s\n", absoulte_file2_path);

				vfs_link_ret = link(input_file1_pointer, input_file1_dentry, absoulte_file2_path);
				if(vfs_link_ret){
					debug_print(__FILE__, __LINE__, "error in hard linking second file to the first", debug_flag);
					retVal = vfs_link_ret;
					goto INFILE2_CLOSE;
				}

				debug_print(__FILE__, __LINE__, "hard linking of second input file to first input file was success", debug_flag);
				
				retVal =  input_file1_inode->i_size;
				goto INFILE2_CLOSE;

			}

		}

	}


	OUTPUT_FILE_CLOSE:
		if(output_file_pointer){
			filp_close(output_file_pointer, NULL);			
		}
	INFILE2_CLOSE:
		if(input_file2_pointer){
			filp_close(input_file2_pointer, NULL);
		}
		if(temp_buff){
			kfree(temp_buff);
		}
	INFILE1_CLOSE:
		filp_close(input_file1_pointer, NULL);
	FREE_ARGS:
		kfree(xdedup_args);
	NO_FILE_OPEN:
		return retVal;
}

static int __init init_sys_xdedup(void)
{
	printk("installed new sys_xdedup module\n");
	if (sysptr == NULL)
		sysptr = xdedup;
	return 0;
}
static void  __exit exit_sys_xdedup(void)
{
	if (sysptr != NULL)
		sysptr = NULL;
	printk("removed sys_xdedup module\n");
}

module_init(init_sys_xdedup);
module_exit(exit_sys_xdedup);
MODULE_LICENSE("GPL");

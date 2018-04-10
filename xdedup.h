#ifndef HEADERFILE_H
#define HEADERFILE_H

#define N_FLAG_RETRIEVE 0x01
#define P_FLAG_RETRIEVE 0x02
#define D_FLAG_RETRIEVE 0x04

struct syscall_args {
	unsigned int flag:3;
	char * output_file;
	char * input_file_1;
	char * input_file_2;
};

#endif
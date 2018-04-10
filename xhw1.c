#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "xdedup.h"

#ifndef __NR_xdedup
#error xdedup system call not defined
#endif

int main(int argc, char * const argv[])	
{
	int rc;

	struct syscall_args xdedupArgs;

	int c;

	char * incorrect_arg_err = "Unexpected arguments";
	char * input_file_read_error = "No read permission for the input file:";
	char * input_file_exist_error = "Input file does not exist:";
	char * wrong_flag_error = "flags are not correct";
	
	while((c = getopt(argc, argv, "ndp")) != -1){
		switch(c){

			case 'd':
				xdedupArgs.flag = xdedupArgs.flag | 4;
				break;

			case 'p':
				xdedupArgs.flag = xdedupArgs.flag | 2;
				break;

			case 'n':
				xdedupArgs.flag = xdedupArgs.flag | 1;
				break;

			default:
				printf("%s\n", wrong_flag_error);
				return -1;
				break;
		}
	}

	printf("%d\n", xdedupArgs.flag);

	if((xdedupArgs.flag & 2) == 2 ){
		if((xdedupArgs.flag & 1) == 1 && (argc-optind < 2 || argc-optind > 2)){
			printf("%s\n", incorrect_arg_err);
			return -1;
		}

		if((xdedupArgs.flag & 1) == 0 && (argc-optind < 3 || argc-optind > 3)){
			printf("%s\n", incorrect_arg_err);
			return -1;			
		}
	}

	if( (xdedupArgs.flag & 2) == 0 && (argc-optind < 2 || argc-optind > 2) ){
		printf("%s\n", incorrect_arg_err);
		return -1;
	}

	//printf("%d\n", PATH_MAX+1);

	//char actual_path[PATH_MAX+1];

	int j = 0;
	
	while(optind < argc && j<2)
	{
		if(access(argv[optind], F_OK) != -1){

			if(access(argv[optind], R_OK) != -1){
				printf("%d\n", j);
				if(j==0){
					xdedupArgs.input_file_1 =  argv[optind];
					//printf("%s\n", xdedupArgs.output_file);

				}
				if(j==1){
					xdedupArgs.input_file_2 =  argv[optind];
					//printf("%s\n", xdedupArgs.output_file);
				}
			}else{
				printf("%s %s\n", input_file_read_error, argv[optind]);
				return -1;
			}

		}else{
			printf("%s %s\n", input_file_exist_error, argv[optind]);
			return -1;
		}

		optind++;
		j++;
	}

	printf("%s\n", xdedupArgs.input_file_2);

	if( (xdedupArgs.flag & 2) == 2 && (xdedupArgs.flag & 1) == 0){
				xdedupArgs.output_file = argv[optind];
	}

	
	printf("%u\n", xdedupArgs.flag);


  	rc = syscall(__NR_xdedup, (void *) &xdedupArgs);

	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

	exit(rc);

	return 0;

}

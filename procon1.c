#include <unistd.h>  
#include <stdlib.h>  
#include <fcntl.h>  
#include <limits.h>  
#include <sys/types.h>  
#include <sys/stat.h>  
#include <stdio.h>  
#include <string.h>  
  
int main()  
{  
    const char *fifo_name = "/tmp/transform";  
    int pipe_fd = -1;      
    int res = -1;
    const int open_mode = O_WRONLY;    

 	
		//创建管道
		if(mkfifo(fifo_name, 0777)!=0)  
		{  
		    fprintf(stderr, "Could not create fifo %s\n", fifo_name);  
		    exit(EXIT_FAILURE);  
		} 

  
    printf("Writer opening FIFO O_WRONLY\n", getpid());   
    pipe_fd = open(fifo_name, open_mode);   
    printf("Writer result %d\n", pipe_fd);  
  
    if(pipe_fd != -1)  
    {    
            //向FIFO文件写数据  
            res = write(pipe_fd, "1", 10);  
            if(res == -1)  
            {  
                fprintf(stderr, "Fail write into fifo\n");  
                exit(EXIT_FAILURE);  
            }   
        close(pipe_fd);  
    }  
    else  
        exit(EXIT_FAILURE);  
  
    printf("Writer finished\n");  
    exit(EXIT_SUCCESS);  
}

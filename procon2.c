#include <unistd.h>  
#include <stdlib.h>  
#include <stdio.h>  
#include <fcntl.h>  
#include <sys/types.h>  
#include <sys/stat.h>  
#include <limits.h>  
#include <string.h>  
  
int main()  
{  
    const char *fifo_name = "/tmp/transform";  
    int pipe_fd = -1; 
    int open_mode = O_RDONLY;  
    char buffer[10 + 1];    
  
    printf("Reader opening FIFO O_RDONLY\n");    
    pipe_fd = open(fifo_name, open_mode);    
    printf("Reader result %d\n", pipe_fd);  
  
    if(pipe_fd != -1)  
    {  
     
            //读取FIFO中的数据，并把它保存在文件DataFormFIFO.txt文件中  
            read(pipe_fd, buffer, PIPE_BUF);  
            printf("Reader receive (%s) from Writer",buffer); 
       
        close(pipe_fd);   
    }  
    else  
        exit(EXIT_FAILURE);  
    printf("\n");
    printf("Reader finished read\n");  
    exit(EXIT_SUCCESS);  
}

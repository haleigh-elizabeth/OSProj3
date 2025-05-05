#include "io_helper.h"
#include "request.h"
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

// Worked with Eli in the tutoring lab for some of this

#define MAXBUF (8192)

// below default values are defined in 'request.h'
int num_threads = DEFAULT_THREADS;
int buffer_max_size = DEFAULT_BUFFER_SIZE;
int scheduling_algo = DEFAULT_SCHED_ALGO;	

pthread_cond_t notempty_buffer = PTHREAD_COND_INITIALIZER;
pthread_cond_t notfull_buffer = PTHREAD_COND_INITIALIZER;


//creating buffer 
//#define buffer_size;

typedef struct {
    int fd; 
    char filename [MAXBUF];
    int buffer_size;
} request_t;
//req.array.add(request_t);
request_t reqbuffer[MAXBUF];
pthread_mutex_t reqbufferLock;
int buffer_size = 0;

void request_error(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) {
    char buf[MAXBUF], body[MAXBUF];
    
    // Create the body of error message first (have to know its length for header)
    sprintf(body, ""
	    "<!doctype html>\r\n"
	    "<head>\r\n"
	    "  <title>CYB-3053 WebServer Error</title>\r\n"
	    "</head>\r\n"
	    "<body>\r\n"
	    "  <h2>%s: %s</h2>\r\n" 
	    "  <p>%s: %s</p>\r\n"
	    "</body>\r\n"
	    "</html>\r\n", errnum, shortmsg, longmsg, cause);
    
    // Write out the header information for this response
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    write_or_die(fd, buf, strlen(buf));
    
    sprintf(buf, "Content-Type: text/html\r\n");
    write_or_die(fd, buf, strlen(buf));
    
    sprintf(buf, "Content-Length: %lu\r\n\r\n", strlen(body));
    write_or_die(fd, buf, strlen(buf));
    
    // Write out the body last
    write_or_die(fd, body, strlen(body));
    
    // close the socket connection
    close_or_die(fd);
}

//
// Reads and discards everything up to an empty text line
//
void request_read_headers(int fd) {
    char buf[MAXBUF];
    
    readline_or_die(fd, buf, MAXBUF);
    while (strcmp(buf, "\r\n")) {
	readline_or_die(fd, buf, MAXBUF);
    }
    return;
}

//
// Return 1 if static, 0 if dynamic content (executable file)
// Calculates filename (and cgiargs, for dynamic) from uri
int request_parse_uri(char *uri, char *filename, char *cgiargs) {
    char *ptr;
    
    if (!strstr(uri, "cgi")) { 
	// static
	strcpy(cgiargs, "");
	sprintf(filename, ".%s", uri);
	if (uri[strlen(uri)-1] == '/') {
	    strcat(filename, "index.html");
	}
	return 1;
    } else { 
	// dynamic
	ptr = index(uri, '?');
	if (ptr) {
	    strcpy(cgiargs, ptr+1);
	    *ptr = '\0';
	} else {
	    strcpy(cgiargs, "");
	}
	sprintf(filename, ".%s", uri);
	return 0;
    }
}

//
// Fills in the filetype given the filename
//
void request_get_filetype(char *filename, char *filetype) {
    if (strstr(filename, ".html")) 
	strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif")) 
	strcpy(filetype, "image/gif");
    else if (strstr(filename, ".jpg")) 
	strcpy(filetype, "image/jpeg");
    else 
	strcpy(filetype, "text/plain");
}

//
// Handles requests for static content
//
void request_serve_static(int fd, char *filename, int filesize) {
    int srcfd;
    char *srcp, filetype[MAXBUF], buf[MAXBUF];
    
    request_get_filetype(filename, filetype);
    srcfd = open_or_die(filename, O_RDONLY, 0);
    
    // Rather than call read() to read the file into memory, 
    // which would require that we allocate a buffer, we memory-map the file
    srcp = mmap_or_die(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
    close_or_die(srcfd);
    
    // put together response
    sprintf(buf, ""
	    "HTTP/1.0 200 OK\r\n"
	    "Server: OSTEP WebServer\r\n"
	    "Content-Length: %d\r\n"
	    "Content-Type: %s\r\n\r\n", 
	    filesize, filetype);
       
    write_or_die(fd, buf, strlen(buf));
    
    //  Writes out to the client socket the memory-mapped file 
    write_or_die(fd, srcp, filesize);
    munmap_or_die(srcp, filesize);
}

//
// Fetches the requests from the buffer and handles them (thread logic)
//
void* thread_request_serve_static(void* arg)
{
    // TODO: write code to actualy respond to HTTP requests
    // Pull from global buffer of requests
    // 0 - FIFO, 1 - SFF, 2 - RANDOM
    // get indv. requests from buffer
    // lock buffer array before reading
    pthread_mutex_lock(&reqbufferLock);
        
    while (buffer_size == 0){
        pthread_cond_wait(&notempty_buffer, &reqbufferLock);
    }
    // signal that we are ready to start
    pthread_cond_signal(&notempty_buffer);
    request_t request;
    switch (arg)
    {
    case arg == 0:
        /* case of FIFO */
        for (i = 0, i < buffer_size-1, i++){
            request = reqbuffer[i];
            // shrink the array after
            for (j = 0, j < buffer_size-1, j++){
                reqbuffer[j] = reqbuffer[j+1];
            }
            //process request
            request_serve_static(request.fd, request.filename, request.buffer_size);
            close_or_die(request.fd);
            //decrement size of buffer
            buffer_size--;
        }
        break;
    case arg == 1:
        /* case of SFF */
        // while starvation mode remains under 50, run
        while(starvation_switch < 10){
            //int smallest_file = 0 ;
            int smallest_file_size = 0;

            for(i = 0, i < buffer_size-1, i++){
                if (filesize < smallest_file_size)
                smallest_file_size = filesize;
                //process it
                request_serve_static(request.fd, request.filename, request.buffer_size);
                close_or_die(request.fd);
        }
        // else if starvation mode of 10 iterations has been reached, quit
        }
        break;
    case arg == 2:
        // case of Random
        for (k=0, k < buffer_size-1, k++){
            //select a random number and the pull that value from the buffer
            int rand_value = rand();
            reqbuffer[rand_value];
            //process request 
            request_serve_static(request.fd, request.filename, request.buffer_size);
            close_or_die(request.fd);
            //decrement size of buffer and take out the processed request
            buffer_size = buffer_size - buffer_size[rand_value];
        }
        break;
    }
    pthread_mutex_unlock(&reqbufferLock);
    pthread_cond_signal(&notfull_buffer);
}

//
// Initial handling of the request
//
void request_handle(int fd) {
    int is_static;
    struct stat sbuf;
    char buf[MAXBUF], method[MAXBUF], uri[MAXBUF], version[MAXBUF];
    char filename[MAXBUF], cgiargs[MAXBUF];
    
    // get the request type, file path and HTTP version
    readline_or_die(fd, buf, MAXBUF);
    sscanf(buf, "%s %s %s", method, uri, version);
    printf("method:%s uri:%s version:%s\n", method, uri, version);

    // verify if the request type is GET or not
    if (strcasecmp(method, "GET")) {
	request_error(fd, method, "501", "Not Implemented", "server does not implement this method");
	return;
    }
    request_read_headers(fd);
    
    // check requested content type (static/dynamic)
    is_static = request_parse_uri(uri, filename, cgiargs);
    
    // get some data regarding the requested file, also check if requested file is present on server
    if (stat(filename, &sbuf) < 0) {
	request_error(fd, filename, "404", "Not found", "server could not find this file");
	return;
    }
    
    // verify if requested content is static
    if (is_static) {
	if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
		request_error(fd, filename, "403", "Forbidden", "server could not read this file");
		return;
	}
    
	// TODO: directory traversal mitigation	
    if (strstr(uri, "../")){
        request_error(fd, filename,  "403", "Forbidden", "server could not read this file");
        return;
    }

	// TODO: write code to add HTTP requests in the buffer
    //	TODO: add code to create and manage the shared global buffer of requests

    // should i use a cache buffer? no.

//	HINT: You will need synchronization primitives.
//		pthread_mutuex_t lock_var is a viable option.

// lock when copying data to buffer?
// Schrick said to use a "request buffer"

// Sends out HTTP response in case of errors
// verify if the request type is GET or not
        request_t request = {fd, filename, sbuf.st_size};
        // lock the buffer & specify what you are locking (buffer)
        pthread_mutex_lock(&reqbufferLock);
        // add request to array
        reqbuffer[buffer_size] = {request};
        //increase buffer size 
        buffer_size++;
        //unlock buffer
        pthread_mutex_unlock(&reqbufferLock);

    } else {
	request_error(fd, filename, "501", "Not Implemented", "server does not serve dynamic content request");
    }
}

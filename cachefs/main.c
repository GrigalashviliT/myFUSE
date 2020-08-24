/*
	File System in userspace using FUSE
	Author: Tornike Grigalashvili
*/

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

int sock = -1;
uid_t super_user = 0;
const int MAX_SEGMENT_SIZE = 4048;
const int MAX_MSG_SIZE = 128;
const int MAX_NUMBER_LEN = 16;
const int MAX_PATH_SIZE = 251;
const int MAX_FILE_SIZE = 1073800000;
const char FILE_SYSTEM_CHECK[] = "D1M1TR110";

void read_one_chunk(const char*, char*, size_t, off_t, int, int);
void write_one_chunk(const char*, char*, size_t, off_t, int, int);

void memcached_connect();
void memcached_disconnect();
void memcached_get(char*, char*);
void memcached_set(char*, int, int, int, char*);
void memcached_add(char*, int, int, int, char*);
void memcached_append(char*, int, int, int, char*);
void memcached_flush();
void memcached_delete(char*);

void remove_subdir(char*, char*);
void remove_xattr(char*, char*);
void get_xattr(char*, char*);
int get_xattrs(char*);
void get_content(char*);
void get_mode_and_owner(char*);
void get_permissions(char*);
int check_permision(char*, int, int);
int has_permision(mode_t, uid_t, gid_t, uid_t, gid_t, int);
mode_t get_mode(char*);
uid_t get_owner(char*);
void set_mode(char*, int);
void set_link_mode(char*, int);
void set_user(char*, int);
void set_group(char*, int);
int file_or_dir_exists(char*);
int file_exists(char*);
int dir_exists(char*);
int dir_empty(char*);
void get_file_elem(char*, char*);
void get_dir_elem(char*, char*);
void get_x_elem(char*, char*);
void get_parent_and_dir(char*, char*, char*);
void get_parent_and_file(char*, char*, char*);
int get_file_length(char*);
void set_file_length(char*, int);
void get_file_chunk(char*, int);
void get_original_path(char*, char*, char*);
void get_symbol_link(char*, char*);
void get_link_content(char*);

static void* my_init(struct fuse_conn_info* conn, struct fuse_config* cfg){
	(void)conn;
	cfg->kernel_cache = 1;

	memcached_connect();

	super_user = getuid();

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get((char*)FILE_SYSTEM_CHECK, buff);
	
	if(strcmp(buff, "END\r\n") == 0){
		memcached_flush();
		memcached_add((char*)FILE_SYSTEM_CHECK, 0, 0, strlen((char*)FILE_SYSTEM_CHECK), (char*)FILE_SYSTEM_CHECK);
		get_permissions(buff);
		memcached_add("d://", 0, 0, strlen(buff), buff);
	}

	return NULL;
}

static void my_destroy(void* private_data){
	memcached_disconnect();

	super_user = -1;

	return;
}

static int my_mkdir(const char* path, mode_t mode){
	if(file_or_dir_exists((char*)path) == 1)
		return -EEXIST;
	
	char parent_path[MAX_PATH_SIZE];
	strcpy(parent_path, (char*)path);
	
	int i = strlen(parent_path) - 1;
	while(parent_path[i] != '/'){
		parent_path[i] = '\0';

		i--;
	}

	if(strlen(parent_path) != 1)
		parent_path[i] = '\0';

	if(check_permision(parent_path, 1, 1) == 0)
		return -EACCES;

	char parent_dir[MAX_PATH_SIZE];
	char dir_name[MAX_PATH_SIZE];
	get_parent_and_dir(parent_dir, dir_name, (char*)path);

	memcached_append(parent_dir, 0, 0, strlen(dir_name), dir_name);

	char dir_elem[MAX_PATH_SIZE];
	get_dir_elem(dir_elem, (char*)path);

	char parent_info[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(parent_dir, parent_info);

	get_mode_and_owner(parent_info);
	memcached_add(dir_elem, 0, 0, strlen(parent_info), parent_info);

	memcached_get(dir_elem, parent_info);
	set_mode(parent_info, (mode|S_IFDIR));
	memcached_set(dir_elem, 0, 0, strlen(parent_info), parent_info);

	memcached_get(dir_elem, parent_info);
	set_user(parent_info, getuid());
	memcached_set(dir_elem, 0, 0, strlen(parent_info), parent_info);

	memcached_get(dir_elem, parent_info);
	set_group(parent_info, getgid());
	memcached_set(dir_elem, 0, 0, strlen(parent_info), parent_info);

	return 0;
}

static int my_rmdir(const char* path){
	if(dir_exists((char*)path) == 0)
		return -ENOENT;
	
	if(check_permision((char*)path, 1, 1) == 0)
		return -EACCES;

	char dir_elem[MAX_PATH_SIZE];
	get_dir_elem(dir_elem, (char*)path);

	if(dir_empty(dir_elem) == 0)
		return -ENOTEMPTY;

	memcached_delete(dir_elem);

	char parent_dir[MAX_PATH_SIZE];
	char dir_name[MAX_PATH_SIZE];
	get_parent_and_dir(parent_dir, dir_name, (char*)path);

	dir_name[strlen(dir_name) - 2] = '\0';

	char sub_dirs[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(parent_dir, sub_dirs);

	remove_subdir(sub_dirs, dir_name);

	memcached_set(parent_dir, 0, 0, strlen(sub_dirs), sub_dirs);

	return 0;
}

static int my_opendir(const char* path, struct fuse_file_info* fi){
	if(dir_exists((char*)path) == 0)
		return -ENOENT;

	if(check_permision((char*)path, 0, 1) == 0)
		return -EACCES;

	return 0;
}

static int my_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi, enum fuse_readdir_flags flags){
	(void)offset;
	(void)fi;
	(void)flags;

	if(dir_exists((char*)path) == 0)
		return -ENOENT;

	if(check_permision((char*)path, 0, 1) == 0)
		return -EACCES;

	filler(buf, ".", NULL, 0, 0);
	filler(buf, "..", NULL, 0, 0);

	char dir_elem[MAX_PATH_SIZE];
	get_dir_elem(dir_elem, (char*)path);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(dir_elem, buff);

	get_content(buff);

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(buff, s);
	while(token != NULL){
		if(strncmp(token, "d:", 2) == 0 || strncmp(token, "f:", 2) == 0 || strncmp(token, "s:", 2) == 0)
			filler(buf, token + 2, NULL, 0, 0);
		
		token = strtok(NULL, s);
  	}

	return 0;
}

static int my_releasedir(const char* path, struct fuse_file_info* fi){
	return 0;
}

static int my_unlink(const char* path){
	if(check_permision((char*)path, 1, 0) == 0)
			return -EACCES;

	if(file_exists((char*)path) != 0){
		char parent_dir[MAX_PATH_SIZE];
		char file_name[MAX_PATH_SIZE];
		get_parent_and_file(parent_dir, file_name, (char*)path);

		file_name[strlen(file_name) - 2] = '\0';

		char sub_dirs[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
		memcached_get(parent_dir, sub_dirs);

		remove_subdir(sub_dirs, file_name);

		memcached_set(parent_dir, 0, 0, strlen(sub_dirs), sub_dirs);

		char file_elem[MAX_PATH_SIZE];
		get_file_elem(file_elem, (char*)path);

		char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
		memcached_get(file_elem, buff);

		memcached_delete(file_elem);

		int len = get_file_length(buff);

		for(int i = 0; i <= len / MAX_SEGMENT_SIZE; i++){
			char new_file_chunk[MAX_PATH_SIZE];
			get_file_elem(new_file_chunk, (char*)path);
			get_file_chunk(new_file_chunk, i);

			memcached_delete(new_file_chunk);
		}
	}else{
		char sym_name[MAX_PATH_SIZE];
		get_symbol_link((char*)path, sym_name);

		char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
		memcached_get(sym_name, buff);

		if(strcmp(buff, "END\r\n") == 0)
			return -ENOENT;

		char parent_dir[MAX_PATH_SIZE];
		char file_name[MAX_PATH_SIZE];
		get_parent_and_file(parent_dir, file_name, (char*)path);

		file_name[strlen(file_name) - 2] = '\0';
		file_name[0] = 's';

		char sub_dirs[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
		memcached_get(parent_dir, sub_dirs);

		remove_subdir(sub_dirs, file_name);

		memcached_set(parent_dir, 0, 0, strlen(sub_dirs), sub_dirs);

		memcached_delete(sym_name);
	}

	return 0;
}

static int my_create(const char* path, mode_t mode, struct fuse_file_info* fi){
	if(file_or_dir_exists((char*)path) == 1)
		return -EEXIST;

	char parent_path[MAX_PATH_SIZE];
	strcpy(parent_path, (char*)path);
	
	int i = strlen(parent_path) - 1;
	while(parent_path[i] != '/'){
		parent_path[i] = '\0';

		i--;
	}

	if(strlen(parent_path) != 1)
		parent_path[i] = '\0';

	if(check_permision(parent_path, 1, 1) == 0)
		return -EACCES;

	char parent_dir[MAX_PATH_SIZE];
	char file_name[MAX_PATH_SIZE];
	get_parent_and_file(parent_dir, file_name, (char*)path);

	memcached_append(parent_dir, 0, 0, strlen(file_name), file_name);

	char file_elem[MAX_PATH_SIZE];
	get_file_elem(file_elem, (char*)path);

	char parent_info[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(parent_dir, parent_info);

	get_mode_and_owner(parent_info);

	memcached_add(file_elem, 0, 0, strlen(parent_info), parent_info);

	memcached_get(file_elem, parent_info);
	set_mode(parent_info, (mode|S_IFREG));
	memcached_set(file_elem, 0, 0, strlen(parent_info), parent_info);

	memcached_get(file_elem, parent_info);
	set_user(parent_info, getuid());
	memcached_set(file_elem, 0, 0, strlen(parent_info), parent_info);

	memcached_get(file_elem, parent_info);
	set_group(parent_info, getgid());
	memcached_set(file_elem, 0, 0, strlen(parent_info), parent_info);

	memcached_append(file_elem, 0, 0, 5, "l:0\r\n");

	get_file_chunk(file_elem, 0);

	memcached_add(file_elem, 0, 0, 0, "");

	return 0;
}

static int my_open(const char* path, struct fuse_file_info* fi){
	if(file_exists((char*)path) == 0)
		return -ENOENT;

	if(check_permision((char*)path, 0, 0) == 0)
		return -EACCES;

	return 0;
}

static int my_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi){
	(void)fi;

	if(file_exists((char*)path) == 0)
		return -ENOENT;

	if(check_permision((char*)path, 0, 0) == 0)
		return -EACCES;

	char file_elem[MAX_PATH_SIZE];
	get_file_elem(file_elem, (char*)path);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(file_elem, buff);

	int len = get_file_length(buff);

	if(offset < len){
		if(offset + size > len)
			size = len - offset;

		int first_chunk_num = (offset / MAX_SEGMENT_SIZE);
		int first_offset = offset % MAX_SEGMENT_SIZE;

		int first_size;
		if(MAX_SEGMENT_SIZE - first_offset > size)
			first_size = size;
		else
			first_size = MAX_SEGMENT_SIZE - first_offset;

		read_one_chunk(path, buf, first_size, first_offset, first_chunk_num, 0);

		if(first_size == size)
			return size;

		int chunk_num;
		for(chunk_num = first_chunk_num + 1; chunk_num < size / MAX_SEGMENT_SIZE; chunk_num++)
			read_one_chunk(path, buf, MAX_SEGMENT_SIZE, 0, chunk_num, first_size + (chunk_num - first_chunk_num - 1) * MAX_SEGMENT_SIZE);

		int last_size = (size - first_size) % MAX_SEGMENT_SIZE;
		read_one_chunk(path, buf, last_size, 0, chunk_num, first_size + (chunk_num - first_chunk_num - 1) * MAX_SEGMENT_SIZE);
	}else{
		size = 0;
	}

	return size;
}

void read_one_chunk(const char* path, char* buf, size_t size, off_t offset, int chunk_number, int main_offset){
	char file_elem[MAX_PATH_SIZE];
	get_file_elem(file_elem, (char*)path);
	get_file_chunk(file_elem, chunk_number);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(file_elem, buff);

	get_content(buff);

	size_t len;
	len = strlen(buff);

	if(offset < len){
		if(offset + size > len)
			size = len - offset;

		memcpy(buf + main_offset, buff + offset, size);
	}
}

static int my_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi){
	(void)fi;

	if(file_exists((char*)path) == 0)
		return -ENOENT;

	if(check_permision((char*)path, 1, 0) == 0)
		return -EACCES;

	if(offset + size > MAX_FILE_SIZE)
		return -ENOSPC;

	char file_elem[MAX_PATH_SIZE];
	get_file_elem(file_elem, (char*)path);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(file_elem, buff);

	int len = get_file_length(buff);

	char spaces[MAX_SEGMENT_SIZE + 1];
	memset(spaces, ' ', MAX_SEGMENT_SIZE);
	spaces[MAX_SEGMENT_SIZE] = '\0';

	if(offset > size){
		char last_file_chunk[MAX_PATH_SIZE];
		get_file_elem(last_file_chunk, (char*)path);
		get_file_chunk(last_file_chunk, len / MAX_SEGMENT_SIZE);

		char last_file_content[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
		memcached_get(last_file_chunk, last_file_content);

		get_content(last_file_content);

		memset(last_file_content + (len % MAX_SEGMENT_SIZE), ' ', MAX_SEGMENT_SIZE - (len % MAX_SEGMENT_SIZE));
		last_file_content[MAX_SEGMENT_SIZE] = '\0';

		memcached_set(last_file_chunk, 0, 0, strlen((last_file_content)), last_file_content);
	}

	for(int i = (len / MAX_SEGMENT_SIZE) + 1; i <= (offset + size) / MAX_SEGMENT_SIZE; i++){
		char new_file_chunk[MAX_PATH_SIZE];
		get_file_elem(new_file_chunk, (char*)path);
		get_file_chunk(new_file_chunk, i);

		if(i < (offset / MAX_SEGMENT_SIZE)){
			memcached_set(new_file_chunk, 0, 0, MAX_SEGMENT_SIZE, spaces);
		}else if(i == (offset / MAX_SEGMENT_SIZE)){
			spaces[offset % MAX_SEGMENT_SIZE] = '\0';
			memcached_set(new_file_chunk, 0, 0, (offset % MAX_SEGMENT_SIZE), spaces);
			spaces[offset % MAX_SEGMENT_SIZE] = ' ';
		}else{
			memcached_set(new_file_chunk, 0, 0, 0, "");
		}
	}

	if(offset + size > len)
		set_file_length(buff, offset + size);
	else
		set_file_length(buff, len);

	memcached_set(file_elem, 0, 0, strlen(buff), buff);
	
	int first_chunk_num = (offset / MAX_SEGMENT_SIZE);
	int first_offset = offset % MAX_SEGMENT_SIZE;

	int first_size;
	if(MAX_SEGMENT_SIZE - first_offset > size)
		first_size = size;
	else
		first_size = MAX_SEGMENT_SIZE - first_offset;

	write_one_chunk(path, (char*)buf, first_size, first_offset, first_chunk_num, 0);

	if(first_size == size)
		return size;

	int chunk_num;
	for(chunk_num = first_chunk_num + 1; chunk_num < size / MAX_SEGMENT_SIZE; chunk_num++)
		write_one_chunk(path, (char*)buf, MAX_SEGMENT_SIZE, 0, chunk_num, first_size + (chunk_num - first_chunk_num - 1) * MAX_SEGMENT_SIZE);

	int last_size = (size - first_size) % MAX_SEGMENT_SIZE;
	write_one_chunk(path, (char*)buf, last_size, 0, chunk_num, first_size + (chunk_num - first_chunk_num - 1) * MAX_SEGMENT_SIZE);

	return size;
}

void write_one_chunk(const char* path, char* buf, size_t size, off_t offset, int chunk_number, int main_offset){
	char file_elem[MAX_PATH_SIZE];
	get_file_elem(file_elem, (char*)path);
	get_file_chunk(file_elem, chunk_number);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(file_elem, buff);

	get_content(buff);

	memcpy(buff + offset, buf + main_offset, size);

	memcached_set(file_elem, 0, 0, strlen(buff), buff);
}

static int my_release(const char* path, struct fuse_file_info* fi){
	return 0;
}

static int my_flush(const char* path, struct fuse_file_info* fi){
	return 0;
}

static int my_fsync(const char* path, int isdatasync, struct fuse_file_info* fi){
	return 0;
}

static int my_getattr(const char* path, struct stat* stbuf, struct fuse_file_info* fi){
	(void)fi;
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));

	char dir_name[MAX_PATH_SIZE];
	get_dir_elem(dir_name, (char*)path);

	char file_name[MAX_PATH_SIZE];
	get_file_elem(file_name, (char*)path);

	char sym_name[MAX_PATH_SIZE];
	get_symbol_link((char*)path, sym_name);

	char buff1[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(dir_name, buff1);

	char buff2[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(file_name, buff2);

	char buff3[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(sym_name, buff3);

	if(strcmp(buff2, "END\r\n") != 0){
		stbuf->st_mode = get_mode(buff2);
		stbuf->st_nlink = 1;
		stbuf->st_size = get_file_length(buff2);
	}else if(strcmp(buff1, "END\r\n") != 0){
		stbuf->st_mode = get_mode(buff1);
		stbuf->st_nlink = 1;
	}else if(strcmp(buff3, "END\r\n") != 0){
		stbuf->st_mode = get_mode(buff3);
		stbuf->st_nlink = 1;
	}else{
		res = -ENOENT;
	}

	return res;
}

static int my_access(const char* path, int mask){
	if(file_or_dir_exists((char*)path) == 0)
		return -ENOENT;

	int permission = 0;
	if(mask == R_OK){
		permission = (check_permision((char*)path, 0, 0) || check_permision((char*)path, 0, 1));
	}else if(mask == W_OK){
		permission = (check_permision((char*)path, 1, 0) || check_permision((char*)path, 1, 1));
	}else if(mask == X_OK){
		permission = (check_permision((char*)path, 2, 0) || check_permision((char*)path, 2, 1));
	}else if(mask == (R_OK||W_OK)){
		permission = ( (check_permision((char*)path, 0, 0) || check_permision((char*)path, 0, 1)) && (check_permision((char*)path, 1, 0) || check_permision((char*)path, 1, 1)) );
	}else if(mask == (R_OK||X_OK)){
		permission = ( (check_permision((char*)path, 0, 0) || check_permision((char*)path, 0, 1)) && (check_permision((char*)path, 2, 0) || check_permision((char*)path, 2, 1)) );
	}else if(mask == (X_OK||W_OK)){
		permission = ( (check_permision((char*)path, 2, 0) || check_permision((char*)path, 2, 1)) && (check_permision((char*)path, 1, 0) || check_permision((char*)path, 1, 1)) );
	}else if(mask == (R_OK||W_OK||X_OK)){
		permission = ( (check_permision((char*)path, 0, 0) || check_permision((char*)path, 0, 1)) && (check_permision((char*)path, 1, 0) || check_permision((char*)path, 1, 1)) && (check_permision((char*)path, 2, 0) || check_permision((char*)path, 2, 1)) );
	}

	return 0;
}

static int my_setxattr(const char* path, const char* name, const char* value, size_t size, int flags){
	if(file_or_dir_exists((char*)path) == 0)
		return -ENOENT;

	char elem[MAX_PATH_SIZE];
	get_x_elem(elem, (char*)path);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(elem, buff);

	char content[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(content, 0, sizeof(content));

	char key[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(key, 0, sizeof(key));
	memcpy(key, (char*)name, strlen((char*)name));
	memcpy(key + strlen(key), ":", 2);

	if(strcmp(buff, "END\r\n") != 0){
		remove_xattr(buff, key);
		memcpy(content, buff, strlen(buff));
	}

	memcpy(content + strlen(content), key, strlen(key));
	memcpy(content + strlen(content), (char*)value, size);
	memcpy(content + strlen(content), "\r\n", 3);

	memcached_set(elem, 0, 0, strlen(content), content);

	return 0;
}

static int my_getxattr(const char* path, const char* name, char* value, size_t size){
	if(file_or_dir_exists((char*)path) == 0)
		return -ENOENT;

	char elem[MAX_PATH_SIZE];
	get_x_elem(elem, (char*)path);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(elem, buff);

	char key[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(key, 0, sizeof(key));
	memcpy(key, (char*)name, strlen((char*)name));
	memcpy(key + strlen(key), ":", 2);

	if(strcmp(buff, "END\r\n") != 0){
		get_xattr(buff, key);

		if(strlen(buff) == 0)
			return -ENODATA;

		if(value == NULL)
			return strlen(buff);

		memcpy(value, buff, strlen(buff));
		return strlen(buff);
	}else{
		return -ENODATA;
	}

	return 0;
}

static int my_listxattr(const char* path, char* list, size_t size){
	if(file_or_dir_exists((char*)path) == 0)
		return -ENOENT;

	char elem[MAX_PATH_SIZE];
	get_x_elem(elem, (char*)path);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(elem, buff);

	if(strcmp(buff, "END\r\n") != 0){
		get_content(buff);
		int len = get_xattrs(buff);

		if(list != NULL)
			memcpy(list, buff, len);

		return len;
	}

	return 0;
}

static int my_removexattr(const char* path, const char* name){
	if(file_or_dir_exists((char*)path) == 0)
		return -ENOENT;

	char elem[MAX_PATH_SIZE];
	get_x_elem(elem, (char*)path);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(elem, buff);

	char content[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(content, 0, sizeof(content));

	char key[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(key, 0, sizeof(key));
	memcpy(key, (char*)name, strlen((char*)name));
	memcpy(key + strlen(key), ":", 2);

	if(strcmp(buff, "END\r\n") != 0){
		remove_xattr(buff, key);
		memcpy(content, buff, strlen(buff));
	}else{
		return -ENODATA;
	}

	memcached_set(elem, 0, 0, strlen(content), content);

	return 0;
}

static int my_chmod(const char* path, mode_t mode, struct fuse_file_info* fi){
	char file_elem[MAX_PATH_SIZE];
	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];

	if(file_exists((char*)path) == 1){
		get_file_elem(file_elem, (char*)path);
	}else if(dir_exists((char*)path) == 1){
		get_dir_elem(file_elem, (char*)path);
	}else{
		return -ENOENT;
	}

	char owner[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(file_elem, owner);
	if(get_owner(owner) != getuid() && super_user != getuid())
		return -EACCES;

	memcached_get(file_elem, buff);
	set_mode(buff, mode);
	memcached_set(file_elem, 0, 0, strlen(buff), buff);

	return 0;
}

static int my_chown(const char* path, uid_t uid, gid_t gid, struct fuse_file_info* fi){
	if(super_user != getuid())
		return -EACCES;

	char file_elem[MAX_PATH_SIZE];
	get_file_elem(file_elem, (char*)path);

	char dir_elem[MAX_PATH_SIZE];
	get_dir_elem(dir_elem, (char*)path);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];

	if(file_exists((char*)path) == 1){
		if(uid != -1){
			memcached_get(file_elem, buff);
			set_user(buff, uid);
			memcached_set(file_elem, 0, 0, strlen(buff), buff);
		}

		if(gid != -1){
			memcached_get(file_elem, buff);
			set_group(buff, gid);
			memcached_set(file_elem, 0, 0, strlen(buff), buff);
		}
	}else if(dir_exists((char*)path) == 1){
		if(uid != -1){
			memcached_get(dir_elem, buff);
			set_user(buff, uid);
			memcached_set(dir_elem, 0, 0, strlen(buff), buff);
		}

		if(gid != -1){
			memcached_get(dir_elem, buff);
			set_group(buff, gid);
			memcached_set(dir_elem, 0, 0, strlen(buff), buff);
		}
	}else{
		return -ENOENT;
	}

	return 0;
}

static int my_symlink(const char* from, const char* to){
	if(file_or_dir_exists((char*)to) == 1)
		return -EEXIST;

	char new_from[MAX_PATH_SIZE];
	memset(new_from, 0, sizeof(new_from));
	strcpy(new_from, (char*)from);
	char new_to[MAX_PATH_SIZE];
	memset(new_to, 0, sizeof(new_to));
	strcpy(new_to, (char*)to);

	char to_elem[MAX_PATH_SIZE];
	get_symbol_link(new_to, to_elem);

	char full_from[MAX_PATH_SIZE];
	get_original_path(new_from, new_to, full_from);

	if(file_or_dir_exists(full_from) == 0)
		return -ENOENT;

	char content[MAX_SEGMENT_SIZE];
	strcpy(content, from);
	strcpy(content + strlen(content), "\r\n");
	memcached_add(to_elem, 0, 0, strlen(content), content);

	char file_elem[MAX_PATH_SIZE];
	get_file_elem(file_elem, full_from);
	char dir_elem[MAX_PATH_SIZE];
	get_dir_elem(dir_elem, full_from);
	char sym_name[MAX_PATH_SIZE];
	get_symbol_link(full_from, sym_name);

	char parent_info[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char parent_dir[MAX_PATH_SIZE];
	char file_name[MAX_PATH_SIZE];

	memcached_get(file_elem, parent_info);
	if(strcmp(parent_info, "END\r\n") == 0){
		memcached_get(dir_elem, parent_info);

		if(strcmp(parent_info, "END\r\n") == 0){
			memcached_get(sym_name, parent_info);
			get_parent_and_dir(parent_dir, file_name, (char*)to);
			file_name[0] = 's';
		}else{
			get_parent_and_dir(parent_dir, file_name, (char*)to);
		}
	}else{
		get_parent_and_file(parent_dir, file_name, (char*)to);
	}

	file_name[0] = 's';
	
	set_link_mode(parent_info, O_RDONLY|S_IFLNK);
	memcached_append(to_elem, 0, 0, strlen(parent_info), parent_info);

	memcached_append(parent_dir, 0, 0, strlen(file_name), file_name);

	return 0;
}

static int my_readlink(const char* path, char* buf, size_t size){
	char sym_link[MAX_PATH_SIZE];
	get_symbol_link((char*)path, sym_link);

	char original_link[MAX_SEGMENT_SIZE + MAX_PATH_SIZE];
	memcached_get(sym_link, original_link);

	if(strcmp(original_link, "END\r\n") == 0)
		return -ENOENT;

	get_link_content(original_link);

	memcpy(buf, original_link, size);

	return 0;
}

static int my_utimens(const char* path, const struct timespec tv[2], struct fuse_file_info *fi){
	return 0;
}

static struct fuse_operations hello_oper = {
	.init = my_init,
	.destroy = my_destroy,
	.mkdir = my_mkdir,
	.rmdir = my_rmdir,
	.opendir = my_opendir,
	.readdir = my_readdir,
	.releasedir  = my_releasedir,
	.unlink = my_unlink,
	.create = my_create,
	.open = my_open,
	.read = my_read,
	.write = my_write,
	.release = my_release,
	.flush = my_flush,
	.fsync = my_fsync,
	.getattr = my_getattr,
	.access = my_access,
	.setxattr = my_setxattr,
	.getxattr = my_getxattr,
	.listxattr = my_listxattr,
	.removexattr = my_removexattr,
	.chmod = my_chmod,
	.chown = my_chown,
	.symlink = my_symlink,
	.readlink = my_readlink,
	.utimens = my_utimens,
};

void memcached_connect(){
	struct sockaddr_in memcached_addr;

	while(sock == -1)
		sock = socket(AF_INET, SOCK_STREAM, 0);
	
	memcached_addr.sin_family = AF_INET;
    memcached_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    memcached_addr.sin_port = htons(11211);

	while(connect(sock, (const struct sockaddr*)(&memcached_addr), sizeof(memcached_addr)) != 0);

	return;
}

void memcached_disconnect(){
	close(sock);

	sock = -1;

	return;
}

void memcached_get(char* key, char* res){
	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];

	memset(buff, 0, sizeof(buff));
	sprintf(buff, "get %s\r\n", key);

	write(sock, buff, strlen(buff));

	memset(buff, 0, sizeof(buff));
	read(sock, buff, sizeof(buff));

	memcpy(res, buff, sizeof(buff));

	return;
}

void memcached_set(char* key, int flags, int exp_time, int length, char* value){
	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char flag[MAX_NUMBER_LEN];
	sprintf(flag, "%d", flags);
	char exp[MAX_NUMBER_LEN];
	sprintf(exp, "%d", exp_time);
	char len[MAX_NUMBER_LEN];
	sprintf(len, "%d", length);

	memset(buff, 0, sizeof(buff));
	sprintf(buff, "set %s %s %s %s\r\n%s\r\n", key, flag, exp, len, value);

	write(sock, buff, strlen(buff));

	read(sock, buff, sizeof(buff));

	return;
}

void memcached_add(char* key, int flags, int exp_time, int length, char* value){
	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char flag[MAX_NUMBER_LEN];
	sprintf(flag, "%d", flags);
	char exp[MAX_NUMBER_LEN];
	sprintf(exp, "%d", exp_time);
	char len[MAX_NUMBER_LEN];
	sprintf(len, "%d", length);

	memset(buff, 0, sizeof(buff));
	sprintf(buff, "add %s %s %s %s\r\n%s\r\n", key, flag, exp, len, value);

	write(sock, buff, strlen(buff));

	read(sock, buff, sizeof(buff));

	return;
}

void memcached_append(char* key, int flags, int exp_time, int length, char* value){
	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char flag[MAX_NUMBER_LEN];
	sprintf(flag, "%d", flags);
	char exp[MAX_NUMBER_LEN];
	sprintf(exp, "%d", exp_time);
	char len[MAX_NUMBER_LEN];
	sprintf(len, "%d", length);

	memset(buff, 0, sizeof(buff));
	sprintf(buff, "append %s %s %s %s\r\n%s\r\n", key, flag, exp, len, value);

	write(sock, buff, strlen(buff));

	read(sock, buff, sizeof(buff));

	return;
}

void memcached_flush(){
	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];

	memset(buff, 0, sizeof(buff));
	sprintf(buff, "flush_all\r\n");

	write(sock, buff, strlen(buff));

	read(sock, buff, sizeof(buff));

	return;
}

void memcached_delete(char* key){
	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];

	memset(buff, 0, sizeof(buff));
	sprintf(buff, "delete %s\r\n", key);

	write(sock, buff, strlen(buff));

	read(sock, buff, sizeof(buff));

	return;
}

void remove_subdir(char* buff, char* cur_dir){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	strcpy(new_buff, buff + 6);

	new_buff[strlen(new_buff) - 5] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);
	token = strtok(NULL, s);

	while(token != NULL){
		if(strcmp(cur_dir, token) != 0){
			strcpy(result + strlen(result), token);
			strcpy(result + strlen(result), "\r\n");
		}
		
		token = strtok(NULL, s);
  	}

	memset(buff, 0, sizeof(buff));
	strcpy(buff, result);
}

void remove_xattr(char* buff, char* cur_dir){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	strcpy(new_buff, buff + 6);

	new_buff[strlen(new_buff) - 5] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);
	token = strtok(NULL, s);

	while(token != NULL){
		if(strncmp(cur_dir, token, strlen(cur_dir)) != 0){
			strcpy(result + strlen(result), token);
			strcpy(result + strlen(result), "\r\n");
		}
		
		token = strtok(NULL, s);
  	}

	memset(buff, 0, sizeof(buff));
	strcpy(buff, result);
}

void get_xattr(char* buff, char* cur_dir){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	strcpy(new_buff, buff + 6);

	new_buff[strlen(new_buff) - 5] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);
	token = strtok(NULL, s);

	while(token != NULL){
		if(strncmp(cur_dir, token, strlen(cur_dir)) == 0){
			strcpy(result + strlen(result), token + strlen(cur_dir));
		}
		
		token = strtok(NULL, s);
  	}

	memset(buff, 0, sizeof(buff));
	strcpy(buff, result);
}

int get_xattrs(char* buff){
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(result, 0, sizeof(result));

	int len = 0;

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(buff, s);

	while(token != NULL){
		int i;
		for(i = 0; i < strlen(token); i++){
			if(token[i] == ':')
				break;
		}

		strncpy(result + len, token, i);
		len += i;
		strcpy(result + len, "\0");
		len++;
		
		token = strtok(NULL, s);
  	}

	memset(buff, 0, sizeof(buff));
	memcpy(buff, result, len);

	return len;
}

void get_content(char* buff){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	memcpy(new_buff, buff + 6, sizeof(new_buff) - 6);

	new_buff[strlen(new_buff) - 1] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);

	memcpy(result, buff + 8 + strlen(token), (strlen(buff) - 14 - strlen(token)));

	memset(buff, 0, sizeof(buff));
	memcpy(buff, result, sizeof(result));
}

void get_mode_and_owner(char* buff){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	strcpy(new_buff, buff);

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);

	while(token != NULL){
		if(strncmp(token, "m:", 2) == 0 ||  strncmp(token, "u:", 2) == 0 ||  strncmp(token, "g:", 2) == 0){
			strcpy(result + strlen(result), token);
			strcpy(result + strlen(result), "\r\n");
		}
		
		token = strtok(NULL, s);
  	}

	memset(buff, 0, sizeof(buff));
	strcpy(buff, result);
}

void get_link_content(char* buff){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	memcpy(new_buff, buff + 6, sizeof(new_buff) - 6);

	new_buff[strlen(new_buff) - 5] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);
	token = strtok(NULL, s);

	while(token != NULL){
		if(strncmp(token, "m:", 2) != 0){
			strcpy(result + strlen(result), token);
		}
		
		token = strtok(NULL, s);
  	}

	memset(buff, 0, sizeof(buff));
	strcpy(buff, result);
}

void get_permissions(char* buff){
	char number[MAX_NUMBER_LEN];

	memset(buff, 0, sizeof(buff));

	int len = 0;
	memcpy(buff + len, "m:", 3);
	len += 2;
	sprintf(number, "%d", (S_IFDIR|0755));
	memcpy(buff + len, number, strlen(number));
	len += strlen(number);
	memcpy(buff + len, "\r\n", 3);
	len += 2;
	
	memcpy(buff + len, "g:", 3);
	len += 2;
	sprintf(number, "%d", getgid());
	memcpy(buff + len, number, strlen(number));
	len += strlen(number);
	memcpy(buff + len, "\r\n", 3);
	len += 2;
	
	memcpy(buff + len, "u:", 3);
	len += 2;
	sprintf(number, "%d", getuid());
	memcpy(buff + len, number, strlen(number));
	len += strlen(number);
	memcpy(buff + len, "\r\n", 3);
	len += 2;

	return;
}

int check_permision(char* path, int action, int dir){
	mode_t mode;
	uid_t uid;
	gid_t gid;
	
	char number[MAX_NUMBER_LEN];
	char elem[MAX_PATH_SIZE];
	if(dir == 1)
		get_dir_elem(elem, path);
	else
		get_file_elem(elem, path);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(elem, buff);

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(buff, s);
	char* gela;

	while(token != NULL){
		if(strncmp("m:", token, 2) == 0){
			strcpy(number, token + 2);
			mode = (mode_t)strtol(number, &gela, 10);
		}else if(strncmp("g:", token, 2) == 0){
			strcpy(number, token + 2);
			gid = (gid_t)strtol(number, &gela, 10);
		}else if(strncmp("u:", token, 2) == 0){
			strcpy(number, token + 2);
			uid = (uid_t)strtol(number, &gela, 10);
		}

		token = strtok(NULL, s);
	}

	return has_permision(mode, uid, gid, getuid(), getgid(), action);
}

int has_permision(mode_t file_mode, uid_t file_uid, gid_t file_gid, uid_t cur_uid, gid_t cur_gid, int action){
	if(cur_uid == file_uid){
		return (action == 0 && ((file_mode & S_IRUSR) != 0)) || (action == 1 && ((file_mode & S_IWUSR) != 0)) || (action == 2 && ((file_mode & S_IXUSR) != 0));
	}else if(cur_gid == file_gid){
		return (action == 0 && ((file_mode & S_IRGRP) != 0)) || (action == 1 && ((file_mode & S_IWGRP) != 0)) || (action == 2 && ((file_mode & S_IXGRP) != 0));
	}else{
		return (action == 0 && ((file_mode & S_IROTH) != 0)) || (action == 1 && ((file_mode & S_IWOTH) != 0)) || (action == 2 && ((file_mode & S_IXOTH) != 0));
	}

	return 0;
}

void set_mode(char* buff, int mode){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	strcpy(new_buff, buff + 6);

	new_buff[strlen(new_buff) - 5] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);
	token = strtok(NULL, s);

	while(token != NULL){
		if(strncmp(token, "m:", 2) == 0){
			char number[MAX_NUMBER_LEN];
			sprintf(number, "%d", mode);
			char new_token[MAX_PATH_SIZE];
			strcpy(new_token, token);

			strncpy(new_token + 2, number, strlen(number) + 1);

			strcpy(result + strlen(result), new_token);
			strcpy(result + strlen(result), "\r\n");
		}else{
			strcpy(result + strlen(result), token);
			strcpy(result + strlen(result), "\r\n");
		}
		
		token = strtok(NULL, s);
  	}

	memset(buff, 0, sizeof(buff));
	strcpy(buff, result);
}

void set_link_mode(char* buff, int mode){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	strcpy(new_buff, buff + 6);

	new_buff[strlen(new_buff) - 5] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);
	token = strtok(NULL, s);

	while(token != NULL){
		if(strncmp(token, "m:", 2) == 0){
			char number[MAX_NUMBER_LEN];
			sprintf(number, "%d", mode);
			char new_token[MAX_PATH_SIZE];
			strcpy(new_token, token);

			strncpy(new_token + 2, number, strlen(number) + 1);

			strcpy(result + strlen(result), new_token);
			strcpy(result + strlen(result), "\r\n");
		}
		
		token = strtok(NULL, s);
  	}

	memset(buff, 0, sizeof(buff));
	strcpy(buff, result);
}

mode_t get_mode(char* buff){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	strcpy(new_buff, buff + 6);

	new_buff[strlen(new_buff) - 5] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);
	token = strtok(NULL, s);

	while(token != NULL){
		if(strncmp(token, "m:", 2) == 0){
			strcpy(result, token + 2);
			strcpy(result + strlen(result), "\0");
		}
		
		token = strtok(NULL, s);
  	}

	char* temp;
	return (mode_t)strtol(result, &temp, 10);
}

uid_t get_owner(char* buff){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	strcpy(new_buff, buff + 6);

	new_buff[strlen(new_buff) - 5] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);
	token = strtok(NULL, s);

	while(token != NULL){
		if(strncmp(token, "u:", 2) == 0){
			strcpy(result, token + 2);
			strcpy(result + strlen(result), "\0");
		}
		
		token = strtok(NULL, s);
  	}

	char* temp;
	return (uid_t)strtol(result, &temp, 10);
}

void set_user(char* buff, int mode){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	strcpy(new_buff, buff + 6);

	new_buff[strlen(new_buff) - 5] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);
	token = strtok(NULL, s);

	while(token != NULL){
		if(strncmp(token, "u:", 2) == 0){
			char number[MAX_NUMBER_LEN];
			sprintf(number, "%d", mode);
			char new_token[MAX_PATH_SIZE];
			strcpy(new_token, token);

			strncpy(new_token + 2, number, strlen(number) + 1);
			token = new_token;
		}

		strcpy(result + strlen(result), token);
		strcpy(result + strlen(result), "\r\n");
		
		token = strtok(NULL, s);
  	}

	memset(buff, 0, sizeof(buff));
	strcpy(buff, result);
}

void set_group(char* buff, int mode){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	strcpy(new_buff, buff + 6);

	new_buff[strlen(new_buff) - 5] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);
	token = strtok(NULL, s);

	while(token != NULL){
		if(strncmp(token, "g:", 2) == 0){
			char number[MAX_NUMBER_LEN];
			sprintf(number, "%d", mode);
			char new_token[MAX_PATH_SIZE];
			strcpy(new_token, token);

			strncpy(new_token + 2, number, strlen(number) + 1);
			token = new_token;
		}

		strcpy(result + strlen(result), token);
		strcpy(result + strlen(result), "\r\n");
		
		token = strtok(NULL, s);
  	}

	memset(buff, 0, sizeof(buff));
	strcpy(buff, result);
}

int file_or_dir_exists(char* path){
	return (file_exists(path) || dir_exists(path));
}

int file_exists(char* path){
	char dir_elem[MAX_PATH_SIZE];
	get_file_elem(dir_elem, path);

	char sym_link[MAX_PATH_SIZE];
	get_symbol_link(path, sym_link);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(dir_elem, buff);

	char buff1[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(sym_link, buff1);
	
	if(strcmp(buff, "END\r\n") != 0 || strcmp(buff1, "END\r\n"))
		return 1;

	return 0;
}

int dir_exists(char* path){
	char dir_elem[MAX_PATH_SIZE];
	get_dir_elem(dir_elem, path);

	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(dir_elem, buff);
	
	if(strcmp(buff, "END\r\n") != 0)
		return 1;

	return 0;
}

int dir_empty(char* dir_elem){
	char buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memcached_get(dir_elem, buff);

	get_content(buff);
	
	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(buff, s);

	while(token != NULL){
		if(strncmp(token, "d:", 2) == 0 ||  strncmp(token, "f:", 2) == 0)
			return 0;
		
		token = strtok(NULL, s);
  	}

	return 1;
}

void get_file_elem(char* dir_elem, char* path){
	strcpy(dir_elem, "f:");
	strcpy(dir_elem + strlen(dir_elem), path);
}

void get_dir_elem(char* dir_elem, char* path){
	strcpy(dir_elem, "d:");
	strcpy(dir_elem + strlen(dir_elem), path);
	strcpy(dir_elem + strlen(dir_elem), "/");
}

void get_x_elem(char* dir_elem, char* path){
	strcpy(dir_elem, "x:");
	strcpy(dir_elem + strlen(dir_elem), path);
}

void get_parent_and_dir(char* parent_dir, char* dir_name, char* path){
	strcpy(parent_dir, "d:");
	strcpy(parent_dir + strlen(parent_dir), path);

	int i = strlen(parent_dir) - 1;
	while(parent_dir[i] != '/'){
		parent_dir[i] = '\0';
		i--;
	}
	if(strcmp("d:/", parent_dir) == 0){
		strcpy(parent_dir + strlen(parent_dir), "/");
	}

	strcpy(dir_name, "d:");
	strcpy(dir_name + strlen(dir_name), path + i - 1);
	strcpy(dir_name + strlen(dir_name), "\r\n");
}

void get_parent_and_file(char* parent_dir, char* dir_name, char* path){
	strcpy(parent_dir, "d:");
	strcpy(parent_dir + strlen(parent_dir), path);

	int i = strlen(parent_dir) - 1;
	while(parent_dir[i] != '/'){
		parent_dir[i] = '\0';
		i--;
	}
	if(strcmp("d:/", parent_dir) == 0){
		strcpy(parent_dir + strlen(parent_dir), "/");
	}

	strcpy(dir_name, "f:");
	strcpy(dir_name + strlen(dir_name), path + i - 1);
	strcpy(dir_name + strlen(dir_name), "\r\n");
}

int get_file_length(char* buff){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	strcpy(new_buff, buff + 6);

	new_buff[strlen(new_buff) - 5] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);
	token = strtok(NULL, s);

	while(token != NULL){
		if(strncmp(token, "l:", 2) == 0){
			strcpy(result + strlen(result), token);
			break;
		}
		
		token = strtok(NULL, s);
  	}

	int i = strlen(result) - 1;
	while(result[i] != ':')
		i--;
	
	char number[MAX_NUMBER_LEN];
	strcpy(number, result + i + 1);

	return (int)strtol(number, (char **)NULL, 10);
}

void set_file_length(char* buff, int new_len){
	char new_buff[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	char result[MAX_SEGMENT_SIZE + MAX_MSG_SIZE];
	memset(new_buff, 0, sizeof(new_buff));
	memset(result, 0, sizeof(result));

	strcpy(new_buff, buff + 6);

	new_buff[strlen(new_buff) - 5] = '\0';

	const char s[3] = "\r\n";
	char *token;
	
	token = strtok(new_buff, s);
	token = strtok(NULL, s);

	while(token != NULL){
		if(strncmp(token, "l:", 2) == 0){
			char str[MAX_NUMBER_LEN];
			sprintf(str, "%d", new_len);
			strcpy(token + 2, str);	
		}

		strcpy(result + strlen(result), token);
		strcpy(result + strlen(result), "\r\n");

		token = strtok(NULL, s);
  	}
	
	memset(buff, 0, sizeof(buff));
	strcpy(buff, result);
}

void get_file_chunk(char* file_elem, int num){
	char str[MAX_NUMBER_LEN];
	sprintf(str, "%d", num);
	
	strcpy(file_elem + strlen(file_elem), ":");
	strcpy(file_elem + strlen(file_elem), str);
}

void get_original_path(char* from, char* to, char* res){
	memset(res, 0, sizeof(res));

	char temp_to[MAX_PATH_SIZE];
	memset(temp_to, 0, sizeof(temp_to));
	memcpy(temp_to, to, strlen(to));

	int i = strlen(temp_to) - 1;
	while(temp_to[i] != '/'){
		temp_to[i] = '\0';
		i--;
	}

	int j = 0;
	while(strncmp(from + j, "..", 2) == 0){
		temp_to[i] = '\0';
		i--;
		while(temp_to[i] != '/'){
			temp_to[i] = '\0';
			i--;
		}

		j += 3;
	}

	strcpy(res, temp_to);
	strcpy(res + strlen(res), (from + j));

	return;
}

void get_symbol_link(char* to, char* res){
	memset(res, 0, sizeof(res));
	sprintf(res, "s:%s", to);
}

static void show_help(const char* progname){
	printf("usage: %s <mountpoint>\n\n", progname);
}

int main(int argc, char* argv[]){
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);

	if(argc >= 3 && strcmp(argv[2], "--help") == 0){
		show_help(argv[0]);
	}

	ret = fuse_main(args.argc, args.argv, &hello_oper, NULL);
	fuse_opt_free_args(&args);

	return ret;
}

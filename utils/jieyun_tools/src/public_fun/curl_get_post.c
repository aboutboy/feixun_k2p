#include "curl_get_post.h"

static struct MemoryStruct {
  char *memory;
  size_t size;
};


static size_t
curl_WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    /* out of memory! */
    log_file_write("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}


int curl_send_get_resquest(const char *addr)
{
       CURL *curl;
       CURLcode res;
       struct MemoryStruct chunk;
       if (NULL == addr) {return 0;}
       chunk.memory = malloc(1);  /* will be grown as needed by realloc above */
       chunk.size = 0;    /* no data at this point */

       curl_global_init(CURL_GLOBAL_ALL);
       curl = curl_easy_init();
       if (curl) {
               curl_easy_setopt(curl, CURLOPT_URL, addr);
               /* send all data to this function  */
               curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_WriteMemoryCallback);

                /* we pass our 'chunk' struct to the callback function */
               curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

               res = curl_easy_perform(curl);
               if (res != CURLE_OK) {
                       log_file_write("curl perform failed:%s", curl_easy_strerror(res));
               }
               log_file_write("peer server get response:%s", chunk.memory);
               
               if (chunk.memory) { free(chunk.memory);}
               curl_easy_cleanup(curl);
       }
       curl_global_cleanup();
       return 0;       

}

int curl_send_post_request(char *data, const char *addr)
{
       CURL *curl;
       CURLcode res;
       struct MemoryStruct chunk;
       if (NULL == addr) {return 0;}
       
       chunk.memory = malloc(1);  /* will be grown as needed by realloc above */
       chunk.size = 0;    /* no data at this point */

       curl_global_init(CURL_GLOBAL_ALL);
       curl = curl_easy_init();
       if (curl) {
               curl_easy_setopt(curl, CURLOPT_POST, 1);
               curl_easy_setopt(curl, CURLOPT_URL, addr);
               struct curl_slist *plist = curl_slist_append(NULL,
                               "Content-Type:application/json;charset=UTF-8");
               curl_easy_setopt(curl, CURLOPT_HTTPHEADER, plist);
               curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
               /* send all data to this function  */
               curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_WriteMemoryCallback);

                /* we pass our 'chunk' struct to the callback function */
               curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

               res = curl_easy_perform(curl);
               if (res != CURLE_OK) {
                       log_file_write("curl perform failed:%s", curl_easy_strerror(res));
               }
               log_file_write("peer server post response:%s", chunk.memory);
               curl_slist_free_all(plist);
               if (chunk.memory) { free(chunk.memory);}
               curl_easy_cleanup(curl);
       }
       curl_global_cleanup();
       return 0;       

}

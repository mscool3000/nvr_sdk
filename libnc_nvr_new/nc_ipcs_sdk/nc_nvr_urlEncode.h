#ifndef __URL_ENCODE_H__
#define __URL_ENCODE_H__

#ifdef __cplusplus
extern "C" {
#endif

    int nc_nvr_url_decode(char *str, int len);
    char *nc_nvr_url_encode(char const *s, int len, int *new_length);

#ifdef __cplusplus
}
#endif

#endif

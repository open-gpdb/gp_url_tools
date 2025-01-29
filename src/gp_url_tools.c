#include "postgres.h"

#include "fmgr.h"
#include "mb/pg_wchar.h"
#include "utils/builtins.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(url_encode);
PG_FUNCTION_INFO_V1(url_decode);
PG_FUNCTION_INFO_V1(uri_encode);
PG_FUNCTION_INFO_V1(uri_decode);

Datum url_encode(PG_FUNCTION_ARGS);
Datum url_decode(PG_FUNCTION_ARGS);
Datum uri_encode(PG_FUNCTION_ARGS);
Datum uri_decode(PG_FUNCTION_ARGS);

static bool allowed_character(const char c, const char *unreserved_special);
static unsigned char char2hex(char c);
static char *write_character(char *output, const char c);
static text *encode(text *input, const char *unreserved_special);

static const unsigned char hexlookup[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,
    9,  -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

unsigned char char2hex(char c) {
    unsigned char res = hexlookup[(unsigned char)c];
    if (res < 0) {
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("invalid hexadecimal digit: \"%c\"", c)));
    }
    return res;
}

bool allowed_character(const char c, const char *unreserved_special) {
    return ('0' <= c && c <= '9') || ('A' <= c && c <= 'Z') ||
           ('a' <= c && c <= 'z') || (strchr(unreserved_special, c) != NULL);
}

char *write_character(char *output, const char c) {
    *output = c;
    return ++output;
}

text *encode(text *input, const char *unreserved_special) {
    int input_lenght;
    text *output;
    char *cinput, *coutput, *current;

    // Convert input data for processing
    cinput = text_to_cstring(input);
    input_lenght = strlen(cinput);
    // Allocate memory for result url string
    coutput = palloc(sizeof(*coutput) * (3 * input_lenght + 1));
    current = coutput;

    for (int i = 0; i < input_lenght; ++i) {
        if (allowed_character(cinput[i], unreserved_special)) {
            // single character => does not encode it or skip it
            current = write_character(current, cinput[i]);
        } else {
            // some characters => process them all into '%XX' or '%XXXX'
            // notation
            current += sprintf(current, "%%%02X", (unsigned char)cinput[i]);
        }
    }
    current = write_character(current, 0);

    // Convert to text and return
    output = cstring_to_text(coutput);
    pfree(coutput);
    return output;
}

static uint32_t decode_utf16_pair(uint16_t c1, uint16_t c2) {
    uint32_t code;

    Assert(0xD800 <= c1 && c1 <= 0xDBFF);
    Assert(0xDC00 <= c2 && c2 <= 0xDFFF);

    code = 0x10000;
    code += (c1 & 0x03FF) << 10;
    code += (c2 & 0x03FF);

    return code;
}

static text *decode(text *in_text, const char *unreserved_special) {
    text *result;
    char *read_ptr = VARDATA_ANY(in_text);
    char *write_ptr;
    int len = VARSIZE_ANY_EXHDR(in_text);
    int real_len;
    int processed;

    real_len = 0;

    result = (text *)palloc(len + VARHDRSZ);
    write_ptr = VARDATA(result);

    processed = 0;
    while (processed < len) {
        if (*read_ptr != '%') {
            char c = *read_ptr;

            if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (strchr(unreserved_special, c) != NULL)) {
                *write_ptr++ = c;
                real_len += 1;
                processed += 1;
                read_ptr += 1;
            } else
                elog(ERROR, "unaccepted chars in url code");
        } else {
            if (processed + 1 >= len)
                elog(ERROR, "incomplete input string");

            /* next two/four chars are part of UTF16 char */
            if (read_ptr[1] == 'u' || read_ptr[1] == 'U') {
                unsigned char b1;
                unsigned char b2;
                uint32_t u;
                unsigned char buffer[10];
                int utf8len;

                uint16_t c1;
                uint16_t c2;

                /* read first two bytes */
                if (processed + 6 > len)
                    elog(ERROR, "incomplete input string");

                b1 = (char2hex(read_ptr[2]) << 4) | char2hex(read_ptr[3]);
                b2 = (char2hex(read_ptr[4]) << 4) | char2hex(read_ptr[5]);

                /*
                 * expect input in UTF16-BE (Big Endian) and convert it
                 * to LE used by Intel.
                 */
                c1 = b2 | (b1 << 8);

                /* is surrogate pairs */
                if (0xD800 <= c1 && c1 <= 0xDBFF) {
                    if (processed + 10 > len)
                        elog(ERROR, "incomplete input string");

                    b1 = (char2hex(read_ptr[6]) << 4) | char2hex(read_ptr[7]);
                    b2 = (char2hex(read_ptr[8]) << 4) | char2hex(read_ptr[9]);
                    c2 = b2 | (b1 << 8);

                    if (!(0xDC00 <= c2 && c2 <= 0xDFFF))
                        elog(ERROR, "invalid utf16 input char");

                    u = decode_utf16_pair(c1, c2);
                    processed += 10;
                    read_ptr += 10;
                } else {
                    u = c1;
                    processed += 6;
                    read_ptr += 6;
                }

                unicode_to_utf8((pg_wchar)u, buffer);
                utf8len = pg_utf_mblen(buffer);
                strncpy(write_ptr, (const char *)buffer, utf8len);
                write_ptr += utf8len;
                real_len += utf8len;
            } else {
                /*
                 * next two/three chars are part of UTF8 char, but it can
                 * be decoded byte by byte.
                 */
                if (processed + 3 > len)
                    elog(ERROR, "incomplete input string");

                *((unsigned char *)write_ptr++) =
                    (char2hex(read_ptr[1]) << 4) | char2hex(read_ptr[2]);
                real_len += 1;
                processed += 3;
                read_ptr += 3;
            }
        }
    }

    SET_VARSIZE(result, real_len + VARHDRSZ);

    return result;
}

Datum url_encode(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) {
        PG_RETURN_NULL();
    }
    PG_RETURN_TEXT_P(encode(PG_GETARG_TEXT_PP(0), ".-~_"));
}

Datum url_decode(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) {
        PG_RETURN_NULL();
    }
    PG_RETURN_TEXT_P(decode(PG_GETARG_TEXT_PP(0), ".-~_"));
}

Datum uri_encode(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) {
        PG_RETURN_NULL();
    }
    PG_RETURN_TEXT_P(encode(PG_GETARG_TEXT_PP(0), "-_.!~*'();/?:@&=+$,#"));
}

Datum uri_decode(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) {
        PG_RETURN_NULL();
    }
    PG_RETURN_TEXT_P(decode(PG_GETARG_TEXT_PP(0), "-_.!~*'();/?:@&=+$,#"));
}

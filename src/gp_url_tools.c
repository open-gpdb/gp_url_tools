#include "postgres.h"

#include "fmgr.h"
#include "mb/pg_wchar.h"
#include "utils/builtins.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(encode_url);
PG_FUNCTION_INFO_V1(decode_url);
PG_FUNCTION_INFO_V1(encode_uri);
PG_FUNCTION_INFO_V1(decode_uri);

Datum url_encode(PG_FUNCTION_ARGS);
Datum url_decode(PG_FUNCTION_ARGS);
Datum uri_encode(PG_FUNCTION_ARGS);
Datum uri_decode(PG_FUNCTION_ARGS);

static bool allowed_character(const char c, const char *unreserved_special);
static unsigned char char2hex(char c);
static char *write_character(char *output, const char c);
static text *encode(text *input, const char *unreserved_special);
static bool valid_utf16(unsigned int byte);
static unsigned int decode_utf16_pair(unsigned int bytes[2]);
static text *decode(text *input, const char *unreserved_special);
static bool is_utf8(const char *sequence, int lenght);
static bool is_utf16(const char *sequence, int lenght);
static void fetch_utf16(unsigned int *byte, const char *input);

static const unsigned int utf16_low = 0xD800;
static const unsigned int utf16_high = 0xDBFF;
static const unsigned int utf16_decode = 0x03FF;
static const unsigned int utf16_decode_base = 0x10000;

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

bool valid_utf16(unsigned int byte) {
    return utf16_low <= byte && byte <= utf16_high;
}

unsigned int decode_utf16_pair(unsigned int bytes[2]) {
    Assert(valid_utf16(bytes[0]));
    Assert(valid_utf16(bytes[1]));

    return (utf16_decode_base + ((bytes[0] & utf16_decode) << 10) +
            (bytes[1] & utf16_decode));
}

bool is_utf8(const char *sequence, int lenght) {
    return 3 <= lenght && sequence[0] == '%' && sequence[1] != 'u' &&
           sequence[1] != 'U';
}

bool is_utf16(const char *sequence, int lenght) {
    return 6 <= lenght && sequence[0] == '%' &&
           (sequence[1] == 'u' || sequence[1] == 'U');
}

void fetch_utf16(unsigned int *byte, const char *input) {
    for (int i = 0; i < 4; ++i) {
        *byte = ((*byte) << 4) | char2hex(input[i]);
    }
}

text *decode(text *input, const char *unreserved_special) {
    int input_lenght;
    text *output;
    char *cinput, *coutput, *current;

    // Convert input data for processing
    cinput = text_to_cstring(input);
    input_lenght = strlen(cinput);
    // Allocate memory for result string
    coutput = palloc(sizeof(*coutput) * (input_lenght + 1));
    current = coutput;

    for (int i = 0; i < input_lenght;) {
        if (cinput[i] == '%') {
            // special character => start process '%XX' or '%XXXX' sequence of
            // chars
            if (is_utf16(cinput + i, input_lenght - i)) {
                // current sequence is in utf16 encoding
                unsigned int result;
                unsigned int bytes[2];
                unsigned char buffer[10];

                fetch_utf16(bytes, cinput + i + 2);

                if (valid_utf16(bytes[0])) {
                    if (10 < input_lenght - i) {
                        elog(ERROR, "incomplete input string");
                    }

                    fetch_utf16(bytes + 1, cinput + i + 6);
                    if (!valid_utf16(bytes[1])) {
                        elog(ERROR, "invalid utf16 input char");
                    }

                    result = decode_utf16_pair(bytes);
                    i += 10;
                } else {
                    result = bytes[0];
                    i += 6;
                }

                unicode_to_utf8((pg_wchar)result, buffer);
                strncpy(current, (const char *)buffer, pg_utf_mblen(buffer));
                current += pg_utf_mblen(buffer);
            } else if (is_utf8(cinput + i, input_lenght - i)) {
                // current sequence is in utf8 encoding
                current =
                    write_character(current, (char2hex(cinput[i + 1]) << 4) |
                                                 char2hex(cinput[i + 2]));
                i += 3;
            } else {
                // common case: not enough characters in line to decode special
                // sequence => error 'incorrect sequence of tokens'
                elog(ERROR, "incorrect sequence of tokens");
            }
        } else if (allowed_character(cinput[i], unreserved_special)) {
            // allowed and not '%' character => just copy it into result string
            current = write_character(current, cinput[i]);
            i += 1;
        } else {
            // cinput[i] - is not '%' and not allowed character => error
            // 'unexpected character'
            elog(ERROR,
                 "unaccepted chars in url code"); // TODO rework text of errors
        }
    }
    current = write_character(current, 0);

    // Convert to text and return
    output = cstring_to_text(coutput);
    pfree(coutput);
    return output;
}

Datum encode_url(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) {
        PG_RETURN_NULL();
    }
    PG_RETURN_TEXT_P(encode(PG_GETARG_TEXT_PP(0), ".-~_"));
}

Datum decode_url(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) {
        PG_RETURN_NULL();
    }
    PG_RETURN_TEXT_P(decode(PG_GETARG_TEXT_PP(0), ".-~_"));
}

Datum encode_uri(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) {
        PG_RETURN_NULL();
    }
    PG_RETURN_TEXT_P(encode(PG_GETARG_TEXT_PP(0), "-_.!~*'();/?:@&=+$,#"));
}

Datum decode_uri(PG_FUNCTION_ARGS) {
    if (PG_ARGISNULL(0)) {
        PG_RETURN_NULL();
    }
    PG_RETURN_TEXT_P(decode(PG_GETARG_TEXT_PP(0), "-_.!~*'();/?:@&=+$,#"));
}

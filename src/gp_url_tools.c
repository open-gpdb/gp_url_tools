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
static bool is_utf8(const char *sequence, int length);
static bool is_utf16(const char *sequence, int length);
static void fetch_utf16(unsigned int *byte, const char *input);

static const unsigned int utf16_low = 0xD800;
static const unsigned int utf16_high = 0xDBFF;
static const unsigned int utf16_decode = 0x03FF;
static const unsigned int utf16_decode_base = 0x10000;

unsigned char char2hex(char c) {
    if ('0' <= c && c <= '9') {
        return c - '0';
    } else if ('A' <= c && c <= 'Z') {
        return c - 'A' + 10;
    } else if ('a' <= c && c <= 'z') {
        return c - 'a' + 10;
    }
    ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                    errmsg("invalid hexadecimal digit: \"%c\"", c)));
    return -1;
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
    int input_length;
    text *output;
    char *cinput, *coutput, *current;

    // Convert input data for processing
    cinput = text_to_cstring(input);
    input_length = strlen(cinput);
    // Allocate memory for result url string
    coutput = palloc(sizeof(*coutput) * (3 * input_length + 1));
    current = coutput;

    for (int i = 0; i < input_length; ++i) {
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

// Check that sequence of bytes starts with 'symbol' in UTF-8 encoding
//
// UTF-16 'symbols' starts with '%' or '%', and 'XX' after it.
// 'XX' - hex sequence that encode bytes
bool is_utf8(const char *sequence, int length) {
    return 3 <= length && sequence[0] == '%' && sequence[1] != 'u' &&
           sequence[1] != 'U';
}

// Check that sequence of bytes starts with 'symbol' in UTF-16 encoding
//
// UTF-16 'symbols' starts with '%u' or '%U', and 'XXXX' after it.
// 'XXXX' - hex sequence that encode bytes (optinally sequence 'XXXX' ->
// 'XXXXXXXX')
bool is_utf16(const char *sequence, int length) {
    return 6 <= length && sequence[0] == '%' &&
           (sequence[1] == 'u' || sequence[1] == 'U');
}

void fetch_utf16(unsigned int *byte, const char *input) {
    for (int i = 0; i < 4; ++i) {
        *byte = ((*byte) << 4) | char2hex(input[i]);
    }
}

text *decode(text *input, const char *unreserved_special) {
    int input_length;
    text *output;
    char *cinput, *coutput, *current;

    // Convert input data for processing
    cinput = text_to_cstring(input);
    input_length = strlen(cinput);
    // Allocate memory for result string
    coutput = palloc(sizeof(*coutput) * (input_length + 1));
    current = coutput;

    for (int i = 0; i < input_length;) {
        if (cinput[i] == '%') {
            // special character => start process '%XX' or '%XXXX' sequence of
            // chars
            if (is_utf16(cinput + i, input_length - i)) {
                unsigned int result;
                unsigned int bytes[2];
                unsigned char buffer[10];

                fetch_utf16(bytes, cinput + i + 2);

                if (valid_utf16(bytes[0])) {
                    if (10 < input_length - i) {
                        ereport(
                            ERROR,
                            (errcode(ERRCODE_CHARACTER_NOT_IN_REPERTOIRE),
                             errmsg("invalid sequence: not enough characters "
                                    "to decode UTF-16 symbol from %d position",
                                    i)));
                    }

                    fetch_utf16(bytes + 1, cinput + i + 6);
                    if (!valid_utf16(bytes[1])) {
                        ereport(
                            ERROR,
                            (errcode(ERRCODE_CHARACTER_NOT_IN_REPERTOIRE),
                             errmsg("invalid UTF-16 byte: characters from %d "
                                    "position define invalid UTF-16 symbol",
                                    i + 6)));
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
            } else if (is_utf8(cinput + i, input_length - i)) {
                current =
                    write_character(current, (char2hex(cinput[i + 1]) << 4) |
                                                 char2hex(cinput[i + 2]));
                i += 3;
            } else {
                // common case: not enough characters in line to decode special
                // sequence => error 'incorrect sequence of tokens'
                ereport(ERROR,
                        (errcode(ERRCODE_CHARACTER_NOT_IN_REPERTOIRE),
                         errmsg("invalid sequence: not enough characters to "
                                "decode any UTF-typed symbol from %d position",
                                i)));
            }
        } else if (allowed_character(cinput[i], unreserved_special)) {
            // allowed and not '%' character => just copy it into result string
            current = write_character(current, cinput[i]);
            i += 1;
        } else {
            // cinput[i] - is not '%' and not allowed character => error
            // 'unexpected character'
            ereport(ERROR, (errcode(ERRCODE_CHARACTER_NOT_IN_REPERTOIRE),
                            errmsg("unalloweed characters in url code: \"%c\"",
                                   cinput[i])));
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

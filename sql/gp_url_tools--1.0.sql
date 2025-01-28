/* gp_url_tools--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION gp_url_tools" to load this file. \quit

CREATE SCHEMA IF NOT EXISTS url_tools_schema;

CREATE FUNCTION url_tools_schema.encode_url(text)
RETURNS text
AS 'MODULE_PATHNAME', 'url_encode'
LANGUAGE C STRICT EXECUTE ON MASTER;

CREATE FUNCTION url_tools_schema.decode_url(text)
RETURNS text
AS 'MODULE_PATHNAME', 'url_decode'
LANGUAGE C STRICT EXECUTE ON MASTER;

CREATE FUNCTION url_tools_schema.encode_uri(text)
RETURNS text
AS 'MODULE_PATHNAME', 'uri_encode'
LANGUAGE C STRICT EXECUTE ON MASTER;

CREATE FUNCTION url_tools_schema.decode_uri(text)
RETURNS text
AS 'MODULE_PATHNAME', 'uri_decode'
LANGUAGE C STRICT EXECUTE ON MASTER;


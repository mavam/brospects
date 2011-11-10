# Check whether the CN field of a TLS certificate subject contains a NUL byte.
function tls_cn_contains_nul(subject)
{
    return tls_extract_field("CN", subject) ~ /\\x00/;
}

# Check whether a TLS server name (SNI) matches the subject CN field advertised
# in the certificate.
# Returns true on mismatch and false otherwise.
function tls_wildcard_mismatch(server_name, subject)
{
    if (server_name == "-")
        return 0;

    cn = tls_subject_field("CN", subject)
    if (cn == "")
        return 0;

    wildcard = index(cn, "*");
    if (wildcard > 0)
    {
        suffix = substr(cn, wildcard + 2, length(cn) - wildcard - 1);
        if (index(server_name, suffix) > 0)
            return 0;
    }
    else if (server_name == cn)
        return 0;

    return 1;
}

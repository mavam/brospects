# Extract the value of TLS certificate subject field.
# Returns the extracted value or the empty string if the field does not exist.
function extract_field(field, subject)
{
    cn = "";
    split(subject, s, /,/);
    for (i in s)
    {
        split(s[i], kv, /=/);
        if (kv[1] == field)
        {
            cn = kv[2];
            break;
        }
    }

    return cn;
}

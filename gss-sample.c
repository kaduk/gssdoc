#include <unistd.h>
#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gssapi/gssapi.h>

/*
 * Pipes for communication between initiator and acceptor.
 * We use a very simple communication protocol, that can only ever
 * send context negotiation tokens and no other application data.
 * The framing is that we write a 32-bit unsigned integer which is
 * the byte count of the following token, followed by the token.
 */
int pipefds_itoa[2];
int pipefds_atoi[2];

static void
release_buffer(gss_buffer_t buf)
{
    free(buf->value);
    buf->value = NULL;
    buf->length = 0;
}

static int
send_token(int fd, gss_buffer_t token)
{
    int ret;
    OM_uint32 length;

    assert(sizeof(length) == 4);
    length = token->length;
    ret = write(fd, &length, 4);
    if (ret != 4) {
	warnx("send_token could not write length\n");
	return 1;
    }
    ret = write(fd, token->value, length);
    if (ret != length) {
	warnx("send_token could not write token\n");
	return 1;
    }
    return 0;
}

static int
receive_token(int fd, gss_buffer_t token)
{
    int ret;
    OM_uint32 length;

    assert(sizeof(length) == 4);
    ret = read(fd, &length, 4);
    if (ret != 4) {
	warnx("receive_token could not read length, ret %u\n", length);
	return 1;
    }
    /* Do a little sanity checking. */
    if (length > 64 * 1024*1024) {
	warnx("Attempting to receive token larger than 64M\n");
	return 1;
    }
    token->value = malloc(length);
    if (token->value == NULL) {
	warnx("Could not allocate memory to receive token\n");
	return 1;
    }
    ret = read(fd, token->value, length);
    if (ret != length) {
	warnx("Could not receive token\n");
	return 1;
    }
    token->length = length;
    return 0;
}

static void
do_initiator(void)
{
    int context_established = 0;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    OM_uint32 major, minor, req_flags, ret_flags;
    gss_buffer_desc input_token, output_token;
    gss_name_t target_name = GSS_C_NO_NAME;
    OM_uint32 ret;

    memset(&input_token, 0, sizeof(input_token));
    memset(&output_token, 0, sizeof(output_token));

    /* Applications should set target_name to a real value. */
#if 24729
    gss_buffer_desc name_buf;
    name_buf.value = "kaduk";
    name_buf.length = 5;
    major = gss_import_name(&minor, &name_buf, GSS_C_NT_USER_NAME,
			    &target_name);
    if (GSS_ERROR(major))
	errx(1, "Could not import name\n");
#endif

    req_flags = GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;

    while (!context_established) {
	/* The initiator_cred_handle, mech_type, time_req, input_chan_bindings,
	 * actual_mech_type, and time_rec parameters are not needed in many
	 * cases.  We pass GSS_C_NO_CREDENTIAL, GSS_C_NO_OID, 0, NULL, NULL,
	 * and NULL for them, respectively. */
	major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &ctx,
				     target_name, GSS_C_NO_OID, req_flags, 0,
				     NULL, &input_token, NULL, &output_token,
				     &ret_flags, NULL);
	/* This memory is no longer needed. */
	release_buffer(&input_token);
	/* The test against GSS_S_CONTINUE_NEEDED is checking whether we
	 * require a(nother) token from the acceptor.  We should send
	 * what we have in that case, regardless of its length.  If the
	 * token's length is positive, we must send it always, too. */
	if ((GSS_SUPPLEMENTARY_INFO(major) & GSS_S_CONTINUE_NEEDED) != 0 ||
	    output_token.length > 0) {
	    ret = send_token(pipefds_itoa[1], &output_token);
	    if (ret != 0)
		goto cleanup;
	}
	/* This error check occurs after we send the token so that we will
	 * send an error token if one is generated. */
	if (GSS_ERROR(major))
	    errx(1, "gss_init_sec_context() error major %u\n", major);
	/* Having sent any output_token, release the storage for it. */
	(void)gss_release_buffer(&minor, &output_token);

	if ((GSS_SUPPLEMENTARY_INFO(major) & GSS_S_CONTINUE_NEEDED) != 0) {
	    ret = receive_token(pipefds_atoi[0], &input_token);
	} else if (major == GSS_S_COMPLETE) {
	    context_established = 1;
	} else {
	    errx(1, "major not complete or continue-needed but not error\n");
	}
    }	/* while(!context_established) */
    if ((ret_flags & req_flags) != req_flags)
	errx(1, "Negotiated context does not support requested flags\n");
    printf("Initiator's context negotiation successful\n");
    /* Do not request a context deletion token, pass NULL. */
cleanup:
    major = gss_delete_sec_context(&minor, &ctx, NULL);
}

static void
do_acceptor(void)
{
    int context_established = 0, ret;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    OM_uint32 major, minor, ret_flags;
    gss_buffer_desc input_token, output_token;
    gss_name_t client_name;

    memset(&input_token, 0, sizeof(input_token));
    memset(&output_token, 0, sizeof(output_token));

    context_established = 0;
    major = GSS_S_CONTINUE_NEEDED;

    while(!context_established) {
	/* We always need at least one token from the peer.  Get it first. */
	if ((GSS_SUPPLEMENTARY_INFO(major) & GSS_S_CONTINUE_NEEDED) != 0) {
	    ret = receive_token(pipefds_itoa[0], &input_token);
	    if (ret != 0)
		goto cleanup;
	} else if (major == GSS_S_COMPLETE) {
	    context_established = 1;
	    break;
	} else {
	    errx(1, "major not complete or continue-needed but not error\n");
	}
	/* We can use the default behavior or do not need the returned
	 * information for the parameters acceptor_cred_handle,
	 * input_chan_bindings, mech_type, time_rec, and delegated_cred_handle
	 * and pass the values GSS_C_NO_CREDENTIAL, NULL, NULL, NULL, and NULL,
	 * respectively.  In some cases the src_name will not be needed, but
	 * most likely it will be needed for some authorization or logging
	 * functionality. */
	major = gss_accept_sec_context(&minor, &ctx, GSS_C_NO_CREDENTIAL,
				       &input_token, NULL, &client_name, NULL,
				       &output_token, &ret_flags, NULL, NULL);
	/* Release memory no longer needed. */
	release_buffer(&input_token);
	/* The test against GSS_S_CONTINUE_NEEDED is checking whether we
	 * require a(nother) token from the initiator.  We should send
	 * what we have in that case, regardless of its length.  If the
	 * token's length is positive, we must send it always, too. */
	if ((GSS_SUPPLEMENTARY_INFO(major) & GSS_S_CONTINUE_NEEDED) != 0 ||
	    output_token.length > 0) {
	    ret = send_token(pipefds_atoi[1], &output_token);
	    if (ret != 0)
		goto cleanup;
	}
	/* This error check occurs after we send the token so that we will
	 * send an error token if one is generated. */
	if (GSS_ERROR(major))
	    errx(1, "gss_accept_sec_context() error major %u\n", major);
	/* Release the output token's storage; we don't need it anymore. */
	(void)gss_release_buffer(&minor, &output_token);
    }	/* while(!context_established) */
    if ((ret_flags & GSS_C_INTEG_FLAG) != GSS_C_INTEG_FLAG)
	errx(1, "Negotiated context does not support integrity\n");
    printf("Acceptor's context negotiation successful\n");
    /* Do not request a context deletion token, pass NULL. */
cleanup:
    major = gss_delete_sec_context(&minor, &ctx, NULL);
}

int main(int argc, char **argv)
{
    pid_t pid;

    if (pipe(pipefds_itoa) != 0)
	err(1, "pipe failed for itoa\n");
    if (pipe(pipefds_atoi) != 0)
	err(1, "pipe failed for atoi\n");
    pid = fork();
    if (pid == 0)
	do_initiator();
    else if (pid > 0)
	do_acceptor();
    else
	err(1, "fork() failed\n");
    exit(0);
}

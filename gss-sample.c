#define KADUK	24729
#include <unistd.h>
#if KADUK
#include <assert.h>
#endif
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gssapi/gssapi.h>

#if KADUK
/*
 * Pipes for communication between initiator and acceptor.
 * We use a very simple communication protocol, that can only ever
 * send context negotiation tokens and no other application data.
 * The framing is that we write a 32-bit unsigned integer which is
 * the byte count of the following token, followed by the token.
 */
static int pipefds_itoa[2];
static int pipefds_atoi[2];
#endif

/*
 * This helper is used only on buffers that we allocate ourselves (e.g.,
 * from receive_token()).  Buffers allocated by GSS routines must use
 * gss_release_buffer().
 */
static void
release_buffer(gss_buffer_t buf)
{
    free(buf->value);
    buf->value = NULL;
    buf->length = 0;
}

/*
 * Helper to send a token on the specified fd.
 *
 * If errors are encountered, this routine must not directly cause
 * termination of the process, because compliant GSS applications
 * must release resources allocated by the GSS library before
 * exiting.
 *
 * Returns 0 on success, non-zero on failure.
 */
static int
send_token(int fd, gss_buffer_t token)
{
    /*
     * Supply token framing and transmission code here.
     *
     * It is advisable for the application protocol to specify the
     * length of the token being transmitted, unless the underlying
     * transit does so implicitly.
     *
     * In addition to checking for error returns from whichever
     * syscall(s) are used to send data, applications should have
     * a loop to handle EINTR returns.
     */
#if KADUK
    ssize_t ret;
    OM_uint32 length;

    assert(sizeof(length) == 4);
    if (token->length > UINT32_MAX) {
	warnx("send_token received token too large for framing\n");
	return 1;
    }
    length = (OM_uint32)token->length;
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
#else
    return 1;
#endif
}

/*
 * Helper to receive a token on the specified fd.
 *
 * If errors are encountered, this routine must not directly cause
 * termination of the process, because compliant GSS applications
 * must release resources allocated by the GSS library before
 * exiting.
 *
 * Returns 0 on success, non-zero on failure.
 */
static int
receive_token(int fd, gss_buffer_t token)
{
    /*
     * Supply token framing and transmission code here.
     *
     * In addition to checking for error returns from whichever
     * syscall(s) are used to receive data, applications should have
     * a loop to handle EINTR returns.
     *
     * This routine is assumed to allocate memory for the local copy
     * of the received token, which must be freed with release_buffer().
     */
#if KADUK
    ssize_t ret;
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
#else
    return 1;
#endif
}

static void
do_initiator(int readfd, int writefd, int anon)
{
    int initiator_established = 0, ret;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    OM_uint32 major, minor, req_flags, ret_flags;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
    gss_name_t target_name = GSS_C_NO_NAME;

    /* Applications should set target_name to a real value. */
#if KADUK
    name_buf.value = "kaduk";
    name_buf.length = 5;
    major = gss_import_name(&minor, &name_buf, GSS_C_NT_USER_NAME,
			    &target_name);
    if (GSS_ERROR(major))
	errx(1, "Could not import name\n");
#else
    name_buf.value = "<service>@<hostname.domain>";
    name_buf.length = strlen(name_buf.value);
    major = gss_import_name(&minor, &name_buf,
			    GSS_C_NT_HOSTBASED_SERVICE, &target_name);
    if (GSS_ERROR(major)) {
	warnx(1, "Could not import name\n");
	goto cleanup;
    }
#endif

    /* Mutual authentication will require a token from acceptor to
     * initiator, and thus a second call to gss_init_sec_context(). */
    req_flags = GSS_C_MUTUAL_FLAG | GSS_C_CONF_FLAG | GSS_C_INTEG_FLAG;
    if (anon)
	req_flags |= GSS_C_ANON_FLAG;

    while (!initiator_established) {
	/* The initiator_cred_handle, mech_type, time_req,
	 * input_chan_bindings, actual_mech_type, and time_rec
	 * parameters are not needed in many cases.  We pass
	 * GSS_C_NO_CREDENTIAL, GSS_C_NO_OID, 0, NULL, NULL, and NULL
	 * for them, respectively. */
	major = gss_init_sec_context(&minor, GSS_C_NO_CREDENTIAL, &ctx,
				     target_name, GSS_C_NO_OID,
				     req_flags, 0, NULL, &input_token,
				     NULL, &output_token, &ret_flags,
				     NULL);
	/* This was allocated by receive_token() and is no longer
	 * needed.  Free it now to avoid leaks if the loop continues. */
	release_buffer(&input_token);
	if (anon) {
	    /* Initiators which wish to remain anonymous must check
	     * whether their request has been honored before sending
	     * each token. */
	    if (!(ret_flags & GSS_C_ANON_FLAG)) {
		warnx("Anonymous requested but not available\n");
		goto cleanup;
	    }
	}
	/* Always send a token if we are expecting another input token
	 * (GSS_S_CONTINUE_NEEDED is set) or if it is nonempty. */
	if ((major & GSS_S_CONTINUE_NEEDED) ||
	    output_token.length > 0) {
	    ret = send_token(writefd, &output_token);
	    if (ret != 0)
		goto cleanup;
	}
	/* Check for errors after sending the token so that we will send
	 * error tokens. */
	if (GSS_ERROR(major)) {
	    warnx("gss_init_sec_context() error major 0x%x\n", major);
	    goto cleanup;
	}
	/* Free the output token's storage; we don't need it anymore.
	 * gss_release_buffer() is safe to call on the output buffer
	 * from gss_int_sec_context(), even if there is no storage
	 * associated with that buffer. */
	(void)gss_release_buffer(&minor, &output_token);

	if (major & GSS_S_CONTINUE_NEEDED) {
	    ret = receive_token(readfd, &input_token);
	    if (ret != 0)
		goto cleanup;
	} else if (major == GSS_S_COMPLETE) {
	    initiator_established = 1;
	} else {
	    /* This situation is forbidden by RFC 2743.  Bail out. */
	    warnx("major not complete or continue but not error\n");
	    goto cleanup;
	}
    }	/* while (!initiator_established) */
    if ((ret_flags & req_flags) != req_flags) {
	warnx("Negotiated context does not support requested flags\n");
	goto cleanup;
    }
    printf("Initiator's context negotiation successful\n");
cleanup:
    /* We are required to release storage for nonzero-length output
     * tokens.  gss_release_buffer() zeros the length, so we are
     * will not attempt to release the same buffer twice. */
    if (output_token.length > 0)
	(void)gss_release_buffer(&minor, &output_token);
    /* Do not request a context deletion token; pass NULL. */
    (void)gss_delete_sec_context(&minor, &ctx, NULL);
    (void)gss_release_name(&minor, &target_name);
}

/*
 * Perform authorization checks on the initiator's GSS name object.
 *
 * Returns 0 on success (the initiator is authorized) and nonzero
 * when the initiator is not authorized.
 */
static int
check_authz(gss_name_t client_name)
{
    /*
     * Supply authorization checking code here.
     *
     * Options include bitwise comparison of the exported name against
     * a local database, and introspection against name attributes.
     */
    return 0;
}

static void
do_acceptor(int readfd, int writefd)
{
    int acceptor_established = 0, ret;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    OM_uint32 major, minor, ret_flags;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_name_t client_name;

    major = GSS_S_CONTINUE_NEEDED;

    while (!acceptor_established) {
	if (major & GSS_S_CONTINUE_NEEDED) {
	    ret = receive_token(readfd, &input_token);
	    if (ret != 0)
		goto cleanup;
	} else if (major == GSS_S_COMPLETE) {
	    acceptor_established = 1;
	    break;
	} else {
	    /* This situation is forbidden by RFC 2743.  Bail out. */
	    warnx("major not complete or continue but not error\n");
	    goto cleanup;
	}
	/* We can use the default behavior or do not need the returned
	 * information for the parameters acceptor_cred_handle,
	 * input_chan_bindings, mech_type, time_rec, and
	 * delegated_cred_handle and pass the values
	 * GSS_C_NO_CREDENTIAL, NULL, NULL, NULL, and NULL,
	 * respectively.  In some cases the src_name will not be
	 * needed, but most likely it will be needed for some
	 * authorization or logging functionality. */
	major = gss_accept_sec_context(&minor, &ctx,
				       GSS_C_NO_CREDENTIAL,
				       &input_token, NULL,
				       &client_name, NULL,
				       &output_token, &ret_flags, NULL,
				       NULL);
	/* This was allocated by receive_token() and is no longer
	 * needed.  Free it now to avoid leaks if the loop continues. */
	release_buffer(&input_token);
	/* Always send a token if we are expecting another input token
	 * (GSS_S_CONTINUE_NEEDED is set) or if it is nonempty. */
	if ((major & GSS_S_CONTINUE_NEEDED) ||
	    output_token.length > 0) {
	    ret = send_token(writefd, &output_token);
	    if (ret != 0)
		goto cleanup;
	}
	/* Check for errors after sending the token so that we will send
	 * error tokens. */
	if (GSS_ERROR(major)) {
	    warnx("gss_accept_sec_context() error major 0x%x\n", major);
	    goto cleanup;
	}
	/* Free the output token's storage; we don't need it anymore.
	 * gss_release_buffer() is safe to call on the output buffer
	 * from gss_accept_sec_context(), even if there is no storage
	 * associated with that buffer. */
	(void)gss_release_buffer(&minor, &output_token);
    }	/* while (!acceptor_established) */
    if (!(ret_flags & GSS_C_INTEG_FLAG)) {
	warnx("Negotiated context does not support integrity\n");
	goto cleanup;
    }
    printf("Acceptor's context negotiation successful\n");
    ret = check_authz(client_name);
    if (ret != 0)
	printf("Client is not authorized; rejecting access\n");
cleanup:
    release_buffer(&input_token);
    /* We are required to release storage for nonzero-length output
     * tokens.  gss_release_buffer() zeros the length, so we are
     * will not attempt to release the same buffer twice. */
    if (output_token.length > 0)
	(void)gss_release_buffer(&minor, &output_token);
    /* Do not request a context deletion token, pass NULL. */
    (void)gss_delete_sec_context(&minor, &ctx, NULL);
    (void)gss_release_name(&minor, &client_name);
}

int
main(void)
{
    pid_t pid;
    int fd1 = -1, fd2 = -1;

#if KADUK
    if (pipe(pipefds_itoa) != 0)
	err(1, "pipe failed for itoa\n");
    if (pipe(pipefds_atoi) != 0)
	err(1, "pipe failed for atoi\n");
    pid = fork();
    if (pid == 0)
	do_initiator(pipefds_atoi[0], pipefds_itoa[1], 0);
    else if (pid > 0)
	do_acceptor(pipefds_itoa[0], pipefds_atoi[1]);
    else
	err(1, "fork() failed\n");
#else
    /* Create fds for reading/writing here. */
    pid = fork();
    if (pid == 0)
	do_initiator(fd1, fd2, 0);
    else if (pid > 0)
	do_acceptor(fd2, fd1);
    else
	err(1, "fork() failed\n");
#endif
    exit(0);
}

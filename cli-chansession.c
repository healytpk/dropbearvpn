#include "includes.h"
#include "packet.h"
#include "buffer.h"
#include "session.h"
#include "dbutil.h"
#include "channel.h"
#include "ssh.h"
#include "runopts.h"
#include "termcodes.h"

static void cli_closechansess(struct Channel *channel);
static int cli_initchansess(struct Channel *channel);

static void start_channel_request(struct Channel *channel, unsigned char *type);

static void send_chansess_pty_req(struct Channel *channel);
static void send_chansess_shell_req(struct Channel *channel);

static void cli_tty_setup();
void cli_tty_cleanup();

static const struct ChanType clichansess = {
	0, /* sepfds */
	"session", /* name */
	cli_initchansess, /* inithandler */
	NULL, /* checkclosehandler */
	NULL, /* reqhandler */
	cli_closechansess, /* closehandler */
};

/* If the main session goes, we close it up */
static void cli_closechansess(struct Channel *channel) {

	/* This channel hasn't gone yet, so we have > 1 */
	if (ses.chancount > 1) {
		dropbear_log(LOG_INFO, "Waiting for other channels to close...");
	}

	cli_tty_cleanup(); /* Restore tty modes etc */

}

static void start_channel_request(struct Channel *channel, 
		unsigned char *type) {

	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_REQUEST);
	buf_putint(ses.writepayload, channel->remotechan);

	buf_putstring(ses.writepayload, type, strlen(type));

}

/* Taken from OpenSSH's sshtty.c:
 * RCSID("OpenBSD: sshtty.c,v 1.5 2003/09/19 17:43:35 markus Exp "); */
static void cli_tty_setup() {

	struct termios tio;

	TRACE(("enter cli_pty_setup"));

	if (cli_ses.tty_raw_mode == 1) {
		TRACE(("leave cli_tty_setup: already in raw mode!"));
		return;
	}

	if (tcgetattr(STDIN_FILENO, &tio) == -1) {
		dropbear_exit("Failed to set raw TTY mode");
	}

	/* make a copy */
	cli_ses.saved_tio = tio;

	tio.c_iflag |= IGNPAR;
	tio.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
#ifdef IUCLC
	tio.c_iflag &= ~IUCLC;
#endif
	tio.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
#ifdef IEXTEN
	tio.c_lflag &= ~IEXTEN;
#endif
	tio.c_oflag &= ~OPOST;
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;
	if (tcsetattr(STDIN_FILENO, TCSADRAIN, &tio) == -1) {
		dropbear_exit("Failed to set raw TTY mode");
	}

	cli_ses.tty_raw_mode = 1;
	TRACE(("leave cli_tty_setup"));
}

void cli_tty_cleanup() {

	TRACE(("enter cli_tty_cleanup"));

	if (cli_ses.tty_raw_mode == 0) {
		TRACE(("leave cli_tty_cleanup: not in raw mode"));
		return;
	}

	if (tcsetattr(STDIN_FILENO, TCSADRAIN, &cli_ses.saved_tio) == -1) {
		dropbear_log(LOG_WARNING, "Failed restoring TTY");
	} else {
		cli_ses.tty_raw_mode = 0; 
	}

	TRACE(("leave cli_tty_cleanup"));
}

static void put_termcodes() {

	TRACE(("enter put_termcodes"));

	struct termios tio;
	unsigned int sshcode;
	const struct TermCode *termcode;
	unsigned int value;
	unsigned int mapcode;

	unsigned int bufpos1, bufpos2;

	if (tcgetattr(STDIN_FILENO, &tio) == -1) {
		dropbear_log(LOG_WARNING, "Failed reading termmodes");
		buf_putint(ses.writepayload, 1); /* Just the terminator */
		buf_putbyte(ses.writepayload, 0); /* TTY_OP_END */
		return;
	}

	bufpos1 = ses.writepayload->pos;
	buf_putint(ses.writepayload, 0); /* A placeholder for the final length */

	/* As with Dropbear server, we ignore baud rates for now */
	for (sshcode = 1; sshcode < MAX_TERMCODE; sshcode++) {

		termcode = &termcodes[sshcode];
		mapcode = termcode->mapcode;

		switch (termcode->type) {

			case TERMCODE_NONE:
				continue;

			case TERMCODE_CONTROLCHAR:
				value = tio.c_cc[mapcode];
				break;

			case TERMCODE_INPUT:
				value = tio.c_iflag & mapcode;
				break;

			case TERMCODE_OUTPUT:
				value = tio.c_oflag & mapcode;
				break;

			case TERMCODE_LOCAL:
				value = tio.c_lflag & mapcode;
				break;

			case TERMCODE_CONTROL:
				value = tio.c_cflag & mapcode;
				break;

			default:
				continue;

		}

		/* If we reach here, we have something to say */
		buf_putbyte(ses.writepayload, sshcode);
		buf_putint(ses.writepayload, value);
	}

	buf_putbyte(ses.writepayload, 0); /* THE END, aka TTY_OP_END */

	/* Put the string length at the start of the buffer */
	bufpos2 = ses.writepayload->pos;

	buf_setpos(ses.writepayload, bufpos1); /* Jump back */
	buf_putint(ses.writepayload, bufpos2 - bufpos1 - 4); /* len(termcodes) */
	buf_setpos(ses.writepayload, bufpos2); /* Back where we were */

	TRACE(("leave put_termcodes"));
}

static void put_winsize() {

	struct winsize ws;

	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) < 0) {
		/* Some sane defaults */
		ws.ws_row = 25;
		ws.ws_col = 80;
		ws.ws_xpixel = 0;
		ws.ws_ypixel = 0;
	}

	buf_putint(ses.writepayload, ws.ws_col); /* Cols */
	buf_putint(ses.writepayload, ws.ws_row); /* Rows */
	buf_putint(ses.writepayload, ws.ws_xpixel); /* Width */
	buf_putint(ses.writepayload, ws.ws_ypixel); /* Height */

}

static void sigwinch_handler(int dummy) {

	cli_ses.winchange = 1;

}

void cli_chansess_winchange() {

	unsigned int i;
	struct Channel *channel = NULL;

	for (i = 0; i < ses.chansize; i++) {
		channel = ses.channels[i];
		if (channel != NULL && channel->type == &clichansess) {
			CHECKCLEARTOWRITE();
			buf_putbyte(ses.writepayload, SSH_MSG_CHANNEL_REQUEST);
			buf_putint(ses.writepayload, channel->remotechan);
			buf_putstring(ses.writepayload, "window-change", 13);
			buf_putbyte(ses.writepayload, 0); /* FALSE says the spec */
			put_winsize();
			encrypt_packet();
		}
	}
	cli_ses.winchange = 0;
}

static void send_chansess_pty_req(struct Channel *channel) {

	unsigned char* term = NULL;

	TRACE(("enter send_chansess_pty_req"));

	start_channel_request(channel, "pty-req");

	/* Don't want replies */
	buf_putbyte(ses.writepayload, 0);

	/* Get the terminal */
	term = getenv("TERM");
	if (term == NULL) {
		term = "vt100"; /* Seems a safe default */
	}
	buf_putstring(ses.writepayload, term, strlen(term));

	/* Window size */
	put_winsize();

	/* Terminal mode encoding */
	put_termcodes();

	encrypt_packet();

	/* Set up a window-change handler */
	if (signal(SIGWINCH, sigwinch_handler) == SIG_ERR) {
		dropbear_exit("signal error");
	}
	TRACE(("leave send_chansess_pty_req"));
}

static void send_chansess_shell_req(struct Channel *channel) {

	unsigned char* reqtype = NULL;

	TRACE(("enter send_chansess_shell_req"));

	if (cli_opts.cmd) {
		reqtype = "exec";
	} else {
		reqtype = "shell";
	}

	start_channel_request(channel, reqtype);

	/* XXX TODO */
	buf_putbyte(ses.writepayload, 0); /* Don't want replies */
	if (cli_opts.cmd) {
		buf_putstring(ses.writepayload, cli_opts.cmd, strlen(cli_opts.cmd));
	}

	encrypt_packet();
	TRACE(("leave send_chansess_shell_req"));
}

static int cli_initchansess(struct Channel *channel) {

	channel->infd = STDOUT_FILENO;
	//channel->outfd = STDIN_FILENO;
	//channel->errfd = STDERR_FILENO;

	if (cli_opts.wantpty) {
		send_chansess_pty_req(channel);
	}

	send_chansess_shell_req(channel);

	if (cli_opts.wantpty) {
		cli_tty_setup();
	}

	return 0; /* Success */

}

void cli_send_chansess_request() {

	TRACE(("enter cli_send_chansess_request"));
	if (send_msg_channel_open_init(STDIN_FILENO, &clichansess) 
			== DROPBEAR_FAILURE) {
		dropbear_exit("Couldn't open initial channel");
	}

	/* No special channel request data */
	encrypt_packet();
	TRACE(("leave cli_send_chansess_request"));

}

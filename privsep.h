#ifndef PRIVSEP_DOT_H_
#define	PRIVSEP_DOT_H_

enum {
	PRIV_NOP,
	PRIV_GET_CONF_FD,
	PRIV_GET_AUDITPIPE_FD,
	PRIV_GET_LOGDIR_FD
};

int 	 may_read(int, void *, size_t);
void	 must_read(int, void *, size_t);
void	 must_write(int, void *, size_t);
int	 priv_init(void);
FILE	*priv_config_open(void);
FILE	*priv_auditpipe_open(void);

#endif	/* PRIVSEP_DOT_H_ */

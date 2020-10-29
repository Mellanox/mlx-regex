/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2019 Mellanox Technologies. All Rights Reserved.
 */

#include <stdint.h>
#include <stdlib.h>
#include <malloc.h>
#include <stdio.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "mlx5_regex_ifc.h"
#include "devx_prm.h"

#include <infiniband/mlx5dv.h>

int debug = 0;

struct mem_desc {
	void* ptr;
	struct mlx5dv_devx_umem *umem;
};

struct mlx5_database_ctx {
	uint32_t umem_id;
	uint64_t offset;
	struct mem_desc mem_desc;
};

struct regex_caps {
	uint8_t supported;
	u8 num_of_engines;
	u8 log_crspace_size;
	u8 regexp_params;
};

struct mlx5_regex_ctx {
	struct ibv_context *ibv_ctx;
	struct mlx5_database_ctx* db_ctx;
	struct regex_caps caps;
};

static void print_raw(void *ptr, size_t size)
{
	uint32_t dump_index = 0;
	size_t i, j;
	size_t buff_off = 0;
	while (size  > dump_index) {
			char buff[2560];
			buff_off = 0;
			syslog(LOG_NOTICE,  " ");
			for (i = 0; i < 64 ; i += 16) {
					if (!i)
							buff_off += sprintf(buff + buff_off,"0x%x:\t", dump_index);
					else
							buff_off += sprintf(buff + buff_off,"\t");
					for (j = 0; j < 16; j += 4) {
							buff_off += sprintf(buff + buff_off, "%02x", (((uint8_t *)((ptr)))[dump_index*64 + i + j + 0]));
							buff_off += sprintf(buff + buff_off, "%02x", (((uint8_t *)((ptr)))[dump_index*64 + i + j + 1]));
							buff_off += sprintf(buff + buff_off, "%02x", (((uint8_t *)((ptr)))[dump_index*64 + i + j + 2]));
							buff_off += sprintf(buff + buff_off, "%02x", (((uint8_t *)((ptr)))[dump_index*64 + i + j + 3]));
							buff_off += sprintf(buff + buff_off, " ");
					}

					syslog(LOG_NOTICE, "%s", buff);
					buff_off = 0;
			}
			buff_off = 0;
			dump_index++;
	}
}

static int
mlx5_regex_query_cap(struct ibv_context *ctx,
				struct regex_caps *caps)
{
	uint32_t out[DEVX_ST_SZ_DW(query_hca_cap_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(query_hca_cap_in)] = {0};
	int err;

	DEVX_SET(query_hca_cap_in, in, opcode,
		 MLX5_CMD_OP_QUERY_HCA_CAP);
	DEVX_SET(query_hca_cap_in, in, op_mod,
		 MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE |
		 HCA_CAP_OPMOD_GET_CUR);

	err = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		syslog(LOG_ERR, "Query general failed %d\n", err);
		return err;
	}
	
	if (debug) print_raw(out, 1);
	caps->supported = DEVX_GET(query_hca_cap_out, out,
				   capability.cmd_hca_cap.regexp);
	caps->num_of_engines= DEVX_GET(query_hca_cap_out, out,
					capability.cmd_hca_cap.regexp_num_of_engines);
	caps->log_crspace_size = DEVX_GET(query_hca_cap_out, out,
					  capability.cmd_hca_cap.regexp_log_crspace_size);
	return 0;
}

static int
mlx5_regex_is_supported(struct ibv_context *ibv_ctx)
{
	struct regex_caps caps;
	int err;

	err = mlx5_regex_query_cap(ibv_ctx, &caps);
	if (err)
		return 0;

	return caps.supported;
}

static int
mlx5_regex_database_set(struct mlx5_regex_ctx *ctx, int engine_id)
{
	uint32_t out[DEVX_ST_SZ_DW(set_regexp_params_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(set_regexp_params_in)] = {0};
	int err;

	DEVX_SET(set_regexp_params_in, in, opcode, MLX5_CMD_SET_REGEX_PARAMS);
	DEVX_SET(set_regexp_params_in, in, engine_id, engine_id);
	
	DEVX_SET(set_regexp_params_in, in, regexp_params.stop_engine, 1);
	DEVX_SET(set_regexp_params_in, in, field_select.stop_engine, 1);

	DEVX_SET(set_regexp_params_in, in, regexp_params.db_umem_id, ctx->db_ctx[engine_id].mem_desc.umem->umem_id);
	/*  Currently not supported
		DEVX_SET64(set_regexp_params_in, in, regexp_params.db_umem_offset, ctx->db_ctx[engine_id].offset); */
	DEVX_SET(set_regexp_params_in, in, field_select.db_umem_id, 1);

	if (debug) print_raw(in, 1);
	err = mlx5dv_devx_general_cmd(ctx->ibv_ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		syslog(LOG_ERR, "Set regexp params failed %d\n", err);
		return err;
	}
	return 0;
}

/*static int
mlx5_regex_database_query(struct ibv_context *ctx, int engine_id,
			    struct mlx5_database_ctx *db_ctx)
{
	uint32_t out[DEVX_ST_SZ_DW(query_regexp_params_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(query_regexp_params_in)] = {0};
	int err;

	DEVX_SET(query_regexp_params_in, in, opcode, MLX5_CMD_QUERY_REGEX_PARAMS);
	DEVX_SET(query_regexp_params_in, in, engine_id, engine_id);

	err = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		syslog(LOG_ERR, "Query regexp params failed %d\n", err);
		return err;
	}
	db_ctx->umem_id = DEVX_GET(query_regexp_params_out, out, regexp_params.db_umem_id);
	db_ctx->offset = DEVX_GET(query_regexp_params_out, out, regexp_params.db_umem_offset);
	return 0;
}

static int
mlx5_regex_register_write(struct ibv_context *ctx, int engine_id,
			      uint32_t addr, uint32_t data) {
	uint32_t out[DEVX_ST_SZ_DW(set_regexp_register_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(set_regexp_register_in)] = {};
	int err;

	DEVX_SET(set_regexp_register_in, in, opcode, MLX5_CMD_SET_REGEX_REGISTERS);
	DEVX_SET(set_regexp_register_in, in, engine_id, engine_id);
	DEVX_SET(set_regexp_register_in, in, register_address, addr);
	DEVX_SET(set_regexp_register_in, in, register_data, data);

	err = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		syslog(LOG_ERR, "Set regexp register failed %d\n", err);
		return err;
	}
	return 0;
}

static int
mlx5_regex_register_read(struct ibv_context *ctx, int engine_id,
			     uint32_t addr, uint32_t *data) {
	uint32_t out[DEVX_ST_SZ_DW(query_regexp_register_out)] = {};
	uint32_t in[DEVX_ST_SZ_DW(query_regexp_register_in)] = {};
	int err;

	DEVX_SET(query_regexp_register_in, in, opcode, MLX5_CMD_QUERY_REGEX_REGISTERS);
	DEVX_SET(query_regexp_register_in, in, engine_id, engine_id);
	DEVX_SET(query_regexp_register_in, in, register_address, addr);

	err = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		syslog(LOG_ERR, "Query regexp register failed %d\n", err);
		return err;
	}
	*data = DEVX_GET(query_regexp_register_out, out, register_data);
	return 0;
}
*/
int register_database(struct mlx5_regex_ctx* ctx, int engine_id)
{
	/* alloc database 128MB */
	size_t db_size = 1 << 27;

	/* Alloc data - here is a huge page allocation example */
	ctx->db_ctx[engine_id].mem_desc.ptr = mmap(NULL, db_size,
			 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS |
			 MAP_POPULATE | MAP_HUGETLB, -1, 0);

	if (!ctx->db_ctx[engine_id].mem_desc.ptr) {
		syslog(LOG_NOTICE,"Allocation failed\n");
		return -ENOMEM;
	}

	/* Register the memory */
	ctx->db_ctx[engine_id].mem_desc.umem =
			mlx5dv_devx_umem_reg(ctx->ibv_ctx,
					     ctx->db_ctx[engine_id].mem_desc.ptr,
					     db_size, 7);

	
	if (!ctx->db_ctx[engine_id].mem_desc.umem) {
		syslog(LOG_ERR,"Registration failed.\n");
		syslog(LOG_ERR,"Please make sure huge pages in the system\n");
		syslog(LOG_ERR,"Hint: cat /proc/meminfo\n");
		syslog(LOG_ERR,"      echo NUM_PAGES > /proc/sys/vm/nr_hugepages\n");
		return -ENOMEM;
	}
	memset(ctx->db_ctx[engine_id].mem_desc.ptr, 0, db_size);
	return 0;
}

void handle_signal(int sig)
{
        if (sig == SIGINT) {
                syslog(LOG_NOTICE, "SIG_INIT recived...\n");
                /* Reset signal handling to default behavior */
                signal(SIGINT, SIG_DFL);
        } else if (sig == SIGHUP) {     
                syslog(LOG_NOTICE, "SIG_HUP recived...\n");
        } else if (sig == SIGCHLD) {
                syslog(LOG_NOTICE, "SIG_CHLD recived...\n");
        }
}

static void daemonize()
{
    pid_t pid;
	int x;

    /* Catch, ignore and handle signals */
    signal(SIGCHLD, handle_signal);
    signal(SIGHUP, handle_signal);

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");

    /* Close all open file descriptors */
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close (x);
    }

    /* Open the log file */
    openlog ("regex", LOG_PID, LOG_DAEMON);
}

int mlx5_regex_ctx_init(struct ibv_context *ibv_ctx, struct mlx5_regex_ctx *ctx)
{
	int err;
	size_t i;

	ctx->ibv_ctx = ibv_ctx;
	mlx5_regex_query_cap(ctx->ibv_ctx, &ctx->caps);
	ctx->db_ctx = malloc(sizeof(*ctx->db_ctx)*ctx->caps.num_of_engines);
	for (i = 0; i < ctx->caps.num_of_engines; i++) {
		err = register_database(ctx, i);
		if (err)
			return err;
			
		err = mlx5_regex_database_set(ctx, i);
		if (err)
			return err;
	}
	return 0;
}

int main()
{	
	int num, devn = 0;
	struct ibv_context *ibv_ctx = NULL;
	struct mlx5dv_context_attr attr = {0};
	struct mlx5_regex_ctx ctx;
	int err = 0;
	int i;
	struct ibv_device **list;

	daemonize();
    list = ibv_get_device_list(&num);

	if (num == 0) {
		syslog(LOG_NOTICE,"No devices found.\n");
		return -1;
	}

	attr.flags = MLX5DV_CONTEXT_FLAGS_DEVX;

	for (i = 0; i < num; i++)
		if (mlx5dv_is_supported(list[devn])) {
			ibv_ctx = mlx5dv_open_device(list[devn], &attr);
			if (ctx.ibv_ctx == NULL) {
 					syslog(LOG_ERR, "Devx not supported.\n");
                	return -EOPNOTSUPP;
		        }
			if (ibv_ctx && mlx5_regex_is_supported(ibv_ctx)) {
				err = mlx5_regex_ctx_init(ibv_ctx, &ctx);
				break;
			}
			ibv_close_device(ibv_ctx);
			ibv_ctx = NULL;
		}

	if (ctx.ibv_ctx == NULL) {
		syslog(LOG_NOTICE, "Regex not supported on all devices.\n");
		return -EOPNOTSUPP;
	}

	if (err)
		return err;

	while(1)
	{
		sleep(10);
	}

	return 0;
}

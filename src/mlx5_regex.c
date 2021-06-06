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




/**
 * Macro to align a value to a given power-of-two. The resultant value
 *  * will be of the same type as the first parameter, and will be no
 *   * bigger than the first parameter. Second parameter must be a
 *    * power-of-two value.
 *     */
#define RTE_ALIGN_FLOOR(val, align) \
        (typeof(val))((val) & (~((typeof(val))((align) - 1))))

/**
 *  * Macro to align a value to a given power-of-two. The resultant value
 *   * will be of the same type as the first parameter, and will be no lower
 *    * than the first parameter. Second parameter must be a power-of-two
 *     * value.
 *      */
#define RTE_ALIGN_CEIL(val, align) \
        RTE_ALIGN_FLOOR(((val) + ((typeof(val)) (align) - 1)), align)

/**
 * Macro to align a value to a given power-of-two. The resultant
 *  * value will be of the same type as the first parameter, and
 *   * will be no lower than the first parameter. Second parameter
 *    * must be a power-of-two value.
 *     * This function is the same as RTE_ALIGN_CEIL
 *      */
#define RTE_ALIGN(val, align) RTE_ALIGN_CEIL(val, align)


int debug = 0;

static inline uint32_t
rte_bsf32(uint32_t v)
{
        return (uint32_t)__builtin_ctz(v);
}


static inline uint32_t
rte_combine32ms1b(uint32_t x)
{
        x |= x >> 1;
        x |= x >> 2;
        x |= x >> 4;
        x |= x >> 8;
        x |= x >> 16;

        return x;
}

static inline uint32_t
rte_align32pow2(uint32_t x)
{
        x--;
        x = rte_combine32ms1b(x);

        return x + 1;
}

static inline uint32_t
rte_log2_u32(uint32_t v)
{
        if (v == 0)
                return 0;
        v = rte_align32pow2(v);
        return rte_bsf32(v);
}

/* devX creation object */
struct mlx5_devx_obj {
        void *obj; /* The DV object. */
        int id; /* The object ID. */
};

struct mlx5_devx_mkey_attr {
	uint64_t addr;
	uint64_t size;
	uint32_t umem_id;
	uint32_t pd;
	uint32_t log_entity_size;
	uint32_t pg_access:1;
	uint32_t relaxed_ordering_write:1;
	uint32_t relaxed_ordering_read:1;
	uint32_t umr_en:1;
	uint32_t crypto_en:2;
	uint32_t set_remote_rw:1;
	//struct mlx5_klm *klm_array;
	//int klm_num;
};

#if 0
struct mlx5_regex_mkey {
	struct mlx5dv_devx_umem *umem;
	struct mlx5_devx_obj *mkey;
	uint64_t offset;
};
#endif

struct mlx5_regex_mkey {
	void* ptr;
	struct mlx5dv_devx_umem *umem;
	struct mlx5_devx_obj *mkey;
};

struct mlx5_database_ctx {
	uint32_t umem_id;
	uint64_t offset;
	struct mlx5_regex_mkey mem_desc;
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
        struct ibv_pd *pd;
};


static struct mlx5_regex_ctx *ctx_ptr = NULL ;

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

static inline int
regex_get_pdn(void *pd, uint32_t *pdn)
{
	struct mlx5dv_obj obj;
	struct mlx5dv_pd pd_info;
	int ret = 0;
	obj.pd.in = pd;
	obj.pd.out = &pd_info;
	ret = mlx5dv_init_obj(&obj, MLX5DV_OBJ_PD);
	if (ret) {
                syslog(LOG_ERR, "Failed to get PD object info\n");
		//DRV_LOG(DEBUG, "Fail to get PD object info");
		return ret;
	}
	*pdn = pd_info.pdn;
	return 0;
}

struct ibv_pd *
regex_alloc_pd(void *ctx)
{
	//struct mlx5dv_obj *ppd;

        //ppd = calloc(1, sizeof(*ppd));
        return ibv_alloc_pd(ctx);
}

static int
rxp_create_mkey(struct mlx5_regex_ctx *ctx, void *ptr, size_t size,
	uint32_t access, struct mlx5_regex_mkey *mkey)
{
	uint32_t pdn;
	struct mlx5_devx_mkey_attr mkey_attr;
	int ret;
        struct mlx5_devx_obj *tmp_mkey;
        void *mkc;
        size_t pgsize ;
        uint32_t translation_size;
	uint32_t in[DEVX_ST_SZ_DW(create_mkey_in)] = {0};
        uint32_t out[DEVX_ST_SZ_DW(create_mkey_out)] = {0};

        pgsize = sysconf(_SC_PAGESIZE);
        if (pgsize == (size_t) -1) {
                syslog(LOG_ERR, "Failed to get page siza\ne");
		return -ENOMEM;
        }
        tmp_mkey = calloc(1, sizeof(*tmp_mkey));

        syslog(LOG_ERR, "GERRY: tmp_mkey = %p\n", tmp_mkey);

	if (!tmp_mkey) {
                syslog(LOG_ERR, "Failed to allocate memory!\n");
		return -ENOMEM;
	}

	/* Register the memory. */
        mkey->umem = mlx5dv_devx_umem_reg(ctx->ibv_ctx, ptr, size,access);

	if (!mkey->umem) {
                syslog(LOG_ERR, "Failed to register memory!\n");
		return -ENODEV;
	}
	/* Create mkey */
	ret = regex_get_pdn(ctx->pd, &pdn);
	if (ret < 0) {
                syslog(LOG_ERR, "Failed to get pdn!\n");
		return -ENODEV;
	}

        syslog(LOG_ERR, "GERRY: mkey->umem->umem_id = 0x%x\n", (mkey->umem)->umem_id);

	mkey_attr = (struct mlx5_devx_mkey_attr) {
		.addr = (uintptr_t)ptr,
		.size = (uint32_t)size,
		.umem_id = (mkey->umem)->umem_id,
		.pg_access = 1,
		.umr_en = 0,
		.pd = pdn,
	};

translation_size = (RTE_ALIGN(mkey_attr.size, pgsize) * 8) / 16;
        DEVX_SET(create_mkey_in, in, opcode, MLX5_CMD_OP_CREATE_MKEY);

        mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);

DEVX_SET(mkc, mkc, log_page_size, rte_log2_u32(pgsize));
        DEVX_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_MTT);

        DEVX_SET(create_mkey_in, in, mkey_umem_id, mkey_attr.umem_id);

        DEVX_SET(create_mkey_in, in, pg_access, mkey_attr.pg_access);
	DEVX_SET(mkc, mkc, lw, 0x1);
	DEVX_SET(mkc, mkc, lr, 0x1);

        DEVX_SET(mkc, mkc, qpn, 0xffffff);

        DEVX_SET(mkc, mkc, pd, mkey_attr.pd);
        DEVX_SET(mkc, mkc, mkey_7_0, mkey_attr.umem_id & 0xFF);
        DEVX_SET(mkc, mkc, umr_en, mkey_attr.umr_en);

        DEVX_SET(mkc, mkc, translations_octword_size, translation_size);

        DEVX_SET(mkc, mkc, relaxed_ordering_write, 0);
	DEVX_SET(mkc, mkc, relaxed_ordering_read, 0);
        DEVX_SET64(mkc, mkc, start_addr, mkey_attr.addr);
	DEVX_SET64(mkc, mkc, len, mkey_attr.size);

        //DEVX_SET(mkc, mkc, crypto_en, 0);

        syslog(LOG_ERR, "GERRY: calling mlx5dv_devx_obj_create for mkey->mkey\n");
        tmp_mkey->obj = mlx5dv_devx_obj_create(ctx->ibv_ctx, in, sizeof(in), out, sizeof(out));
	if (!tmp_mkey->obj) {
                syslog(LOG_ERR, "Failed to create direct mkey!!\n");
		return -ENODEV;
	}
        tmp_mkey->id = DEVX_GET(create_mkey_out, out, mkey_index);
        tmp_mkey->id = (tmp_mkey->id << 8) | (mkey_attr.umem_id & 0xFF);

        syslog(LOG_ERR, "GERRY: tmp_mkey->obj = %p\n", tmp_mkey->obj);
        syslog(LOG_ERR, "GERRY: tmp_mkey->id = 0x%x\n", tmp_mkey->id);

        mkey->mkey = tmp_mkey;

        syslog(LOG_ERR, "GERRY: mkey->mkey = %p\n", mkey->mkey);
        syslog(LOG_ERR, "GERRY: mkey->ptr = %p\n", mkey->ptr);
        syslog(LOG_ERR, "GERRY: mkey->mkey->id = 0x%x\n", mkey->mkey->id);
        syslog(LOG_ERR, "GERRY - leaving rxp_create_mkey\n");
	return 0;
}

static inline void
rxp_destroy_mkey(struct mlx5_regex_mkey *mkey)
{
    int tmp = 0 ;

        syslog(LOG_NOTICE,"GERRY: in rxp_destroy_mkey for mlx5_regex_mkey 0x%x\n", mkey);
        syslog(LOG_NOTICE,"GERRY: in     meky->ptr = %p\n", mkey->ptr);
        syslog(LOG_NOTICE,"GERRY: in     meky->umem = %p\n", mkey->umem);
        syslog(LOG_NOTICE,"GERRY: in     meky->mkey = %p\n", mkey->mkey);
	if (mkey->mkey)
		tmp = mlx5dv_devx_obj_destroy(mkey->mkey->obj);
        syslog(LOG_NOTICE,"GERRY: destroyed mkey for 0x%x, ret = %d\n", mkey->mkey, tmp);

	if (mkey->umem)
                tmp = mlx5dv_devx_umem_dereg(mkey->umem);
        syslog(LOG_NOTICE,"GERRY: deregister umem for 0x%x, ret = %dx\n", mkey->umem, tmp);
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

	caps->supported = DEVX_GET(query_hca_cap_out, out, capability.cmd_hca_cap.regexp_params);
	caps->num_of_engines= DEVX_GET(query_hca_cap_out, out, capability.cmd_hca_cap.regexp_num_of_engines);
#if 0	
	caps->log_crspace_size = DEVX_GET(query_hca_cap_out, out,
					  capability.cmd_hca_cap.regexp_log_crspace_size);
#endif
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

        syslog(LOG_ERR, "GERRY: regex is supported\n");
	return caps.supported;
}

static int
mlx5_devx_regex_database_disconnect(void *ctx, uint8_t engine, uint32_t db_mkey, uint64_t db_mkey_va)
{
	uint32_t out[DEVX_ST_SZ_DW(set_regexp_params_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(set_regexp_params_in)] = {0};
	int err = 0;

        syslog(LOG_ERR, "GERRY: disconnecting db_mkey = 0x%x, db_key_va = %p\n", db_mkey, db_mkey_va);
	DEVX_SET(set_regexp_params_in, in, opcode, MLX5_CMD_SET_REGEX_PARAMS);
	DEVX_SET(set_regexp_params_in, in, engine_id, engine);
        DEVX_SET(set_regexp_params_in, in, regexp_params.stop_engine, 1);
        DEVX_SET(set_regexp_params_in, in, field_select.stop_engine, 1);
	DEVX_SET(set_regexp_params_in, in, regexp_params.db_mkey, db_mkey);
	//DEVX_SET64(set_regexp_params_in, in, regexp_params.db_mkey_free, 1);
	DEVX_SET(set_regexp_params_in, in, regexp_params.db_mkey_free, 1);
	DEVX_SET64(set_regexp_params_in, in, regexp_params.db_mkey_va, db_mkey_va);
	DEVX_SET(set_regexp_params_in, in, field_select.db_mkey, 1);

	err = mlx5dv_devx_general_cmd(ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		syslog(LOG_ERR, "Database disconnect failed %d", err);
		return err;
	}
	return 0;
}

static int
mlx5_regex_database_set(struct mlx5_regex_ctx *ctx, int engine_id)
{
	uint32_t out[DEVX_ST_SZ_DW(set_regexp_params_out)] = {0};
	uint32_t in[DEVX_ST_SZ_DW(set_regexp_params_in)] = {0};
	int err;

	DEVX_SET(set_regexp_params_in, in, opcode, MLX5_CMD_SET_REGEX_PARAMS);
	DEVX_SET(set_regexp_params_in, in, engine_id, engine_id);

        syslog(LOG_ERR, "GERRY: mlx5_regex_database_set 2, engine id = %d \n", engine_id);
	DEVX_SET(set_regexp_params_in, in, regexp_params.stop_engine, 1);
	DEVX_SET(set_regexp_params_in, in, field_select.stop_engine, 1);

        syslog(LOG_ERR, "GERRY: mlx5_regex_database_set 3, db_mkey = %p, id = 0x%x, va = %p \n", ctx->db_ctx[engine_id].mem_desc.mkey,ctx->db_ctx[engine_id].mem_desc.mkey->id, ctx->db_ctx[engine_id].mem_desc.ptr);

	DEVX_SET(set_regexp_params_in, in, regexp_params.db_mkey, ctx->db_ctx[engine_id].mem_desc.mkey->id);
	DEVX_SET64(set_regexp_params_in, in, regexp_params.db_mkey_va, ctx->db_ctx[engine_id].mem_desc.ptr);
	/*  Currently not supported
		DEVX_SET64(set_regexp_params_in, in, regexp_params.db_umem_offset, ctx->db_ctx[engine_id].offset); */
        syslog(LOG_ERR, "GERRY: mlx5_regex_database_set 4 \n");
	DEVX_SET(set_regexp_params_in, in, field_select.db_mkey, 1);

        syslog(LOG_ERR, "GERRY: calling mlx5dv_devx_general_cmd\n");
	if (debug) print_raw(in, 1);
	err = mlx5dv_devx_general_cmd(ctx->ibv_ctx, in, sizeof(in), out, sizeof(out));
	if (err) {
		syslog(LOG_ERR, "Set regexp params failed %d\n", err);
		return err;
	}
        syslog(LOG_ERR, "GERRY: called mlx5dv_devx_general_cmd\n");
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
        int ret;
	/* alloc database 128MB */
	size_t db_size = 1 << 27;

	/* Alloc data - here is a huge page allocation example */
        ctx->db_ctx[engine_id].mem_desc.ptr = mmap(NULL, db_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE | MAP_HUGETLB, -1, 0);

	if (!ctx->db_ctx[engine_id].mem_desc.ptr) {
		syslog(LOG_NOTICE,"Allocation failed\n");
		return -ENOMEM;
	}

        syslog(LOG_ERR, "GERRY: mmap success for engine id %d, ptr = %p\n", engine_id,
                                    ctx->db_ctx[engine_id].mem_desc.ptr);

	/* Register the umem and create mkey */

        ret = rxp_create_mkey(ctx, ctx->db_ctx[engine_id].mem_desc.ptr, db_size, 7, &ctx->db_ctx[engine_id].mem_desc);

        syslog(LOG_ERR, "GERRY: mem_desc = %p, mkey = %p\n", ctx->db_ctx[engine_id].mem_desc, ctx->db_ctx[engine_id].mem_desc.mkey);
        syslog(LOG_ERR, "GERRY: mkey->obj = %p, mkey->id = 0x%x\n", ctx->db_ctx[engine_id].mem_desc.mkey->obj, ctx->db_ctx[engine_id].mem_desc.mkey->id);
#if 0
	ctx->db_ctx[engine_id].mem_desc.umem =
			mlx5dv_devx_umem_reg(ctx->ibv_ctx,
					     ctx->db_ctx[engine_id].mem_desc.ptr,
					     db_size, 7);
#endif
	
	//if (!ctx->db_ctx[engine_id].mem_desc.umem) {
	if (ret < 0) {
		syslog(LOG_ERR,"Registration failed.\n");
		syslog(LOG_ERR,"Please make sure huge pages in the system\n");
		syslog(LOG_ERR,"Hint: cat /proc/meminfo\n");
		syslog(LOG_ERR,"      echo NUM_PAGES > /proc/sys/vm/nr_hugepages\n");
		return -ENOMEM;
	}
        syslog(LOG_ERR, "GERRY: mlx5dv_create_mkey completed\n");
	memset(ctx->db_ctx[engine_id].mem_desc.ptr, 0, db_size);
        syslog(LOG_ERR, "GERRY: mlx5dv_create_mkey completed, memset done\n");
	return 0;
}

void handle_signal(int sig)
{
    int i ;
    int err = 0 ;
        
        if (sig == SIGINT) {
                syslog(LOG_NOTICE, "SIG_INIT recived...\n");
                /* Reset signal handling to default behavior */
                signal(SIGINT, SIG_DFL);
        } else if (sig == SIGHUP) {     
                syslog(LOG_NOTICE, "SIG_HUP recived...\n");
        } else if (sig == SIGCHLD) {
                syslog(LOG_NOTICE, "SIG_CHLD recived...\n");
        }
          else if (sig == SIGTERM) {
                syslog(LOG_NOTICE, "SIG_TERM recived...\n");

                for (i = 0; i < ctx_ptr->caps.num_of_engines; i++) {

                err = mlx5_devx_regex_database_disconnect(ctx_ptr->ibv_ctx, i,
                                 ctx_ptr->db_ctx[i].mem_desc.mkey->id,
                                 ctx_ptr->db_ctx[i].mem_desc.ptr );

                if (err)
                    syslog(LOG_ERR, "GERRY: disconnecting db err = %d for engine %d\n", err, i);

                syslog(LOG_NOTICE, "GERRY: Destroying db mkey for engine %d\n", i);

                    rxp_destroy_mkey(&ctx_ptr->db_ctx[i].mem_desc);

                syslog(LOG_NOTICE, "GERRY: Freeing mkey memory for engine %d\n", i);
                free(ctx_ptr->db_ctx[i].mem_desc.mkey);

                syslog(LOG_NOTICE, "GERRY: Unmapping memory for engine id %d\n", i);
                err = munmap(ctx_ptr->db_ctx[i].mem_desc.ptr, 1 << 27); 
                syslog(LOG_NOTICE, "GERRY: Unmapping memory returned %d\n", err);

                }

                exit(err);
        }
}

static void daemonize()
{
    pid_t pid;
	int x;

    /* Catch, ignore and handle signals */
    signal(SIGCHLD, handle_signal);
    signal(SIGHUP, handle_signal);
    signal(SIGTERM, handle_signal);

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

        ctx->pd = regex_alloc_pd(ibv_ctx);
        syslog(LOG_ERR, "GERRY: pd = %p.\n", ctx->pd);
        if (!ctx->pd) {
                syslog(LOG_ERR, "Devx not supported.\n");
		return -ENOMEM;
        }

	mlx5_regex_query_cap(ctx->ibv_ctx, &ctx->caps);


        syslog(LOG_ERR, "GERRY: caps.num_of_engines = %d", ctx->caps.num_of_engines);
	ctx->db_ctx = malloc(sizeof(*ctx->db_ctx)*ctx->caps.num_of_engines);
	for (i = 0; i < ctx->caps.num_of_engines; i++) {
		err = register_database(ctx, i);
	        syslog(LOG_ERR, "GERRY: err = %d\n", err);		
		if (err)
			return err;
	        syslog(LOG_ERR, "GERRY: calling mlx5_regex_database_set\n");		
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

        ctx_ptr = &ctx ;

        list = ibv_get_device_list(&num);

	if (num == 0) {
		syslog(LOG_NOTICE,"No devices found.\n");
		return -1;
	}

        syslog(LOG_NOTICE, "GERRY: %d devices found\n", num);

	attr.flags = MLX5DV_CONTEXT_FLAGS_DEVX;

	for (i = 0; i < num; i++)
		if (mlx5dv_is_supported(list[devn])) {
			ibv_ctx = mlx5dv_open_device(list[devn], &attr);
		        syslog(LOG_NOTICE, "GERRY: ibv_ctx = %p, i = %d\n", ibv_ctx, i);
			if (ibv_ctx == NULL) {
 					syslog(LOG_ERR, "Devx not supported. 1\n");
                	return -EOPNOTSUPP;
		        }
			if (ibv_ctx && mlx5_regex_is_supported(ibv_ctx)) {
                                syslog(LOG_ERR, "ibv_ctx and regex supported. 1\n");
				err = mlx5_regex_ctx_init(ibv_ctx, &ctx);
				break;
			}
			ibv_close_device(ibv_ctx);
			ibv_ctx = NULL;
		}

	if (ctx.ibv_ctx == NULL) {
		syslog(LOG_NOTICE, "Regex not supported on all devices. num = %d, i = %d\n", num, i);
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

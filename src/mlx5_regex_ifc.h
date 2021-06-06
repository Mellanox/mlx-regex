/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2019 Mellanox Technologies. All Rights Reserved.
 */


#ifndef MLX5_REGEX_IFC_H
#define MLX5_REGEX_IFC_H

#define u8 uint8_t

#define __mlx5_nullp(typ) ((struct mlx5_ifc_##typ##_bits *)0)
#define __mlx5_bit_sz(typ, fld) sizeof(__mlx5_nullp(typ)->fld)
#define __mlx5_bit_off(typ, fld) ((unsigned int)(unsigned long) \
				  (&(__mlx5_nullp(typ)->fld)))
#define __mlx5_dw_bit_off(typ, fld) (32 - __mlx5_bit_sz(typ, fld) - \
				    (__mlx5_bit_off(typ, fld) & 0x1f))
#define __mlx5_dw_off(typ, fld) (__mlx5_bit_off(typ, fld) / 32)
#define __mlx5_64_off(typ, fld) (__mlx5_bit_off(typ, fld) / 64)
#define __mlx5_dw_mask(typ, fld) (__mlx5_mask(typ, fld) << \
				  __mlx5_dw_bit_off(typ, fld))
#define __mlx5_mask(typ, fld) ((u32)((1ull << __mlx5_bit_sz(typ, fld)) - 1))
#define __mlx5_16_off(typ, fld) (__mlx5_bit_off(typ, fld) / 16)
#define __mlx5_16_bit_off(typ, fld) (16 - __mlx5_bit_sz(typ, fld) - \
				    (__mlx5_bit_off(typ, fld) & 0xf))
#define __mlx5_mask16(typ, fld) ((u16)((1ull << __mlx5_bit_sz(typ, fld)) - 1))
#define __mlx5_16_mask(typ, fld) (__mlx5_mask16(typ, fld) << \
				  __mlx5_16_bit_off(typ, fld))
#define MLX5_ST_SZ_BYTES(typ) (sizeof(struct mlx5_ifc_##typ##_bits) / 8)
#define MLX5_ST_SZ_DW(typ) (sizeof(struct mlx5_ifc_##typ##_bits) / 32)
#define MLX5_BYTE_OFF(typ, fld) (__mlx5_bit_off(typ, fld) / 8)
#define MLX5_ADDR_OF(typ, p, fld) ((char *)(p) + MLX5_BYTE_OFF(typ, fld))


/* insert a value to a struct */
#define MLX5_SET(typ, p, fld, v) \
	do { \
		u32 _v = v; \
		*((rte_be32_t *)(p) + __mlx5_dw_off(typ, fld)) = \
		rte_cpu_to_be_32((rte_be_to_cpu_32(*((u32 *)(p) + \
				  __mlx5_dw_off(typ, fld))) & \
				  (~__mlx5_dw_mask(typ, fld))) | \
				 (((_v) & __mlx5_mask(typ, fld)) << \
				   __mlx5_dw_bit_off(typ, fld))); \
	} while (0)

#define MLX5_SET64(typ, p, fld, v) \
	do { \
		MLX5_ASSERT(__mlx5_bit_sz(typ, fld) == 64); \
		*((rte_be64_t *)(p) + __mlx5_64_off(typ, fld)) = \
			rte_cpu_to_be_64(v); \
	} while (0)

#define MLX5_SET16(typ, p, fld, v) \
	do { \
		u16 _v = v; \
		*((rte_be16_t *)(p) + __mlx5_16_off(typ, fld)) = \
		rte_cpu_to_be_16((rte_be_to_cpu_16(*((rte_be16_t *)(p) + \
				  __mlx5_16_off(typ, fld))) & \
				  (~__mlx5_16_mask(typ, fld))) | \
				 (((_v) & __mlx5_mask16(typ, fld)) << \
				  __mlx5_16_bit_off(typ, fld))); \
	} while (0)

#define MLX5_GET_VOLATILE(typ, p, fld) \
	((rte_be_to_cpu_32(*((volatile __be32 *)(p) +\
	__mlx5_dw_off(typ, fld))) >> __mlx5_dw_bit_off(typ, fld)) & \
	__mlx5_mask(typ, fld))
#define MLX5_GET(typ, p, fld) \
	((rte_be_to_cpu_32(*((rte_be32_t *)(p) +\
	__mlx5_dw_off(typ, fld))) >> __mlx5_dw_bit_off(typ, fld)) & \
	__mlx5_mask(typ, fld))
#define MLX5_GET16(typ, p, fld) \
	((rte_be_to_cpu_16(*((rte_be16_t *)(p) + \
	  __mlx5_16_off(typ, fld))) >> __mlx5_16_bit_off(typ, fld)) & \
	 __mlx5_mask16(typ, fld))
#define MLX5_GET64(typ, p, fld) rte_be_to_cpu_64(*((rte_be64_t *)(p) + \
						   __mlx5_64_off(typ, fld)))
#define MLX5_FLD_SZ_BYTES(typ, fld) (__mlx5_bit_sz(typ, fld) / 8)


enum mlx5_cap_mode {
        HCA_CAP_OPMOD_GET_CUR   = 1
};

enum {
	MLX5_SET_HCA_CAP_OP_MOD_GENERAL_DEVICE        = 0x0
};

enum {
	MLX5_CMD_OP_QUERY_HCA_CAP                 = 0x100,
        MLX5_CMD_OP_CREATE_MKEY = 0x200,
	MLX5_CMD_SET_REGEX_PARAMS		  = 0xb04,
	MLX5_CMD_QUERY_REGEX_PARAMS		  = 0xb05,
	MLX5_CMD_SET_REGEX_REGISTERS		  = 0xb06,
	MLX5_CMD_QUERY_REGEX_REGISTERS		  = 0xb07,
	MLX5_CMD_OP_MAX
};

struct mlx5_ifc_cmd_hca_cap_bits {
	u8 reserved_at_0[0x30];
	u8 vhca_id[0x10];
	u8 reserved_at_40[0x40];
	u8 log_max_srq_sz[0x8];
	u8 log_max_qp_sz[0x8];
	u8 reserved_at_90[0x9];
	u8 wqe_index_ignore_cap[0x1];
	u8 dynamic_qp_allocation[0x1];
	u8 log_max_qp[0x5];
	u8 reserved_at_a0[0x4];
	u8 regexp_num_of_engines[0x4];
	u8 reserved_at_a8[0x1];
	u8 reg_c_preserve[0x1];
	u8 reserved_at_aa[0x1];
	u8 log_max_srq[0x5];
	u8 reserved_at_b0[0xb];
	u8 scatter_fcs_w_decap_disable[0x1];
	u8 reserved_at_bc[0x4];
	u8 reserved_at_c0[0x8];
	u8 log_max_cq_sz[0x8];
	u8 reserved_at_d0[0xb];
	u8 log_max_cq[0x5];
	u8 log_max_eq_sz[0x8];
	u8 relaxed_ordering_write[0x1];
	u8 relaxed_ordering_read[0x1];
	u8 access_register_user[0x1];
	u8 log_max_mkey[0x5];
	u8 reserved_at_f0[0x8];
	u8 dump_fill_mkey[0x1];
	u8 reserved_at_f9[0x3];
	u8 log_max_eq[0x4];
	u8 max_indirection[0x8];
	u8 fixed_buffer_size[0x1];
	u8 log_max_mrw_sz[0x7];
	u8 force_teardown[0x1];
	u8 reserved_at_111[0x1];
	u8 log_max_bsf_list_size[0x6];
	u8 umr_extended_translation_offset[0x1];
	u8 null_mkey[0x1];
	u8 log_max_klm_list_size[0x6];
	u8 non_wire_sq[0x1];
	u8 reserved_at_121[0x9];
	u8 log_max_ra_req_dc[0x6];
	u8 reserved_at_130[0x3];
	u8 log_max_static_sq_wq[0x5];
	u8 reserved_at_138[0x2];
	u8 log_max_ra_res_dc[0x6];
	u8 reserved_at_140[0xa];
	u8 log_max_ra_req_qp[0x6];
	u8 reserved_at_150[0xa];
	u8 log_max_ra_res_qp[0x6];
	u8 end_pad[0x1];
	u8 cc_query_allowed[0x1];
	u8 cc_modify_allowed[0x1];
	u8 start_pad[0x1];
	u8 cache_line_128byte[0x1];
	u8 reserved_at_165[0xa];
	u8 qcam_reg[0x1];
	u8 gid_table_size[0x10];
	u8 out_of_seq_cnt[0x1];
	u8 vport_counters[0x1];
	u8 retransmission_q_counters[0x1];
	u8 debug[0x1];
	u8 modify_rq_counter_set_id[0x1];
	u8 rq_delay_drop[0x1];
	u8 max_qp_cnt[0xa];
	u8 pkey_table_size[0x10];
	u8 vport_group_manager[0x1];
	u8 vhca_group_manager[0x1];
	u8 ib_virt[0x1];
	u8 eth_virt[0x1];
	u8 vnic_env_queue_counters[0x1];
	u8 ets[0x1];
	u8 nic_flow_table[0x1];
	u8 eswitch_manager[0x1];
	u8 device_memory[0x1];
	u8 mcam_reg[0x1];
	u8 pcam_reg[0x1];
	u8 local_ca_ack_delay[0x5];
	u8 port_module_event[0x1];
	u8 enhanced_error_q_counters[0x1];
	u8 ports_check[0x1];
	u8 reserved_at_1b3[0x1];
	u8 disable_link_up[0x1];
	u8 beacon_led[0x1];
	u8 port_type[0x2];
	u8 num_ports[0x8];
	u8 reserved_at_1c0[0x1];
	u8 pps[0x1];
	u8 pps_modify[0x1];
	u8 log_max_msg[0x5];
	u8 reserved_at_1c8[0x4];
	u8 max_tc[0x4];
	u8 temp_warn_event[0x1];
	u8 dcbx[0x1];
	u8 general_notification_event[0x1];
	u8 reserved_at_1d3[0x2];
	u8 fpga[0x1];
	u8 rol_s[0x1];
	u8 rol_g[0x1];
	u8 reserved_at_1d8[0x1];
	u8 wol_s[0x1];
	u8 wol_g[0x1];
	u8 wol_a[0x1];
	u8 wol_b[0x1];
	u8 wol_m[0x1];
	u8 wol_u[0x1];
	u8 wol_p[0x1];
	u8 stat_rate_support[0x10];
	u8 reserved_at_1f0[0xc];
	u8 cqe_version[0x4];
	u8 compact_address_vector[0x1];
	u8 striding_rq[0x1];
	u8 reserved_at_202[0x1];
	u8 ipoib_enhanced_offloads[0x1];
	u8 ipoib_basic_offloads[0x1];
	u8 reserved_at_205[0x1];
	u8 repeated_block_disabled[0x1];
	u8 umr_modify_entity_size_disabled[0x1];
	u8 umr_modify_atomic_disabled[0x1];
	u8 umr_indirect_mkey_disabled[0x1];
	u8 umr_fence[0x2];
	u8 reserved_at_20c[0x3];
	u8 drain_sigerr[0x1];
	u8 cmdif_checksum[0x2];
	u8 sigerr_cqe[0x1];
	u8 reserved_at_213[0x1];
	u8 wq_signature[0x1];
	u8 sctr_data_cqe[0x1];
	u8 reserved_at_216[0x1];
	u8 sho[0x1];
	u8 tph[0x1];
	u8 rf[0x1];
	u8 dct[0x1];
	u8 qos[0x1];
	u8 eth_net_offloads[0x1];
	u8 roce[0x1];
	u8 atomic[0x1];
	u8 reserved_at_21f[0x1];
	u8 cq_oi[0x1];
	u8 cq_resize[0x1];
	u8 cq_moderation[0x1];
	u8 reserved_at_223[0x3];
	u8 cq_eq_remap[0x1];
	u8 pg[0x1];
	u8 block_lb_mc[0x1];
	u8 reserved_at_229[0x1];
	u8 scqe_break_moderation[0x1];
	u8 cq_period_start_from_cqe[0x1];
	u8 cd[0x1];
	u8 reserved_at_22d[0x1];
	u8 apm[0x1];
	u8 vector_calc[0x1];
	u8 umr_ptr_rlky[0x1];
	u8 imaicl[0x1];
	u8 reserved_at_232[0x4];
	u8 qkv[0x1];
	u8 pkv[0x1];
	u8 set_deth_sqpn[0x1];
	u8 reserved_at_239[0x3];
	u8 xrc[0x1];
	u8 ud[0x1];
	u8 uc[0x1];
	u8 rc[0x1];
	u8 uar_4k[0x1];
	u8 reserved_at_241[0x8];
	u8 regexp_params[0x1];
	u8 uar_sz[0x6];
	u8 reserved_at_250[0x8];
	u8 log_pg_sz[0x8];
	u8 bf[0x1];
	u8 driver_version[0x1];
	u8 pad_tx_eth_packet[0x1];
	u8 reserved_at_263[0x8];
	u8 log_bf_reg_size[0x5];
	u8 reserved_at_270[0xb];
	u8 lag_master[0x1];
	u8 num_lag_ports[0x4];
	u8 reserved_at_280[0x10];
	u8 max_wqe_sz_sq[0x10];
	u8 reserved_at_2a0[0xc];
	u8 regexp_mmo[0x1];
	u8 regexp_version[0x3];
	u8 max_wqe_sz_rq[0x10];
	u8 max_flow_counter_31_16[0x10];
	u8 max_wqe_sz_sq_dc[0x10];
	u8 reserved_at_2e0[0x7];
	u8 max_qp_mcg[0x19];
	u8 reserved_at_300[0x10];
	u8 flow_counter_bulk_alloc[0x08];
	u8 log_max_mcg[0x8];
	u8 reserved_at_320[0x3];
	u8 log_max_transport_domain[0x5];
	u8 reserved_at_328[0x3];
	u8 log_max_pd[0x5];
	u8 reserved_at_330[0xb];
	u8 log_max_xrcd[0x5];
	u8 nic_receive_steering_discard[0x1];
	u8 receive_discard_vport_down[0x1];
	u8 transmit_discard_vport_down[0x1];
	u8 reserved_at_343[0x5];
	u8 log_max_flow_counter_bulk[0x8];
	u8 max_flow_counter_15_0[0x10];
	u8 modify_tis[0x1];
	u8 flow_counters_dump[0x1];
	u8 reserved_at_360[0x1];
	u8 log_max_rq[0x5];
	u8 reserved_at_368[0x3];
	u8 log_max_sq[0x5];
	u8 reserved_at_370[0x3];
	u8 log_max_tir[0x5];
	u8 reserved_at_378[0x3];
	u8 log_max_tis[0x5];
	u8 basic_cyclic_rcv_wqe[0x1];
	u8 reserved_at_381[0x2];
	u8 log_max_rmp[0x5];
	u8 reserved_at_388[0x3];
	u8 log_max_rqt[0x5];
	u8 reserved_at_390[0x3];
	u8 log_max_rqt_size[0x5];
	u8 reserved_at_398[0x3];
	u8 log_max_tis_per_sq[0x5];
	u8 ext_stride_num_range[0x1];
	u8 reserved_at_3a1[0x2];
	u8 log_max_stride_sz_rq[0x5];
	u8 reserved_at_3a8[0x3];
	u8 log_min_stride_sz_rq[0x5];
	u8 reserved_at_3b0[0x3];
	u8 log_max_stride_sz_sq[0x5];
	u8 reserved_at_3b8[0x3];
	u8 log_min_stride_sz_sq[0x5];
	u8 hairpin[0x1];
	u8 reserved_at_3c1[0x2];
	u8 log_max_hairpin_queues[0x5];
	u8 reserved_at_3c8[0x3];
	u8 log_max_hairpin_wq_data_sz[0x5];
	u8 reserved_at_3d0[0x3];
	u8 log_max_hairpin_num_packets[0x5];
	u8 reserved_at_3d8[0x3];
	u8 log_max_wq_sz[0x5];
	u8 nic_vport_change_event[0x1];
	u8 disable_local_lb_uc[0x1];
	u8 disable_local_lb_mc[0x1];
	u8 log_min_hairpin_wq_data_sz[0x5];
	u8 reserved_at_3e8[0x3];
	u8 log_max_vlan_list[0x5];
	u8 reserved_at_3f0[0x3];
	u8 log_max_current_mc_list[0x5];
	u8 reserved_at_3f8[0x3];
	u8 log_max_current_uc_list[0x5];
	u8 general_obj_types[0x40];
	u8 sq_ts_format[0x2];
	u8 rq_ts_format[0x2];
	u8 reserved_at_444[0x1C];
	u8 reserved_at_460[0x10];
	u8 max_num_eqs[0x10];
	u8 reserved_at_480[0x3];
	u8 log_max_l2_table[0x5];
	u8 reserved_at_488[0x8];
	u8 log_uar_page_sz[0x10];
	u8 reserved_at_4a0[0x20];
	u8 device_frequency_mhz[0x20];
	u8 device_frequency_khz[0x20];
	u8 reserved_at_500[0x20];
	u8 num_of_uars_per_page[0x20];
	u8 flex_parser_protocols[0x20];
	u8 max_geneve_tlv_options[0x8];
	u8 reserved_at_568[0x3];
	u8 max_geneve_tlv_option_data_len[0x5];
	u8 reserverd_at_570[0x4c];
	u8 mini_cqe_resp_stride_index[0x1];
	u8 cqe_128_always[0x1];
	u8 cqe_compression_128[0x1];
	u8 cqe_compression[0x1];
	u8 cqe_compression_timeout[0x10];
	u8 cqe_compression_max_num[0x10];
	u8 reserved_at_5e0[0x10];
	u8 tag_matching[0x1];
	u8 rndv_offload_rc[0x1];
	u8 rndv_offload_dc[0x1];
	u8 log_tag_matching_list_sz[0x5];
	u8 reserved_at_5f8[0x3];
	u8 log_max_xrq[0x5];
	u8 affiliate_nic_vport_criteria[0x8];
	u8 native_port_num[0x8];
	u8 num_vhca_ports[0x8];
	u8 reserved_at_618[0x6];
	u8 sw_owner_id[0x1];
	u8 reserved_at_61f[0x1e1];
};


union mlx5_ifc_hca_cap_union_bits {
	struct mlx5_ifc_cmd_hca_cap_bits cmd_hca_cap;
	u8         reserved_at_0[0x8000];
};

#if 0
union mlx5_ifc_hca_cap_union_bits {
	struct mlx5_ifc_cmd_hca_cap_bits cmd_hca_cap;
	struct mlx5_ifc_per_protocol_networking_offload_caps_bits
	       per_protocol_networking_offload_caps;
	struct mlx5_ifc_qos_cap_bits qos_cap;
	struct mlx5_ifc_virtio_emulation_cap_bits vdpa_caps;
	struct mlx5_ifc_flow_table_nic_cap_bits flow_table_nic_cap;
	struct mlx5_ifc_roce_caps_bits roce_caps;
	u8 reserved_at_0[0x8000];
};
#endif

struct mlx5_ifc_query_hca_cap_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];

	u8         syndrome[0x20];

	u8         reserved_at_40[0x40];

	union mlx5_ifc_hca_cap_union_bits capability;
};

struct mlx5_ifc_query_hca_cap_in_bits {
	u8         opcode[0x10];
	u8         uid[0x10];

	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];
	u8		   other_function[0x1];
	u8		   reserved_at_30[0xf];
	u8		   function_id[0x10];

	u8         reserved_at_40[0x20];
};

struct regexp_params_field_select_bits {
	u8 reserved_at_0[0x1d];
	u8 rof_mkey[0x1];
	u8 stop_engine[0x1];
	u8 db_mkey[0x1];
};

struct mlx5_ifc_regexp_params_bits {
	u8         db_mkey_free[0x1];
	u8         reserved_at_0[0x1e];
	u8         stop_engine[0x1];
        u8 db_mkey[0x20];
	u8 db_mkey_va[0x40];
	u8 rof_mkey[0x20];
	u8 rof_size[0x20];
	u8 rof_mkey_va[0x40];
	u8 reserved_at_100[0x80];
};

struct mlx5_ifc_set_regexp_params_in_bits {
	u8         opcode[0x10];
	u8         uid[0x10];

	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];

	u8         reserved_at_40[0x18];
	u8         engine_id[0x8];
	struct regexp_params_field_select_bits field_select;
	struct mlx5_ifc_regexp_params_bits regexp_params;
};

struct mlx5_ifc_set_regexp_params_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];

	u8         syndrome[0x20];
	u8         reserved_at_18[0x40];
};

struct mlx5_ifc_query_regexp_params_in_bits {
	u8         opcode[0x10];
	u8         uid[0x10];

	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];

	u8         reserved_at_40[0x18];
	u8         engine_id[0x8];
	u8         reserved[0x20];
};

struct mlx5_ifc_query_regexp_params_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];

	u8         syndrome[0x20];
	u8         reserved[0x40];
	struct mlx5_ifc_regexp_params_bits regexp_params;
};

struct mlx5_ifc_set_regexp_register_in_bits {
	u8         opcode[0x10];
	u8         uid[0x10];

	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];

	u8         reserved_at_40[0x18];
	u8         engine_id[0x8];
	u8         register_address[0x20];
	u8         register_data[0x20];
	u8         reserved[0x40];
};

struct mlx5_ifc_set_regexp_register_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];

	u8         syndrome[0x20];
	u8         reserved[0x40];
};

struct mlx5_ifc_query_regexp_register_in_bits {
	u8         opcode[0x10];
	u8         uid[0x10];

	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];

	u8         reserved_at_40[0x18];
	u8         engine_id[0x8];
	u8         register_address[0x20];
};

struct mlx5_ifc_query_regexp_register_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];

	u8         syndrome[0x20];
	u8         reserved[0x20];
	u8         register_data[0x20];
};

struct mlx5_ifc_mkc_bits {
	u8         reserved_at_0[0x1];
	u8         free[0x1];
	u8         reserved_at_2[0x1];
	u8         access_mode_4_2[0x3];
	u8         reserved_at_6[0x7];
	u8         relaxed_ordering_write[0x1];
	u8         reserved_at_e[0x1];
	u8         small_fence_on_rdma_read_response[0x1];
	u8         umr_en[0x1];
	u8         a[0x1];
	u8         rw[0x1];
	u8         rr[0x1];
	u8         lw[0x1];
	u8         lr[0x1];
	u8         access_mode_1_0[0x2];
	u8         reserved_at_18[0x8];
	u8         qpn[0x18];
	u8         mkey_7_0[0x8];
	u8         reserved_at_40[0x20];
	u8         length64[0x1];
	u8         bsf_en[0x1];
	u8         sync_umr[0x1];
	u8         reserved_at_63[0x2];
	u8         expected_sigerr_count[0x1];
	u8         reserved_at_66[0x1];
	u8         en_rinval[0x1];
	u8         pd[0x18];
	u8         start_addr[0x40];
	u8         len[0x40];
	u8         bsf_octword_size[0x20];
	u8         reserved_at_120[0x80];
	u8         translations_octword_size[0x20];
	u8         reserved_at_1c0[0x19];
	u8		   relaxed_ordering_read[0x1];
	u8		   reserved_at_1da[0x1];
	u8         log_page_size[0x5];
	u8         reserved_at_1e0[0x20];
};

struct mlx5_ifc_create_mkey_out_bits {
	u8         status[0x8];
	u8         reserved_at_8[0x18];
	u8         syndrome[0x20];
	u8         reserved_at_40[0x8];
	u8         mkey_index[0x18];
	u8         reserved_at_60[0x20];
};

struct mlx5_ifc_create_mkey_in_bits {
	u8         opcode[0x10];
	u8         reserved_at_10[0x10];
	u8         reserved_at_20[0x10];
	u8         op_mod[0x10];
	u8         reserved_at_40[0x20];
	u8         pg_access[0x1];
	u8         reserved_at_61[0x1f];
	struct mlx5_ifc_mkc_bits memory_key_mkey_entry;
	u8         reserved_at_280[0x80];
	u8         translations_octword_actual_size[0x20];
	u8         mkey_umem_id[0x20];
	u8         mkey_umem_offset[0x40];
	u8         reserved_at_380[0x500];
	u8         klm_pas_mtt[][0x20];
};

enum {
        MLX5_MKC_ACCESS_MODE_MTT   = 0x1,
        MLX5_MKC_ACCESS_MODE_KLM   = 0x2,
        MLX5_MKC_ACCESS_MODE_KLM_FBS = 0x3,
};

#endif /* MLX5_REGEX_IFC_H */

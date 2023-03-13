#ifndef LFSCK_H
#define LFSCK_H

/* This is unfortunately needed for older lustre_user.h to be usable */
#define LASSERT(cond)		do { } while (0)

#ifdef HAVE_LUSTRE_LUSTREAPI_H
#include <lustre/lustreapi.h>
#elif HAVE_LUSTRE_LIBLUSTREAPI_H
#include <lustre/liblustreapi.h>
#endif

#ifndef DFID
#define DFID "[%#llx:0x%x:0x%x]"
#define PFID(fid) (unsigned long long)fid_seq(fid), fid_oid(fid), fid_ver(fid)
struct lu_fid {
	__u64   f_seq;
	__u32   f_oid;
	__u32   f_ver;
};
#endif /* !DFID */

/* Unfortunately, neither the 1.8 or 2.x lustre_idl.h file is suitable
 * for inclusion by userspace programs because of external dependencies.
 * Define the minimum set of replacement functions here until that is fixed. */
#ifndef HAVE_LUSTRE_LUSTRE_IDL_H
#define fid_seq(fid) ((fid)->f_seq)
#define fid_oid(fid) ((fid)->f_oid)
#define fid_ver(fid) ((fid)->f_ver)

static inline void fid_be_to_cpu(struct lu_fid *dst, struct lu_fid *src)
{
	dst->f_seq = ext2fs_be64_to_cpu(src->f_seq);
	dst->f_oid = ext2fs_be32_to_cpu(src->f_oid);
	dst->f_ver = ext2fs_be32_to_cpu(src->f_ver);
}

static inline void fid_le_to_cpu(struct lu_fid *dst, struct lu_fid *src)
{
	dst->f_seq = ext2fs_le64_to_cpu(src->f_seq);
	dst->f_oid = ext2fs_le32_to_cpu(src->f_oid);
	dst->f_ver = ext2fs_le32_to_cpu(src->f_ver);
}
#endif /* HAVE_LUSTRE_LUSTRE_IDL_H */

#define LUSTRE_XATTR_MDT_LOV	"lov"
#define LUSTRE_XATTR_MDT_LMA	"lma"
#define LUSTRE_XATTR_MDT_LINK	"link"
#define LUSTRE_XATTR_OST_FID	"fid"

#ifndef LMA_OLD_SIZE
#ifndef LMA_INCOMPAT_SUPP
struct lustre_mdt_attrs {
	__u32		lma_compat;
	__u32		lma_incompat;
	struct lu_fid	lma_self_fid;
};
struct lustre_ost_attrs {
	struct lustre_mdt_attrs	loa_lma;
	struct lu_fid		loa_parent_fid;
	__u32			loa_stripe_size;
	__u32			loa_pfl_id;
	__u64			loa_pfl_start;
	__u64			loa_pfl_end;
};
#endif

struct filter_fid_old {
	struct lu_fid	ff_parent;
	__u64		ff_objid;
	__u64		ff_seq;
};

struct filter_fid_210 {
	struct lu_fid	ff_parent;
	__u32		ff_stripe_size;
	__u32		ff_stripe_count;
	__u64		ff_pfl_start;
	__u64		ff_pfl_end;
	__u32		ff_pfl_id;
};

struct filter_fid {
	struct lu_fid	ff_parent;
	__u32		ff_stripe_size;
	__u32		ff_stripe_count;
	__u64		ff_pfl_start;
	__u64		ff_pfl_end;
	__u32		ff_pfl_id;
	__u32		ff_layout_version;
	__u32		ff_range;
} __attribute__((packed));

#define LMA_OLD_SIZE 64
#endif /* !LMA_OLD_SIZE */

#define PFID_STRIPE_IDX_BITS	16
#define PFID_STRIPE_COUNT_MASK	((1 << PFID_STRIPE_IDX_BITS) - 1)

#ifndef LINK_EA_MAGIC
/** Hardlink data is name and parent fid.
 * Stored in this crazy struct for maximum packing and endian-neutrality */
struct link_ea_entry {
	/** lee_reclen is a __u16 stored big-endian, unaligned */
	unsigned char	lee_reclen[2];	/* record size in bytes */
	unsigned char	lee_parent_fid[sizeof(struct lu_fid)];
	char		lee_name[0];	/* filename without trailing NUL */
}__attribute__((packed));

/** The link ea holds 1 \a link_ea_entry for each hardlink */
#define LINK_EA_MAGIC 0x11EAF1DFUL
struct link_ea_header {
	__u32 leh_magic;		/* LINK_EA_MAGIC */
	__u32 leh_reccount;		/* number of records in leh_entry[] */
	__u64 leh_len;			/* total size in bytes */
	__u32 leh_overflow_time;	/* when link xattr ran out of space */
	__u32 padding;
	struct link_ea_entry leh_entry[0]; /* packed array of variable-size entries */
};
#endif

#endif /* LFSCK_H */

/*
 * The rough manner in which shadow copies work (at least from the perspective
 * of this module) is as follows. When you traverse to the "Previous Versions"
 * tab in the properties menu in the Windows Explorer shell, the
 * get_shadow_copy_data function in this module is invoked with the name of
 * the directory containing the file in question. After this module returns
 * a list of available "Volume labels" (snapshots), windows begins stat'ing
 * them in sequence using some combination of the path, the filename and the
 * @GMT formatted Volume label. For example,
 *
 * path/@GMT-*/to/file
 * @GMT-*/path/to.file
 * ./@GMT-*/file
 *
 * These are translated into absolute pathnames corresponding to snapshots
 * using the HAMMER TID format by this module. Windows looks at the stat
 * results of each valid return and lists all versions of the file which it
 * deems to be different based on the stat result.
 */

// XXX
#include <syslog.h>
#include <stdarg.h>
// XXX

#include <fcntl.h>
#include <string.h>
#include <time.h>

#include <sys/param.h>
#include <sys/queue.h>
#include <fs/hammer/hammer_disk.h>
#include <fs/hammer/hammer_ioctl.h>

#include "includes.h"

typedef struct hammer_snapshot {
    hammer_tid_t        tid;
    u_int64_t           ts;
    char                label[64];
    TAILQ_ENTRY(hammer_snapshot)	snap;
} *hammer_snapshot_t;

TAILQ_HEAD(hammer_snapshots_list, hammer_snapshot);
typedef struct hammer_snapshots {
    u_int32_t				count;
    TAILQ_HEAD(, hammer_snapshot)	snaps;
} *hammer_snapshots_t;

static
void
hammer_free_snapshots(hammer_snapshots_t snapshots)
{
    (void)talloc_free(snapshots);
}

static
hammer_snapshots_t
hammer_get_snapshots(TALLOC_CTX *mem_ctx, int fd)
{
    struct hammer_ioc_pseudofs_rw ioc_pfs;
    struct hammer_pseudofs_data pfs_data;
    struct hammer_ioc_info ioc_info;
    struct hammer_ioc_snapshot ioc_snapshot;
    hammer_snapshots_t ret_snapshots;
    int i;

    memset(&ioc_pfs, 0, sizeof(ioc_pfs));
    memset(&pfs_data, 0, sizeof(pfs_data));
    ioc_pfs.pfs_id = -1;
    ioc_pfs.ondisk = &pfs_data;
    ioc_pfs.bytes = sizeof(pfs_data);
    if (ioctl(fd, HAMMERIOC_GET_PSEUDOFS, &ioc_pfs) < 0)
        return (NULL);

    memset(&ioc_info, 0, sizeof(ioc_info));
    if (ioctl(fd, HAMMERIOC_GET_INFO, &ioc_info) < 0)
        return (NULL);

    ret_snapshots = (hammer_snapshots_t)
        talloc_size(mem_ctx, sizeof(*ret_snapshots));
    if (ret_snapshots == NULL)
        return (NULL);

    ret_snapshots->count = 0;
    TAILQ_INIT(&ret_snapshots->snaps);

    memset(&ioc_snapshot, 0, sizeof(ioc_snapshot));
    do {
        if (ioctl(fd, HAMMERIOC_GET_SNAPSHOT, &ioc_snapshot) < 0)
            goto fail;

        for (i = 0; i < ioc_snapshot.count; ++i) {
            struct hammer_snapshot_data *snap = &ioc_snapshot.snaps[i];
            hammer_snapshot_t ret_snap;            

            ret_snap = (hammer_snapshot_t)
                talloc_size(ret_snapshots, sizeof(*ret_snap));
            if (ret_snap == NULL)
                goto fail;

            memcpy(&ret_snap->tid, &snap->tid, sizeof(ret_snap->tid));
            memcpy(&ret_snap->ts, &snap->ts, sizeof(ret_snap->ts));
            memcpy(&ret_snap->label, &snap->label, sizeof(*ret_snap->label));

            TAILQ_INSERT_HEAD(&ret_snapshots->snaps, ret_snap, snap);
            ++ret_snapshots->count;
        }
    } while (ioc_snapshot.head.error == 0 && ioc_snapshot.count > 0);

    return (ret_snapshots);

fail:
    hammer_free_snapshots(ret_snapshots);
    return (NULL);
}

static
int
hammer_fstat(vfs_handle_struct *handle, files_struct *fsp,
             SMB_STRUCT_STAT *sbuf)
{
    return (SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf));
}

static
int
hammer_lstat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
    return (SMB_VFS_NEXT_LSTAT(handle, smb_fname));
}

static
int
hammer_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
    int ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
    char *l = NULL;

/* XXX: MAD HAX BEWARE ZOMG */

#define SHADOW_COPY_PREFIX "@GMT-"
    l = strnstr(smb_fname->base_name, SHADOW_COPY_PREFIX, sizeof(SHADOW_COPY_PREFIX));
    if (l != NULL) {
        strncpy(l, "@@0x00000002058622d0", 20);
        l += 20;
        strncpy(l, l + 4, strlen(l + 4));
        smb_fname->base_name[strlen(smb_fname->base_name) - 4] = '\0';
        ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
    }

    return (ret);
}

static
int
hammer_open(vfs_handle_struct *handle, struct smb_filename *smb_fname,
            files_struct *fsp, int flags, mode_t mode)
{
    return (SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode));
}

static
SMB_STRUCT_DIR *
hammer_opendir(vfs_handle_struct *handle, const char *path, const char *mask,
               uint32 attr)
{
    SMB_STRUCT_DIR *sd = SMB_VFS_NEXT_OPENDIR(handle, path, mask, attr);

syslog(LOG_CRIT, "HAMMER: hammer_opendir: path: %s, mask: %s", path, mask);

    while (1) {
        SMB_STRUCT_DIRENT *d;

        d = SMB_VFS_NEXT_READDIR(handle, sd, NULL);
        if (d == NULL)
            break;

// syslog(LOG_CRIT, "HAMMER: hammer_opendir, hide?: %s", d->d_name);
    }

    SMB_VFS_NEXT_REWINDDIR(handle, sd);
    return (sd);
}



#define GMT_LABEL_FORMAT	"@GMT-%Y.%m.%d-%H.%M.%S"

static
int
hammer_get_shadow_copy_data(vfs_handle_struct *handle, files_struct *fsp,
                            SHADOW_COPY_DATA *shadow_copy_data, bool labels)
{
    int filled_labels = 0;
    int fd, error = -1;
    hammer_snapshots_t snapshots;
    hammer_snapshot_t snapshot;

    shadow_copy_data->num_volumes = 0;
    shadow_copy_data->labels = NULL;

    fd = open(fsp->conn->connectpath, O_RDONLY);
    if (fd < 0)
        return (error);

    snapshots = hammer_get_snapshots(shadow_copy_data->mem_ctx, fd);
    if (snapshots == NULL) {
        close(fd);
        return (error);
    }

snapshots->count = 3; // XXX
syslog(LOG_CRIT, "HAMMER: Got %d snapshots for file/dir", snapshots->count);
    shadow_copy_data->num_volumes = snapshots->count;
    error = 0;

    if (labels) {
syslog(LOG_CRIT, "Filling labels");
        SHADOW_COPY_LABEL *rlabels = TALLOC_ZERO_ARRAY(shadow_copy_data->mem_ctx,
           SHADOW_COPY_LABEL, snapshots->count);
        if (rlabels == NULL)
            goto done;

        TAILQ_FOREACH(snapshot, &snapshots->snaps, snap) {
            time_t t = snapshot->ts / 1000000ULL;
            struct tm *tp = gmtime(&t);
            strftime(rlabels[filled_labels++], sizeof(*rlabels),
                GMT_LABEL_FORMAT, tp);

            syslog(LOG_CRIT, "HAMMER: Adding label: %s", rlabels[filled_labels-1]);
if (filled_labels == 3) break; // XXX
        }

        shadow_copy_data->labels = rlabels;
    }

syslog(LOG_CRIT, "HAMMER: Filled %d labels", filled_labels);
syslog(LOG_CRIT, "HAMMER: Found %d snapshots", shadow_copy_data->num_volumes);

done:
    close(fd);
    hammer_free_snapshots(snapshots);
    return (error);
}


static struct vfs_fn_pointers vfs_hammer_shadow_copy_fns = {
    .fstat = hammer_fstat,
    .lstat = hammer_lstat,
    .stat = hammer_stat,
    .open = hammer_open,
    .opendir = hammer_opendir,
    .get_shadow_copy_data = hammer_get_shadow_copy_data
};

NTSTATUS init_samba_module(void)
{
    NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
        "vfs_hammer_shadow_copy", &vfs_hammer_shadow_copy_fns);

    if (!NT_STATUS_IS_OK(ret))
        return (ret);

    syslog(LOG_CRIT, "HAMMER: init_samba_module");

    return (ret);
}

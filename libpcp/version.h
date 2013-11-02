#ifndef _HAVE_PCP_VERSION
#define _HAVE_PCP_VERSION

#define PCP_VERSION_MAJOR 0
#define PCP_VERSION_MINOR 1
#define PCP_VERSION_PATCH 2

#define PCP_MAKE_VERSION(major, minor, patch) \
    ((major) * 10000 + (minor) * 100 + (patch))
#define PCP_VERSION \
    PCP_MAKE_VERSION(PCP_VERSION_MAJOR, PCP_VERSION_MINOR, PCP_VERSION_PATCH)

int pcp_version();

#endif // _HAVE_PCP_VERSION

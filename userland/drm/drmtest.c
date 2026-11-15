/*
 * drmtest: shows a picture through /dev/dri/card0 with the legacy KMS
 * ioctls, as a Wayland compositor or a KMS demo would, and checks the
 * keyboard's evdev node. Raw ioctls: the structures and numbers are
 * Linux's (include/uapi/drm/drm.h, drm_mode.h, linux/input.h), written
 * out here because musl does not ship the kernel's headers.
 *
 * It shows a red|blue frame with SETCRTC, then page-flips to a green one
 * with DRM_MODE_PAGE_FLIP_EVENT and reads the flip's event from the fd.
 * On success it prints "DRMTEST-OK WxH" and keeps the picture up until
 * it is killed. With --pause it stops on the red|blue frame first: it
 * prints "DRMTEST-SHOWN" and flips on SIGUSR1 (so the screen can be
 * checked in both states).
 */
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

struct drm_version {
	int version_major, version_minor, version_patchlevel;
	size_t name_len;
	char *name;
	size_t date_len;
	char *date;
	size_t desc_len;
	char *desc;
};

struct drm_mode_card_res {
	uint64_t fb_id_ptr, crtc_id_ptr, connector_id_ptr, encoder_id_ptr;
	uint32_t count_fbs, count_crtcs, count_connectors, count_encoders;
	uint32_t min_width, max_width, min_height, max_height;
};

struct drm_mode_modeinfo {
	uint32_t clock;
	uint16_t hdisplay, hsync_start, hsync_end, htotal, hskew;
	uint16_t vdisplay, vsync_start, vsync_end, vtotal, vscan;
	uint32_t vrefresh, flags, type;
	char name[32];
};

struct drm_mode_get_connector {
	uint64_t encoders_ptr, modes_ptr, props_ptr, prop_values_ptr;
	uint32_t count_modes, count_props, count_encoders;
	uint32_t encoder_id, connector_id, connector_type, connector_type_id;
	uint32_t connection, mm_width, mm_height, subpixel, pad;
};

struct drm_mode_get_encoder {
	uint32_t encoder_id, encoder_type, crtc_id, possible_crtcs,
	    possible_clones;
};

struct drm_mode_crtc {
	uint64_t set_connectors_ptr;
	uint32_t count_connectors, crtc_id, fb_id, x, y, gamma_size,
	    mode_valid;
	struct drm_mode_modeinfo mode;
};

struct drm_mode_create_dumb {
	uint32_t height, width, bpp, flags, handle, pitch;
	uint64_t size;
};

struct drm_mode_map_dumb {
	uint32_t handle, pad;
	uint64_t offset;
};

struct drm_mode_fb_cmd2 {
	uint32_t fb_id, width, height, pixel_format, flags;
	uint32_t handles[4], pitches[4], offsets[4];
	uint64_t modifier[4];
};

struct drm_mode_crtc_page_flip {
	uint32_t crtc_id, fb_id, flags, reserved;
	uint64_t user_data;
};

struct drm_get_cap {
	uint64_t capability, value;
};

struct drm_event_vblank {
	uint32_t type, length;
	uint64_t user_data;
	uint32_t tv_sec, tv_usec, sequence, crtc_id;
};

#define D(nr, t) _IOWR('d', nr, struct t)
#define DRM_IOCTL_VERSION D(0x00, drm_version)
#define DRM_IOCTL_GET_CAP D(0x0c, drm_get_cap)
#define DRM_IOCTL_MODE_GETRESOURCES D(0xa0, drm_mode_card_res)
#define DRM_IOCTL_MODE_GETCRTC D(0xa1, drm_mode_crtc)
#define DRM_IOCTL_MODE_SETCRTC D(0xa2, drm_mode_crtc)
#define DRM_IOCTL_MODE_GETENCODER D(0xa6, drm_mode_get_encoder)
#define DRM_IOCTL_MODE_GETCONNECTOR D(0xa7, drm_mode_get_connector)
#define DRM_IOCTL_MODE_PAGE_FLIP D(0xb0, drm_mode_crtc_page_flip)
#define DRM_IOCTL_MODE_CREATE_DUMB D(0xb2, drm_mode_create_dumb)
#define DRM_IOCTL_MODE_MAP_DUMB D(0xb3, drm_mode_map_dumb)
#define DRM_IOCTL_MODE_ADDFB2 D(0xb8, drm_mode_fb_cmd2)

#define DRM_CAP_DUMB_BUFFER 0x1
#define DRM_MODE_PAGE_FLIP_EVENT 0x01
#define DRM_EVENT_FLIP_COMPLETE 0x02
#define DRM_FORMAT_XRGB8888 0x34325258 /* 'XR24' */

#define EVIOCGVERSION _IOR('E', 0x01, int)
#define EVIOCGNAME(len) _IOC(_IOC_READ, 'E', 0x06, len)
#define EVIOCGBIT(ev, len) _IOC(_IOC_READ, 'E', 0x20 + (ev), len)
#define EV_KEY 0x01
#define KEY_A 30
#define KEY_ENTER 28

static int card;
static volatile sig_atomic_t go;

static void on_usr1(int sig)
{
	(void)sig;
	go = 1;
}

static void die(const char *what)
{
	printf("DRMTEST-FAIL %s: %s\n", what, strerror(errno));
	exit(1);
}

static void check(int ok, const char *what)
{
	if (!ok) {
		printf("DRMTEST-FAIL %s\n", what);
		exit(1);
	}
}

static void io(unsigned long req, void *arg, const char *what)
{
	if (ioctl(card, req, arg) != 0)
		die(what);
}

struct buffer {
	uint32_t handle, pitch, fb;
	uint64_t size;
	uint32_t *pixels;
};

/* A dumb buffer of w x h, mapped, wrapped in an XRGB8888 framebuffer. */
static void make_buffer(struct buffer *b, uint32_t w, uint32_t h)
{
	struct drm_mode_create_dumb c = {.height = h, .width = w, .bpp = 32};
	io(DRM_IOCTL_MODE_CREATE_DUMB, &c, "CREATE_DUMB");
	check(c.pitch >= w * 4 && c.size >= (uint64_t)c.pitch * h,
	      "CREATE_DUMB: pitch or size too small");
	struct drm_mode_map_dumb m = {.handle = c.handle};
	io(DRM_IOCTL_MODE_MAP_DUMB, &m, "MAP_DUMB");
	void *p = mmap(0, c.size, PROT_READ | PROT_WRITE, MAP_SHARED, card,
		       m.offset);
	if (p == MAP_FAILED)
		die("mmap of the dumb buffer");
	struct drm_mode_fb_cmd2 f = {
	    .width = w,
	    .height = h,
	    .pixel_format = DRM_FORMAT_XRGB8888,
	    .handles = {c.handle},
	    .pitches = {c.pitch},
	};
	io(DRM_IOCTL_MODE_ADDFB2, &f, "ADDFB2");
	check(f.fb_id != 0, "ADDFB2 gave no framebuffer id");
	b->handle = c.handle;
	b->pitch = c.pitch;
	b->size = c.size;
	b->fb = f.fb_id;
	b->pixels = p;
}

static void fill(struct buffer *b, uint32_t w, uint32_t h, uint32_t left,
		 uint32_t right)
{
	for (uint32_t y = 0; y < h; y++) {
		uint32_t *row = b->pixels + (uint64_t)y * (b->pitch / 4);
		for (uint32_t x = 0; x < w; x++)
			row[x] = x < w / 2 ? left : right;
	}
}

static int bit(const unsigned char *bits, int n)
{
	return bits[n / 8] >> (n % 8) & 1;
}

static void evdev(void)
{
	int fd = open("/dev/input/event0", O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		die("open /dev/input/event0");
	int version = 0;
	if (ioctl(fd, EVIOCGVERSION, &version) != 0)
		die("EVIOCGVERSION");
	char name[256] = {0};
	if (ioctl(fd, EVIOCGNAME(sizeof name), name) < 0)
		die("EVIOCGNAME");
	unsigned char types[4] = {0}, keys[96] = {0};
	if (ioctl(fd, EVIOCGBIT(0, sizeof types), types) < 0)
		die("EVIOCGBIT(0)");
	if (ioctl(fd, EVIOCGBIT(EV_KEY, sizeof keys), keys) < 0)
		die("EVIOCGBIT(EV_KEY)");
	printf("evdev: event0 \"%s\" version %#x, event types %#x, "
	       "KEY_A %d, KEY_ENTER %d\n",
	       name, version, types[0] | types[1] << 8 | types[2] << 16,
	       bit(keys, KEY_A), bit(keys, KEY_ENTER));
	check(name[0] != 0, "EVIOCGNAME: empty name");
	check(bit(types, EV_KEY), "EVIOCGBIT(0): no EV_KEY");
	check(bit(keys, KEY_A) && bit(keys, KEY_ENTER),
	      "EVIOCGBIT(EV_KEY): no KEY_A or KEY_ENTER");
	close(fd);
}

int main(int argc, char **argv)
{
	int pause_first = argc > 1 && strcmp(argv[1], "--pause") == 0;
	setvbuf(stdout, 0, _IONBF, 0);
	if (pause_first) {
		sigset_t usr1;
		sigemptyset(&usr1);
		sigaddset(&usr1, SIGUSR1);
		sigprocmask(SIG_BLOCK, &usr1, 0);
		signal(SIGUSR1, on_usr1);
	}
	evdev();

	card = open("/dev/dri/card0", O_RDWR | O_CLOEXEC);
	if (card < 0)
		die("open /dev/dri/card0");
	char drv[32] = {0};
	struct drm_version v = {.name_len = sizeof drv - 1, .name = drv};
	io(DRM_IOCTL_VERSION, &v, "VERSION");
	struct drm_get_cap cap = {.capability = DRM_CAP_DUMB_BUFFER};
	io(DRM_IOCTL_GET_CAP, &cap, "GET_CAP");
	check(cap.value == 1, "no DRM_CAP_DUMB_BUFFER");

	uint32_t crtcs[4], conns[4], encs[4];
	struct drm_mode_card_res res = {0};
	io(DRM_IOCTL_MODE_GETRESOURCES, &res, "GETRESOURCES (counts)");
	check(res.count_crtcs >= 1 && res.count_crtcs <= 4 &&
		  res.count_connectors >= 1 && res.count_connectors <= 4 &&
		  res.count_encoders >= 1 && res.count_encoders <= 4,
	      "GETRESOURCES: odd counts");
	res.fb_id_ptr = 0;
	res.count_fbs = 0;
	res.crtc_id_ptr = (uintptr_t)crtcs;
	res.connector_id_ptr = (uintptr_t)conns;
	res.encoder_id_ptr = (uintptr_t)encs;
	io(DRM_IOCTL_MODE_GETRESOURCES, &res, "GETRESOURCES");

	struct drm_mode_modeinfo modes[8];
	uint32_t enc_ids[4];
	struct drm_mode_get_connector conn = {.connector_id = conns[0]};
	io(DRM_IOCTL_MODE_GETCONNECTOR, &conn, "GETCONNECTOR (counts)");
	check(conn.connection == 1, "connector not connected");
	check(conn.count_modes >= 1 && conn.count_modes <= 8 &&
		  conn.count_encoders <= 4,
	      "GETCONNECTOR: odd counts");
	conn.modes_ptr = (uintptr_t)modes;
	conn.encoders_ptr = (uintptr_t)enc_ids;
	conn.count_props = 0;
	io(DRM_IOCTL_MODE_GETCONNECTOR, &conn, "GETCONNECTOR");
	struct drm_mode_modeinfo mode = modes[0];
	uint32_t w = mode.hdisplay, h = mode.vdisplay;
	check(w > 0 && h > 0, "mode of size 0");

	struct drm_mode_get_encoder enc = {.encoder_id = conn.encoder_id};
	if (!enc.encoder_id)
		enc.encoder_id = enc_ids[0];
	io(DRM_IOCTL_MODE_GETENCODER, &enc, "GETENCODER");
	uint32_t crtc = enc.crtc_id ? enc.crtc_id : crtcs[0];
	printf("drm: driver %s, %u crtc(s), connector %u, encoder %u, crtc "
	       "%u, mode %s %ux%u@%u\n",
	       drv, res.count_crtcs, conn.connector_id, enc.encoder_id, crtc,
	       mode.name, w, h, mode.vrefresh);

	struct buffer a, b;
	make_buffer(&a, w, h);
	make_buffer(&b, w, h);
	fill(&a, w, h, 0x00FF0000, 0x000000FF);
	fill(&b, w, h, 0x0000FF00, 0x0000FF00);

	struct drm_mode_crtc set = {
	    .set_connectors_ptr = (uintptr_t)&conn.connector_id,
	    .count_connectors = 1,
	    .crtc_id = crtc,
	    .fb_id = a.fb,
	    .mode_valid = 1,
	    .mode = mode,
	};
	io(DRM_IOCTL_MODE_SETCRTC, &set, "SETCRTC");
	struct drm_mode_crtc got = {.crtc_id = crtc};
	io(DRM_IOCTL_MODE_GETCRTC, &got, "GETCRTC");
	check(got.fb_id == a.fb && got.mode_valid, "GETCRTC: not showing");
	if (pause_first) {
		sigset_t none;
		sigemptyset(&none);
		printf("DRMTEST-SHOWN\n");
		while (!go)
			sigsuspend(&none);
	}

	struct drm_mode_crtc_page_flip flip = {
	    .crtc_id = crtc,
	    .fb_id = b.fb,
	    .flags = DRM_MODE_PAGE_FLIP_EVENT,
	    .user_data = 0x5e605e60,
	};
	io(DRM_IOCTL_MODE_PAGE_FLIP, &flip, "PAGE_FLIP");
	struct drm_event_vblank ev;
	ssize_t n = read(card, &ev, sizeof ev);
	if (n < 0)
		die("read of the flip event");
	check(n == 32, "flip event is not 32 bytes");
	printf("drm: event type %u, length %u, user_data %#llx, crtc %u\n",
	       ev.type, ev.length, (unsigned long long)ev.user_data,
	       ev.crtc_id);
	check(ev.type == DRM_EVENT_FLIP_COMPLETE, "event is not FLIP_COMPLETE");
	check(ev.length == 32 && ev.user_data == 0x5e605e60,
	      "flip event length or user_data wrong");

	printf("DRMTEST-OK %ux%u\n", w, h);
	for (;;)
		pause();
}

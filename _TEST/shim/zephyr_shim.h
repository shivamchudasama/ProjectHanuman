/**
 * @file          zephyr_shim.h
 * @brief         Minimal, single-threaded stand-in for the Zephyr kernel,
 *                logging and Bluetooth APIs used by the libraries in _LIB and
 *                the application modules in _ASW, so that they can be
 *                exercised on a host PC by the tests in _TEST/unit.
 *
 *                - Time is simulated (gi64_simNowMs); timers fire only when
 *                  the test calls gv_SimFireTimers(), delayable work only
 *                  when it calls gb_SimRunDelayedWork().
 *                - A k_sem_take() that would block calls gv_SimOnBlock() so the
 *                  simulated link can complete notifications and free credits.
 *                  Inside gv_SimRunThread() a K_FOREVER wait that cannot be
 *                  satisfied ends the thread body (see zephyr_sim.c).
 *                - LOG_* and APP_LOG_* lines are captured (gv_SimLog*) and
 *                  printed only with gb_simVerbose.
 *                - __ASSERT failures can be trapped with SIM_EXPECT_ASSERT().
 *                - bt_gatt_notify_cb, bt_gatt_write_without_response_cb,
 *                  bt_gatt_discover, bt_gatt_subscribe, bt_gatt_unsubscribe,
 *                  bt_gatt_exchange_mtu, bt_gatt_write,
 *                  bt_gatt_is_subscribed and bt_gatt_get_mtu are implemented
 *                  by the test that needs them (simulated link and peer), as
 *                  are the address, advertising, scanning, connection, SMP,
 *                  OOB and bond functions (declarations only).
 *
 * @date          22/09/2026
 * @author        Shivam Chudasama
 * @copyright     Shivam Chudasama
 * @license       MIT
 */

/* SPDX-License-Identifier: MIT */

#ifndef _ZEPHYR_SHIM_H
#define _ZEPHYR_SHIM_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
#include <sys/types.h>

/* ---- errno values missing from some host C libraries (old MinGW) -------- */
#ifndef ENOTCONN
#define ENOTCONN              128
#endif // ENOTCONN
#ifndef EMSGSIZE
#define EMSGSIZE              122
#endif // EMSGSIZE
#ifndef EALREADY
#define EALREADY              120
#endif // EALREADY
#ifndef ENOMSG
#define ENOMSG                42
#endif // ENOMSG
#ifndef ENOTSUP
#define ENOTSUP               134
#endif // ENOTSUP

/* ---- Toolchain / util ---------------------------------------------------- */
#define ARG_UNUSED(x)         (void)(x)
#define __packed              __attribute__((packed))

/* __ASSERT: aborts, unless a SIM_EXPECT_ASSERT() is armed (zephyr_sim.c) */
extern jmp_buf *gpt_simAssertJmp;
extern void gv_SimAssertFail(const char *cpt_msg);
#define __ASSERT(c, msg)      do { if (!(c)) { gv_SimAssertFail(msg); } } while (0)

/** Runs stmt and evaluates to true if it hit an __ASSERT. */
#define SIM_EXPECT_ASSERT(stmt)                                                \
   ({                                                                          \
      jmp_buf st_jb;                                                           \
      bool b_hit = false;                                                      \
      gpt_simAssertJmp = &st_jb;                                               \
      if (setjmp(st_jb) == 0) { stmt; } else { b_hit = true; }                 \
      gpt_simAssertJmp = NULL;                                                 \
      b_hit;                                                                   \
   })

/* IS_ENABLED(CONFIG_X): 1 if CONFIG_X is defined as 1, else 0 (Zephyr's trick) */
#define Z_IS_ENABLED3(ignore_this, val, ...) val
#define Z_IS_ENABLED2(one_or_two_args) Z_IS_ENABLED3(one_or_two_args 1, 0)
#define _XXXX1                _YYYY,
#define Z_IS_ENABLED1(x)      Z_IS_ENABLED2(_XXXX##x)
#define IS_ENABLED(x)         Z_IS_ENABLED1(x)
#ifndef MIN
#define MIN(a, b)             (((a) < (b)) ? (a) : (b))
#endif // MIN
#ifndef MAX
#define MAX(a, b)             (((a) > (b)) ? (a) : (b))
#endif // MAX
#define CLAMP(v, lo, hi)      MIN(MAX((v), (lo)), (hi))
#define ARRAY_SIZE(a)         (sizeof(a) / sizeof((a)[0]))
/* C89-compatible stand-in for Zephyr's BUILD_ASSERT (no _Static_assert). */
#define SHIM_CAT_(a, b)       a##b
#define SHIM_CAT(a, b)        SHIM_CAT_(a, b)
#define BUILD_ASSERT(c, ...)  typedef char SHIM_CAT(shim_build_assert_, __LINE__)[(c) ? 1 : -1]

/* ---- Time ---------------------------------------------------------------- */
typedef struct { int64_t ms; } k_timeout_t;
#define K_NO_WAIT             ((k_timeout_t){ 0 })
#define K_FOREVER             ((k_timeout_t){ -1 })
#define K_MSEC(x)             ((k_timeout_t){ (x) })
#define SYS_FOREVER_MS        (-1)

extern int64_t gi64_simNowMs;
static inline int64_t k_uptime_get(void) { return gi64_simNowMs; }
/* Deferred-log backlog (log_ctrl.h). A test may preload it; like Zephyr's log
   thread, each simulated millisecond of sleep processes one message. */
extern uint32_t gu32_simLogBuffered;
static inline int32_t k_msleep(int32_t ms)
{
   gi64_simNowMs += ms;
   gu32_simLogBuffered -= MIN(gu32_simLogBuffered, (uint32_t)ms);
   return 0;
}

/* ---- Logging (zephyr/logging/log.h and AppLog.h) ------------------------- */
/* Every line is captured (see zephyr_sim.c); printed only with gb_simVerbose. */
extern bool gb_simVerbose;
extern void gv_SimLog(const char *cpt_level, const char *cpt_fmt, ...)
   __attribute__((format(printf, 2, 3)));
extern void gv_SimLogClear(void);
extern uint32_t gu32_SimLogCount(void);
extern const char *gcpt_SimLogLine(uint32_t u32_idx);
extern const char *gcpt_SimLogFind(const char *cpt_text);
#define LOG_MODULE_DECLARE(...)
#define LOG_MODULE_REGISTER(...)
#define LOG_ERR(fmt, ...)     gv_SimLog("ERR", fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...)     gv_SimLog("WRN", fmt, ##__VA_ARGS__)
#define LOG_INF(fmt, ...)     gv_SimLog("INF", fmt, ##__VA_ARGS__)
#define LOG_DBG(fmt, ...)     gv_SimLog("DBG", fmt, ##__VA_ARGS__)
#define APP_LOG_ERR(fmt, ...) LOG_ERR("%s: " fmt, __func__, ##__VA_ARGS__)
#define APP_LOG_WRN(fmt, ...) LOG_WRN("%s: " fmt, __func__, ##__VA_ARGS__)
#define APP_LOG_INF(fmt, ...) LOG_INF("%s: " fmt, __func__, ##__VA_ARGS__)
#define APP_LOG_DBG(fmt, ...) LOG_DBG("%s: " fmt, __func__, ##__VA_ARGS__)
/* A hex dump is captured as one line: the label and the byte count */
#define LOG_HEXDUMP_ERR(d, l, s) gv_SimLog("ERR", "%s (%u bytes)", (s), (unsigned int)(l))
#define LOG_HEXDUMP_WRN(d, l, s) gv_SimLog("WRN", "%s (%u bytes)", (s), (unsigned int)(l))
#define LOG_HEXDUMP_INF(d, l, s) gv_SimLog("INF", "%s (%u bytes)", (s), (unsigned int)(l))
#define LOG_HEXDUMP_DBG(d, l, s) gv_SimLog("DBG", "%s (%u bytes)", (s), (unsigned int)(l))
static inline uint32_t log_buffered_cnt(void) { return gu32_simLogBuffered; }

/* ---- Mutex (single-threaded: never blocks, but counts, so a test can check
        that locks are balanced and held/released where the contract says) -- */
struct k_mutex { int i_held; uint32_t u32_locks; };
#define K_MUTEX_DEFINE(name)  struct k_mutex name = { 0, 0U }
static inline int k_mutex_lock(struct k_mutex *m, k_timeout_t t)
{
   (void)t;
   m->i_held++;
   m->u32_locks++;
   return 0;
}
static inline int k_mutex_unlock(struct k_mutex *m)
{
   if (m->i_held == 0) { return -EPERM; }
   m->i_held--;
   return 0;
}

/* ---- Semaphore ----------------------------------------------------------- */
struct k_sem { unsigned int count; unsigned int limit; };
#define K_SEM_DEFINE(name, init, lim) struct k_sem name = { (init), (lim) }
extern void gv_SimOnBlock(struct k_sem *stpt_sem);
extern jmp_buf *gpt_simThreadJmp;
static inline int k_sem_take(struct k_sem *s, k_timeout_t t)
{
   // A blocking take lets the simulated link make progress once
   if ((s->count == 0U) && (t.ms != 0))
   {
      gv_SimOnBlock(s);
   }
   if (s->count == 0U)
   {
      // A thread body run by gv_SimRunThread() would block for ever: end it
      if ((t.ms < 0) && (gpt_simThreadJmp != NULL))
      {
         longjmp(*gpt_simThreadJmp, 1);
      }
      return -EBUSY;
   }
   s->count--;
   return 0;
}
static inline void k_sem_give(struct k_sem *s) { if (s->count < s->limit) { s->count++; } }
static inline void k_sem_reset(struct k_sem *s) { s->count = 0U; }
static inline int k_sem_init(struct k_sem *s, unsigned int init, unsigned int lim)
{
   s->count = init;
   s->limit = lim;
   return 0;
}

/* ---- FIFO ---------------------------------------------------------------- */
struct k_fifo { void *head; void *tail; };
#define K_FIFO_DEFINE(name)   struct k_fifo name = { NULL, NULL }
static inline void k_fifo_put(struct k_fifo *f, void *item)
{
   *(void **)item = NULL;
   if (f->tail != NULL) { *(void **)f->tail = item; } else { f->head = item; }
   f->tail = item;
}
static inline void *k_fifo_get(struct k_fifo *f, k_timeout_t t)
{
   void *item = f->head;
   (void)t;
   if (item != NULL)
   {
      f->head = *(void **)item;
      if (f->head == NULL) { f->tail = NULL; }
   }
   return item;
}

/* ---- Message queue (k_msgq: copies fixed-size messages, FIFO order) -------
        A put on a full queue fails with -ENOMSG (any timeout: nothing would
        drain it). A get on an empty queue fails with -ENOMSG for K_NO_WAIT,
        -EAGAIN for a finite timeout, and inside gv_SimRunThread() a K_FOREVER
        get ends the thread body, like k_sem_take(). ------------------------- */
struct k_msgq { size_t msg_size; uint32_t max_msgs; uint8_t *buf; uint32_t head; uint32_t used; };
#define K_MSGQ_DEFINE(name, size, max, align) \
   static uint8_t name##_buf[(size) * (max)] __attribute__((aligned(align))); \
   struct k_msgq name = { (size), (max), name##_buf, 0U, 0U }
static inline int k_msgq_put(struct k_msgq *q, const void *data, k_timeout_t t)
{
   (void)t;
   if (q->used >= q->max_msgs) { return -ENOMSG; }
   memcpy(&q->buf[((q->head + q->used) % q->max_msgs) * q->msg_size], data, q->msg_size);
   q->used++;
   return 0;
}
static inline int k_msgq_get(struct k_msgq *q, void *data, k_timeout_t t)
{
   if (q->used == 0U)
   {
      if ((t.ms < 0) && (gpt_simThreadJmp != NULL))
      {
         longjmp(*gpt_simThreadJmp, 1);
      }
      return (t.ms == 0) ? -ENOMSG : -EAGAIN;
   }
   memcpy(data, &q->buf[q->head * q->msg_size], q->msg_size);
   q->head = (q->head + 1U) % q->max_msgs;
   q->used--;
   return 0;
}
static inline uint32_t k_msgq_num_used_get(struct k_msgq *q) { return q->used; }
static inline void k_msgq_purge(struct k_msgq *q) { q->head = 0U; q->used = 0U; }

/* ---- Memory slab --------------------------------------------------------- */
struct k_mem_slab { size_t block; uint32_t num; uint8_t *buf; void *free; bool init; uint32_t used; };
#define K_MEM_SLAB_DEFINE_STATIC(name, bs, n, al) \
   static uint8_t name##_buf[(bs) * (n)] __attribute__((aligned(al))); \
   static struct k_mem_slab name = { (bs), (n), name##_buf, NULL, false, 0U }
static inline int k_mem_slab_alloc(struct k_mem_slab *s, void **mem, k_timeout_t t)
{
   uint32_t i;
   (void)t;
   if (!s->init)
   {
      for (i = 0U; i < s->num; i++) { void *b = &s->buf[i * s->block]; *(void **)b = s->free; s->free = b; }
      s->init = true;
   }
   if (s->free == NULL) { *mem = NULL; return -ENOMEM; }
   *mem = s->free;
   s->free = *(void **)s->free;
   s->used++;
   return 0;
}
static inline void k_mem_slab_free(struct k_mem_slab *s, void *mem)
{
   *(void **)mem = s->free;
   s->free = mem;
   s->used--;
}

/* ---- Timer --------------------------------------------------------------- */
struct k_timer { void (*expiry)(struct k_timer *); int64_t deadline; bool running; };
#define K_TIMER_DEFINE(name, exp, stop) struct k_timer name = { (exp), 0, false }
extern void gv_SimRegisterTimer(struct k_timer *t);
static inline void k_timer_start(struct k_timer *t, k_timeout_t d, k_timeout_t p)
{
   (void)p;
   gv_SimRegisterTimer(t);
   t->deadline = gi64_simNowMs + d.ms;
   t->running = true;
}
static inline void k_timer_stop(struct k_timer *t) { t->running = false; }
static inline uint32_t k_timer_remaining_get(struct k_timer *t)
{
   return (t->running && (t->deadline > gi64_simNowMs)) ? (uint32_t)(t->deadline - gi64_simNowMs) : 0U;
}

/* ---- Delayable work (k_work_delayable) ------------------------------------
        Zephyr's return values: k_work_schedule() gives 1 when it scheduled the
        item and 0 when it was already scheduled (the deadline is kept);
        k_work_cancel_delayable() gives 0 once the item is idle. Nothing runs
        on its own: the test advances gi64_simNowMs and calls
        gb_SimRunDelayedWork(), which runs the handler if the item is due. -- */
struct k_work;
typedef void (*k_work_handler_t)(struct k_work *work);
struct k_work { k_work_handler_t handler; };
struct k_work_delayable { struct k_work work; int64_t deadline; bool pending; };
#define K_WORK_DELAYABLE_DEFINE(name, h)   struct k_work_delayable name = { { (h) }, 0, false }
static inline int k_work_schedule(struct k_work_delayable *w, k_timeout_t d)
{
   if (w->pending) { return 0; }
   w->deadline = gi64_simNowMs + d.ms;
   w->pending = true;
   return 1;
}
/** As Zephyr's: (re)schedule with the new delay, pending or not; gives 1. */
static inline int k_work_reschedule(struct k_work_delayable *w, k_timeout_t d)
{
   w->deadline = gi64_simNowMs + d.ms;
   w->pending = true;
   return 1;
}
static inline int k_work_cancel_delayable(struct k_work_delayable *w)
{
   w->pending = false;
   return 0;
}
static inline bool k_work_delayable_is_pending(const struct k_work_delayable *w) { return w->pending; }
/** Run the item's handler if it is scheduled and due; true if it ran. */
static inline bool gb_SimRunDelayedWork(struct k_work_delayable *w)
{
   if (!w->pending || (w->deadline > gi64_simNowMs)) { return false; }
   w->pending = false;
   w->work.handler(&w->work);
   return true;
}

/* ---- Thread -------------------------------------------------------------- */
#define K_THREAD_DEFINE(name, ss, entry, p1, p2, p3, prio, opt, delay) \
   const int name = 0; \
   void (*const name##_entry)(void *, void *, void *) = (entry)
#define k_thread_start(t)     ((void)(t))
/** Run a thread body until it would block for ever on a k_sem or k_msgq
    (zephyr_sim.c). Calls may nest: a block hook may run another thread. */
extern void gv_SimRunThread(void (*fpt_entry)(void *, void *, void *));

/* ---- Atomics (single-threaded) ------------------------------------------- */
typedef long atomic_t;
typedef long atomic_val_t;
typedef void *atomic_ptr_t;
#define ATOMIC_INIT(v)        (v)
#define ATOMIC_PTR_INIT(p)    (p)
static inline void atomic_set_bit(atomic_t *a, int b) { *a |= (1L << b); }
static inline bool atomic_test_and_clear_bit(atomic_t *a, int b)
{
   bool r = (*a & (1L << b)) != 0;
   *a &= ~(1L << b);
   return r;
}
static inline void atomic_clear_bit(atomic_t *a, int b) { *a &= ~(1L << b); }
static inline atomic_val_t atomic_get(const atomic_t *a) { return *a; }
static inline atomic_val_t atomic_set(atomic_t *a, atomic_val_t v) { atomic_val_t o = *a; *a = v; return o; }
static inline atomic_val_t atomic_inc(atomic_t *a) { return (*a)++; }
static inline atomic_val_t atomic_clear(atomic_t *a) { atomic_val_t o = *a; *a = 0; return o; }
static inline bool atomic_cas(atomic_t *a, atomic_val_t old_v, atomic_val_t new_v)
{
   if (*a != old_v) { return false; }
   *a = new_v;
   return true;
}
static inline void *atomic_ptr_get(const atomic_ptr_t *p) { return *p; }
static inline void *atomic_ptr_set(atomic_ptr_t *p, void *v) { void *o = *p; *p = v; return o; }
static inline bool atomic_test_bit(const atomic_t *a, int b) { return (*a & (1L << b)) != 0; }
static inline bool atomic_ptr_cas(atomic_ptr_t *p, void *old_v, void *new_v)
{
   if (*p != old_v) { return false; }
   *p = new_v;
   return true;
}

/* ---- CRC ----------------------------------------------------------------- */
static inline uint32_t crc32_ieee_update(uint32_t crc, const uint8_t *data, size_t len)
{
   size_t i;
   int k;
   crc = ~crc;
   for (i = 0; i < len; i++)
   {
      crc ^= data[i];
      for (k = 0; k < 8; k++) { crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U))); }
   }
   return ~crc;
}
static inline uint32_t crc32_ieee(const uint8_t *data, size_t len)
{
   return crc32_ieee_update(0U, data, len);
}

/* ---- Byte order ---------------------------------------------------------- */
static inline uint32_t sys_get_le32(const uint8_t *src)
{
   return (uint32_t)src[0] | ((uint32_t)src[1] << 8) | ((uint32_t)src[2] << 16)
      | ((uint32_t)src[3] << 24);
}
static inline void sys_put_le32(uint32_t val, uint8_t *dst)
{
   dst[0] = (uint8_t)val;
   dst[1] = (uint8_t)(val >> 8);
   dst[2] = (uint8_t)(val >> 16);
   dst[3] = (uint8_t)(val >> 24);
}
static inline uint16_t sys_get_le16(const uint8_t *src)
{
   return (uint16_t)(src[0] | ((uint16_t)src[1] << 8));
}
static inline void sys_put_le16(uint16_t val, uint8_t *dst)
{
   dst[0] = (uint8_t)val;
   dst[1] = (uint8_t)(val >> 8);
}
static inline uint32_t sys_get_be32(const uint8_t *src)
{
   return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) | ((uint32_t)src[2] << 8) | (uint32_t)src[3];
}
static inline void sys_put_be32(uint32_t val, uint8_t *dst)
{
   dst[0] = (uint8_t)(val >> 24);
   dst[1] = (uint8_t)(val >> 16);
   dst[2] = (uint8_t)(val >> 8);
   dst[3] = (uint8_t)val;
}

/* ---- Base64 (zephyr/sys/base64.h), RFC 4648 with padding ----------------- */
static inline int base64_encode(uint8_t *dst, size_t dlen, size_t *olen,
   const uint8_t *src, size_t slen)
{
   static const char scar_alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
   size_t need = (((slen + 2U) / 3U) * 4U) + 1U;
   size_t i;
   size_t o = 0U;
   uint32_t v;

   if (dlen < need) { *olen = need; return -ENOMEM; }
   for (i = 0U; i < slen; i += 3U)
   {
      v = (uint32_t)src[i] << 16;
      if ((i + 1U) < slen) { v |= (uint32_t)src[i + 1U] << 8; }
      if ((i + 2U) < slen) { v |= src[i + 2U]; }
      dst[o++] = (uint8_t)scar_alphabet[(v >> 18) & 0x3FU];
      dst[o++] = (uint8_t)scar_alphabet[(v >> 12) & 0x3FU];
      dst[o++] = ((i + 1U) < slen) ? (uint8_t)scar_alphabet[(v >> 6) & 0x3FU] : (uint8_t)'=';
      dst[o++] = ((i + 2U) < slen) ? (uint8_t)scar_alphabet[v & 0x3FU] : (uint8_t)'=';
   }
   dst[o] = 0U;
   *olen = o;
   return 0;
}

/* ---- Bluetooth: UUIDs --------------------------------------------------- */
#define BT_UUID_TYPE_16                    0
#define BT_UUID_TYPE_128                   2
struct bt_uuid { uint8_t type; };
struct bt_uuid_16 { struct bt_uuid uuid; uint16_t val; };
struct bt_uuid_128 { struct bt_uuid uuid; uint8_t val[16]; };
#define BT_UUID_128_ENCODE(w32, w1, w2, w3, w48)    (uint8_t)(w48), (uint8_t)((w48) >> 8), (uint8_t)((w48) >> 16), (uint8_t)((w48) >> 24),    (uint8_t)((w48) >> 32), (uint8_t)((w48) >> 40), (uint8_t)(w3), (uint8_t)((w3) >> 8),    (uint8_t)(w2), (uint8_t)((w2) >> 8), (uint8_t)(w1), (uint8_t)((w1) >> 8),    (uint8_t)(w32), (uint8_t)((w32) >> 8), (uint8_t)((w32) >> 16), (uint8_t)((w32) >> 24)
#define BT_UUID_INIT_128(...)              { { BT_UUID_TYPE_128 }, { __VA_ARGS__ } }
#define BT_UUID_DECLARE_16(v)    ((const struct bt_uuid *)(&(const struct bt_uuid_16){ { BT_UUID_TYPE_16 }, (v) }))
#define BT_UUID_DECLARE_128(...)    ((const struct bt_uuid *)(&(const struct bt_uuid_128){ { BT_UUID_TYPE_128 }, { __VA_ARGS__ } }))
#define BT_UUID_INIT_16(v)                 { { BT_UUID_TYPE_16 }, (v) }
#define BT_UUID_GATT_CCC_VAL               0x2902
/* As in Zephyr: a compound literal, so inside a function it lives on that
   function's stack (ASan catches pointers to it kept past the return) */
#define BT_UUID_GATT_CCC                   BT_UUID_DECLARE_16(BT_UUID_GATT_CCC_VAL)
static inline int bt_uuid_cmp(const struct bt_uuid *u1, const struct bt_uuid *u2)
{
   if (u1->type != u2->type) { return (int)u1->type - (int)u2->type; }
   if (u1->type == BT_UUID_TYPE_16)
   {
      return (int)((const struct bt_uuid_16 *)u1)->val - (int)((const struct bt_uuid_16 *)u2)->val;
   }
   return memcmp(((const struct bt_uuid_128 *)u1)->val, ((const struct bt_uuid_128 *)u2)->val, 16);
}

/* ---- Bluetooth: connection and GATT server ------------------------------- */
struct bt_conn { int i_id; };
struct bt_gatt_attr { const void *uuid; void *user_data; uint16_t handle; };
typedef void (*bt_gatt_complete_func_t)(struct bt_conn *conn, void *user_data);
struct bt_gatt_notify_params
{
   const void *uuid;
   const struct bt_gatt_attr *attr;
   const void *data;
   uint16_t len;
   bt_gatt_complete_func_t func;
   void *user_data;
};
#define BT_GATT_CCC_NOTIFY                 0x0001
#define BT_GATT_WRITE_FLAG_PREPARE         0x01
#define BT_GATT_WRITE_FLAG_CMD             0x02
#define BT_GATT_ERR(e)                     (-(e))
#define BT_ATT_ERR_WRITE_NOT_PERMITTED     0x03
#define BT_ATT_ERR_INVALID_OFFSET          0x07
#define BT_ATT_ERR_AUTHORIZATION           0x08
#define BT_ATT_ERR_INVALID_ATTRIBUTE_LEN   0x0d
#define BT_ATT_ERR_UNLIKELY                0x0e
#define BT_ATT_ERR_INSUFFICIENT_RESOURCES  0x11
#define BT_ATT_ERR_VALUE_NOT_ALLOWED       0x13
#define BT_ATT_ERR_PROCEDURE_IN_PROGRESS   0xfe
/** Same contract as Zephyr's bt_gatt_attr_read() (subsys/bluetooth/host/gatt.c). */
static inline ssize_t bt_gatt_attr_read(struct bt_conn *conn, const struct bt_gatt_attr *attr,
   void *buf, uint16_t buf_len, uint16_t offset, const void *value, uint16_t value_len)
{
   uint16_t len;
   (void)conn; (void)attr;
   if (offset > value_len) { return BT_GATT_ERR(BT_ATT_ERR_INVALID_OFFSET); }
   len = MIN(buf_len, value_len - offset);
   (void)memcpy(buf, (const uint8_t *)value + offset, len);
   return len;
}
static inline struct bt_conn *bt_conn_ref(struct bt_conn *c) { return c; }
static inline void bt_conn_unref(struct bt_conn *c) { (void)c; }
extern int bt_gatt_notify_cb(struct bt_conn *conn, struct bt_gatt_notify_params *params);
extern bool bt_gatt_is_subscribed(struct bt_conn *conn, const struct bt_gatt_attr *attr,
   uint16_t ccc_type);
extern uint16_t bt_gatt_get_mtu(struct bt_conn *conn);

/* ---- Bluetooth: GATT client ---------------------------------------------- */
#define BT_ATT_FIRST_ATTRIBUTE_HANDLE      0x0001
#define BT_ATT_LAST_ATTRIBUTE_HANDLE       0xffff
#define BT_GATT_ITER_STOP                  0
#define BT_GATT_ITER_CONTINUE              1
#define BT_GATT_CHRC_WRITE_WITHOUT_RESP    0x04
#define BT_GATT_CHRC_WRITE                 0x08
#define BT_GATT_CHRC_NOTIFY                0x10
#define BT_GATT_SUBSCRIBE_FLAG_VOLATILE    0
enum
{
   BT_GATT_DISCOVER_PRIMARY,
   BT_GATT_DISCOVER_SECONDARY,
   BT_GATT_DISCOVER_INCLUDE,
   BT_GATT_DISCOVER_CHARACTERISTIC,
   BT_GATT_DISCOVER_DESCRIPTOR,
};
struct bt_gatt_service_val { const struct bt_uuid *uuid; uint16_t end_handle; };
struct bt_gatt_chrc { const struct bt_uuid *uuid; uint16_t value_handle; uint8_t properties; };
struct bt_gatt_discover_params;
typedef uint8_t (*bt_gatt_discover_func_t)(struct bt_conn *conn, const struct bt_gatt_attr *attr,
   struct bt_gatt_discover_params *params);
struct bt_gatt_discover_params
{
   const struct bt_uuid *uuid;
   bt_gatt_discover_func_t func;
   uint16_t start_handle;
   uint16_t end_handle;
   uint8_t type;
};
struct bt_gatt_subscribe_params;
typedef uint8_t (*bt_gatt_notify_func_t)(struct bt_conn *conn,
   struct bt_gatt_subscribe_params *params, const void *data, uint16_t length);
typedef void (*bt_gatt_subscribe_func_t)(struct bt_conn *conn, uint8_t err,
   struct bt_gatt_subscribe_params *params);
struct bt_gatt_subscribe_params
{
   bt_gatt_notify_func_t notify;
   bt_gatt_subscribe_func_t subscribe;
   uint16_t value_handle;
   uint16_t ccc_handle;
   uint16_t value;
   atomic_t flags[1];
};
struct bt_gatt_exchange_params
{
   void (*func)(struct bt_conn *conn, uint8_t err, struct bt_gatt_exchange_params *params);
};
extern int bt_gatt_write_without_response_cb(struct bt_conn *conn, uint16_t handle,
   const void *data, uint16_t length, bool sign, bt_gatt_complete_func_t func, void *user_data);
extern int bt_gatt_discover(struct bt_conn *conn, struct bt_gatt_discover_params *params);
extern int bt_gatt_subscribe(struct bt_conn *conn, struct bt_gatt_subscribe_params *params);
extern int bt_gatt_unsubscribe(struct bt_conn *conn, struct bt_gatt_subscribe_params *params);
extern int bt_gatt_exchange_mtu(struct bt_conn *conn, struct bt_gatt_exchange_params *params);
struct bt_gatt_write_params;
typedef void (*bt_gatt_write_func_t)(struct bt_conn *conn, uint8_t err,
   struct bt_gatt_write_params *params);
struct bt_gatt_write_params
{
   bt_gatt_write_func_t func;
   uint16_t handle;
   uint16_t offset;
   const void *data;
   uint16_t length;
};
extern int bt_gatt_write(struct bt_conn *conn, struct bt_gatt_write_params *params);

/* ---- Bluetooth: addresses, advertising, scanning, connections, SMP --------
        Declarations only, with Zephyr's names, layouts and contracts
        (bluetooth.h, conn.h, addr.h). A test that reaches them defines them
        and records the calls; the macros build the same compound literals as
        Zephyr's, with representative values. -------------------------------- */
#define BT_ID_DEFAULT                      0
#ifndef CONFIG_BT_ID_MAX
#define CONFIG_BT_ID_MAX                   1
#endif
#define BT_ADDR_LE_PUBLIC                  0x00
#define BT_ADDR_LE_RANDOM                  0x01
typedef struct { uint8_t val[6]; } bt_addr_t;
typedef struct { uint8_t type; bt_addr_t a; } bt_addr_le_t;
static inline int bt_addr_le_cmp(const bt_addr_le_t *a, const bt_addr_le_t *b)
{
   return memcmp(a, b, sizeof(*a));
}
struct net_buf_simple;
struct bt_data { uint8_t type; uint8_t data_len; const uint8_t *data; };
#define BT_LE_ADV_OPT_CONN                 (1U << 1)
#define BT_LE_ADV_OPT_DIR_MODE_LOW_DUTY    (1U << 4)
struct bt_le_adv_param
{
   uint8_t id;
   uint8_t sid;
   uint8_t secondary_max_skip;
   uint32_t options;
   uint32_t interval_min;
   uint32_t interval_max;
   const bt_addr_le_t *peer;
};
#define BT_LE_ADV_CONN_DIR_LOW_DUTY(_peer) \
   (&(struct bt_le_adv_param){ 0U, 0U, 0U, BT_LE_ADV_OPT_CONN | BT_LE_ADV_OPT_DIR_MODE_LOW_DUTY, \
      0x0060U, 0x0090U, (_peer) })
extern int bt_le_adv_start(const struct bt_le_adv_param *param, const struct bt_data *ad,
   size_t ad_len, const struct bt_data *sd, size_t sd_len);
extern int bt_le_adv_stop(void);
#define BT_GAP_ADV_TYPE_ADV_IND            0x00
#define BT_GAP_ADV_TYPE_ADV_DIRECT_IND     0x01
#define BT_GAP_ADV_TYPE_ADV_SCAN_IND       0x02
#define BT_GAP_ADV_TYPE_ADV_NONCONN_IND    0x03
#define BT_LE_SCAN_TYPE_PASSIVE            0x00
struct bt_le_scan_param { uint8_t type; uint32_t options; uint16_t interval; uint16_t window; };
#define BT_LE_SCAN_PASSIVE \
   (&(struct bt_le_scan_param){ BT_LE_SCAN_TYPE_PASSIVE, 0U, 0x0060U, 0x0060U })
typedef void bt_le_scan_cb_t(const bt_addr_le_t *addr, int8_t rssi, uint8_t adv_type,
   struct net_buf_simple *buf);
extern int bt_le_scan_start(const struct bt_le_scan_param *param, bt_le_scan_cb_t cb);
extern int bt_le_scan_stop(void);
struct bt_conn_le_create_param { uint32_t options; uint16_t interval; uint16_t window; };
#define BT_CONN_LE_CREATE_CONN \
   (&(struct bt_conn_le_create_param){ 0U, 0x0060U, 0x0060U })
struct bt_le_conn_param { uint16_t interval_min; uint16_t interval_max; uint16_t latency; uint16_t timeout; };
#define BT_LE_CONN_PARAM(a, b, c, d)       (&(struct bt_le_conn_param){ (a), (b), (c), (d) })
extern int bt_conn_le_create(const bt_addr_le_t *peer,
   const struct bt_conn_le_create_param *create_param,
   const struct bt_le_conn_param *conn_param, struct bt_conn **conn);
#define BT_HCI_ERR_REMOTE_USER_TERM_CONN   0x13
extern int bt_conn_disconnect(struct bt_conn *conn, uint8_t reason);
extern const bt_addr_le_t *bt_conn_get_dst(const struct bt_conn *conn);
extern void bt_id_get(bt_addr_le_t *addrs, size_t *count);
struct bt_bond_info { bt_addr_le_t addr; };
extern void bt_foreach_bond(uint8_t id, void (*func)(const struct bt_bond_info *info,
   void *user_data), void *user_data);
extern int bt_unpair(uint8_t id, const bt_addr_le_t *addr);
typedef enum
{
   BT_SECURITY_L0, BT_SECURITY_L1, BT_SECURITY_L2, BT_SECURITY_L3, BT_SECURITY_L4,
} bt_security_t;
enum bt_security_err
{
   BT_SECURITY_ERR_SUCCESS,
   BT_SECURITY_ERR_AUTH_FAIL,
   BT_SECURITY_ERR_PIN_OR_KEY_MISSING,
   BT_SECURITY_ERR_OOB_NOT_AVAILABLE,
   BT_SECURITY_ERR_AUTH_REQUIREMENT,
   BT_SECURITY_ERR_PAIR_NOT_SUPPORTED,
   BT_SECURITY_ERR_PAIR_NOT_ALLOWED,
   BT_SECURITY_ERR_INVALID_PARAM,
   BT_SECURITY_ERR_KEY_REJECTED,
   BT_SECURITY_ERR_UNSPECIFIED,
};
extern int bt_conn_set_security(struct bt_conn *conn, bt_security_t sec);
extern bt_security_t bt_conn_get_security(const struct bt_conn *conn);
struct bt_le_oob_sc_data { uint8_t r[16]; uint8_t c[16]; };
struct bt_le_oob { bt_addr_le_t addr; struct bt_le_oob_sc_data le_sc_data; };
extern int bt_le_oob_get_local(uint8_t id, struct bt_le_oob *oob);
extern void bt_le_oob_set_sc_flag(bool enable);
extern int bt_le_oob_set_sc_data(struct bt_conn *conn, const struct bt_le_oob_sc_data *oobd_local,
   const struct bt_le_oob_sc_data *oobd_remote);
struct bt_conn_oob_info
{
   enum { BT_CONN_OOB_LE_LEGACY, BT_CONN_OOB_LE_SC } type;
   union
   {
      struct
      {
         enum
         {
            BT_CONN_OOB_LOCAL_ONLY,
            BT_CONN_OOB_REMOTE_ONLY,
            BT_CONN_OOB_BOTH_PEERS,
            BT_CONN_OOB_NO_DATA,
         } oob_config;
      } lesc;
   };
};
struct bt_conn_pairing_feat
{
   uint8_t io_capability;
   uint8_t oob_data_flag;
   uint8_t auth_req;
   uint8_t max_enc_key_size;
   uint8_t init_key_dist;
   uint8_t resp_key_dist;
};
#define BT_PASSKEY_RAND                    0xffffffffU
/* CONFIG_BT_APP_PASSKEY is assumed on: app_passkey is always a member */
struct bt_conn_auth_cb
{
   enum bt_security_err (*pairing_accept)(struct bt_conn *conn,
      const struct bt_conn_pairing_feat *const feat);
   void (*passkey_display)(struct bt_conn *conn, unsigned int passkey);
   uint32_t (*app_passkey)(struct bt_conn *conn);
   void (*passkey_entry)(struct bt_conn *conn);
   void (*passkey_confirm)(struct bt_conn *conn, unsigned int passkey);
   void (*oob_data_request)(struct bt_conn *conn, struct bt_conn_oob_info *info);
   void (*cancel)(struct bt_conn *conn);
   void (*pairing_confirm)(struct bt_conn *conn);
};
struct bt_conn_auth_info_cb
{
   void (*pairing_complete)(struct bt_conn *conn, bool bonded);
   void (*pairing_failed)(struct bt_conn *conn, enum bt_security_err reason);
};
extern int bt_conn_auth_cb_register(const struct bt_conn_auth_cb *cb);
extern int bt_conn_auth_cb_overlay(struct bt_conn *conn, const struct bt_conn_auth_cb *cb);
extern int bt_conn_auth_info_cb_register(struct bt_conn_auth_info_cb *cb);
extern int bt_conn_auth_cancel(struct bt_conn *conn);

#endif // _ZEPHYR_SHIM_H

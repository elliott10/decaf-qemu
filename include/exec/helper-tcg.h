/* Helper file for declaring TCG helper functions.
   This one defines data structures private to tcg.c.  */

#ifndef HELPER_TCG_H
#define HELPER_TCG_H 1

#include <exec/helper-head.h>

#define DEF_HELPER_FLAGS_0(NAME, FLAGS, ret) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) },

#define DEF_HELPER_FLAGS_1(NAME, FLAGS, ret, t1) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) },

#define DEF_HELPER_FLAGS_2(NAME, FLAGS, ret, t1, t2) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) },

#define DEF_HELPER_FLAGS_3(NAME, FLAGS, ret, t1, t2, t3) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) },

#define DEF_HELPER_FLAGS_4(NAME, FLAGS, ret, t1, t2, t3, t4) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) },

#define DEF_HELPER_FLAGS_5(NAME, FLAGS, ret, t1, t2, t3, t4, t5) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
    | dh_sizemask(t5, 5) },

#ifdef CONFIG_TCG_TAINT
#define DEF_HELPER_FLAGS_6(NAME, FLAGS, ret, t1, t2, t3, t4, t5, t6) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
    | dh_sizemask(t5, 5)| dh_sizemask(t6, 6) },
#define DEF_HELPER_FLAGS_7(NAME, FLAGS, ret, t1, t2, t3, t4, t5, t6, t7) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
    | dh_sizemask(t5, 5)| dh_sizemask(t6, 6)| dh_sizemask(t7, 7) },
#define DEF_HELPER_FLAGS_8(NAME, FLAGS, ret, t1, t2, t3, t4, t5, t6, t7, t8) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
    | dh_sizemask(t5, 5)| dh_sizemask(t6, 6)| dh_sizemask(t7, 7)| dh_sizemask(t8, 8) },
#define DEF_HELPER_FLAGS_9(NAME, FLAGS, ret, t1, t2, t3, t4, t5, t6, t7, t8, t9) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
    | dh_sizemask(t5, 5)| dh_sizemask(t6, 6)| dh_sizemask(t7, 7)| dh_sizemask(t8, 8)| dh_sizemask(t9, 9) },
#define DEF_HELPER_FLAGS_10(NAME, FLAGS, ret, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
    | dh_sizemask(t5, 5)| dh_sizemask(t6, 6)| dh_sizemask(t7, 7)| dh_sizemask(t8, 8)| dh_sizemask(t9, 9)| dh_sizemask(t10, 10) },
#define DEF_HELPER_FLAGS_11(NAME, FLAGS, ret, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
    | dh_sizemask(t5, 5)| dh_sizemask(t6, 6)| dh_sizemask(t7, 7)| dh_sizemask(t8, 8)| dh_sizemask(t9, 9)| dh_sizemask(t10, 10)| dh_sizemask(t11, 11)},
#define DEF_HELPER_FLAGS_12(NAME, FLAGS, ret, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12) \
  { .func = HELPER(NAME), .name = #NAME, .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) | dh_sizemask(t3, 3) | dh_sizemask(t4, 4) \
    | dh_sizemask(t5, 5)| dh_sizemask(t6, 6)| dh_sizemask(t7, 7)| dh_sizemask(t8, 8)| dh_sizemask(t9, 9)| dh_sizemask(t10, 10)| dh_sizemask(t11, 11)| dh_sizemask(t12, 12) },
#endif /* CONFIG_TCG_TAINT */

#include "helper.h"
#include "trace/generated-helpers.h"
#include "tcg-runtime.h"

#undef DEF_HELPER_FLAGS_0
#undef DEF_HELPER_FLAGS_1
#undef DEF_HELPER_FLAGS_2
#undef DEF_HELPER_FLAGS_3
#undef DEF_HELPER_FLAGS_4
#undef DEF_HELPER_FLAGS_5
#ifdef CONFIG_TCG_TAINT
#undef DEF_HELPER_FLAGS_6
#undef DEF_HELPER_FLAGS_7
#undef DEF_HELPER_FLAGS_8
#undef DEF_HELPER_FLAGS_9
#undef DEF_HELPER_FLAGS_10
#undef DEF_HELPER_FLAGS_11
#undef DEF_HELPER_FLAGS_12
#endif /* CONFIG_TCG_TAINT */

#endif /* HELPER_TCG_H */

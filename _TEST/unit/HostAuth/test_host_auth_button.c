/**
 * @file          test_host_auth_button.c
 * @brief         Host unit tests for the host window button
 *                (_ASW/_HOST_AUTH/HostAuthButton.c): a short press opens the
 *                window, a press held CONFIG_HOST_AUTH_FORGET_HOLD_MS forgets the
 *                host and opens it, each press is judged on its own, other
 *                buttons are ignored. The DK library and the HostAuth entry
 *                points are stubbed; time is simulated.
 *
 * @date          25/10/2026
 * @author        Shivam Chudasama [SC]
 * @copyright     Bajaj Auto Technology Limited (BATL)
 */

#define CONFIG_HOST_AUTH_FORGET_HOLD_MS 3000
#include "HostAuthButton.c"
#include "unity.h"

/******************************************************************************/
/*  Stubs                                                                     */
/******************************************************************************/
static struct button_handler *sstpt_handler;
static uint32_t su32_adds;
void dk_button_handler_add(struct button_handler *handler)
{
   su32_adds++;
   sstpt_handler = handler;
}

static uint32_t su32_open;
static uint32_t su32_forget;
void gv_HostAuth_OpenWindow(void) { su32_open++; }
void gv_HostAuth_ForgetHostAndOpen(void) { su32_forget++; }

/******************************************************************************/
/*  Helpers                                                                   */
/******************************************************************************/
#define BTN   DK_BTN2_MSK                    /* SW3: the DK library's second button */
#define WIPE  DK_BTN1_MSK                    /* Button 0, the wipe button */

static void sv_Buttons(uint32_t u32_state, uint32_t u32_changed)
{
   TEST_ASSERT_NOT_NULL(sstpt_handler);
   sstpt_handler->cb(u32_state, u32_changed);
}

static void sv_Wait(int64_t i64_ms)
{
   gi64_simNowMs += i64_ms;
   (void)gb_SimRunDelayedWork(&sst_holdWork);
}

void setUp(void)
{
   su32_adds = 0U;
   su32_open = 0U;
   su32_forget = 0U;
   gi64_simNowMs = 0;
   (void)k_work_cancel_delayable(&sst_holdWork);
   (void)atomic_set(&st_pressed, 0);
   gv_SimLogClear();
   TEST_ASSERT_EQUAL_INT(0, gi_HostAuthButton_Init());
}

void tearDown(void) {}

/******************************************************************************/
/*  Tests                                                                     */
/******************************************************************************/
static void test_InitAddsAHandler(void)
{
   TEST_ASSERT_EQUAL_UINT32(1U, su32_adds);
   TEST_ASSERT_EQUAL_PTR(sv_ButtonChanged, sstpt_handler->cb);
}

static void test_ShortPressOpensTheWindow(void)
{
   sv_Buttons(BTN, BTN);
   sv_Wait(500);
   sv_Buttons(0U, BTN);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_open);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_forget);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("opening the host window"));
   // Nothing happens later
   sv_Wait(CONFIG_HOST_AUTH_FORGET_HOLD_MS);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_forget);
}

static void test_HoldForgetsTheHost(void)
{
   sv_Buttons(BTN, BTN);
   sv_Wait(CONFIG_HOST_AUTH_FORGET_HOLD_MS - 1);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_forget);
   sv_Wait(1);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_forget);
   TEST_ASSERT_NOT_NULL(gcpt_SimLogFind("forgetting the host"));
   // Its release is no short press
   sv_Buttons(0U, BTN);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_open);
}

static void test_ReleaseJustBeforeTheHoldIsAShortPress(void)
{
   sv_Buttons(BTN, BTN);
   sv_Wait(CONFIG_HOST_AUTH_FORGET_HOLD_MS - 1);
   sv_Buttons(0U, BTN);
   sv_Wait(10);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_open);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_forget);
}

static void test_EachPressIsTimedOnItsOwn(void)
{
   // Short, then a new press: its hold counts from its own start
   sv_Buttons(BTN, BTN);
   sv_Wait(2000);
   sv_Buttons(0U, BTN);
   sv_Buttons(BTN, BTN);
   sv_Wait(2000);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_forget);
   sv_Wait(1000);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_forget);
   TEST_ASSERT_EQUAL_UINT32(1U, su32_open);
}

static void test_OtherButtonsAreIgnored(void)
{
   // The wipe button, and a change report without this button's bit
   sv_Buttons(WIPE, WIPE);
   sv_Wait(CONFIG_HOST_AUTH_FORGET_HOLD_MS);
   sv_Buttons(0U, WIPE);
   sv_Buttons(BTN, 0U);
   sv_Wait(CONFIG_HOST_AUTH_FORGET_HOLD_MS);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_open);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_forget);
}

static void test_ReleaseWithoutPressDoesNothing(void)
{
   sv_Buttons(0U, BTN);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_open);
   TEST_ASSERT_EQUAL_UINT32(0U, su32_forget);
}

int main(void)
{
   (void)setvbuf(stdout, NULL, _IONBF, 0);
   UNITY_BEGIN();
   RUN_TEST(test_InitAddsAHandler);
   RUN_TEST(test_ShortPressOpensTheWindow);
   RUN_TEST(test_HoldForgetsTheHost);
   RUN_TEST(test_ReleaseJustBeforeTheHoldIsAShortPress);
   RUN_TEST(test_EachPressIsTimedOnItsOwn);
   RUN_TEST(test_OtherButtonsAreIgnored);
   RUN_TEST(test_ReleaseWithoutPressDoesNothing);
   return UNITY_END();
}

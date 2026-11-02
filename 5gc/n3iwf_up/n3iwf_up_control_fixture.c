/* Isolated primary for real Go-secondary/C-primary IPC tests. No ONVM/NICs.
 * SPDX-License-Identifier: Apache-2.0 */
#include "n3iwf_up_control.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_pause.h>

static volatile sig_atomic_t stopping;
static void stop(int signal_number) { (void)signal_number; stopping = 1; }

int main(int argc, char **argv)
{
    struct n3iwf_up_control control;
    struct n3iwf_up_stats_wire stats = {0};
    if (rte_eal_init(argc, argv) < 0) return 1;
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    if (getenv("N3DP_TEST_PRIMARY_ONLY") != NULL) {
        puts("N3DP primary ready");
        fflush(stdout);
        while (!stopping) usleep(10000);
        return rte_eal_cleanup() != 0;
    }
    struct n3iwf_up_session_table *sessions = rte_zmalloc(NULL, sizeof(*sessions), 64);
    struct n3iwf_up_child_sa_table *sas = rte_zmalloc(NULL, sizeof(*sas), 64);
    if (sessions == NULL || sas == NULL) return 1;
    n3iwf_up_session_table_init(sessions);
    n3iwf_up_child_sa_table_init(sas);
    const char *name = getenv("N3DP_TEST_NAME");
    if (n3iwf_up_control_open(&control, name != NULL ? name : "N3DP_TEST",
                             sessions, sas, &stats) != 0) return 1;
    puts("N3DP fixture ready");
    fflush(stdout);
    while (!stopping) {
        n3iwf_up_control_poll(&control);
        rte_pause();
    }
    n3iwf_up_control_close(&control);
    n3iwf_up_child_sa_table_clear(sas);
    rte_free(sas);
    rte_free(sessions);
    return rte_eal_cleanup() != 0;
}

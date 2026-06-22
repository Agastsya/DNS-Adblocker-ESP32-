#pragma once

/* Start the HTTP server: a dark-mode status dashboard at "/" and a
 * GET /api/stats JSON endpoint it polls. */
void web_server_start(void);

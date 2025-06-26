/*
MooPilot -- MCP server for Remember The Milk API
Copyright (C) 2025 rivst.

MooPilot is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

MooPilot is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

import { Router } from "express";
import { getBaseUrl } from "../util";

const router: Router = Router();

router.get("/oauth-protected-resource", (req, res) => {
  const baseUrl = getBaseUrl(req);

  res.json({
    authorization_servers: [
      {
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/authorize`,
      },
    ],
  });
});

router.get("/oauth-authorization-server", (req, res) => {
  const baseUrl = getBaseUrl(req);

  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/authorize`,
    token_endpoint: `${baseUrl}/token`,
    scopes_supported: ["tasks"],
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
  });
});

export default router;

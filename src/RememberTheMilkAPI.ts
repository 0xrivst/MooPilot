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

import crypto from "crypto";

interface RTMConfig {
  apiKey: string;
  sharedSecret: string;
  authToken?: string;
}

export class RememberTheMilkAPI {
  #config: RTMConfig;
  #baseUrl = "https://api.rememberthemilk.com/services/rest/";

  constructor(config: RTMConfig) {
    this.#config = config;
  }

  private signRequest(params: Record<string, string>): string {
    const sortedKeys = Object.keys(params).sort();

    let paramString = "";
    for (const key of sortedKeys) {
      paramString += key + params[key];
    }

    const stringToSign = this.#config.sharedSecret + paramString;
    return crypto.createHash("md5").update(stringToSign).digest("hex");
  }

  async #makeRequest(
    method: string,
    params: Record<string, string> = {}
  ): Promise<any> {
    const allParams: Record<string, string> = {
      ...params,
      method,
      api_key: this.#config.apiKey,
      format: "json",
    };

    if (this.#config.authToken) {
      allParams.auth_token = this.#config.authToken;
    }

    allParams.api_sig = this.signRequest(allParams);

    const url = new URL(this.#baseUrl);
    Object.entries(allParams).forEach(([key, value]) => {
      url.searchParams.append(key, value);
    });

    const response = await fetch(url.toString());
    const data = (await response.json()) as any;

    if (data.rsp.stat === "fail") {
      throw new Error(
        `RTM API Error: ${data.rsp.err.msg} (code: ${data.rsp.err.code})`
      );
    }

    return data.rsp;
  }

  async getFrob(): Promise<string> {
    const response = await this.#makeRequest("rtm.auth.getFrob");
    return response.frob;
  }

  getAuthUrl(
    frob: string,
    perms: "read" | "write" | "delete" = "delete"
  ): string {
    const params = {
      api_key: this.#config.apiKey,
      perms,
      frob,
    };

    const api_sig = this.signRequest(params);

    return `https://www.rememberthemilk.com/services/auth/?api_key=${params.api_key}&perms=${params.perms}&frob=${params.frob}&api_sig=${api_sig}`;
  }

  async getToken(frob: string): Promise<{ token: string; user: any }> {
    const response = await this.#makeRequest("rtm.auth.getToken", { frob });
    return {
      token: response.auth.token,
      user: response.auth.user,
    };
  }

  async checkToken(): Promise<any> {
    const response = await this.#makeRequest("rtm.auth.checkToken");
    return response.auth;
  }

  async getLists(): Promise<any> {
    const response = await this.#makeRequest("rtm.lists.getList");
    return response.lists;
  }

  async getTasks(listId?: string, lastSync?: string): Promise<any> {
    const params: Record<string, string> = {};
    if (listId) params.list_id = listId;
    if (lastSync) params.last_sync = lastSync;

    const response = await this.#makeRequest("rtm.tasks.getList", params);
    return response.tasks;
  }

  async createTimeline(): Promise<string> {
    const response = await this.#makeRequest("rtm.timelines.create");
    return response.timeline;
  }

  async addTask(listId: string, name: string, timeline: string): Promise<any> {
    const response = await this.#makeRequest("rtm.tasks.add", {
      list_id: listId,
      name,
      timeline,
    });
    return response;
  }

  async deleteTask(
    listId: string,
    taskseriesId: string,
    taskId: string,
    timeline: string
  ): Promise<any> {
    const response = await this.#makeRequest("rtm.tasks.delete", {
      list_id: listId,
      taskseries_id: taskseriesId,
      task_id: taskId,
      timeline,
    });
    return response;
  }

  async setPriority(
    listId: string,
    taskseriesId: string,
    taskId: string,
    priority: string,
    timeline: string
  ): Promise<any> {
    const response = await this.#makeRequest("rtm.tasks.setPriority", {
      list_id: listId,
      taskseries_id: taskseriesId,
      task_id: taskId,
      priority,
      timeline,
    });
    return response;
  }
}

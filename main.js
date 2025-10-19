const fs = require("fs");
const path = require("path");
const axios = require("axios");
const colors = require("colors");
const { HttpsProxyAgent } = require("https-proxy-agent");
const readline = require("readline");
const user_agents = require("./config/userAgents");
const settings = require("./config/config.js");
const { sleep, loadData, getRandomNumber, saveToken, isTokenExpired, saveJson, getRandomElement } = require("./utils/utils.js");
const { checkBaseUrl } = require("./utils/checkAPI.js");
const { headers } = require("./core/header.js");
const { showBanner } = require("./core/banner.js");
const localStorage = require("./localStorage.json");
const ethers = require("ethers");
const { PromisePool } = require("@supercharge/promise-pool");
const TasksSv = require("./services/task.js");
const refcodes = loadData("reffCodes.txt");
const { Impit } = require("impit");
const UserAgent = require("user-agents");

class ClientAPI {
  constructor(itemData, accountIndex, proxy) {
    this.headers = headers;
    this.baseURL = settings.BASE_URL;
    this.baseURL_v2 = settings.BASE_URL_V2;
    this.localItem = null;
    this.itemData = itemData;
    this.accountIndex = accountIndex;
    this.proxy = proxy;
    this.proxyIP = null;
    this.session_name = null;
    this.session_user_agents = this.#load_session_data();
    this.token = null;
    this.identity_token = null;
    this.localStorage = localStorage;
    this.provider = null;
    this.sepoProvider = null;
    this.wallet = new ethers.Wallet(itemData.privateKey);
    this.refCode = getRandomElement(refcodes) || settings.REF_CODE;
    this.sessionCookie = null;
    this.impit = new Impit({
      browser: "chrome",
      proxyUrl: this.proxy || undefined,
      ignoreTlsErrors: true,
    });
  }

  #load_session_data() {
    try {
      const filePath = path.join(process.cwd(), "session_user_agents.json");
      const data = fs.readFileSync(filePath, "utf8");
      return JSON.parse(data);
    } catch (error) {
      if (error.code === "ENOENT") {
        return {};
      } else {
        throw error;
      }
    }
  }

  #get_user_agent() {
    if (this.session_user_agents[this.session_name]) {
      return this.session_user_agents[this.session_name];
    }
    const agent = new UserAgent({
      deviceCategory: "desktop",
    }).random();
    const newUserAgent = agent.toString();
    this.session_user_agents[this.session_name] = newUserAgent;
    this.#save_session_data(this.session_user_agents);
    return newUserAgent;
  }

  #save_session_data(session_user_agents) {
    const filePath = path.join(process.cwd(), "session_user_agents.json");
    fs.writeFileSync(filePath, JSON.stringify(session_user_agents, null, 2));
  }

  #get_platform(userAgent) {
    const platformPatterns = [
      { pattern: /iPhone/i, platform: "ios" },
      { pattern: /Android/i, platform: "android" },
      { pattern: /iPad/i, platform: "ios" },
    ];

    for (const { pattern, platform } of platformPatterns) {
      if (pattern.test(userAgent)) {
        return platform;
      }
    }

    return "Unknown";
  }

  #set_headers() {
    const platform = this.#get_platform(this.#get_user_agent());
    this.headers["sec-ch-ua"] = `Not)A;Brand";v="99", "${platform} WebView";v="127", "Chromium";v="127`;
    this.headers["sec-ch-ua-platform"] = platform;
    this.headers["User-Agent"] = this.#get_user_agent();
  }

  createUserAgent() {
    try {
      this.session_name = this.itemData.address;
      this.#get_user_agent();
    } catch (error) {
      this.log(`Can't create user agent: ${error.message}`, "error");
      return;
    }
  }

  async log(msg, type = "info") {
    const accountPrefix = `[NEURA][${this.accountIndex + 1}][${this.itemData.address}]`;
    let ipPrefix = "[Local IP]";
    if (settings.USE_PROXY) {
      ipPrefix = this.proxyIP ? `[${this.proxyIP}]` : "[Unknown IP]";
    }
    let logMessage = "";

    switch (type) {
      case "success":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.green;
        break;
      case "error":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.red;
        break;
      case "warning":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.yellow;
        break;
      case "custom":
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.magenta;
        break;
      default:
        logMessage = `${accountPrefix}${ipPrefix} ${msg}`.blue;
    }
    console.log(logMessage);
  }

  async checkProxyIP() {
    try {
      const proxyAgent = new HttpsProxyAgent(this.proxy);
      const response = await axios.get("https://api.ipify.org?format=json", { httpsAgent: proxyAgent });
      if (response.status === 200) {
        this.proxyIP = response.data.ip;
        return response.data.ip;
      } else {
        throw new Error(`Cannot check proxy IP. Status code: ${response.status}`);
      }
    } catch (error) {
      throw new Error(`Error checking proxy IP: ${error.message}`);
    }
  }

  async makeRequest(
    url,
    method,
    data = {},
    options = {
      retries: 5,
      isAuth: false,
      extraHeaders: {},
      refreshToken: null,
    }
  ) {
    if (!url || typeof url !== "string") {
      throw new Error("URL must be a valid string");
    }
    if (!["GET", "POST", "PUT", "DELETE", "PATCH"].includes(method.toUpperCase())) {
      throw new Error("Invalid HTTP method");
    }

    const { retries = 5, isAuth = false, extraHeaders = {}, refreshToken = null } = options;

    const headers = {
      ...this.headers,
      "privy-app-id": "cme1z1mrb0055l10b9azj4jci",
      "privy-ca-id": "018a58c0-3930-4295-9309-da87bbb01ca6",
      "privy-client": "react-auth:2.24.0",
      ...(!isAuth ? { authorization: `Bearer ${this.localItem.identity_token}` } : {}),
      ...(this.localItem
        ? {
            cookie: this.localItem?.cookie ? this.localItem.cookie : `privy-token=${this.localItem.token}; privy-id-token=${this.localItem.identity_token}; privy-session=privy.neuraprotocol.io`,
          }
        : {}),
      ...extraHeaders,
    };

    const proxyAgent = settings.USE_PROXY ? new HttpsProxyAgent(this.proxy) : null;

    const fetchOptions = {
      method: method.toUpperCase(),
      headers,
      credentials: "include",
      timeout: 120000,
      ...(proxyAgent ? { agent: proxyAgent } : {}),
      ...(method.toLowerCase() !== "get" ? { body: JSON.stringify(data) } : {}),
    };

    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const response = await this.impit.fetch(url, fetchOptions);
        const jsonResponse = await response.json();

        if (response.status < 400) {
          return {
            responseHeader: response.headers,
            status: response.status,
            success: true,
            data: jsonResponse?.data || jsonResponse,
            error: null,
          };
        } else {
          return {
            responseHeader: response.headers,
            status: response.status,
            success: false,
            data: null,
            error: jsonResponse,
          };
        }
      } catch (error) {
        const errorStatus = error.status || 500;
        const errorMessage = error?.response?.data?.error || error?.response?.data || error.message;

        if (errorStatus >= 400 && errorStatus < 500) {
          if (errorStatus === 401) {
            const token = await this.getValidToken(url.includes("sessions") ? true : false);
            if (!token) {
              return { success: false, status: errorStatus, error: "Failed to refresh token", data: null };
            }
            this.token = token;
            return await this.makeRequest(url, method, data, options);
          }
          if (errorStatus === 400) {
            return { success: false, status: errorStatus, error: errorMessage, data: null };
          }
          if (errorStatus === 429) {
            return { success: false, status: errorStatus, error: "You've reached daily limitation", data: null };
          }
          return { success: false, status: errorStatus, error: errorMessage, data: null };
        }

        if (attempt === retries) {
          return { success: false, status: errorStatus, error: errorMessage, data: null };
        }

        await sleep(5);
      }
    }

    return { success: false, status: 500, error: "Request failed after retries", data: null };
  }

  extractSessionId(data) {
    const cookieString = [
      `mp_5638bc422c4e56491e4807aaf844a91f_mixpanel=${encodeURIComponent(
        JSON.stringify({
          distinct_id: `$device:${data.user.id}`,
          $device_id: data.user.id,
          $initial_referrer: "$direct",
          $initial_referring_domain: "$direct",
          __mps: {},
          __mpso: {
            $initial_referrer: "$direct",
            $initial_referring_domain: "$direct",
          },
          __mpus: {},
          __mpa: {},
          __mpu: {},
          __mpr: [],
          __mpap: [],
        })
      )}; max-age=86400; path=/; HttpOnly`,
      `privy-session=t; max-age=86400; path=/; HttpOnly`,
      `privy-token=${data.token}; max-age=86400; path=/; HttpOnly`,
      `privy-id-token=${data.identity_token}; max-age=86400; path=/; HttpOnly`,
    ].join("; ");

    return cookieString || null;
  }

  async getUserData() {
    return this.makeRequest(`${settings.BASE_URL}/users`, "get");
  }

  async applyRefCode() {
    return this.makeRequest(`${settings.BASE_URL}/users`, "post", {
      json: {
        username: null,
        referralCode: this.refCode,
      },
      meta: {
        values: {
          username: ["undefined"],
        },
      },
    });
  }

  async getNonce() {
    return this.makeRequest(
      `https://auth.privy.io/api/v1/siwe/init`,
      "post",
      {
        address: this.itemData.address,
      },
      {
        isAuth: true,
        extraHeaders: {
          "privy-app-id": "cme1z1mrb0055l10b9azj4jci",
          "privy-ca-id": "018a58c0-3930-4295-9309-da87bbb01ca6",
          "privy-client": "react-auth:2.24.0",
        },
      }
    );
  }

  async creatingWallet() {
    return this.makeRequest(
      `https://auth.privy.io/api/v1/wallets`,
      "post",
      {
        chain_type: "ethereum",
      },
      {
        extraHeaders: {
          "privy-app-id": "cme1z1mrb0055l10b9azj4jci",
          "privy-ca-id": "018a58c0-3930-4295-9309-da87bbb01ca6",
          "privy-client": "react-auth:2.24.0",
          authorization: `Bearer ${this.localItem.token}`,
          cookie: this.localItem.cookie,
        },
      }
    );
  }

  async refreshToken() {
    let res = null;
    res = await this.makeRequest(
      `https://auth.privy.io/api/v1/sessions`,
      "post",
      {
        refresh_token: this.localItem?.refresh_token,
      },
      {
        extraHeaders: {
          authorization: `Bearer ${this.localItem.privy_access_token}`,
          cookie: this.localItem.cookie,
        },
      }
    );
    return res;
  }

  async auth() {
    const resNonce = await this.getNonce();
    const nonce = resNonce?.data?.nonce || null;
    if (!nonce) return { success: false, error: `Can't get nonce` };
    const mess = `basejump.fun wants you to sign in with your Ethereum account:
${this.wallet.address}

By signing, you are proving you own this wallet and logging in. This does not initiate a transaction or cost any fees.

URI: https://basejump.fun
Version: 1
Chain ID: 1
Nonce: ${nonce}
Issued At: ${new Date().toISOString()}
Resources:
- https://privy.io`;
    const signature = await this.wallet.signMessage(mess);
    return await this.makeRequest(
      `https://auth.privy.io/api/v1/siwe/authenticate`,
      "post",
      {
        message: mess,
        signature: signature,
        chainId: "eip155:1",
        walletClientType: "metamask",
        connectorType: "injected",
        mode: "login-or-sign-up",
      },
      {
        isAuth: true,
        extraHeaders: {
          "privy-app-id": "cme1z1mrb0055l10b9azj4jci",
          "privy-ca-id": "018a58c0-3930-4295-9309-da87bbb01ca6",
          "privy-client": "react-auth:2.24.0",
        },
      }
    );
  }

  async handleExcute() {
    const prams = {
      makeRequest: (url, method, data, options) => this.makeRequest(url, method, data, options),
      log: (ms, type) => this.log(ms, type),
      token: this.token,
    };

    if (settings.AUTO_TASK) {
      const sv = new TasksSv(prams);
      await sv.handleTasks();
    }
  }

  async getValidToken(isNew = false, isRefresh = false) {
    const existingToken = this.token;
    let loginRes = { success: false, data: null };
    const { isExpired: isExp, expirationDate } = isTokenExpired(existingToken);
    this.log(`Access token status: ${isExp ? "Expired".yellow : "Valid".green} | Acess token exp: ${expirationDate}`);

    if (existingToken && !isNew && !isExp && !isRefresh) {
      this.log("Using valid token", "success");
      return existingToken;
    }

    this.log("No found token or experied, trying get new token...", "warning");
    if ((isExp && this?.localItem?.cookie && !isNew) || isRefresh) {
      this.log(`Refreshing token...`);
      loginRes = await this.refreshToken();
    }

    if (!loginRes?.data) {
      this.log(`Getting new token...`);
      loginRes = await this.auth();
    }
    const data = loginRes.data;
    if (data?.token) {
      const cookie = this.extractSessionId(data);
      await saveJson(
        this.session_name,
        JSON.stringify({
          ...data,
          cookie,
        }),
        "localStorage.json"
      );
      this.localItem = {
        ...data,
        cookie,
      };
      return data?.token;
    }
    this.log(`Can't get new token | ${JSON.stringify(loginRes)}...`, "warning");
    return null;
  }

  async handleSyncData(rt = 1) {
    this.log(`Sync data...`);
    let userData = { success: false, data: null, status: 0 },
      retries = 0;
    do {
      userData = await this.getUserData();
      if (userData?.success) break;
      retries++;
    } while (retries < 1 && userData.status !== 400);
    if (userData?.success) {
      const { referredBy, referralCode, totalGames, points } = userData.data?.json;
      if (!referredBy) {
        this.log(`Applying ref code: ${this.refCode}`);
        await this.applyRefCode();
      }
      this.log(`Reff code: ${referralCode} | Total points: ${points}`, "custom");
    } else {
      if (userData?.error?.error == "missing wallets" && rt > 0) {
        this.log(`Creating smart wallet...`);
        const resCrete = await this.creatingWallet();
        if (resCrete.success) {
          this.log(`Created smart wallet success ${resCrete.data?.address}`, "success");
          this.token = await this.getValidToken(false, true);
          await this.applyRefCode();
        }
        return await this.handleSyncData(0);
      }
      this.log("Can't sync new data...skipping", "warning");
    }
    return userData;
  }

  async runAccount() {
    const accountIndex = this.accountIndex;
    this.session_name = this.itemData.address;
    this.localItem = JSON.parse(this.localStorage[this.session_name] || "{}");
    this.token = this.localItem?.token;

    this.#set_headers();
    if (settings.USE_PROXY) {
      try {
        this.proxyIP = await this.checkProxyIP();
      } catch (error) {
        this.log(`Cannot check proxy IP: ${error.message}`, "warning");
        return;
      }
    }
    const timesleep = getRandomNumber(settings.DELAY_START_BOT[0], settings.DELAY_START_BOT[1]);
    console.log(`=========Tài khoản ${accountIndex + 1} | ${this.proxyIP || "Local IP"} | Bắt đầu sau ${timesleep} giây...`.green);
    await sleep(timesleep);

    try {
      const token = await this.getValidToken();
      if (!token) return;
      this.token = token;

      const userData = await this.handleSyncData();
      if (userData.success) {
        await this.handleExcute();
        await sleep(1);
      } else {
        this.log("Can't get use info...skipping", "error");
      }
    } catch (error) {}
  }
}

async function main() {
  console.clear();
  showBanner();
  const privateKeys = loadData("privateKeys.txt");
  const proxies = loadData("proxy.txt");

  if (privateKeys.length == 0 || (privateKeys.length > proxies.length && settings.USE_PROXY)) {
    console.log("Số lượng proxy và data phải bằng nhau.".red);
    console.log(`Data: ${privateKeys.length}`);
    console.log(`Proxy: ${proxies.length}`);
    process.exit(1);
  }
  if (!settings.USE_PROXY) {
    console.log(`You are running bot without proxies!!!`.yellow);
  }
  let maxThreads = settings.USE_PROXY ? settings.MAX_THEADS : settings.MAX_THEADS_NO_PROXY;

  const data = privateKeys.map((val, index) => {
    const prvk = val.startsWith("0x") ? val : `0x${val}`;
    const wallet = new ethers.Wallet(prvk);
    const item = {
      address: wallet.address,
      privateKey: prvk,
    };
    new ClientAPI(item, index, proxies[index]).createUserAgent();
    return item;
  });
  await sleep(1);

  while (true) {
    const { results, errors } = await PromisePool.withConcurrency(maxThreads)
      .for(data)
      .process(async (itemData, index, pool) => {
        try {
          const to = new ClientAPI(itemData, index, proxies[index % proxies.length]);
          await Promise.race([to.runAccount(), new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout")), 24 * 60 * 60 * 1000))]);
        } catch (error) {
          console.log("err", error.message);
        } finally {
        }
      });
    await sleep(5);
    console.log(`Completed all account | Waiting ${settings.TIME_SLEEP} minutes to new circle`.magenta);
    await sleep(settings.TIME_SLEEP * 60);
  }
}

main().catch((error) => {
  console.log("Lỗi rồi:", error);
  process.exit(1);
});

import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url));
const port = 8123;
const host = "127.0.0.1";
const directApiBaseUrl = "https://api.direct.yandex.com/json/v5";
const directApiV501BaseUrl = "https://api.direct.yandex.com/json/v501";
const russiaGeoRegionId = "225";
const metrikaCounterId = 103620466;
const conversionGoalId = 459749119;
const campaignImages = new Map([
  ["kuh1", "kuh1.jpg"],
  ["kuh2", "kuh2.jpg"],
]);
const maxAdImageBytes = 10 * 1024 * 1024;
const customImageExtensions = new Map([
  ["image/jpeg", "jpg"],
  ["image/png", "png"],
  ["image/gif", "gif"],
]);
const authConfigPath = path.join(root, "auth-config.json");
const authCookieName = "rm_direct_session";
const authSessionDurationSeconds = 12 * 60 * 60;
const authLoginWindowMs = 15 * 60 * 1000;
const authMaxLoginAttempts = 5;
const authLoginAttempts = new Map();
const authConfig = await loadAuthConfig();
const networkAdGroupTemplates = [
  "Ключ (о): демонтаж, ремонт, дизайн проект",
  "Ключ (о): штукатурка, шпаклевка, грунтовка, выравнивание",
  "Ключ (о): ванна, унитаз, инсталляция, биде, раковина, душевая, душевая система, полотенцесушитель",
  "Ключ (о): подоконники, окна, двери",
  "Ключ (о): паркет, ламинат, стяжка пола, наливной пол, плинтус, галтель",
  "Ключ (о): плитка, кафель, керамогранит",
  "Ключ (о): натяжной потолок, подвесной потолок",
  "Ключ (о): поклейка обоев, обои, краска для обоев, покраска стен",
  "Ключ (ц): купить, продажа",
  "Ключ (ц): кухни",
  "Ключ (ц): встроенные, встраиваемые",
  "Ключ (ц): угловые",
  "Ключ (ц): маленькие",
  "Ключ (ц): гарнитур",
  "Ключ (ц): лдсп, мдф, шпон",
  "Ключ (ц): дом",
  "Ключ (ц): современные",
  "Ключ (ц): дизайн, проект, замер",
  "Ключ (ц): цена, стоимость, расчет",
  "Ключ (ц): лучшие, где, адреса, рейтинг, отзывы",
  "Ключ (с): маленькие",
  "Ключ (с): рассрочка",
  "Ключ (с): по размерам, под ключ",
  "Ключ (с): производитель, производство, изготовление, фирма, фабрика",
  "Ключ (с): заказ, заказать",
].map((name, index) => ({ name, groupNumber: index + 1 }));
networkAdGroupTemplates.push({
  name: "Ретаргетинг на неотказы",
  groupNumber: 26,
  autotargeting: false,
  audienceInterests: false,
});
const searchAdGroupTemplates = networkAdGroupTemplates.slice(20, 25);
const networkAudienceInterestNames = [
  "Текстиль",
  "Мебель для ванной",
  "Мебель для спальни",
  "Кровати",
  "Встраиваемые духовые шкафы",
  "Шкафы",
  "Мягкая мебель",
  "Посудомоечные машины",
  "Двери",
  "Напольные покрытия",
  "Мебель для прихожей",
  "Мебель для детской",
  "Мебель для кухни",
  "Мебель для гостиной",
  "Кухонные вытяжки",
  "Мебель для офиса и кабинета",
  "Сантехника",
  "Натяжные потолки",
  "Столы",
  "Плитка",
  "Стиральные машины",
];

async function loadAuthConfig() {
  try {
    const rawConfig = await fs.readFile(authConfigPath, "utf8");
    const config = JSON.parse(rawConfig);
    const username = String(config.username || "").trim();
    const password = config.password || {};
    const iterations = Number(password.iterations);
    const salt = Buffer.from(String(password.salt || ""), "base64");
    const hash = Buffer.from(String(password.hash || ""), "base64");
    const sessionSecret = Buffer.from(String(config.sessionSecret || ""), "base64");

    if (!username || username.length > 128) {
      throw new Error("Некорректный логин.");
    }

    if (
      password.algorithm !== "pbkdf2-sha256" ||
      !Number.isInteger(iterations) ||
      iterations < 100000 ||
      salt.length < 16 ||
      hash.length < 32 ||
      sessionSecret.length < 32
    ) {
      throw new Error("Некорректные параметры защиты пароля.");
    }

    return {
      username,
      password: { iterations, salt, hash },
      sessionSecret,
    };
  } catch (error) {
    if (error.code === "ENOENT") {
      console.warn("Authorization is not configured: auth-config.json is missing.");
    } else {
      console.error(`Authorization configuration error: ${error.message}`);
    }

    return null;
  }
}

function sendJson(res, statusCode, payload, headers = {}) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...headers,
  });
  res.end(JSON.stringify(payload));
}

async function readJson(req) {
  const chunks = [];
  let totalBytes = 0;

  for await (const chunk of req) {
    totalBytes += chunk.length;

    if (totalBytes > 16 * 1024 * 1024) {
      throw new Error("Тело запроса слишком большое.");
    }

    chunks.push(chunk);
  }

  const rawBody = Buffer.concat(chunks).toString("utf8");
  return rawBody ? JSON.parse(rawBody) : {};
}

function timingSafeStringEqual(left, right) {
  const leftDigest = crypto.createHash("sha256").update(String(left)).digest();
  const rightDigest = crypto.createHash("sha256").update(String(right)).digest();
  return crypto.timingSafeEqual(leftDigest, rightDigest);
}

function derivePasswordHash(password) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(
      String(password),
      authConfig.password.salt,
      authConfig.password.iterations,
      authConfig.password.hash.length,
      "sha256",
      (error, derivedKey) => {
        if (error) {
          reject(error);
          return;
        }

        resolve(derivedKey);
      },
    );
  });
}

function parseCookies(req) {
  return String(req.headers.cookie || "")
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((cookies, part) => {
      const separatorIndex = part.indexOf("=");

      if (separatorIndex > 0) {
        cookies[part.slice(0, separatorIndex)] = decodeURIComponent(
          part.slice(separatorIndex + 1),
        );
      }

      return cookies;
    }, {});
}

function createSessionToken() {
  const payload = Buffer.from(
    JSON.stringify({
      username: authConfig.username,
      expiresAt: Date.now() + authSessionDurationSeconds * 1000,
      nonce: crypto.randomBytes(16).toString("base64url"),
    }),
  ).toString("base64url");
  const signature = crypto
    .createHmac("sha256", authConfig.sessionSecret)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}

function readSession(req) {
  if (!authConfig) {
    return null;
  }

  const token = parseCookies(req)[authCookieName];

  if (!token) {
    return null;
  }

  const [payload, signature, extraPart] = token.split(".");

  if (!payload || !signature || extraPart) {
    return null;
  }

  const expectedSignature = crypto
    .createHmac("sha256", authConfig.sessionSecret)
    .update(payload)
    .digest("base64url");

  if (!timingSafeStringEqual(signature, expectedSignature)) {
    return null;
  }

  try {
    const session = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));

    if (
      session.username !== authConfig.username ||
      !Number.isFinite(session.expiresAt) ||
      session.expiresAt <= Date.now()
    ) {
      return null;
    }

    return session;
  } catch (error) {
    return null;
  }
}

function getLoginAttemptKey(req) {
  return req.socket.remoteAddress || "local";
}

function getActiveLoginAttempt(req) {
  const key = getLoginAttemptKey(req);
  const attempt = authLoginAttempts.get(key);

  if (attempt && attempt.resetAt <= Date.now()) {
    authLoginAttempts.delete(key);
    return null;
  }

  return attempt || null;
}

function registerFailedLogin(req) {
  const key = getLoginAttemptKey(req);
  const currentAttempt = getActiveLoginAttempt(req);
  const attempt = currentAttempt || {
    count: 0,
    resetAt: Date.now() + authLoginWindowMs,
  };

  attempt.count += 1;
  authLoginAttempts.set(key, attempt);
  return attempt;
}

async function handleAuthLoginApi(req, res) {
  if (!authConfig) {
    sendJson(res, 503, {
      error: "Авторизация не настроена. Запустите set-auth.ps1 на основном компьютере.",
      configured: false,
    });
    return;
  }

  const activeAttempt = getActiveLoginAttempt(req);

  if (activeAttempt?.count >= authMaxLoginAttempts) {
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((activeAttempt.resetAt - Date.now()) / 1000),
    );
    sendJson(
      res,
      429,
      {
        error: "Слишком много попыток входа. Попробуйте позже.",
        retryAfterSeconds,
      },
      { "Retry-After": String(retryAfterSeconds) },
    );
    return;
  }

  try {
    const payload = await readJson(req);
    const username = String(payload.username || "").trim();
    const password = String(payload.password || "");
    const derivedHash = await derivePasswordHash(password);
    const usernameMatches = timingSafeStringEqual(username, authConfig.username);
    const passwordMatches = crypto.timingSafeEqual(
      derivedHash,
      authConfig.password.hash,
    );

    if (!usernameMatches || !passwordMatches) {
      const attempt = registerFailedLogin(req);
      const isBlocked = attempt.count >= authMaxLoginAttempts;
      sendJson(res, isBlocked ? 429 : 401, {
        error: isBlocked
          ? "Слишком много попыток входа. Попробуйте через 15 минут."
          : "Неверный логин или пароль.",
      });
      return;
    }

    authLoginAttempts.delete(getLoginAttemptKey(req));
    const sessionToken = createSessionToken();
    sendJson(
      res,
      200,
      { authenticated: true, username: authConfig.username },
      {
        "Set-Cookie": `${authCookieName}=${encodeURIComponent(sessionToken)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${authSessionDurationSeconds}`,
      },
    );
  } catch (error) {
    sendJson(res, 400, { error: "Не удалось обработать данные для входа." });
  }
}

function handleAuthStatusApi(req, res) {
  const session = readSession(req);
  sendJson(res, 200, {
    configured: Boolean(authConfig),
    authenticated: Boolean(session),
    username: session?.username || "",
  });
}

function handleAuthLogoutApi(req, res) {
  sendJson(
    res,
    200,
    { authenticated: false },
    {
      "Set-Cookie": `${authCookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
    },
  );
}

function directHeaders(token, clientLogin = "") {
  const headers = {
    Authorization: `Bearer ${token}`,
    "Accept-Language": "ru",
    "Content-Type": "application/json; charset=utf-8",
  };

  if (clientLogin) {
    headers["Client-Login"] = clientLogin;
  }

  return headers;
}

function parseDirectError(payload) {
  const apiError = payload.error || {};
  return apiError.error_detail || apiError.error_string || "Ошибка API Яндекс Директа.";
}

function formatClientName(client) {
  const login = client.Login || "";
  const id = client.ClientId ? String(client.ClientId) : "";
  const info = client.ClientInfo;
  const infoText =
    typeof info === "string"
      ? info
      : info && typeof info === "object"
        ? Object.values(info).filter(Boolean).join(" ")
        : "";
  const baseName = infoText || login || id;

  return login && infoText ? `${infoText} (${login})` : baseName;
}

async function directRequest(token, pathName, body, options = {}) {
  const baseUrl = options.baseUrl || directApiBaseUrl;
  let response;

  try {
    response = await fetch(`${baseUrl}/${pathName}`, {
      method: "POST",
      headers: directHeaders(token, options.clientLogin),
      body: JSON.stringify(body),
    });
  } catch (error) {
    const technicalReason = [error.message, error.cause?.code]
      .filter(Boolean)
      .join(", ");

    throw new Error(
      `Не удалось подключиться к API Яндекс Директа (${baseUrl}). Проверьте интернет, VPN/прокси и доступ к api.direct.yandex.com. Технически: ${technicalReason}`,
    );
  }

  const responseText = await response.text();
  let payload;

  try {
    payload = JSON.parse(responseText);
  } catch (error) {
    throw new Error(
      `API вернул не JSON. Проверьте endpoint: ${responseText.slice(0, 120)}`,
    );
  }

  if (!response.ok || payload.error) {
    throw new Error(parseDirectError(payload));
  }

  return payload.result || {};
}

function moneyToApiUnits(value) {
  return Math.round(Number(value) * 1000000);
}

function getTodayDate() {
  return new Date().toISOString().slice(0, 10);
}

function normalizePromotionObject(value) {
  const trimmedValue = String(value || "").trim();

  if (!trimmedValue || /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmedValue)) {
    return trimmedValue;
  }

  return `https://${trimmedValue}`;
}

function getFirstParenthesizedValue(value) {
  const match = String(value || "").match(/\(([^()]*)\)/);

  return match ? match[1].trim() : "";
}

function getCampaignName(params) {
  const cityName = getPrimaryGeoRegionName(params);
  const clientMarker =
    getFirstParenthesizedValue(params.clientName) || String(params.clientName || "").trim();
  const placementName = params.placementType === "network" ? "РСЯ" : "Поиск";

  return `Кухни - ЕПК - ${cityName} - ${clientMarker} (${placementName})`;
}

function formatActionErrors(errors = []) {
  return errors
    .map((error) => {
      return [error.Message, error.Details].filter(Boolean).join(": ");
    })
    .filter(Boolean)
    .join("; ");
}

function getActionResultErrors(actionResults = []) {
  return actionResults
    .flatMap((result, index) => {
      return (result.Errors || []).map((error) => {
        const details = [error.Message, error.Details].filter(Boolean).join(": ");
        return details ? `#${index + 1}: ${details}` : "";
      });
    })
    .filter(Boolean);
}

function normalizeDictionaryName(value) {
  return String(value).trim().replace(/\s+/g, " ").toLocaleLowerCase("ru");
}

function parseJsonArray(value, fallback = []) {
  if (Array.isArray(value)) {
    return value;
  }

  if (!value || typeof value !== "string") {
    return fallback;
  }

  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : fallback;
  } catch (error) {
    return fallback;
  }
}

function getExpectedAdTitleCount(placementType) {
  return placementType === "network" ? 7 : 5;
}

function parseCustomAdTitles(value, placementType) {
  const titles = parseJsonArray(value)
    .map((title) => String(title || "").trim())
    .filter(Boolean);

  if (titles.length === 0) {
    return [];
  }

  const expectedCount = getExpectedAdTitleCount(placementType);

  if (titles.length !== expectedCount) {
    throw new Error(
      `Количество заголовков должно быть ${expectedCount}, сейчас ${titles.length}.`,
    );
  }

  return titles;
}

function normalizeOptionValue(value) {
  return String(value || "").trim().toLocaleLowerCase("ru");
}

function capitalizeFirstLetter(value) {
  const text = String(value || "").trim();

  if (!text) {
    return "";
  }

  return `${text.slice(0, 1).toLocaleUpperCase("ru")}${text.slice(1)}`;
}

async function loadAdGroupTemplatesWithKeywords(templates) {
  const filePath = path.join(root, "key web.txt");
  const text = await fs.readFile(filePath, "utf8");
  const blocks = new Map();
  const blockPattern = /(?:^|\r?\n)\s*(\d{1,2})\s*-\s*([\s\S]*?)(?=(?:\r?\n\s*)+\d{1,2}\s*-|$)/g;
  let match;

  while ((match = blockPattern.exec(text)) !== null) {
    const groupNumber = Number(match[1]);
    const keywords = match[2]
      .split(",")
      .map((keyword) => keyword.trim())
      .filter(Boolean);

    blocks.set(groupNumber, keywords);
  }

  return templates.map((template) => {
    return {
      ...template,
      keywords: blocks.get(template.groupNumber) || [],
    };
  });
}

async function loadNetworkKeywordsByGroup() {
  return loadAdGroupTemplatesWithKeywords(networkAdGroupTemplates);
}

async function loadSearchKeywordsByGroup() {
  return loadAdGroupTemplatesWithKeywords(searchAdGroupTemplates);
}

function chunkArray(items, chunkSize) {
  const chunks = [];

  for (let index = 0; index < items.length; index += chunkSize) {
    chunks.push(items.slice(index, index + chunkSize));
  }

  return chunks;
}

async function loadDirectClients(token) {
  try {
    const result = await directRequest(token, "agencyclients", {
      method: "get",
      params: {
        SelectionCriteria: {},
        FieldNames: ["ClientId", "Login", "ClientInfo"],
      },
    });
    const agencyClients = (result.Clients || []).map((client) => ({
      id: client.ClientId ? String(client.ClientId) : "",
      login: client.Login || "",
      name: formatClientName(client),
    }));

    if (agencyClients.length > 0) {
      return agencyClients;
    }
  } catch (error) {
    // If the token is not an agency token, fall back to the current advertiser.
  }

  const result = await directRequest(token, "clients", {
    method: "get",
    params: {
      FieldNames: ["ClientId", "Login", "ClientInfo"],
    },
  });
  return (result.Clients || []).map((client) => ({
    id: client.ClientId ? String(client.ClientId) : "",
    login: client.Login || "",
    name: formatClientName(client),
  }));
}

function collectRussiaRegionIds(geoRegions) {
  const childrenByParent = new Map();

  for (const region of geoRegions) {
    const parentId = region.ParentId == null ? "root" : String(region.ParentId);
    const children = childrenByParent.get(parentId) || [];
    children.push(region);
    childrenByParent.set(parentId, children);
  }

  const regionIds = new Set();
  const queue = [russiaGeoRegionId];

  while (queue.length > 0) {
    const regionId = queue.shift();

    if (regionIds.has(regionId)) {
      continue;
    }

    regionIds.add(regionId);

    for (const child of childrenByParent.get(regionId) || []) {
      queue.push(String(child.GeoRegionId));
    }
  }

  return regionIds;
}

async function loadGeoRegions(token) {
  const result = await directRequest(token, "dictionaries", {
    method: "get",
    params: {
      DictionaryNames: ["GeoRegions"],
    },
  });
  const geoRegions = result.GeoRegions || [];
  const russianRegionIds = collectRussiaRegionIds(geoRegions);
  const regionsById = new Map(
    geoRegions.map((region) => [String(region.GeoRegionId), region]),
  );
  const allowedRegions = geoRegions.filter((region) => {
    const type = region.GeoRegionType;
    return (
      russianRegionIds.has(String(region.GeoRegionId)) &&
      (type === "Administrative area" || type === "City")
    );
  });
  const cityNameCounts = new Map();

  for (const region of allowedRegions) {
    if (region.GeoRegionType !== "City") {
      continue;
    }

    cityNameCounts.set(
      region.GeoRegionName,
      (cityNameCounts.get(region.GeoRegionName) || 0) + 1,
    );
  }

  function isSubjectRegionName(name) {
    return (
      /(область|край|республика|автономная область|город федерального значения)/i.test(
        name,
      ) &&
      !/(район|округ)/i.test(name)
    );
  }

  function getSubjectRegionName(region) {
    let parentId = region.ParentId == null ? "" : String(region.ParentId);
    let administrativeAreaName = "";

    while (parentId) {
      const parent = regionsById.get(parentId);

      if (!parent) {
        return "";
      }

      if (String(parent.GeoRegionId) === russiaGeoRegionId) {
        parentId = parent.ParentId == null ? "" : String(parent.ParentId);
        continue;
      }

      const parentName = parent.GeoRegionName || "";

      if (isSubjectRegionName(parentName)) {
        return parentName;
      }

      if (
        !administrativeAreaName &&
        parent.GeoRegionType === "Administrative area" &&
        !/(район|округ)/i.test(parentName)
      ) {
        administrativeAreaName = parentName;
      }

      parentId = parent.ParentId == null ? "" : String(parent.ParentId);
    }

    return administrativeAreaName;
  }

  return allowedRegions
    .map((region) => {
      const parentName = getSubjectRegionName(region);

      return {
        id: String(region.GeoRegionId),
        name: region.GeoRegionName,
        label:
          region.GeoRegionType === "City" &&
          cityNameCounts.get(region.GeoRegionName) > 1 &&
          parentName
            ? `${region.GeoRegionName} (${parentName})`
            : region.GeoRegionName,
        type: region.GeoRegionType,
        parentId: region.ParentId == null ? "" : String(region.ParentId),
        parentName,
      };
    })
    .sort((a, b) => a.label.localeCompare(b.label, "ru"));
}

function getUnifiedBiddingStrategy({ placementType, weeklyBudget, maxBid }) {
  const strategy = {
    WeeklySpendLimit: moneyToApiUnits(weeklyBudget),
    BidCeiling: moneyToApiUnits(maxBid),
    GoalId: conversionGoalId,
  };

  if (placementType === "network") {
    return {
      Search: {
        BiddingStrategyType: "SERVING_OFF",
      },
      Network: {
        BiddingStrategyType: "WB_MAXIMUM_CONVERSION_RATE",
        WbMaximumConversionRate: strategy,
        PlacementTypes: {
          Network: "YES",
          Maps: "NO",
        },
      },
    };
  }

  return {
    Search: {
      BiddingStrategyType: "WB_MAXIMUM_CONVERSION_RATE",
      WbMaximumConversionRate: strategy,
      PlacementTypes: {
        SearchResults: "YES",
        ProductGallery: "NO",
        DynamicPlaces: "YES",
        Maps: "NO",
        SearchOrganizationList: "NO",
      },
    },
    Network: {
      BiddingStrategyType: "SERVING_OFF",
    },
  };
}

async function createNetworkAdGroups(token, params, campaignId) {
  const regionIds = params.geoRegionIds.map((regionId) => Number(regionId));
  const result = await directRequest(
    token,
    "adgroups",
    {
      method: "add",
      params: {
        AdGroups: networkAdGroupTemplates.map((template) => ({
          Name: template.name,
          CampaignId: campaignId,
          RegionIds: regionIds,
          UnifiedAdGroup: {
            OfferRetargeting: "NO",
          },
        })),
      },
    },
    {
      baseUrl: directApiV501BaseUrl,
      clientLogin: params.clientLogin,
    },
  );
  const actionErrors = getActionResultErrors(result.AddResults || []);

  if (actionErrors.length > 0) {
    throw new Error(`Группы не созданы: ${actionErrors.join("; ")}`);
  }

  const adGroupIds = (result.AddResults || []).map((item) => item.Id);

  if (adGroupIds.length !== networkAdGroupTemplates.length || adGroupIds.some((id) => !id)) {
    throw new Error("Яндекс Директ вернул не все ID созданных групп.");
  }

  return adGroupIds;
}

async function createSearchAdGroups(token, params, campaignId) {
  const regionIds = params.geoRegionIds.map((regionId) => Number(regionId));
  const result = await directRequest(
    token,
    "adgroups",
    {
      method: "add",
      params: {
        AdGroups: searchAdGroupTemplates.map((template) => ({
          Name: template.name,
          CampaignId: campaignId,
          RegionIds: regionIds,
          UnifiedAdGroup: {
            OfferRetargeting: "NO",
          },
        })),
      },
    },
    {
      baseUrl: directApiV501BaseUrl,
      clientLogin: params.clientLogin,
    },
  );
  const actionErrors = getActionResultErrors(result.AddResults || []);

  if (actionErrors.length > 0) {
    throw new Error(`Группы поиска не созданы: ${actionErrors.join("; ")}`);
  }

  const adGroupIds = (result.AddResults || []).map((item) => item.Id);

  if (adGroupIds.length !== searchAdGroupTemplates.length || adGroupIds.some((id) => !id)) {
    throw new Error("Яндекс Директ вернул не все ID созданных групп поиска.");
  }

  return adGroupIds;
}

async function createNetworkKeywords(token, params, adGroupIds) {
  const templates = await loadNetworkKeywordsByGroup();
  const keywords = templates.flatMap((template, index) => {
    return template.keywords.map((keyword) => ({
      AdGroupId: adGroupIds[index],
      Keyword: keyword,
    }));
  });
  const keywordIds = [];

  for (const keywordChunk of chunkArray(keywords, 1000)) {
    const result = await directRequest(
      token,
      "keywords",
      {
        method: "add",
        params: {
          Keywords: keywordChunk,
        },
      },
      {
        clientLogin: params.clientLogin,
      },
    );
    const actionErrors = getActionResultErrors(result.AddResults || []);

    if (actionErrors.length > 0) {
      throw new Error(`Ключевые фразы не созданы: ${actionErrors.join("; ")}`);
    }

    keywordIds.push(...(result.AddResults || []).map((item) => item.Id).filter(Boolean));
  }

  return {
    keywordCount: keywords.length,
    keywordIds,
    groupKeywordCounts: templates.map((template) => template.keywords.length),
  };
}

function normalizeMinusPhrase(line) {
  return String(line || "")
    .trim()
    .replace(/^\uFEFF/, "")
    .replace(/^-\s*/, "")
    .trim();
}

function normalizeGeoCompareValue(value) {
  return normalizeMinusPhrase(value)
    .split(" (")[0]
    .replace(/[!+\[\]"']/g, "")
    .replace(/ё/g, "е")
    .replace(/Ё/g, "Е")
    .toLocaleLowerCase("ru")
    .replace(/[^a-zа-я0-9]+/gi, " ")
    .trim()
    .replace(/\s+/g, " ");
}

function getSelectedGeoCompareValues(geoRegions) {
  const values = new Set();

  for (const region of Array.isArray(geoRegions) ? geoRegions : []) {
    for (const value of [region.name, region.label]) {
      const normalizedValue = normalizeGeoCompareValue(value);

      if (normalizedValue) {
        values.add(normalizedValue);
      }
    }
  }

  return values;
}

async function loadSearchNegativeKeywords(params) {
  const filePath = path.join(root, "minus.txt");
  const text = await fs.readFile(filePath, "utf8");
  const geoValues = getSelectedGeoCompareValues(params.geoRegions);
  const removedByGeo = [];
  const negativeKeywords = [];
  const seenKeywords = new Set();

  for (const line of text.split(/\r?\n/)) {
    const keyword = normalizeMinusPhrase(line);

    if (!keyword) {
      continue;
    }

    const normalizedKeyword = normalizeGeoCompareValue(keyword);

    if (geoValues.has(normalizedKeyword)) {
      removedByGeo.push(keyword);
      continue;
    }

    if (seenKeywords.has(keyword)) {
      continue;
    }

    seenKeywords.add(keyword);
    negativeKeywords.push(keyword);
  }

  return {
    negativeKeywords,
    removedByGeo,
  };
}

function getPrimaryGeoRegionName(params) {
  const regions = Array.isArray(params.geoRegions) ? params.geoRegions : [];
  const region = regions.find((item) => item.type === "City");
  const rawName = region?.name || region?.label || "";

  return rawName.split(" (")[0].trim();
}

function getPrepositionalCityName(cityName) {
  const name = String(cityName || "").trim();
  const lowerName = name.toLocaleLowerCase("ru");
  const exceptions = new Map([
    ["москва", "Москве"],
    ["санкт-петербург", "Санкт-Петербурге"],
    ["нижний новгород", "Нижнем Новгороде"],
    ["великий новгород", "Великом Новгороде"],
    ["великие луки", "Великих Луках"],
    ["минеральные воды", "Минеральных Водах"],
    ["ростов-на-дону", "Ростове-на-Дону"],
    ["набережные челны", "Набережных Челнах"],
    ["люберцы", "Люберцах"],
    ["мытищи", "Мытищах"],
    ["химки", "Химках"],
    ["сочи", "Сочи"],
    ["йошкар-ола", "Йошкар-Оле"],
    ["улан-удэ", "Улан-Удэ"],
    ["орехово-зуево", "Орехово-Зуево"],
    ["гусь-хрустальный", "Гусь-Хрустальном"],
    ["комсомольск-на-амуре", "Комсомольске-на-Амуре"],
    ["камень-на-оби", "Камне-на-Оби"],
    ["сосновый бор", "Сосновом Бору"],
    ["старый оскол", "Старом Осколе"],
    ["новый уренгой", "Новом Уренгое"],
    ["нижний тагил", "Нижнем Тагиле"],
    ["петропавловск-камчатский", "Петропавловске-Камчатском"],
    ["ленинск-кузнецкий", "Ленинске-Кузнецком"],
    ["юрьев-польский", "Юрьеве-Польском"],
    ["елец", "Ельце"],
    ["орёл", "Орле"],
    ["орел", "Орле"],
  ]);

  if (exceptions.has(lowerName)) {
    return exceptions.get(lowerName);
  }

  function declineAdjective(word) {
    if (/(с|ц)кий$/i.test(word)) {
      return `${word.slice(0, -2)}ом`;
    }

    if (/ий$/i.test(word)) {
      return `${word.slice(0, -2)}ем`;
    }

    if (/[ыо]й$/i.test(word)) {
      return `${word.slice(0, -2)}ом`;
    }

    if (/ая$/i.test(word)) {
      return `${word.slice(0, -2)}ой`;
    }

    if (/яя$/i.test(word)) {
      return `${word.slice(0, -2)}ей`;
    }

    if (/ое$/i.test(word)) {
      return `${word.slice(0, -2)}ом`;
    }

    if (/ее$/i.test(word)) {
      return `${word.slice(0, -2)}ем`;
    }

    if (/ые$/i.test(word)) {
      return `${word.slice(0, -2)}ых`;
    }

    if (/ие$/i.test(word)) {
      return `${word.slice(0, -2)}их`;
    }

    return word;
  }

  function declineNoun(word) {
    if (/а$/i.test(word)) {
      return `${word.slice(0, -1)}е`;
    }

    if (/я$/i.test(word)) {
      return `${word.slice(0, -1)}е`;
    }

    if (/ь$/i.test(word)) {
      return `${word.slice(0, -1)}и`;
    }

    if (/й$/i.test(word)) {
      return `${word.slice(0, -1)}е`;
    }

    if (/[ыи]$/i.test(word)) {
      return `${word.slice(0, -1)}ах`;
    }

    if (/[еёиоуэю]$/i.test(word)) {
      return word;
    }

    return `${word}е`;
  }

  function declineWord(word, isLastWord) {
    const adjective = declineAdjective(word);

    if (adjective !== word) {
      return adjective;
    }

    if (!isLastWord) {
      return word;
    }

    return declineNoun(word);
  }

  const words = name.split(" ");

  if (words.length > 1) {
    return words
      .map((word, index) => declineWord(word, index === words.length - 1))
      .join(" ");
  }

  if (name.includes("-")) {
    const parts = name.split("-");
    return parts
      .map((part, index) => {
        if (part.toLocaleLowerCase("ru") === "на") {
          return part;
        }

        return declineWord(part, index === parts.length - 1);
      })
      .join("-");
  }

  return declineWord(name, true);
}

function getNetworkAdText(params) {
  const isMeasurementFree = normalizeOptionValue(params.kitchenMeasurement) === "бесплатно";
  const isDeliveryFree =
    normalizeOptionValue(params.kitchenDeliveryInstallation) === "бесплатно";

  if (isMeasurementFree && isDeliveryFree) {
    return "Выезд на замер и 3D-проект - 0 руб. Доставка и установка - 0 руб. Рассрочка - 0%.";
  }

  if (!isMeasurementFree && !isDeliveryFree) {
    return "Выезд на замер и 3D-проект. Доставка и установка. Рассрочка - 0%.";
  }

  if (!isMeasurementFree && isDeliveryFree) {
    return "Выезд на замер и 3D-проект. Доставка и установка - 0 руб. Рассрочка - 0%.";
  }

  return "Выезд на замер и 3D-проект - 0 руб. Доставка и установка. Рассрочка - 0%.";
}

function getTitleWithFallback(title, fallbackTitle) {
  const maxTitleLength = 56;

  return title.length > maxTitleLength ? fallbackTitle : title;
}

function getDayWord(value) {
  const number = Math.abs(Number(value));
  const lastTwoDigits = number % 100;
  const lastDigit = number % 10;

  if (lastTwoDigits >= 11 && lastTwoDigits <= 14) {
    return "дней";
  }

  if (lastDigit === 1) {
    return "день";
  }

  if (lastDigit >= 2 && lastDigit <= 4) {
    return "дня";
  }

  return "дней";
}

function getDayWordAfterFrom(value) {
  const number = Math.abs(Number(value));

  return number % 10 === 1 && number % 100 !== 11 ? "дня" : "дней";
}

function getGiftAdTitle(params, cityName, prepositionalCityName) {
  const gift = capitalizeFirstLetter(params.kitchenGift);

  if (!gift) {
    return `Кухни на заказ в ${prepositionalCityName}. Подарок на сайте`;
  }

  return getTitleWithFallback(
    `Кухни на заказ в ${prepositionalCityName}. ${gift} в подарок!`,
    `Кухни на заказ. ${cityName}. ${gift} в подарок!`,
  );
}

function getNetworkAdTitles(params) {
  const nominativeCityName = getPrimaryGeoRegionName(params);
  const cityName = getPrepositionalCityName(nominativeCityName);
  const productionTime = params.kitchenProductionTime;
  const productionTimeText = `${productionTime} ${getDayWord(productionTime)}`;
  const kitchenPrice = params.kitchenPrice;
  const isMeasurementFree = normalizeOptionValue(params.kitchenMeasurement) === "бесплатно";
  const freeMeasurementTitle = getTitleWithFallback(
    `Кухни на заказ в ${cityName}. Бесплатный выезд на замер`,
    `Кухни на заказ в ${cityName}. Бесплатный замер`,
  );
  const smallKitchenTitle = getTitleWithFallback(
    `Нужна маленькая кухня в ${cityName}? Цены от ${kitchenPrice} тыс. руб.`,
    `Нужна маленькая кухня в ${cityName}? Цены от ${kitchenPrice} т. р.`,
  );

  return [
    `Нужна новая кухня в ${cityName}? Изготовим за ${productionTimeText}!`,
    `Кухни от производителя в ${cityName}`,
    smallKitchenTitle,
    isMeasurementFree
      ? freeMeasurementTitle
      : `Кухни на заказ в ${cityName}. Выезд на замер`,
    getGiftAdTitle(params, nominativeCityName, cityName),
    `Кухни на заказ в ${cityName}. Рассрочка - 0%`,
    `Кухни на заказ в ${cityName}. Цены от ${kitchenPrice} тыс. руб.`,
  ];
}

function getSearchAdTitles(params) {
  const nominativeCityName = getPrimaryGeoRegionName(params);
  const cityName = getPrepositionalCityName(nominativeCityName);
  const kitchenPrice = params.kitchenPrice;
  const isMeasurementFree = normalizeOptionValue(params.kitchenMeasurement) === "бесплатно";
  const freeMeasurementTitle = getTitleWithFallback(
    `Кухни на заказ в ${cityName}. Бесплатный выезд на замер`,
    `Кухни на заказ в ${cityName}. Бесплатный замер`,
  );

  return [
    `Кухни на заказ в ${cityName}. Цены от ${kitchenPrice} тыс. руб.`,
    `Кухни на заказ в ${cityName}. Рассрочка - 0%`,
    getGiftAdTitle(params, nominativeCityName, cityName),
    isMeasurementFree
      ? freeMeasurementTitle
      : `Кухни на заказ в ${cityName}. Выезд на замер`,
    `Кухни от производителя в ${cityName}`,
  ];
}

function getAdTitles(params) {
  if (Array.isArray(params.customAdTitles) && params.customAdTitles.length > 0) {
    return params.customAdTitles;
  }

  return params.placementType === "network"
    ? getNetworkAdTitles(params)
    : getSearchAdTitles(params);
}

function getSitelinks(params) {
  const href = params.promotionObject;
  const productionTime = params.kitchenProductionTime;
  const productionTimeText = `${productionTime} ${getDayWord(productionTime)}`;
  const productionTimeAfterFrom = `${productionTime} ${getDayWordAfterFrom(productionTime)}`;
  const isDeliveryFree =
    normalizeOptionValue(params.kitchenDeliveryInstallation) === "бесплатно";
  const deliveryTitle = isDeliveryFree
    ? "Доставка и установка - 0 руб."
    : "Доставка и установка";

  return [
    {
      Title: `Скидка ${params.kitchenDiscount}%`,
      Href: href,
      Description: "Успейте заказать кухню до повышения цен",
    },
    {
      Title: `Гарантия ${params.kitchenWarranty}`,
      Href: href,
      Description: "Мы твердо уверены в высоком качестве своих изделий",
    },
    {
      Title: "Рассрочка 0%",
      Href: href,
      Description: "Закажите кухню уже сейчас, не нагружая семейный бюджет",
    },
    {
      Title: "Замер и 3D-проект - 0 руб.",
      Href: href,
      Description: "Замер и 3D-проект не требуют предоплаты",
    },
    {
      Title: deliveryTitle,
      Href: href,
      Description: "Бережно доставим и качественно установим новую кухню",
    },
    {
      Title: `Изготовление за ${productionTimeText}`,
      Href: href,
      Description: `Срок изготовления новой кухни - от ${productionTimeAfterFrom}`,
    },
    {
      Title: "Подарок на выбор",
      Href: href,
      Description: "Даём возможность выбрать подарок при заказе на сайте",
    },
    {
      Title: "Приборка после установки",
      Href: href,
      Description: "Гарантируем чистоту и порядок после выполнения всех работ",
    },
  ];
}

async function createSitelinkSet(token, params) {
  const result = await directRequest(
    token,
    "sitelinks",
    {
      method: "add",
      params: {
        SitelinksSets: [
          {
            Sitelinks: getSitelinks(params),
          },
        ],
      },
    },
    {
      clientLogin: params.clientLogin,
    },
  );
  const firstResult = result.AddResults?.[0];
  const errors = firstResult?.Errors || [];

  if (errors.length > 0) {
    throw new Error(`Быстрые ссылки не созданы: ${formatActionErrors(errors)}`);
  }

  if (!firstResult?.Id) {
    throw new Error("Яндекс Директ не вернул ID набора быстрых ссылок.");
  }

  return firstResult.Id;
}

function getJpegDimensions(buffer) {
  if (buffer.length < 4 || buffer[0] !== 0xff || buffer[1] !== 0xd8) {
    return null;
  }

  const startOfFrameMarkers = new Set([
    0xc0,
    0xc1,
    0xc2,
    0xc3,
    0xc5,
    0xc6,
    0xc7,
    0xc9,
    0xca,
    0xcb,
    0xcd,
    0xce,
    0xcf,
  ]);
  let offset = 2;

  while (offset + 4 <= buffer.length) {
    if (buffer[offset] !== 0xff) {
      offset += 1;
      continue;
    }

    while (offset < buffer.length && buffer[offset] === 0xff) {
      offset += 1;
    }

    const marker = buffer[offset];
    offset += 1;

    if (marker === 0xd9 || marker === 0xda) {
      break;
    }

    if (marker >= 0xd0 && marker <= 0xd7) {
      continue;
    }

    if (offset + 2 > buffer.length) {
      break;
    }

    const segmentLength = buffer.readUInt16BE(offset);

    if (segmentLength < 2 || offset + segmentLength > buffer.length) {
      break;
    }

    if (startOfFrameMarkers.has(marker) && segmentLength >= 7) {
      return {
        width: buffer.readUInt16BE(offset + 5),
        height: buffer.readUInt16BE(offset + 3),
      };
    }

    offset += segmentLength;
  }

  return null;
}

function getImageDimensions(buffer, mimeType) {
  if (
    mimeType === "image/png" &&
    buffer.length >= 24 &&
    buffer.subarray(0, 8).equals(
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    )
  ) {
    return {
      width: buffer.readUInt32BE(16),
      height: buffer.readUInt32BE(20),
    };
  }

  if (
    mimeType === "image/gif" &&
    buffer.length >= 10 &&
    ["GIF87a", "GIF89a"].includes(buffer.subarray(0, 6).toString("ascii"))
  ) {
    return {
      width: buffer.readUInt16LE(6),
      height: buffer.readUInt16LE(8),
    };
  }

  if (mimeType === "image/jpeg") {
    return getJpegDimensions(buffer);
  }

  return null;
}

function isValidAdImageSize(width, height) {
  const ratio = width / height;
  const isRegular =
    width >= 450 &&
    width <= 5000 &&
    height >= 450 &&
    height <= 5000 &&
    ratio >= 3 / 4 &&
    ratio <= 4 / 3;
  const isWide =
    width >= 1080 &&
    width <= 5000 &&
    height >= 607 &&
    height <= 2812 &&
    Math.abs(ratio - 16 / 9) <= 0.01;

  return isRegular || isWide;
}

function parseCustomAdImage(params) {
  const dataUrl = String(params.customImageData || "");
  const match = dataUrl.match(
    /^data:(image\/(?:jpeg|png|gif));base64,([A-Za-z0-9+/]+={0,2})$/,
  );

  if (!match) {
    throw new Error("Не удалось прочитать собственное изображение.");
  }

  const mimeType = match[1].toLowerCase();
  const base64Data = match[2];
  const extension = customImageExtensions.get(mimeType);

  if (!extension) {
    throw new Error("Допустимы только изображения JPG, PNG или GIF.");
  }

  const buffer = Buffer.from(base64Data, "base64");
  const normalizedBase64 = base64Data.replace(/=+$/, "");

  if (
    buffer.length === 0 ||
    buffer.toString("base64").replace(/=+$/, "") !== normalizedBase64
  ) {
    throw new Error("Собственное изображение повреждено.");
  }

  if (buffer.length > maxAdImageBytes) {
    throw new Error("Размер изображения не должен превышать 10 МБ.");
  }

  const dimensions = getImageDimensions(buffer, mimeType);

  if (!dimensions) {
    throw new Error("Формат собственного изображения не соответствует файлу.");
  }

  if (!isValidAdImageSize(dimensions.width, dimensions.height)) {
    throw new Error(
      "Нужно изображение 450–5000 px с пропорциями от 3:4 до 4:3 или 16:9 от 1080×607 px.",
    );
  }

  const requestedName = String(params.customImageName || "").trim();
  const name = requestedName || `custom-image.${extension}`;

  if (name.length > 255) {
    throw new Error("Название изображения не должно превышать 255 символов.");
  }

  return { buffer, name, mimeType, ...dimensions };
}

function validateCampaignImageSelection(params) {
  if (campaignImages.has(params.selectedImage)) {
    return;
  }

  if (params.selectedImage === "custom") {
    parseCustomAdImage(params);
    return;
  }

  throw new Error("Выберите изображение для РСЯ.");
}

async function getCampaignImageSource(params) {
  if (params.selectedImage === "custom") {
    return parseCustomAdImage(params);
  }

  const imageFileName = campaignImages.get(params.selectedImage);

  if (!imageFileName) {
    throw new Error("Выберите изображение для РСЯ.");
  }

  const imagePath = path.join(root, imageFileName);
  const buffer = await fs.readFile(imagePath);

  return { buffer, name: imageFileName };
}

async function createAdImage(token, params) {
  const imageSource = await getCampaignImageSource(params);
  const result = await directRequest(
    token,
    "adimages",
    {
      method: "add",
      params: {
        AdImages: [
          {
            ImageData: imageSource.buffer.toString("base64"),
            Type: "AUTO",
            Name: imageSource.name,
          },
        ],
      },
    },
    {
      baseUrl: directApiV501BaseUrl,
      clientLogin: params.clientLogin,
    },
  );
  const firstResult = result.AddResults?.[0];
  const errors = firstResult?.Errors || [];

  if (errors.length > 0) {
    throw new Error(`Изображение не загружено: ${formatActionErrors(errors)}`);
  }

  if (!firstResult?.AdImageHash) {
    throw new Error("Яндекс Директ не вернул хэш изображения.");
  }

  return firstResult.AdImageHash;
}

async function createTextAds(token, params, adGroupIds, titles, errorPrefix) {
  const text = getNetworkAdText(params);
  const sitelinkSetId = await createSitelinkSet(token, params);
  const adImageHash = params.adImageHash || null;
  const ads = adGroupIds.map((adGroupId) => {
    const responsiveAd = {
      Titles: titles,
      Texts: [text],
      Href: params.promotionObject,
      SitelinkSetId: sitelinkSetId,
    };

    if (adImageHash) {
      responsiveAd.AdImageHashes = [adImageHash];
    }

    return {
      AdGroupId: adGroupId,
      ResponsiveAd: responsiveAd,
    };
  });
  const result = await directRequest(
    token,
    "ads",
    {
      method: "add",
      params: {
        Ads: ads,
      },
    },
    {
      baseUrl: directApiV501BaseUrl,
      clientLogin: params.clientLogin,
    },
  );
  const actionErrors = getActionResultErrors(result.AddResults || []);

  if (actionErrors.length > 0) {
    throw new Error(`${errorPrefix}: ${actionErrors.join("; ")}`);
  }

  return {
    adCount: ads.length,
    adIds: (result.AddResults || []).map((item) => item.Id).filter(Boolean),
    sitelinkSetId,
    adImageHash,
  };
}

async function createNetworkAds(token, params, adGroupIds) {
  const adImageHash = await createAdImage(token, params);

  return createTextAds(
    token,
    { ...params, adImageHash },
    adGroupIds,
    getAdTitles(params),
    "Объявления РСЯ не созданы",
  );
}

async function createSearchAds(token, params, adGroupIds) {
  return createTextAds(
    token,
    params,
    adGroupIds,
    getAdTitles(params),
    "Объявления поиска не созданы",
  );
}

async function createSearchKeywords(token, params, adGroupIds) {
  const templates = await loadSearchKeywordsByGroup();
  const keywords = templates.flatMap((template, index) => {
    return template.keywords.map((keyword) => ({
      AdGroupId: adGroupIds[index],
      Keyword: keyword,
    }));
  });
  const keywordIds = [];

  for (const keywordChunk of chunkArray(keywords, 1000)) {
    const result = await directRequest(
      token,
      "keywords",
      {
        method: "add",
        params: {
          Keywords: keywordChunk,
        },
      },
      {
        baseUrl: directApiV501BaseUrl,
        clientLogin: params.clientLogin,
      },
    );
    const actionErrors = getActionResultErrors(result.AddResults || []);

    if (actionErrors.length > 0) {
      throw new Error(`Ключевые фразы поиска не созданы: ${actionErrors.join("; ")}`);
    }

    keywordIds.push(...(result.AddResults || []).map((item) => item.Id).filter(Boolean));
  }

  return {
    keywordCount: keywords.length,
    keywordIds,
    groupKeywordCounts: templates.map((template) => template.keywords.length),
  };
}

async function createNetworkAutotargetings(token, params, adGroupIds) {
  const autotargetings = adGroupIds
    .filter((_, index) => networkAdGroupTemplates[index]?.autotargeting !== false)
    .map((adGroupId) => ({
      AdGroupId: adGroupId,
      Keyword: "---autotargeting",
      StrategyPriority: "NORMAL",
      AutotargetingSettings: {
        Categories: {
          Exact: "YES",
          Narrow: "YES",
          Alternative: "YES",
          Accessory: "YES",
          Broader: "YES",
        },
        BrandOptions: {
          WithoutBrands: "YES",
          WithAdvertiserBrand: "YES",
          WithCompetitorsBrand: "YES",
        },
      },
    }));
  const result = await directRequest(
    token,
    "keywords",
    {
      method: "add",
      params: {
        Keywords: autotargetings,
      },
    },
    {
      baseUrl: directApiV501BaseUrl,
      clientLogin: params.clientLogin,
    },
  );
  const actionErrors = getActionResultErrors(result.AddResults || []);

  if (actionErrors.length > 0) {
    throw new Error(`Автотаргетинг не включен: ${actionErrors.join("; ")}`);
  }

  const autotargetingIds = (result.AddResults || [])
    .map((item) => item.Id)
    .filter(Boolean);

  if (autotargetingIds.length !== autotargetings.length) {
    throw new Error("Яндекс Директ вернул не все ID автотаргетингов.");
  }

  return {
    autotargetingCount: autotargetings.length,
    autotargetingIds,
  };
}

async function createSearchAutotargetings(token, params, adGroupIds) {
  const autotargetings = adGroupIds.map((adGroupId) => ({
    AdGroupId: adGroupId,
    Keyword: "---autotargeting",
    StrategyPriority: "NORMAL",
    AutotargetingSettings: {
      Categories: {
        Exact: "YES",
        Narrow: "YES",
        Alternative: "NO",
        Accessory: "NO",
        Broader: "YES",
      },
      BrandOptions: {
        WithoutBrands: "YES",
        WithAdvertiserBrand: "YES",
        WithCompetitorsBrand: "NO",
      },
    },
  }));
  const result = await directRequest(
    token,
    "keywords",
    {
      method: "add",
      params: {
        Keywords: autotargetings,
      },
    },
    {
      baseUrl: directApiV501BaseUrl,
      clientLogin: params.clientLogin,
    },
  );
  const actionErrors = getActionResultErrors(result.AddResults || []);

  if (actionErrors.length > 0) {
    throw new Error(`Автотаргетинг поиска не включен: ${actionErrors.join("; ")}`);
  }

  const autotargetingIds = (result.AddResults || [])
    .map((item) => item.Id)
    .filter(Boolean);

  if (autotargetingIds.length !== autotargetings.length) {
    throw new Error("Яндекс Директ вернул не все ID автотаргетингов поиска.");
  }

  return {
    autotargetingCount: autotargetings.length,
    autotargetingIds,
  };
}

async function loadNetworkAudienceInterests(token, params) {
  const result = await directRequest(
    token,
    "dictionaries",
    {
      method: "get",
      params: {
        DictionaryNames: ["AudienceInterests"],
      },
    },
    {
      clientLogin: params.clientLogin,
    },
  );
  const shortTermInterestsByName = new Map();

  for (const interest of result.AudienceInterests || []) {
    if (interest.InterestType !== "SHORT_TERM") {
      continue;
    }

    const normalizedName = normalizeDictionaryName(interest.Name);

    if (!shortTermInterestsByName.has(normalizedName)) {
      shortTermInterestsByName.set(normalizedName, interest);
    }
  }

  const missingNames = [];
  const interests = networkAudienceInterestNames
    .map((name) => {
      const interest = shortTermInterestsByName.get(normalizeDictionaryName(name));

      if (!interest) {
        missingNames.push(name);
        return null;
      }

      return {
        name,
        externalId: Number(interest.Id),
      };
    })
    .filter(Boolean);

  if (missingNames.length > 0) {
    throw new Error(
      `Не найдены краткосрочные интересы в справочнике Директа: ${missingNames.join(
        ", ",
      )}.`,
    );
  }

  return interests;
}

async function createNetworkAudienceRetargetingLists(token, params, campaignId, campaignName) {
  const interests = await loadNetworkAudienceInterests(token, params);
  const retargetingLists = [
    {
      Type: "AUDIENCE",
      Name: `${campaignName}`.slice(0, 190) + ` - Интересы и привычки ${campaignId}`,
      Description: `Интересы и привычки: ${networkAudienceInterestNames.join(", ")}.`,
      Rules: [
        {
          Operator: "ANY",
          Arguments: interests.map((interest) => ({
            ExternalId: interest.externalId,
          })),
        },
      ],
    },
  ];
  const result = await directRequest(
    token,
    "retargetinglists",
    {
      method: "add",
      params: {
        RetargetingLists: retargetingLists,
      },
    },
    {
      clientLogin: params.clientLogin,
    },
  );
  const actionErrors = getActionResultErrors(result.AddResults || []);

  if (actionErrors.length > 0) {
    throw new Error(`Условия интересов не созданы: ${actionErrors.join("; ")}`);
  }

  const retargetingListIds = (result.AddResults || [])
    .map((item) => item.Id)
    .filter(Boolean);

  if (retargetingListIds.length !== retargetingLists.length) {
    throw new Error("Яндекс Директ вернул не все ID условий интересов.");
  }

  return {
    interestCount: interests.length,
    retargetingListIds,
  };
}

async function createNetworkAudienceInterestTargets(token, params, adGroupIds, campaignId, campaignName) {
  const retargetingResult = await createNetworkAudienceRetargetingLists(
    token,
    params,
    campaignId,
    campaignName,
  );
  const audienceTargets = adGroupIds
    .filter((_, index) => networkAdGroupTemplates[index]?.audienceInterests !== false)
    .flatMap((adGroupId) => {
      return retargetingResult.retargetingListIds.map((retargetingListId) => ({
        AdGroupId: adGroupId,
        RetargetingListId: retargetingListId,
        StrategyPriority: "NORMAL",
      }));
    });
  const audienceTargetIds = [];

  for (const targetChunk of chunkArray(audienceTargets, 1000)) {
    const result = await directRequest(
      token,
      "audiencetargets",
      {
        method: "add",
        params: {
          AudienceTargets: targetChunk,
        },
      },
      {
        clientLogin: params.clientLogin,
      },
    );
    const actionErrors = getActionResultErrors(result.AddResults || []);

    if (actionErrors.length > 0) {
      throw new Error(`Интересы не привязаны к группам: ${actionErrors.join("; ")}`);
    }

    audienceTargetIds.push(
      ...(result.AddResults || []).map((item) => item.Id).filter(Boolean),
    );
  }

  return {
    interestCount: retargetingResult.interestCount,
    retargetingListCount: retargetingResult.retargetingListIds.length,
    audienceTargetCount: audienceTargets.length,
    retargetingListIds: retargetingResult.retargetingListIds,
    audienceTargetIds,
  };
}

async function createCampaignDraft(token, params) {
  const campaignName = getCampaignName(params);
  const negativeKeywordResult =
    params.placementType === "search"
      ? await loadSearchNegativeKeywords(params)
      : { negativeKeywords: [], removedByGeo: [] };
  const campaignAddItem = {
    Name: campaignName,
    StartDate: getTodayDate(),
    TimeZone: "Europe/Moscow",
    UnifiedCampaign: {
      BiddingStrategy: getUnifiedBiddingStrategy(params),
      Settings: [
        {
          Option: "ADD_METRICA_TAG",
          Value: "YES",
        },
        {
          Option: "ENABLE_AREA_OF_INTEREST_TARGETING",
          Value: "NO",
        },
        {
          Option: "ENABLE_SITE_MONITORING",
          Value: "YES",
        },
        {
          Option: "ALTERNATIVE_TEXTS_ENABLED",
          Value: "NO",
        },
      ],
      CounterIds: {
        Items: [metrikaCounterId],
      },
      PriorityGoals: {
        Items: [
          {
            GoalId: conversionGoalId,
            Value: moneyToApiUnits(params.maxBid),
            IsMetrikaSourceOfValue: "NO",
          },
        ],
      },
      TrackingParams: params.urlParameters,
      AttributionModel: "AUTO",
    },
  };

  if (negativeKeywordResult.negativeKeywords.length > 0) {
    campaignAddItem.NegativeKeywords = {
      Items: negativeKeywordResult.negativeKeywords,
    };
  }

  const result = await directRequest(
    token,
    "campaigns",
    {
      method: "add",
      params: {
        Campaigns: [campaignAddItem],
      },
    },
    {
      baseUrl: directApiV501BaseUrl,
      clientLogin: params.clientLogin,
    },
  );
  const firstResult = result.AddResults?.[0];
  const errors = firstResult?.Errors || [];

  if (errors.length > 0) {
    throw new Error(formatActionErrors(errors) || "Яндекс Директ не создал черновик.");
  }
  const campaignId = firstResult?.Id || null;

  if (!campaignId) {
    throw new Error("Яндекс Директ не вернул ID созданной кампании.");
  }

  let adGroupIds = [];
  let keywordResult = {
    keywordCount: 0,
    keywordIds: [],
    groupKeywordCounts: [],
  };
  let autotargetingResult = {
    autotargetingCount: 0,
    autotargetingIds: [],
  };
  let adResult = {
    adCount: 0,
    adIds: [],
    sitelinkSetId: null,
    adImageHash: null,
  };
  let audienceInterestResult = {
    interestCount: 0,
    retargetingListCount: 0,
    audienceTargetCount: 0,
    retargetingListIds: [],
    audienceTargetIds: [],
  };

  if (params.placementType === "network") {
    adGroupIds = await createNetworkAdGroups(token, params, campaignId);
    autotargetingResult = await createNetworkAutotargetings(token, params, adGroupIds);
    audienceInterestResult = await createNetworkAudienceInterestTargets(
      token,
      params,
      adGroupIds,
      campaignId,
      campaignName,
    );
    keywordResult = await createNetworkKeywords(token, params, adGroupIds);
    adResult = await createNetworkAds(token, params, adGroupIds);
  }

  if (params.placementType === "search") {
    adGroupIds = await createSearchAdGroups(token, params, campaignId);
    autotargetingResult = await createSearchAutotargetings(token, params, adGroupIds);
    keywordResult = await createSearchKeywords(token, params, adGroupIds);
    adResult = await createSearchAds(token, params, adGroupIds);
  }

  const bidModifierResult = await directRequest(
    token,
    "bidmodifiers",
    {
      method: "add",
      params: {
        BidModifiers: [
          {
            CampaignId: campaignId,
            DemographicsAdjustments: [
              {
                Age: "AGE_0_17",
                BidModifier: 0,
              },
            ],
          },
        ],
      },
    },
    {
      clientLogin: params.clientLogin,
    },
  );
  const firstBidModifierResult = bidModifierResult.AddResults?.[0];
  const bidModifierErrors = firstBidModifierResult?.Errors || [];

  if (bidModifierErrors.length > 0) {
    throw new Error(
      `Кампания создана, но корректировка не добавлена: ${formatActionErrors(
        bidModifierErrors,
      )}`,
    );
  }

  return {
    campaignId,
    campaignName,
    adGroupCount: adGroupIds.length,
    adCount: adResult.adCount,
    sitelinkSetId: adResult.sitelinkSetId,
    adImageHash: adResult.adImageHash,
    negativeKeywordCount: negativeKeywordResult.negativeKeywords.length,
    removedNegativeKeywordCount: negativeKeywordResult.removedByGeo.length,
    removedNegativeKeywords: negativeKeywordResult.removedByGeo,
    autotargetingCount: autotargetingResult.autotargetingCount,
    keywordCount: keywordResult.keywordCount,
    groupKeywordCounts: keywordResult.groupKeywordCounts,
    audienceInterestCount: audienceInterestResult.interestCount,
    audienceRetargetingListCount: audienceInterestResult.retargetingListCount,
    audienceTargetCount: audienceInterestResult.audienceTargetCount,
    adGroupIds,
    adIds: adResult.adIds,
    autotargetingIds: autotargetingResult.autotargetingIds,
    keywordIds: keywordResult.keywordIds,
    audienceRetargetingListIds: audienceInterestResult.retargetingListIds,
    audienceTargetIds: audienceInterestResult.audienceTargetIds,
    bidModifierId: firstBidModifierResult?.Id || null,
    rawResult: result,
  };
}

async function buildCampaignPreview(params) {
  const templates =
    params.placementType === "network"
      ? await loadNetworkKeywordsByGroup()
      : await loadSearchKeywordsByGroup();
  const titles = getAdTitles(params);
  const adText = getNetworkAdText(params);
  const sitelinks = getSitelinks(params);
  const negativeKeywordResult =
    params.placementType === "search"
      ? await loadSearchNegativeKeywords(params)
      : { negativeKeywords: [], removedByGeo: [] };
  const keywordCount = templates.reduce((sum, template) => {
    return sum + template.keywords.length;
  }, 0);

  return {
    campaignName: getCampaignName(params),
    placementType: params.placementType,
    placementName: params.placementType === "network" ? "РСЯ" : "Поиск",
    cityName: getPrimaryGeoRegionName(params),
    adGroupCount: templates.length,
    keywordCount,
    adCount: templates.length,
    adsPerGroup: 1,
    adTitles: titles,
    adText,
    sitelinks,
    negativeKeywordCount: negativeKeywordResult.negativeKeywords.length,
    removedNegativeKeywordCount: negativeKeywordResult.removedByGeo.length,
    removedNegativeKeywords: negativeKeywordResult.removedByGeo,
    imageFileName:
      params.placementType === "network"
        ? params.selectedImage === "custom"
          ? params.customImageName || "Собственное изображение"
          : campaignImages.get(params.selectedImage) || null
        : null,
    groups: templates.map((template) => ({
      number: template.groupNumber,
      name: template.name,
      keywordCount: template.keywords.length,
    })),
  };
}

async function readToken(req, res) {
  const { token } = await readJson(req);

  if (!token || typeof token !== "string") {
    sendJson(res, 400, { error: "Введите OAuth-токен." });
    return "";
  }

  return token.trim();
}

async function handleDirectClientsApi(req, res) {
  try {
    const token = await readToken(req, res);

    if (!token) {
      return;
    }

    const clients = await loadDirectClients(token);
    sendJson(res, 200, { clients });
  } catch (error) {
    sendJson(res, 502, { error: error.message });
  }
}

async function handleGeoRegionsApi(req, res) {
  try {
    const token = await readToken(req, res);

    if (!token) {
      return;
    }

    const regions = await loadGeoRegions(token);
    sendJson(res, 200, { regions });
  } catch (error) {
    sendJson(res, 502, { error: error.message });
  }
}

async function handleCreateCampaignDraftApi(req, res) {
  try {
    const payload = await readJson(req);
    const token = payload.token;
    const promotionObject = normalizePromotionObject(payload.promotionObject);
    const weeklyBudget = Number(payload.weeklyBudget);
    const maxBid = Number(payload.maxBid);
    const geoRegionIds = parseJsonArray(payload.geoRegionIds)
      .map((regionId) => String(regionId).trim())
      .filter(Boolean);
    const geoRegions = parseJsonArray(payload.geoRegions);
    const kitchenPrice = Number(payload.kitchenPrice);
    const kitchenProductionTime = Number(payload.kitchenProductionTime);
    const kitchenDiscount = Number(payload.kitchenDiscount);
    const kitchenWarranty = String(payload.kitchenWarranty || "").trim();
    const selectedImage = String(payload.selectedImage || "").trim();
    const customImageData = String(payload.customImageData || "");
    const customImageName = String(payload.customImageName || "").trim();
    const kitchenMeasurement = String(payload.kitchenMeasurement || "").trim();
    const kitchenDeliveryInstallation = String(
      payload.kitchenDeliveryInstallation || "",
    ).trim();
    let customAdTitles = [];

    if (!token || typeof token !== "string") {
      sendJson(res, 400, { error: "Введите OAuth-токен." });
      return;
    }

    if (!payload.clientLogin) {
      sendJson(res, 400, { error: "Выберите клиента." });
      return;
    }

    try {
      new URL(promotionObject);
    } catch (error) {
      sendJson(res, 400, { error: "Введите сайт объекта продвижения." });
      return;
    }

    if (payload.placementType !== "network" && payload.placementType !== "search") {
      sendJson(res, 400, { error: "Выберите места показа." });
      return;
    }

    try {
      customAdTitles = parseCustomAdTitles(payload.customAdTitles, payload.placementType);
    } catch (error) {
      sendJson(res, 400, { error: error.message });
      return;
    }

    if (geoRegionIds.length === 0) {
      sendJson(res, 400, { error: "Выберите географию показов для групп объявлений." });
      return;
    }

    if (!Number.isFinite(weeklyBudget) || weeklyBudget < 100) {
      sendJson(res, 400, { error: "Введите недельный бюджет не меньше 100." });
      return;
    }

    if (!Number.isFinite(maxBid) || maxBid <= 0) {
      sendJson(res, 400, { error: "Не задана максимальная ставка." });
      return;
    }

    if (!getPrimaryGeoRegionName({ geoRegions })) {
      sendJson(res, 400, { error: "Для объявлений выберите город в географии показов." });
      return;
    }

    if (!Number.isInteger(kitchenPrice) || kitchenPrice < 1 || kitchenPrice > 999) {
      sendJson(res, 400, { error: "Введите цену кухни от 1 до 999." });
      return;
    }

    if (
      !Number.isInteger(kitchenProductionTime) ||
      kitchenProductionTime < 1 ||
      kitchenProductionTime > 120
    ) {
      sendJson(res, 400, { error: "Введите срок изготовления кухни от 1 до 120." });
      return;
    }

    if (!Number.isInteger(kitchenDiscount) || kitchenDiscount < 1 || kitchenDiscount > 99) {
      sendJson(res, 400, { error: "Введите скидку от 1 до 99." });
      return;
    }

    if (!kitchenWarranty) {
      sendJson(res, 400, { error: "Введите гарантию." });
      return;
    }

    if (payload.placementType === "network") {
      try {
        validateCampaignImageSelection({
          selectedImage,
          customImageData,
          customImageName,
        });
      } catch (error) {
        sendJson(res, 400, { error: error.message });
        return;
      }
    }

    if (!["Платно", "Бесплатно"].includes(kitchenMeasurement)) {
      sendJson(res, 400, { error: "Выберите значение для замера." });
      return;
    }

    if (!["Платно", "Бесплатно"].includes(kitchenDeliveryInstallation)) {
      sendJson(res, 400, { error: "Выберите значение для доставки и установки." });
      return;
    }

    const draft = await createCampaignDraft(token.trim(), {
      clientLogin: payload.clientLogin,
      clientName: payload.clientName,
      promotionObject,
      placementType: payload.placementType,
      geoRegionIds,
      geoRegions,
      weeklyBudget,
      kitchenPrice,
      kitchenProductionTime,
      kitchenGift: payload.kitchenGift,
      kitchenWarranty,
      kitchenDiscount,
      selectedImage,
      customImageData,
      customImageName,
      kitchenMeasurement,
      kitchenDeliveryInstallation,
      customAdTitles,
      maxBid,
      urlParameters: payload.urlParameters,
    });

    sendJson(res, 200, { draft });
  } catch (error) {
    sendJson(res, 502, { error: error.message });
  }
}

async function handlePreviewCampaignApi(req, res) {
  try {
    const payload = await readJson(req);
    const promotionObject = normalizePromotionObject(payload.promotionObject);
    const weeklyBudget = Number(payload.weeklyBudget);
    const maxBid = Number(payload.maxBid);
    const geoRegionIds = parseJsonArray(payload.geoRegionIds)
      .map((regionId) => String(regionId).trim())
      .filter(Boolean);
    const geoRegions = parseJsonArray(payload.geoRegions);
    const kitchenPrice = Number(payload.kitchenPrice);
    const kitchenProductionTime = Number(payload.kitchenProductionTime);
    const kitchenDiscount = Number(payload.kitchenDiscount);
    const kitchenWarranty = String(payload.kitchenWarranty || "").trim();
    const selectedImage = String(payload.selectedImage || "").trim();
    const customImageData = String(payload.customImageData || "");
    const customImageName = String(payload.customImageName || "").trim();
    const kitchenMeasurement = String(payload.kitchenMeasurement || "").trim();
    const kitchenDeliveryInstallation = String(
      payload.kitchenDeliveryInstallation || "",
    ).trim();
    let customAdTitles = [];

    if (!payload.clientLogin || !payload.clientName) {
      sendJson(res, 400, { error: "Выберите клиента." });
      return;
    }

    try {
      new URL(promotionObject);
    } catch (error) {
      sendJson(res, 400, { error: "Введите сайт объекта продвижения." });
      return;
    }

    if (payload.placementType !== "network" && payload.placementType !== "search") {
      sendJson(res, 400, { error: "Выберите места показа." });
      return;
    }

    try {
      customAdTitles = parseCustomAdTitles(payload.customAdTitles, payload.placementType);
    } catch (error) {
      sendJson(res, 400, { error: error.message });
      return;
    }

    if (geoRegionIds.length === 0 || !getPrimaryGeoRegionName({ geoRegions })) {
      sendJson(res, 400, { error: "Для предпросмотра выберите город в географии показов." });
      return;
    }

    if (!Number.isFinite(weeklyBudget) || weeklyBudget < 100) {
      sendJson(res, 400, { error: "Введите недельный бюджет не меньше 100." });
      return;
    }

    if (!Number.isFinite(maxBid) || maxBid <= 0) {
      sendJson(res, 400, { error: "Выберите места показа." });
      return;
    }

    if (!Number.isInteger(kitchenPrice) || kitchenPrice < 1 || kitchenPrice > 999) {
      sendJson(res, 400, { error: "Введите цену кухни от 1 до 999." });
      return;
    }

    if (
      !Number.isInteger(kitchenProductionTime) ||
      kitchenProductionTime < 1 ||
      kitchenProductionTime > 120
    ) {
      sendJson(res, 400, { error: "Введите срок изготовления кухни от 1 до 120." });
      return;
    }

    if (!Number.isInteger(kitchenDiscount) || kitchenDiscount < 1 || kitchenDiscount > 99) {
      sendJson(res, 400, { error: "Введите скидку от 1 до 99." });
      return;
    }

    if (!kitchenWarranty) {
      sendJson(res, 400, { error: "Введите гарантию." });
      return;
    }

    if (payload.placementType === "network") {
      try {
        validateCampaignImageSelection({
          selectedImage,
          customImageData,
          customImageName,
        });
      } catch (error) {
        sendJson(res, 400, { error: error.message });
        return;
      }
    }

    if (!["Платно", "Бесплатно"].includes(kitchenMeasurement)) {
      sendJson(res, 400, { error: "Выберите значение для замера." });
      return;
    }

    if (!["Платно", "Бесплатно"].includes(kitchenDeliveryInstallation)) {
      sendJson(res, 400, { error: "Выберите значение для доставки и установки." });
      return;
    }

    const preview = await buildCampaignPreview({
      clientName: payload.clientName,
      promotionObject,
      placementType: payload.placementType,
      geoRegionIds,
      geoRegions,
      weeklyBudget,
      kitchenPrice,
      kitchenProductionTime,
      kitchenGift: payload.kitchenGift,
      kitchenWarranty,
      kitchenDiscount,
      selectedImage,
      customImageData,
      customImageName,
      kitchenMeasurement,
      kitchenDeliveryInstallation,
      customAdTitles,
      maxBid,
      urlParameters: payload.urlParameters,
    });

    sendJson(res, 200, { preview });
  } catch (error) {
    sendJson(res, 502, { error: error.message });
  }
}

async function handleStatic(req, res) {
  try {
    const url = new URL(req.url, `http://${host}:${port}`);
    const staticFiles = new Map([
      ["/", { fileName: "index.html", contentType: "text/html; charset=utf-8" }],
      ["/index.html", { fileName: "index.html", contentType: "text/html; charset=utf-8" }],
      ["/kuh1.jpg", { fileName: "kuh1.jpg", contentType: "image/jpeg" }],
      ["/kuh2.jpg", { fileName: "kuh2.jpg", contentType: "image/jpeg" }],
    ]);
    const staticFile = staticFiles.get(url.pathname);

    if (!staticFile) {
      res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
      res.end("Not found");
      return;
    }

    const filePath = path.join(root, staticFile.fileName);
    const body = await fs.readFile(filePath);
    res.writeHead(200, {
      "Content-Type": staticFile.contentType,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
    });
    res.end(req.method === "HEAD" ? undefined : body);
  } catch (error) {
    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Not found");
  }
}

const server = http.createServer((req, res) => {
  const requestUrl = new URL(req.url, `http://${host}:${port}`);

  if (req.method === "GET" && requestUrl.pathname === "/api/auth/status") {
    handleAuthStatusApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/auth/login") {
    handleAuthLoginApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/auth/logout") {
    handleAuthLogoutApi(req, res);
    return;
  }

  if (requestUrl.pathname.startsWith("/api/") && !readSession(req)) {
    sendJson(res, 401, { error: "Требуется вход в rm-direct." });
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/direct-clients") {
    handleDirectClientsApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/geo-regions") {
    handleGeoRegionsApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/create-campaign-draft") {
    handleCreateCampaignDraftApi(req, res);
    return;
  }

  if (req.method === "POST" && requestUrl.pathname === "/api/preview-campaign") {
    handlePreviewCampaignApi(req, res);
    return;
  }

  if (req.method === "GET" || req.method === "HEAD") {
    handleStatic(req, res);
    return;
  }

  res.writeHead(405, { "Content-Type": "text/plain; charset=utf-8" });
  res.end("Method not allowed");
});

globalThis.directClientsServer = server;

server.listen(port, host, () => {
  console.log(`Server is running: http://${host}:${port}/index.html`);
});

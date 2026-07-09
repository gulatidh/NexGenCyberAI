/**
 * NexGenCyberAI – Azure Entra ID MSAL Configuration
 * All values come from environment variables (REACT_APP_*).
 * Set these in .env.local for development or as App Service config in production.
 */
import { Configuration, BrowserCacheLocation, LogLevel } from "@azure/msal-browser";

export const msalConfig: Configuration = {
  auth: {
    clientId: process.env.REACT_APP_AZURE_CLIENT_ID || "",
    // "organizations" restricts login to work/school accounts — personal
    // outlook.com / hotmail.com accounts are blocked at the Microsoft login page.
    authority: `https://login.microsoftonline.com/${process.env.REACT_APP_AZURE_TENANT_ID || "organizations"}`,
    redirectUri: process.env.REACT_APP_REDIRECT_URI || window.location.origin,
    postLogoutRedirectUri: window.location.origin,
  },
  cache: {
    cacheLocation: BrowserCacheLocation.LocalStorage,
  },
  system: {
    loggerOptions: {
      loggerCallback: (level, message, containsPii) => {
        if (containsPii) return;
        if (process.env.NODE_ENV === "development") console.log("[MSAL]", message);
      },
      logLevel: LogLevel.Warning,
    },
  },
};

/** Scopes requested when logging in — includes the backend API scope */
export const loginRequest = {
  scopes: [
    "openid",
    "profile",
    "email",
    `api://${process.env.REACT_APP_BACKEND_CLIENT_ID}/NexGenCyberAI.Read`,
  ],
};

/** Graph API scopes (for optional user profile picture etc.) */
export const graphRequest = {
  scopes: ["User.Read"],
};

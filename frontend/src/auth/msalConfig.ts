/**
 * NexGenCyberAI – Azure Entra ID MSAL Configuration
 * All values come from environment variables (REACT_APP_*).
 * Set these in .env.local for development or as App Service config in production.
 */
import { Configuration, BrowserCacheLocation, LogLevel } from "@azure/msal-browser";

export const msalConfig: Configuration = {
  auth: {
    clientId: import.meta.env.REACT_APP_AZURE_CLIENT_ID || "",
    // "organizations" restricts login to work/school accounts — personal
    // outlook.com / hotmail.com accounts are blocked at the Microsoft login page.
    authority: `https://login.microsoftonline.com/${import.meta.env.REACT_APP_AZURE_TENANT_ID || "organizations"}`,
    redirectUri: import.meta.env.REACT_APP_REDIRECT_URI || window.location.origin,
    postLogoutRedirectUri: window.location.origin,
  },
  cache: {
    cacheLocation: BrowserCacheLocation.LocalStorage,
  },
  system: {
    loggerOptions: {
      loggerCallback: (level, message, containsPii) => {
        if (containsPii) return;
        if (import.meta.env.DEV) console.log("[MSAL]", message);
      },
      logLevel: LogLevel.Warning,
    },
  },
};

/** Scopes requested when logging in.
 *  We use openid/profile/email + User.Read so MSAL issues a proper ID token
 *  (aud = CLIENT_ID). The backend validates the ID token directly — no
 *  Application ID URI or custom scope registration required in Azure AD.
 */
export const loginRequest = {
  scopes: ["openid", "profile", "email", "User.Read"],
};

/** Graph API scopes (for optional user profile picture etc.) */
export const graphRequest = {
  scopes: ["User.Read"],
};

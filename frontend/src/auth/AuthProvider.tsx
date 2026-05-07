/**
 * NexGenCyberAI – MSAL Auth Provider wrapper.
 * Wraps the entire app so any component can call useMsal() or useIsAuthenticated().
 */
import React from "react";
import { PublicClientApplication, EventType, AuthenticationResult } from "@azure/msal-browser";
import { MsalProvider } from "@azure/msal-react";
import { msalConfig } from "./msalConfig";

export const msalInstance = new PublicClientApplication(msalConfig);

// Set active account from login redirect response
msalInstance.addEventCallback((event) => {
  if (event.eventType === EventType.LOGIN_SUCCESS && event.payload) {
    const payload = event.payload as AuthenticationResult;
    msalInstance.setActiveAccount(payload.account);
  }
});

// Restore active account from cache on startup (e.g. after page refresh)
msalInstance.initialize().then(() => {
  if (!msalInstance.getActiveAccount()) {
    const accounts = msalInstance.getAllAccounts();
    if (accounts.length > 0) {
      msalInstance.setActiveAccount(accounts[0]);
    }
  }
});

interface Props { children: React.ReactNode; }

export function AuthProvider({ children }: Props) {
  return <MsalProvider instance={msalInstance}>{children}</MsalProvider>;
}

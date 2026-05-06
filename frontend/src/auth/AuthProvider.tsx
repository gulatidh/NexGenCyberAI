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

interface Props { children: React.ReactNode; }

export function AuthProvider({ children }: Props) {
  return <MsalProvider instance={msalInstance}>{children}</MsalProvider>;
}

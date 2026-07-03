import React, { createContext, useCallback, useContext, useState } from "react";

interface ClientContextValue {
  clientId: string;
  setClientId: (id: string) => void;
}

const ClientContext = createContext<ClientContextValue>({
  clientId: "",
  setClientId: () => {},
});

export function ClientProvider({ children }: { children: React.ReactNode }) {
  const [clientId, setClientIdState] = useState(
    () => localStorage.getItem("aegis-active-client") || ""
  );

  const setClientId = useCallback((id: string) => {
    setClientIdState(id);
    localStorage.setItem("aegis-active-client", id);
  }, []);

  return (
    <ClientContext.Provider value={{ clientId, setClientId }}>
      {children}
    </ClientContext.Provider>
  );
}

export function useActiveClient() {
  return useContext(ClientContext);
}

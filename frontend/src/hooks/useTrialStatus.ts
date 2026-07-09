import { useQuery } from "@tanstack/react-query";
import { useMsal } from "@azure/msal-react";
import { usersApi } from "../services/api";

export interface TrialInfo {
  is_trial: boolean;
  is_active: boolean;
  days_left: number | null;
  max_clients: number | null;
  max_scans: number | null;
  allowed_agent_group: string | null;
  read_only_configs: boolean;
}

export interface UserMe {
  user_id: string;
  email: string;
  display_name: string;
  is_admin: boolean;
  trial: TrialInfo;
}

export function useTrialStatus() {
  const { accounts } = useMsal();
  const isAuthenticated = accounts.length > 0;

  const { data, isLoading } = useQuery<UserMe>({
    queryKey: ["user-me"],
    queryFn: usersApi.me,
    enabled: isAuthenticated,
    staleTime: 60_000,
  });

  const trial = data?.trial;
  const isAdmin = data?.is_admin ?? false;

  return {
    isLoading,
    isAdmin,
    isTrial: trial?.is_trial ?? false,
    trialActive: trial?.is_active ?? false,
    daysLeft: trial?.days_left ?? null,
    trialExpired: (trial?.is_trial && !trial?.is_active) ?? false,
    readOnlyConfigs: trial?.read_only_configs ?? false,
    maxClients: trial?.max_clients ?? null,
    maxScans: trial?.max_scans ?? null,
    allowedAgentGroup: trial?.allowed_agent_group ?? null,
  };
}

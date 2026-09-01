export function useIsGuest(): boolean {
  return !!sessionStorage.getItem("aegis-guest-jwt");
}

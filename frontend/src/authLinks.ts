const toolsAuth = "https://tools.hacktricks.wiki";

export function authLink(page: "login" | "register"): string {
  return `${toolsAuth}/${page}.html?next=${encodeURIComponent(window.location.href)}`;
}

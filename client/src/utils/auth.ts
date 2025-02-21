import { JwtPayload, jwtDecode } from "jwt-decode";

class AuthService {
  private tokenKey = "auth_token"; // Key for localStorage

  // Get the decoded token (profile information)
  getProfile(): JwtPayload | null {
    const token = this.getToken();
    if (!token) return null;

    try {
      return jwtDecode<JwtPayload>(token);
    } catch (error) {
      console.error("Invalid token", error);
      return null;
    }
  }

  // Check if user is logged in (token exists and is valid)
  loggedIn(): boolean {
    const token = this.getToken();
    return !!token && !this.isTokenExpired(token);
  }

  // Check if token is expired
  isTokenExpired(token: string): boolean {
    try {
      const decoded = jwtDecode<JwtPayload & { exp?: number }>(token);
      if (!decoded.exp) return false; // If no expiration, assume valid

      return decoded.exp * 1000 < Date.now(); // Convert to milliseconds
    } catch (error) {
      return true; // If error occurs, assume token is invalid/expired
    }
  }

  // Get token from localStorage
  getToken(): string | null {
    return localStorage.getItem(this.tokenKey);
  }

  // Store token and redirect to homepage
  login(idToken: string) {
    localStorage.setItem(this.tokenKey, idToken);
    window.location.assign("/"); // Redirect to homepage
  }

  // Remove token and redirect to login
  logout() {
    localStorage.removeItem(this.tokenKey);
    window.location.assign("/login"); // Redirect to login page
  }
}

export default new AuthService();
